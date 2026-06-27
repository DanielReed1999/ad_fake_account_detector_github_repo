#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AD Fake Account Detector (single-file, rules + scoring + correlation).

Purpose:
    Defensive analysis of exported Windows Security logs / JSONL events
    to detect suspicious newly created or suspiciously enabled AD accounts.

Input:
    JSON Lines (one JSON object per line) or JSON array with Windows Security events
    (Winlogbeat / SIEM / Sentinel / custom export preferred).

Output:
    Timestamped report folder with:
      - summary.csv
      - findings.json
      - report.html

Notes:
    - This tool is defensive. It analyzes logs only.
    - It does NOT authenticate, escalate privileges, or perform active exploitation.
    - To collect live Security logs outside exports you may need administrative rights,
      but this script itself works on exported data.

Recommended scenarios:
    - new account created outside business hours
    - rapid enablement and privileged group assignment
    - first logon from non-corporate IP
    - creator not in allow-list
    - burst creation by same creator
    - Kerberos activity shortly after account creation/enablement
"""

from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# ============================================================
# Event model / config
# ============================================================

EVENT_DESCR = {
    4624: "Successful logon",
    4625: "Failed logon",
    4648: "Logon attempted using explicit credentials",
    4672: "Special privileges assigned to new logon",
    4688: "Process creation",
    4720: "User account created",
    4722: "User account enabled",
    4723: "Attempt to change account password",
    4724: "Attempt to reset account password",
    4725: "User account disabled",
    4726: "User account deleted",
    4728: "Member added to security-enabled global group",
    4732: "Member added to security-enabled local group",
    4738: "User account was changed",
    4740: "User account locked out",
    4756: "Member added to security-enabled universal group",
    4768: "Kerberos TGT requested",
    4769: "Kerberos service ticket requested",
    4771: "Kerberos pre-authentication failed",
    4776: "NTLM authentication attempted",
    5136: "Directory Service object modified",
}

SUPPORTED_EVENT_IDS = set(EVENT_DESCR.keys())

PRIV_GROUP_DEFAULT = {
    "domain admins",
    "enterprise admins",
    "administrators",
    "account operators",
    "backup operators",
    "schema admins",
    "server operators",
    "print operators",
    "dnsadmins",
}

# suspicious role-like names
SUSP_NAME_RE = re.compile(
    r"(?i)^(?:admin|administrator|root|support|helpdesk|svc|service|backup|sql|oracle|test|temp|guest|user)\b"
)

# optional org-specific "normal-ish" name pattern can be expanded later
NORMAL_NAME_HINT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{2,32}$")

DEFAULT_WEIGHTS = {
    # positive risk
    "offhours": 20,
    "creator_not_allowed": 15,
    "creator_host_not_allowed": 10,
    "susp_name": 10,
    "rand_name": 10,
    "enabled_soon": 10,
    "priv_group": 35,
    "special_priv": 20,
    "first_logon_ext_ip": 15,
    "many_fails": 10,
    "explicit_creds": 10,
    "pwd_reset_soon": 10,
    "acct_changed_soon": 10,
    "acct_disabled_soon": 5,
    "acct_deleted_soon": 15,
    "lockout_after_create": 10,
    "kerberos_tgt_soon": 5,
    "kerberos_tgs_burst": 10,
    "kerberos_failures": 10,
    "ntlm_attempts": 5,
    "ds_object_changed": 10,
    "burst_creator": 20,
    "activity_chain": 15,
    "enabled_without_create": 15,

    # negative / normalization
    "creator_allowed_bonus": -10,
    "creator_host_allowed_bonus": -5,
    "business_hours_bonus": -5,
    "corp_ip_bonus": -5,
    "normal_name_bonus": -5,
}

GROUP_ADD_EVENT_IDS = {4728, 4732, 4756}
CASE_WINDOW_HOURS_DEFAULT = 24
BURST_WINDOW_MINUTES_DEFAULT = 10
BURST_COUNT_THRESHOLD_DEFAULT = 3

# ============================================================
# Helpers
# ============================================================

def _try_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None

def norm_str(x: Any) -> Optional[str]:
    if x is None:
        return None
    s = str(x).strip()
    return s if s else None

def get_path(d: Dict[str, Any], *paths: str, default=None):
    for p in paths:
        cur = d
        ok = True
        for part in p.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok:
            return cur
    return default

def parse_ts(evt: Dict[str, Any]) -> Optional[datetime]:
    val = get_path(
        evt,
        "@timestamp",
        "timestamp",
        "TimeCreated",
        "time_created",
        "winlog.time_created",
        "event.created",
        "event.ingested",
    )
    if val is None:
        return None

    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)

    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        except Exception:
            return None

    if isinstance(val, str):
        s = val.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None

def is_weekend(dt: datetime) -> bool:
    return dt.weekday() >= 5

def outside_business_hours(dt: datetime, start_hour: int, end_hour: int) -> bool:
    h = dt.hour
    if start_hour < end_hour:
        return not (start_hour <= h < end_hour)
    return (end_hour <= h < start_hour)

def looks_random(name: str) -> bool:
    if not name:
        return False
    n = name.strip()
    if n.endswith("$"):
        # machine account
        return False
    if len(n) >= 14:
        has_alpha = any(c.isalpha() for c in n)
        has_digit = any(c.isdigit() for c in n)
        has_sep = any(c in "._- " for c in n)
        return has_alpha and has_digit and not has_sep
    return False

def normalize_group(g: Optional[str]) -> Optional[str]:
    return g.strip().lower() if g else None

def normalize_identity(x: Optional[str]) -> Optional[str]:
    """
    Normalize user / member identity:
      - strips domain prefix DOMAIN\\user
      - strips UPN user@domain if present
      - extracts CN=user from DN if present
      - lowercases
    """
    if not x:
        return None
    s = x.strip()

    # DN like CN=user1,OU=...
    m = re.search(r"(?i)\bCN=([^,]+)", s)
    if m:
        s = m.group(1).strip()

    # DOMAIN\user
    if "\\" in s:
        s = s.split("\\")[-1]

    # UPN user@domain
    if "@" in s:
        s = s.split("@")[0]

    return s.strip().lower() if s.strip() else None

def member_matches_account(member_name: Optional[str], account: str) -> bool:
    if not member_name or not account:
        return False
    m = normalize_identity(member_name)
    a = normalize_identity(account)
    return bool(m and a and m == a)

def parse_cidrs(cidrs: List[str]) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c.strip(), strict=False))
        except Exception:
            pass
    return nets

def in_any_cidr(ip: str, nets: List[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in nets)
    except Exception:
        return False

def load_list_file(path: Optional[str]) -> Optional[set]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    out = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out

def lc_set(xs: Optional[Set[str]]) -> Set[str]:
    if not xs:
        return set()
    return {str(x).strip().lower() for x in xs if str(x).strip()}

def safe(s: Any) -> str:
    return html.escape(str(s)) if s is not None else ""

def fmt_dt(dt: datetime) -> str:
    return dt.isoformat()

# ============================================================
# Event normalization
# ============================================================

@dataclass
class NormEvent:
    ts: datetime
    event_id: int
    host: Optional[str] = None
    channel: Optional[str] = None
    record_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    # identity context
    subject_user: Optional[str] = None
    subject_domain: Optional[str] = None
    subject_logon_id: Optional[str] = None

    target_user: Optional[str] = None
    target_domain: Optional[str] = None
    target_sid: Optional[str] = None
    target_logon_id: Optional[str] = None

    member_name: Optional[str] = None
    group_name: Optional[str] = None

    # auth/session
    ip_address: Optional[str] = None
    workstation: Optional[str] = None
    logon_type: Optional[str] = None
    process_name: Optional[str] = None

    # optional DS / account change fields
    object_class: Optional[str] = None
    object_dn: Optional[str] = None
    attribute_name: Optional[str] = None
    operation_type: Optional[str] = None

def extract_event_data(evt: Dict[str, Any]) -> Dict[str, Any]:
    ed = get_path(evt, "winlog.event_data", "EventData", "event_data", default={})
    return ed if isinstance(ed, dict) else {}

def normalize(evt: Dict[str, Any]) -> Optional[NormEvent]:
    ts = parse_ts(evt)
    if not ts:
        return None

    event_id = _try_int(get_path(evt, "winlog.event_id", "EventID", "event_id", "Id", "id"))
    if event_id is None or event_id not in SUPPORTED_EVENT_IDS:
        return None

    host = norm_str(get_path(evt, "host.name", "Computer", "winlog.computer_name", "computer_name", "MachineName"))
    channel = norm_str(get_path(evt, "winlog.channel", "Channel", "channel"))
    record_id = norm_str(get_path(evt, "winlog.record_id", "RecordID", "record_id"))

    ed = extract_event_data(evt)

    def ed_get(*keys: str) -> Optional[str]:
        for k in keys:
            if k in ed:
                return norm_str(ed.get(k))
        lower = {str(k).lower(): k for k in ed.keys()}
        for k in keys:
            lk = k.lower()
            if lk in lower:
                return norm_str(ed.get(lower[lk]))
        return None

    return NormEvent(
        ts=ts,
        event_id=event_id,
        host=host,
        channel=channel,
        record_id=record_id,
        raw=evt,
        subject_user=ed_get("SubjectUserName", "SubjectUser"),
        subject_domain=ed_get("SubjectDomainName", "SubjectDomain"),
        subject_logon_id=ed_get("SubjectLogonId", "SubjectLogonID"),
        target_user=ed_get("TargetUserName", "TargetUser"),
        target_domain=ed_get("TargetDomainName", "TargetDomain"),
        target_sid=ed_get("TargetSid", "TargetSID"),
        target_logon_id=ed_get("TargetLogonId", "TargetLogonID"),
        member_name=ed_get("MemberName"),
        group_name=ed_get("GroupName"),
        ip_address=ed_get("IpAddress", "SourceNetworkAddress"),
        workstation=ed_get("WorkstationName", "Workstation"),
        logon_type=ed_get("LogonType"),
        process_name=ed_get("NewProcessName", "ProcessName"),
        object_class=ed_get("ObjectClass"),
        object_dn=ed_get("ObjectDN", "ObjectName", "ObjectDNName"),
        attribute_name=ed_get("AttributeLDAPDisplayName", "AttributeName"),
        operation_type=ed_get("OperationType"),
    )

# ============================================================
# Finding model
# ============================================================

@dataclass
class Finding:
    account: str
    created_at: datetime
    case_origin: str
    risk_score: int
    risk_level: str
    risk_categories: List[str]
    case_type: str
    reasons: List[str]
    creator: Optional[str]
    creator_ip: Optional[str]
    creator_workstation: Optional[str]
    timeline: List[NormEvent]

def risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"

def derive_case_type(categories: Set[str], timeline: List[NormEvent]) -> str:
    has_priv = "privilege" in categories
    has_kerb = "kerberos" in categories
    has_auth = "authentication" in categories
    has_timing = "timing" in categories

    if has_priv and has_kerb:
        return "suspicious_privileged_kerberos_account"
    if has_priv:
        return "suspicious_privileged_account"
    if has_auth and has_timing:
        return "suspicious_account_lifecycle"
    if has_kerb:
        return "suspicious_kerberos_context"
    return "suspicious_new_or_enabled_account"

# ============================================================
# Input ingest
# ============================================================

def read_json_lines(path: Path) -> Iterable[Dict[str, Any]]:
    """
    Supports:
      - JSONL (one object per line)
      - JSON array
    """
    with path.open("r", encoding="utf-8") as f:
        first_nonempty = None
        pos = f.tell()
        for line in f:
            if line.strip():
                first_nonempty = line.lstrip()
                break
        f.seek(pos)

        if first_nonempty and first_nonempty.startswith("["):
            try:
                data = json.load(f)
                if isinstance(data, list):
                    for obj in data:
                        if isinstance(obj, dict):
                            yield obj
                return
            except Exception:
                pass

        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

# ============================================================
# Indexing / correlation
# ============================================================

def build_session_index(events: List[NormEvent]) -> Dict[str, NormEvent]:
    """
    Map TargetLogonId -> earliest 4624 event for session source context.
    """
    idx: Dict[str, NormEvent] = {}
    for e in events:
        if e.event_id == 4624 and e.target_logon_id:
            if e.target_logon_id not in idx or e.ts < idx[e.target_logon_id].ts:
                idx[e.target_logon_id] = e
    return idx

def collect_created_accounts(events: List[NormEvent]) -> Dict[str, NormEvent]:
    created: Dict[str, NormEvent] = {}
    for e in events:
        if e.event_id == 4720 and e.target_user:
            acct = normalize_identity(e.target_user)
            if acct and (acct not in created or e.ts < created[acct].ts):
                created[acct] = e
    return created

def collect_enabled_without_create(
    events: List[NormEvent],
    created: Dict[str, NormEvent],
) -> Dict[str, NormEvent]:
    enabled: Dict[str, NormEvent] = {}
    for e in events:
        if e.event_id == 4722 and e.target_user:
            acct = normalize_identity(e.target_user)
            if acct and acct not in created:
                if acct not in enabled or e.ts < enabled[acct].ts:
                    enabled[acct] = e
    return enabled

def build_creator_burst_index(
    created_events: Dict[str, NormEvent],
    burst_window_minutes: int,
) -> Dict[str, int]:
    """
    For each account -> count how many accounts were created by same creator
    within ±window around this creation.
    """
    by_creator: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    for acct, e in created_events.items():
        creator = normalize_identity(e.subject_user)
        if creator:
            by_creator[creator].append((e.ts, acct))

    out: Dict[str, int] = {}
    delta = timedelta(minutes=burst_window_minutes)

    for creator, items in by_creator.items():
        items.sort(key=lambda x: x[0])
        for i, (ts_i, acct_i) in enumerate(items):
            cnt = 0
            for ts_j, _acct_j in items:
                if abs(ts_j - ts_i) <= delta:
                    cnt += 1
            out[acct_i] = cnt
    return out

def build_account_timeline(
    events: List[NormEvent],
    account: str,
    case_start: datetime,
    window_hours: int,
) -> List[NormEvent]:
    end = case_start + timedelta(hours=window_hours)
    a = normalize_identity(account)
    out: List[NormEvent] = []

    for e in events:
        if e.ts < case_start or e.ts > end:
            continue

        match = False
        if e.target_user and normalize_identity(e.target_user) == a:
            match = True
        elif e.member_name and member_matches_account(e.member_name, account):
            match = True
        elif e.object_dn and a and a in e.object_dn.lower():
            match = True

        if match:
            out.append(e)

    out.sort(key=lambda x: x.ts)
    return out

# ============================================================
# Analysis
# ============================================================

def analyze(
    events: List[NormEvent],
    allowed_creators: Optional[Set[str]],
    allowed_creator_hosts: Optional[Set[str]],
    priv_groups: Set[str],
    business_start: int,
    business_end: int,
    corporate_cidrs: List[ipaddress._BaseNetwork],
    threshold: int,
    case_window_hours: int,
    burst_window_minutes: int,
    burst_threshold: int,
    weights: Dict[str, int],
) -> List[Finding]:
    allowed_creators_lc = lc_set(allowed_creators)
    allowed_creator_hosts_lc = lc_set(allowed_creator_hosts)

    session_idx = build_session_index(events)
    created = collect_created_accounts(events)
    enabled_only = collect_enabled_without_create(events, created)

    burst_counts = build_creator_burst_index(created, burst_window_minutes)

    findings: List[Finding] = []

    # cases from created accounts
    case_defs: List[Tuple[str, NormEvent, str]] = []
    for acct, evt in created.items():
        case_defs.append((acct, evt, "created"))
    for acct, evt in enabled_only.items():
        case_defs.append((acct, evt, "enabled_only"))

    for account, origin_evt, case_origin in case_defs:
        score = 0
        reasons: List[str] = []
        categories: Set[str] = set()

        # key people/context
        creator = normalize_identity(origin_evt.subject_user) if origin_evt.subject_user else None
        creator_ip = None
        creator_ws = None

        if origin_evt.subject_logon_id and origin_evt.subject_logon_id in session_idx:
            sess = session_idx[origin_evt.subject_logon_id]
            creator_ip = sess.ip_address
            creator_ws = normalize_identity(sess.workstation or sess.host)

        timeline = build_account_timeline(events, account, origin_evt.ts, case_window_hours)

        added_keys: Set[str] = set()

        def add_once(key: str, text: str, category: str):
            nonlocal score
            if key in added_keys:
                return
            added_keys.add(key)
            delta = weights.get(key, 0)
            score += delta
            sign = f"{delta:+d}"
            reasons.append(f"{text} ({sign})")
            categories.add(category)

        # ------------------------
        # normalization / reductions first
        # ------------------------
        if creator and creator in allowed_creators_lc:
            add_once("creator_allowed_bonus", f"Создатель в allow-list: {creator}", "identity")

        if creator_ws and allowed_creator_hosts_lc and creator_ws in allowed_creator_hosts_lc:
            add_once("creator_host_allowed_bonus", f"Источник создания в allow-list host/workstation: {creator_ws}", "identity")

        if not outside_business_hours(origin_evt.ts, business_start, business_end) and not is_weekend(origin_evt.ts):
            add_once("business_hours_bonus", "Создание/активация в рабочее время", "timing")

        if creator_ip and corporate_cidrs and in_any_cidr(creator_ip, corporate_cidrs):
            add_once("corp_ip_bonus", f"Источник создания из корпоративного диапазона: {creator_ip}", "authentication")

        if NORMAL_NAME_HINT_RE.match(account or "") and not SUSP_NAME_RE.search(account or "") and not looks_random(account or ""):
            add_once("normal_name_bonus", f"Имя аккаунта выглядит типовым: {account}", "identity")

        # ------------------------
        # core positive rules
        # ------------------------
        if outside_business_hours(origin_evt.ts, business_start, business_end) or is_weekend(origin_evt.ts):
            add_once("offhours", "Создание/активация аккаунта вне рабочих часов или в выходной день", "timing")

        if creator and allowed_creators_lc and creator not in allowed_creators_lc:
            add_once("creator_not_allowed", f"Создатель аккаунта не в allow-list: {creator}", "identity")

        if creator_ws and allowed_creator_hosts_lc and creator_ws not in allowed_creator_hosts_lc:
            add_once("creator_host_not_allowed", f"Создание выполнено с неразрешённого host/workstation: {creator_ws}", "identity")

        if SUSP_NAME_RE.search(account or ""):
            add_once("susp_name", f"Имя аккаунта похоже на служебное/привилегированное: {account}", "identity")

        if looks_random(account or ""):
            add_once("rand_name", f"Имя аккаунта похоже на автоматически сгенерированное: {account}", "identity")

        if case_origin == "enabled_only":
            add_once("enabled_without_create", "Зафиксирована активация аккаунта без наблюдаемого события создания", "timing")

        # burst creation by same creator
        if case_origin == "created":
            burst_count = burst_counts.get(account, 1)
            if creator and burst_count >= burst_threshold:
                add_once(
                    "burst_creator",
                    f"Один и тот же creator создал несколько аккаунтов в коротком окне: {creator}, count={burst_count}",
                    "timing",
                )

        # timeline-driven logic
        enable_evt = None
        group_hits: List[str] = []
        first_logon = None
        failed_logons = 0
        kerberos_tgt_count = 0
        kerberos_tgs_count = 0
        kerberos_fails = 0
        ntlm_attempts = 0
        has_special_priv = False
        has_explicit_creds = False
        has_pwd_reset = False
        has_acct_changed = False
        has_acct_disabled = False
        has_acct_deleted = False
        has_lockout = False
        has_ds_change = False

        for e in timeline:
            if e.event_id == 4722 and enable_evt is None:
                enable_evt = e

            if e.event_id in GROUP_ADD_EVENT_IDS and e.group_name:
                g = normalize_group(e.group_name)
                if g and g in priv_groups:
                    group_hits.append(e.group_name)

            if e.event_id == 4624 and first_logon is None:
                first_logon = e

            if e.event_id == 4625:
                failed_logons += 1

            if e.event_id == 4672:
                has_special_priv = True

            if e.event_id == 4648:
                has_explicit_creds = True

            if e.event_id in (4723, 4724):
                # change/reset password near case start
                if (e.ts - origin_evt.ts).total_seconds() <= 30 * 60:
                    has_pwd_reset = True

            if e.event_id == 4738:
                if (e.ts - origin_evt.ts).total_seconds() <= 30 * 60:
                    has_acct_changed = True

            if e.event_id == 4725 and (e.ts - origin_evt.ts).total_seconds() <= 24 * 3600:
                has_acct_disabled = True

            if e.event_id == 4726 and (e.ts - origin_evt.ts).total_seconds() <= 24 * 3600:
                has_acct_deleted = True

            if e.event_id == 4740:
                has_lockout = True

            if e.event_id == 4768:
                kerberos_tgt_count += 1

            if e.event_id == 4769:
                kerberos_tgs_count += 1

            if e.event_id == 4771:
                kerberos_fails += 1

            if e.event_id == 4776:
                ntlm_attempts += 1

            if e.event_id == 5136:
                has_ds_change = True

        if enable_evt and (enable_evt.ts - origin_evt.ts).total_seconds() <= 15 * 60:
            add_once("enabled_soon", "Аккаунт включён вскоре после создания/обнаружения (<=15 минут)", "timing")

        if group_hits:
            add_once("priv_group", f"Добавление в привилегированные группы: {', '.join(sorted(set(group_hits)))}", "privilege")

        if has_special_priv:
            add_once("special_priv", "Зафиксировано получение специальных привилегий при входе (4672)", "privilege")

        if has_explicit_creds:
            add_once("explicit_creds", "Обнаружена попытка входа с явно заданными учётными данными (4648)", "authentication")

        if has_pwd_reset:
            add_once("pwd_reset_soon", "Вскоре после создания/активации зафиксирована попытка смены/сброса пароля", "identity")

        if has_acct_changed:
            add_once("acct_changed_soon", "Вскоре после создания/активации были изменены параметры аккаунта (4738)", "identity")

        if has_acct_disabled:
            add_once("acct_disabled_soon", "Аккаунт был быстро отключён после создания/активации", "identity")

        if has_acct_deleted:
            add_once("acct_deleted_soon", "Аккаунт был удалён вскоре после создания/активации", "identity")

        if has_lockout:
            add_once("lockout_after_create", "После создания/активации произошла блокировка аккаунта (4740)", "authentication")

        # First logon IP logic
        if first_logon and first_logon.ip_address and corporate_cidrs:
            if not in_any_cidr(first_logon.ip_address, corporate_cidrs):
                add_once("first_logon_ext_ip", f"Первый вход выполнен с IP вне корпоративных диапазонов: {first_logon.ip_address}", "authentication")

        if failed_logons >= 5:
            add_once("many_fails", f"Зафиксировано много неуспешных попыток входа (4625): {failed_logons}", "authentication")

        # Kerberos logic
        if kerberos_tgt_count >= 1:
            # only meaningful if shortly after case start
            first_tgt = next((e for e in timeline if e.event_id == 4768), None)
            if first_tgt and (first_tgt.ts - origin_evt.ts).total_seconds() <= 15 * 60:
                add_once("kerberos_tgt_soon", "Kerberos TGT-запрос зафиксирован вскоре после создания/активации аккаунта (4768)", "kerberos")

        if kerberos_tgs_count >= 3:
            add_once("kerberos_tgs_burst", f"Серия Kerberos service ticket запросов (4769): {kerberos_tgs_count}", "kerberos")

        if kerberos_fails >= 3:
            add_once("kerberos_failures", f"Множественные Kerberos pre-authentication failures (4771): {kerberos_fails}", "kerberos")

        if ntlm_attempts >= 3:
            add_once("ntlm_attempts", f"Зафиксированы повторяющиеся NTLM authentication attempts (4776): {ntlm_attempts}", "authentication")

        if has_ds_change:
            add_once("ds_object_changed", "Обнаружены изменения объекта каталога Directory Services (5136)", "identity")

        # activity chain
        chain_hits = 0
        for key in ("enabled_soon", "priv_group", "special_priv", "first_logon_ext_ip", "explicit_creds", "kerberos_tgt_soon"):
            if key in added_keys:
                chain_hits += 1
        if chain_hits >= 3:
            add_once("activity_chain", "Обнаружена ускоренная цепочка событий после создания/активации аккаунта", "timing")

        # clamp minimum
        if score < 0:
            score = 0

        lvl = risk_level(score)
        case_type = derive_case_type(categories, timeline)

        if score >= threshold:
            findings.append(
                Finding(
                    account=account,
                    created_at=origin_evt.ts,
                    case_origin=case_origin,
                    risk_score=score,
                    risk_level=lvl,
                    risk_categories=sorted(categories),
                    case_type=case_type,
                    reasons=reasons,
                    creator=creator,
                    creator_ip=creator_ip,
                    creator_workstation=creator_ws,
                    timeline=timeline,
                )
            )

    findings.sort(key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}[f.risk_level], -f.risk_score, f.account))
    return findings

# ============================================================
# Reporting
# ============================================================

def write_reports(outdir: Path, findings: List[Finding], all_events: List[NormEvent]) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    # ---------------- summary.csv ----------------
    csv_path = outdir / "summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "account",
            "case_origin",
            "case_type",
            "risk_level",
            "risk_score",
            "created_at",
            "creator",
            "creator_ip",
            "creator_workstation",
            "risk_categories",
            "reasons",
        ])
        for r in findings:
            w.writerow([
                r.account,
                r.case_origin,
                r.case_type,
                r.risk_level,
                r.risk_score,
                fmt_dt(r.created_at),
                r.creator or "",
                r.creator_ip or "",
                r.creator_workstation or "",
                ", ".join(r.risk_categories),
                " | ".join(r.reasons),
            ])

    # ---------------- findings.json ----------------
    json_path = outdir / "findings.json"
    payload = []
    for r in findings:
        payload.append({
            "account": r.account,
            "created_at": fmt_dt(r.created_at),
            "case_origin": r.case_origin,
            "case_type": r.case_type,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "risk_categories": r.risk_categories,
            "creator": r.creator,
            "creator_ip": r.creator_ip,
            "creator_workstation": r.creator_workstation,
            "reasons": r.reasons,
            "timeline": [
                {
                    "ts": fmt_dt(e.ts),
                    "event_id": e.event_id,
                    "event_desc": EVENT_DESCR.get(e.event_id, "Unknown"),
                    "host": e.host,
                    "subject_user": e.subject_user,
                    "target_user": e.target_user,
                    "group_name": e.group_name,
                    "member_name": e.member_name,
                    "ip_address": e.ip_address,
                    "workstation": e.workstation,
                    "logon_type": e.logon_type,
                    "process_name": e.process_name,
                    "object_class": e.object_class,
                    "object_dn": e.object_dn,
                    "attribute_name": e.attribute_name,
                    "operation_type": e.operation_type,
                }
                for e in r.timeline
            ],
        })
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    # ---------------- report.html ----------------
    html_path = outdir / "report.html"

    level_counts = Counter(r.risk_level for r in findings)
    case_type_counts = Counter(r.case_type for r in findings)
    category_counts = Counter(cat for r in findings for cat in r.risk_categories)
    reason_counts = Counter()
    for r in findings:
        for reason in r.reasons:
            reason_counts[reason.split(" (")[0]] += 1

    lines: List[str] = []
    lines.append("<html><head><meta charset='utf-8'>")
    lines.append("""
<style>
body{font-family:Arial,Helvetica,sans-serif;margin:20px}
table{border-collapse:collapse;width:100%;margin:10px 0}
th,td{border:1px solid #ddd;padding:8px;font-size:12px;vertical-align:top}
th{background:#f3f3f3}
.HIGH{background:#ffe6e6}
.MEDIUM{background:#fff7e6}
.LOW{background:#e6f0ff}
.INFO{background:#f7f7f7}
code{background:#f6f6f6;padding:2px 4px}
small{color:#666}
</style>
""")
    lines.append("</head><body>")
    lines.append(f"<h1>AD Fake Account Detection Report</h1>")
    lines.append(f"<p>Generated: {safe(datetime.now(timezone.utc).isoformat())}</p>")
    lines.append(f"<p>Total parsed events: {len(all_events)}</p>")
    lines.append(f"<p>Total suspicious findings: {len(findings)}</p>")

    # Overview
    lines.append("<h2>Overview</h2>")
    lines.append("<table><tr><th>Metric</th><th>Value</th></tr>")
    for lvl in ("HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"<tr><td>Findings: {lvl}</td><td>{level_counts.get(lvl, 0)}</td></tr>")
    lines.append("</table>")

    # Case type distribution
    lines.append("<h2>Case type distribution</h2>")
    lines.append("<table><tr><th>Case type</th><th>Count</th></tr>")
    for ctype, cnt in case_type_counts.most_common():
        lines.append(f"<tr><td>{safe(ctype)}</td><td>{cnt}</td></tr>")
    lines.append("</table>")

    # Category distribution
    lines.append("<h2>Risk category distribution</h2>")
    lines.append("<table><tr><th>Category</th><th>Count</th></tr>")
    for cat, cnt in category_counts.most_common():
        lines.append(f"<tr><td>{safe(cat)}</td><td>{cnt}</td></tr>")
    lines.append("</table>")

    # Top reasons
    lines.append("<h2>Most frequent triggers</h2>")
    lines.append("<table><tr><th>Trigger</th><th>Count</th></tr>")
    for reason, cnt in reason_counts.most_common(15):
        lines.append(f"<tr><td>{safe(reason)}</td><td>{cnt}</td></tr>")
    lines.append("</table>")

    # Summary
    lines.append("<h2>Summary</h2>")
    lines.append("""
<table>
<tr>
  <th>Account</th>
  <th>Case Origin</th>
  <th>Case Type</th>
  <th>Risk</th>
  <th>Score</th>
  <th>Created / Activated</th>
  <th>Creator</th>
  <th>Creator IP</th>
  <th>Creator WS</th>
  <th>Categories</th>
  <th>Reasons</th>
</tr>
""")
    for r in findings:
        lines.append(
            f"<tr class='{safe(r.risk_level)}'>"
            f"<td><a href='#{safe(r.account)}'>{safe(r.account)}</a></td>"
            f"<td>{safe(r.case_origin)}</td>"
            f"<td>{safe(r.case_type)}</td>"
            f"<td>{safe(r.risk_level)}</td>"
            f"<td>{safe(r.risk_score)}</td>"
            f"<td>{safe(fmt_dt(r.created_at))}</td>"
            f"<td>{safe(r.creator)}</td>"
            f"<td>{safe(r.creator_ip)}</td>"
            f"<td>{safe(r.creator_workstation)}</td>"
            f"<td>{safe(', '.join(r.risk_categories))}</td>"
            f"<td>{safe(' | '.join(r.reasons))}</td>"
            "</tr>"
        )
    lines.append("</table>")

    # Details per finding
    lines.append("<h2>Details</h2>")
    for r in findings:
        lines.append(f"<h3 id='{safe(r.account)}'>{safe(r.account)} — {safe(r.risk_level)} ({safe(r.risk_score)})</h3>")
        lines.append("<ul>")
        lines.append(f"<li><b>Case origin:</b> {safe(r.case_origin)}</li>")
        lines.append(f"<li><b>Case type:</b> {safe(r.case_type)}</li>")
        lines.append(f"<li><b>Created / activated:</b> {safe(fmt_dt(r.created_at))}</li>")
        lines.append(f"<li><b>Creator:</b> {safe(r.creator)}</li>")
        lines.append(f"<li><b>Creator source:</b> IP={safe(r.creator_ip)}; WS={safe(r.creator_workstation)}</li>")
        lines.append(f"<li><b>Risk categories:</b> {safe(', '.join(r.risk_categories))}</li>")
        lines.append(f"<li><b>Reasons:</b> {safe(' | '.join(r.reasons))}</li>")
        lines.append("</ul>")

        lines.append("""
<table>
<tr>
  <th>Time</th>
  <th>EventID</th>
  <th>Description</th>
  <th>Host</th>
  <th>SubjectUser</th>
  <th>TargetUser</th>
  <th>Group</th>
  <th>Member</th>
  <th>IP</th>
  <th>Workstation</th>
  <th>LogonType</th>
  <th>Process</th>
  <th>Attribute</th>
</tr>
""")
        for e in r.timeline:
            attr_info = ""
            if e.attribute_name or e.operation_type or e.object_dn:
                attr_info = f"{e.attribute_name or ''} {e.operation_type or ''} {e.object_dn or ''}".strip()
            lines.append(
                "<tr>"
                f"<td>{safe(fmt_dt(e.ts))}</td>"
                f"<td>{safe(e.event_id)}</td>"
                f"<td>{safe(EVENT_DESCR.get(e.event_id, 'Unknown'))}</td>"
                f"<td>{safe(e.host)}</td>"
                f"<td>{safe(e.subject_user)}</td>"
                f"<td>{safe(e.target_user)}</td>"
                f"<td>{safe(e.group_name)}</td>"
                f"<td>{safe(e.member_name)}</td>"
                f"<td>{safe(e.ip_address)}</td>"
                f"<td>{safe(e.workstation)}</td>"
                f"<td>{safe(e.logon_type)}</td>"
                f"<td>{safe(e.process_name)}</td>"
                f"<td>{safe(attr_info)}</td>"
                "</tr>"
            )
        lines.append("</table>")

    lines.append("</body></html>")
    html_path.write_text("\n".join(lines), encoding="utf-8")

# ============================================================
# Main
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description="Detect suspicious/fake AD accounts from exported Windows Security logs (JSONL/JSON)."
    )
    ap.add_argument("--input", required=True, nargs="+", help="Path(s) to JSONL / JSON exported events.")
    ap.add_argument("--out", default="reports", help="Output directory root.")
    ap.add_argument("--threshold", type=int, default=40, help="Risk score threshold to include in report.")
    ap.add_argument("--business-start", type=int, default=9, help="Business hours start (0-23).")
    ap.add_argument("--business-end", type=int, default=18, help="Business hours end (0-23).")
    ap.add_argument("--allowed-creators", default=None, help="File with allowed admin creators, one per line.")
    ap.add_argument("--allowed-creator-hosts", default=None, help="File with allowed creator hosts/workstations, one per line.")
    ap.add_argument("--priv-groups", default=None, help="File with privileged group names, one per line.")
    ap.add_argument("--corp-cidr", action="append", default=[], help="Corporate CIDR, repeatable. Example: 10.0.0.0/8")
    ap.add_argument("--case-window-hours", type=int, default=CASE_WINDOW_HOURS_DEFAULT, help="Case timeline window after creation/activation.")
    ap.add_argument("--burst-window-minutes", type=int, default=BURST_WINDOW_MINUTES_DEFAULT, help="Window for creator burst account creation.")
    ap.add_argument("--burst-threshold", type=int, default=BURST_COUNT_THRESHOLD_DEFAULT, help="How many accounts by same creator in burst window triggers burst rule.")
    args = ap.parse_args()

    allowed_creators = load_list_file(args.allowed_creators)
    allowed_creator_hosts = load_list_file(args.allowed_creator_hosts)

    priv_groups = set(PRIV_GROUP_DEFAULT)
    extra_priv = load_list_file(args.priv_groups)
    if extra_priv:
        priv_groups |= {x.strip().lower() for x in extra_priv if x.strip()}

    corp_nets = parse_cidrs(args.corp_cidr)

    # Read & normalize
    events: List[NormEvent] = []
    for inp in args.input:
        p = Path(inp)
        if not p.exists():
            print(f"[WARN] Input not found: {p}")
            continue

        parsed = 0
        kept = 0
        for obj in read_json_lines(p):
            parsed += 1
            ne = normalize(obj)
            if ne:
                events.append(ne)
                kept += 1
        print(f"[INFO] {p.name}: parsed={parsed}, normalized={kept}")

    if not events:
        print("No valid events parsed. Check input format and event structure.")
        return

    events.sort(key=lambda e: e.ts)

    findings = analyze(
        events=events,
        allowed_creators=allowed_creators,
        allowed_creator_hosts=allowed_creator_hosts,
        priv_groups=priv_groups,
        business_start=args.business_start,
        business_end=args.business_end,
        corporate_cidrs=corp_nets,
        threshold=args.threshold,
        case_window_hours=args.case_window_hours,
        burst_window_minutes=args.burst_window_minutes,
        burst_threshold=args.burst_threshold,
        weights=DEFAULT_WEIGHTS,
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_UTC")
    outdir = Path(args.out) / f"ad_fake_accounts_{stamp}"
    write_reports(outdir, findings, events)

    print(f"[INFO] Total normalized events: {len(events)}")
    print(f"[INFO] Suspicious findings (score>={args.threshold}): {len(findings)}")
    print(f"[INFO] Report folder: {outdir.resolve()}")
    print(f"[INFO] Open: {outdir / 'report.html'}")

if __name__ == "__main__":
    main()


