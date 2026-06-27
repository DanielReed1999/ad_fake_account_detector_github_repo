# AD Fake Account Detection System for Active Directory

A defensive Python-based detection tool for identifying suspicious or fake Active Directory accounts from exported Windows Security logs in JSON/JSONL format.

This repository is based on the diploma project **Detection of Fake Accounts in a Corporate Network (Active Directory)** and contains the detector source code, generated investigation reports, JSON findings, and CSV summaries.

## Project Goal

The project detects suspicious account activity in a corporate Active Directory environment by analyzing Windows Security events, normalizing log fields, correlating account-related event chains, calculating risk scores, and generating analyst-readable reports.

## What This Tool Detects

- account creation outside business hours or on weekends
- suspicious, privileged, service-like, or random-looking account names
- account enablement shortly after account creation
- rapid privileged group assignment
- Kerberos activity after suspicious account creation or activation
- failed and successful logon activity connected to an account timeline
- password reset/change events and directory object modification activity

## Repository Structure

```text
ad_fake_account_detector_github_repo/
├── src/
│   └── ad_fake_account_detector.py
├── outputs/
│   ├── baseline_medium_scenario/
│   │   ├── findings.json
│   │   ├── summary.csv
│   │   └── report.html
│   └── advanced_high_risk_scenario/
│       ├── findings.json
│       ├── summary.csv
│       └── report.html
├── docs/
│   ├── FINAL_Diploma_Project_Detection_of_Fake_Accounts_AD.pdf
│   ├── DETECTION_LOGIC.md
│   ├── EVENT_IDS.md
│   ├── OUTPUT_EXAMPLES.md
│   └── PORTFOLIO_REPORT.pdf
├── examples/
│   └── README.md
├── scripts/
│   └── run_detector_example.sh
├── SECURITY.md
├── requirements.txt
├── .gitignore
└── README.md
```

## Supported Event IDs

```text
4624 - Successful logon
4625 - Failed logon
4648 - Logon using explicit credentials
4672 - Special privileges assigned
4688 - Process creation
4720 - User account created
4722 - User account enabled
4723 - Password change attempt
4724 - Password reset attempt
4725 - User account disabled
4726 - User account deleted
4728 - Member added to security-enabled global group
4732 - Member added to security-enabled local group
4738 - User account changed
4740 - User account locked out
4756 - Member added to security-enabled universal group
4768 - Kerberos TGT requested
4769 - Kerberos service ticket requested
4771 - Kerberos pre-authentication failed
4776 - NTLM authentication attempted
5136 - Directory Service object modified
```

## Included Output Runs

### Baseline Medium Scenario

| Metric | Value |
|---|---:|
| Parsed events | 192 |
| Suspicious findings | 3 |
| HIGH findings | 0 |
| MEDIUM findings | 3 |

Detected accounts:

- `root` - MEDIUM (65) - suspicious_privileged_account
- `user1` - MEDIUM (50) - suspicious_privileged_account
- `suspectuser` - MEDIUM (40) - suspicious_new_or_enabled_account

### Advanced High-Risk Scenario

| Metric | Value |
|---|---:|
| Parsed events | 84 |
| Suspicious findings | 7 |
| HIGH findings | 6 |
| MEDIUM findings | 1 |

Top findings:

- `random123abc456def` - HIGH (95) - suspicious_privileged_kerberos_account
- `svc_backup` - HIGH (90) - suspicious_privileged_kerberos_account
- `admin` - HIGH (75) - suspicious_privileged_account
- `guest` - HIGH (75) - suspicious_privileged_account
- `support` - HIGH (75) - suspicious_privileged_account

## Usage

The detector expects exported Windows Security logs in JSON Lines or JSON array format.

```bash
python3 src/ad_fake_account_detector.py --input path/to/security_events.jsonl --out reports/
```

Generated outputs:

```text
summary.csv
findings.json
report.html
```

## Analyst Value

This project demonstrates:

- Windows Security Log analysis
- Active Directory account activity monitoring
- Event ID correlation
- rule-based detection logic
- weighted risk scoring
- SOC-style report generation
- Python log parsing and normalization
- HTML, CSV, and JSON investigation outputs

## Safety Scope

This is a defensive log-analysis project. It does not authenticate to systems, exploit targets, create accounts, modify Active Directory, or perform privilege escalation. It analyzes exported logs and produces investigation reports.
