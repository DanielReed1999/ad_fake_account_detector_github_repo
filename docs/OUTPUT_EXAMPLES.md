# Output Examples

## Baseline Medium Scenario

| Account | Risk | Score | Case Type |
|---|---|---:|---|
| `root` | MEDIUM | 65 | suspicious_privileged_account |
| `user1` | MEDIUM | 50 | suspicious_privileged_account |
| `suspectuser` | MEDIUM | 40 | suspicious_new_or_enabled_account |

## Advanced High-Risk Scenario

| Account | Risk | Score | Case Type |
|---|---|---:|---|
| `random123abc456def` | HIGH | 95 | suspicious_privileged_kerberos_account |
| `svc_backup` | HIGH | 90 | suspicious_privileged_kerberos_account |
| `admin` | HIGH | 75 | suspicious_privileged_account |
| `guest` | HIGH | 75 | suspicious_privileged_account |
| `support` | HIGH | 75 | suspicious_privileged_account |
