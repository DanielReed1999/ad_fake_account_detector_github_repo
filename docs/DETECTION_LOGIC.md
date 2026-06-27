# Detection Logic

The detector builds account-centered cases from Windows Security events and assigns a weighted risk score.

## Main Signals

- Account creation outside business hours or on weekends
- Suspicious usernames such as `admin`, `root`, `support`, `svc_*`, `test`, `guest`
- Random-looking account names
- Account enablement shortly after creation
- Privileged group assignment soon after account creation
- Kerberos TGT/TGS activity after suspicious account creation
- Failed and successful logons from unexpected sources
- Password reset/change attempts after account creation
- Directory object changes connected to the account case

## Risk Categories

- `identity`
- `timing`
- `privilege`
- `authentication`
- `kerberos`

## Case Output

Each case includes account name, timestamp, creator, source IP/workstation if available, risk score, risk level, reasons, and a correlated event timeline.
