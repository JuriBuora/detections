# Detection: Password spray (Windows)

## Goal
Detect password spraying: multiple failed logons targeting many distinct user accounts from the same source in a short window.

## Data sources required
- Windows Security logs in SIEM (commonly EventID 4625 for failed logon)
- Source IP field (e.g., `IpAddress`) and target account field (e.g., `Account`)

## Detection logic (high level)
Unlike brute force against one account, password spraying spreads attempts across many accounts. We group failures by source IP and flag when distinct targeted users is high within a time window.

## Query / Rule
See: `rules/kql/t0003__password-spray.kql`

## Thresholds
- Window: 15 minutes
- Condition: DistinctUsers >= 10 AND FailCount >= 10 (starting point)

## Expected false positives
- Misconfigured SSO/app trying multiple accounts
- Vulnerability scanners / audit tooling
- Internal admin scripts hitting many accounts (rare but possible)

## Tuning ideas
- Exclude known internal IP ranges and trusted jump hosts
- Require that source IP is external
- Add condition: attempts against high-value accounts (admins/VIPs)
- Correlate: successful logon (4624) from same IP after the spray

## Triage steps
1. Confirm source IP (external vs internal, geo, reputation)
2. Identify targeted accounts (are they real, are any privileged?)
3. Check for success after failures (4624 near the same time)
4. Check account lockouts / password resets triggered
5. Escalate if external + many distinct users, or if any success occurs

## MITRE ATT&CK mapping (optional)
- T1110 (Brute Force) — spraying is a common variant
