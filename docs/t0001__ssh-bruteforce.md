# Detection: SSH brute force (Linux)

## Goal
Detect repeated failed SSH authentication attempts from the same source IP in a short time window.

## Data sources required
- Linux auth logs ingested into SIEM (commonly via Syslog connector)
- Table often named `Syslog` (varies by environment)

## Detection logic (high level)
Brute force attempts generate many `Failed password` messages from `sshd`. We extract the source IP and count failures per time window.

## Query / Rule
See: `rules/kql/t0001__ssh-bruteforce.kql`

## Thresholds
- Window: 5 minutes
- Condition: >= 10 failed attempts from same IP

## Expected false positives
- Vulnerability scanners / pentest tools (authorized)
- Misconfigured automation using wrong credentials
- A user repeatedly mistyping password (usually low volume)

## Tuning ideas
- Exclude known scanner IPs / internal admin networks
- Require multiple distinct target usernames
- Alert only if source is external IP space
- Combine with “successful login after failures” for higher confidence

## Triage steps
1. Confirm source IP is external and check reputation
2. Identify targeted host(s) and usernames
3. Check if any success follows failures (look for successful SSH login events)
4. Verify whether account lockout occurred or the account is privileged
5. Escalate if external + high volume, or if success occurs after failures

## MITRE ATT&CK mapping (optional)
- T1110 (Brute Force)
