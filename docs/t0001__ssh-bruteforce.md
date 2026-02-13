# Detection: SSH brute force (Linux)

## Goal
Detect repeated failed SSH authentication attempts from the same source IP in a short time window.

## Data sources required
- Linux auth logs ingested into SIEM (commonly via Syslog connector)
- Table often named `Syslog` (varies by environment)

## Detection logic (high level)
Brute force attempts generate many `Failed password` messages from `sshd`. We extract the source IP and (when possible) the targeted username, then count failures per time window.

## Query / Rule
See: `rules/kql/t0001__ssh-bruteforce.kql`

## Thresholds
- Window: 5 minutes
- Condition: FailCount >= 10 from same IP (starting point)

## Expected false positives
- Vulnerability scanners / pentest tools (authorized)
- Misconfigured automation using wrong credentials
- A user repeatedly mistyping password (usually low volume)

## Tuning ideas
- Exclude known scanner IPs / internal admin networks
- Require multiple distinct target usernames (e.g., DistinctUsers >= 3)
- Alert only if source is external IP space
- Combine with “successful login after failures” for higher confidence

## Triage steps
1. Confirm whether source IP is external; check IP reputation (threat intel / known VPN/Tor / abuse reports)
2. Identify targeted host(s) and usernames (are privileged accounts targeted?)
3. Check if any success follows failures (successful SSH login events near the same time)
4. Verify whether account lockout occurred or if the account is privileged
5. Escalate if external + high volume, or if success occurs after failures

## MITRE ATT&CK mapping (optional)
- T1110 (Brute Force)
