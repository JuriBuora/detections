# Detection: RDP brute force (Windows)

## Goal
Detect repeated failed RDP logons from the same source IP in a short time window.

## Data sources required
- Windows Security logs in SIEM (e.g., `SecurityEvent` with EventID 4625)

## Detection logic (high level)
Attackers attempt many passwords over RDP. We count failed logons (4625) with LogonType 10 and flag high-volume sources.

## Query / Rule
See: `rules/kql/t0002__rdp-bruteforce.kql`

## Thresholds
- Window: 5 minutes
- Condition: >= 15 failed logons from same IP

## Expected false positives
- Misconfigured service using wrong credentials over RDP
- Vulnerability scanners / IT admin tools
- Legit users repeatedly mistyping password (usually low volume)

## Tuning ideas
- Exclude known internal admin jump hosts
- Raise threshold or require multiple target accounts
- Alert only if source IP is external

## Triage steps
1. Validate source IP (internal/external, geolocation, reputation)
2. Check if there are successful logons (4624 LogonType 10) around the same time
3. Identify targeted accounts and whether any got locked out
4. Escalate if external + high volume or success follows failures

## MITRE ATT&CK mapping (optional)
- T1110 (Brute Force)
