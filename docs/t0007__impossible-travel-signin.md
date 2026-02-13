# Detection: Impossible travel / unusual sign-in

## Goal
Flag sign-in patterns that suggest stolen credentials (sudden geo jumps, unusual locations/devices).

## Data sources required
- Identity provider sign-in logs (e.g., Entra ID `SigninLogs`)

## Detection logic (high level)
If a user signs in from two distant locations in an unrealistic time window, or from a new risky location/device, it may indicate compromise.

## Query / Rule
See: `rules/kql/t0007__impossible-travel-signin.kql`

## Expected false positives
- VPN usage
- Mobile carriers changing exit IPs
- Legit travel

## Tuning ideas
- Incorporate device ID / user agent
- Exclude corporate VPN IP ranges
- Focus on high-value accounts

## Triage steps
1. Check if VPN was used
2. Validate device and session details
3. Look for concurrent sessions or unusual app access
4. Reset credentials and revoke sessions if suspicious
5. Escalate if privileged account or clear anomaly

## MITRE ATT&CK mapping (optional)
- T1078 (Valid Accounts)
