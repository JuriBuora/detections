# Detection: Possible exfiltration (large outbound)

## Goal
Flag unusually large outbound data transfer that could indicate exfiltration.

## Data sources required
- Network telemetry (firewall/proxy logs) OR endpoint network logs
- Fields for bytes sent, source, destination, time

## Detection logic (high level)
We summarize outbound bytes by source and destination over a window and alert when volume exceeds a threshold, especially to uncommon destinations.

## Query / Rule
See: `rules/kql/t0010__possible-exfil-large-outbound.kql`

## Expected false positives
- Backups to cloud storage
- Large software updates
- Legit data transfers (media, engineering)

## Tuning ideas
- Baseline per host role (backup server vs workstation)
- Focus on new/rare destinations
- Correlate with suspicious processes or sign-ins

## Triage steps
1. Validate destination (known service vs unknown)
2. Identify process/user initiating transfer (if available)
3. Check for compression/encryption tools used nearby
4. Look for preceding suspicious activity (phishing, creds)
5. Escalate if workstation + unusual dest + high volume

## MITRE ATT&CK mapping (optional)
- T1041 (Exfiltration Over C2 Channel)
- T1567 (Exfiltration to Cloud Storage)
