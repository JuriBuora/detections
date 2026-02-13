# Detection: Suspicious PowerShell (encoded / download / IEX)

## Goal
Detect potentially malicious PowerShell usage such as encoded commands or common download/execute patterns.

## Data sources required
- Endpoint process telemetry (e.g., Microsoft Defender for Endpoint `DeviceProcessEvents`) or equivalent EDR logs.

## Detection logic (high level)
Many attacks use PowerShell with `-enc` or command lines containing `IEX`, base64 decoding, or web download patterns. We look for suspicious keywords in the command line.

## Query / Rule
See: `rules/kql/t0004__suspicious-powershell.kql`

## Thresholds
- Typically alert per event; optionally add frequency thresholds per user/host.

## Expected false positives
- Legit admin scripts (automation) using PowerShell downloads
- Software deployment tools
- Security tools using PowerShell for collection

## Tuning ideas
- Allowlist known admin tools/scripts paths and signed scripts
- Focus on suspicious parent processes (e.g., Office, browser, WMI)
- Require network indicators or file write events nearby

## Triage steps
1. Review full command line and parent process
2. Identify user context and host role
3. Check network connections around the event
4. Look for follow-on behavior (new process tree, persistence, file drops)
5. Escalate if user is non-admin and behavior is unusual or matches known patterns

## MITRE ATT&CK mapping (optional)
- T1059.001 (PowerShell)
