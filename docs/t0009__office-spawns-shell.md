# Detection: Office spawns shell (cmd/powershell/wscript)

## Goal
Detect likely malicious document execution chains (Office -> shell/script interpreter).

## Data sources required
- Endpoint process telemetry (EDR)

## Detection logic (high level)
Many phishing/macro attacks involve Office spawning cmd/powershell/script hosts. We alert on suspicious parent-child process relationships.

## Query / Rule
See: `rules/kql/t0009__office-spawns-shell.kql`

## Expected false positives
- Legit add-ins or admin automation (rare)
- Some enterprise integrations (uncommon)

## Tuning ideas
- Focus on users who don’t usually run scripts
- Correlate with email attachment opening
- Add filters for known benign command lines

## Triage steps
1. Identify the document/attachment source if available
2. Review the spawned command line
3. Look for network connections/downloads
4. Isolate host if strong indicators present
5. Escalate if lateral movement/persistence follows

## MITRE ATT&CK mapping (optional)
- T1204 (User Execution)
- T1059 (Command and Scripting Interpreter)
