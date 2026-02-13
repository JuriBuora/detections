# Detection: New service or scheduled task created (Windows)

## Goal
Detect persistence via new service installation or scheduled task creation.

## Data sources required
- Windows Security logs (e.g., EventID 4697, 4698) or Sysmon operational logs.

## Detection logic (high level)
Attackers commonly persist by creating services or scheduled tasks. We alert on creation events and then validate if they’re expected.

## Query / Rule
See: `rules/kql/t0006__persistence-service-or-task.kql`

## Expected false positives
- Legit software installs/updates
- IT automation and patch management
- Vendor agents deploying tasks/services

## Tuning ideas
- Allowlist known installers and signed binaries
- Alert when created by unusual accounts or from user temp paths
- Correlate with suspicious parent process or download events

## Triage steps
1. Identify creator account and host
2. Inspect service/task name and command path
3. Check if binary is signed/known
4. Look for network and file activity around creation time
5. Escalate if path is suspicious (Temp/AppData) or creator is unusual

## MITRE ATT&CK mapping (optional)
- T1053 (Scheduled Task/Job)
- T1543 (Create or Modify System Process)
