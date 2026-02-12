# Detection: <title>

## Goal
What threat/behavior this detects, in one sentence.

## Data sources required
- <e.g., Syslog, WindowsSecurityEvent, DeviceProcessEvents, OfficeActivity, etc.>

## Detection logic (high level)
Explain the idea without code.

## Query / Rule
<insert KQL or Sigma>

## Thresholds
- Window: <e.g., 5m>
- Condition: <e.g., >= 10 failures from same IP>

## Expected false positives
List realistic benign causes.

## Tuning ideas
How to reduce FPs (allowlists, exclude service accounts, geofencing, etc.)

## Triage steps
1. What to check first
2. What evidence to collect
3. When to escalate

## MITRE ATT&CK mapping (optional)
- Technique ID: <e.g., T1110>
