# Detection: New account and/or privileged group membership change (Windows)

## Goal
Detect creation of new accounts and/or adding accounts to privileged groups (e.g., local Administrators, Domain Admins).

## Why this matters
Attackers frequently:
- create a “backdoor” account for persistence, and/or
- add a controlled account to admin groups for privilege escalation.

These are high-impact identity changes that often precede further persistence or lateral movement.

## Data sources required
- Windows Security logs (commonly via `SecurityEvent`)
- Account management and group management auditing enabled

## Detection logic (high level)
Alert on:
- **4720** (new user created), and
- **4728/4732/4756** (member added to group) when the group is privileged:
  - `Administrators`
  - `Domain Admins`

## Query / Rule
- Base rule: `rules/kql/t0005__new-local-admin.kql`
- High-confidence correlation (recommended): `rules/kql/t0005a__new-user-then-admin.kql`

## Thresholds
- Alert per event (identity changes are high-signal).
- Consider suppression for known IT automation accounts during known change windows (carefully).

## Expected false positives
- Legit IT provisioning (new hire, role changes)
- Domain join scripts / golden image deployment
- Helpdesk operations (temporary admin grants, troubleshooting)

## Tuning ideas
- Allowlist known IT automation/service accounts as *actors* (do not allowlist the target!)
- Prioritize events outside business hours
- Increase severity when:
  - the actor is unusual OR
  - the target is a new account OR
  - the privileged group is `Domain Admins`
- Correlate with follow-on activity:
  - suspicious process execution (4688 / EDR telemetry)
  - new service/task persistence (4697/4698)
  - log clearing (1102)

## Triage steps
1. Identify who performed the change (actor account) and from which host
2. Identify the target account and the group affected (Administrators vs Domain Admins)
3. Validate approval (ticket/change record)
4. Check whether the target account logged in after the change (4624) and from where
5. Review the host for follow-on persistence/tooling:
   - 4688 process creation / suspicious PowerShell
   - 4697 service install, 4698 scheduled task created
   - unusual outbound connections, new dropped tools in Temp/AppData
6. Escalate if actor is unusual, no change record exists, or any suspicious follow-on activity occurs

## MITRE ATT&CK mapping (optional)
- T1136 (Create Account)
- T1098 (Account Manipulation)
