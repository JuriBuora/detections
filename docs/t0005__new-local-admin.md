# Detection: New local admin created (Windows)

## Goal
Detect creation of new accounts and/or adding accounts to local/admin groups.

## Data sources required
- Windows Security logs (e.g., `SecurityEvent`) capturing account and group management events.

## Detection logic (high level)
Attackers often create a new account or add an account to Administrators for persistence. We alert on account creation and group membership changes.

## Query / Rule
See: `rules/kql/t0005__new-local-admin.kql`

## Thresholds
- Alert per event; optionally suppress if done by known IT admin accounts during change windows.

## Expected false positives
- Legit IT provisioning
- Domain join scripts / golden image setup
- Helpdesk operations

## Tuning ideas
- Allowlist known admin actors
- Alert only when performed outside business hours
- Require correlation with suspicious logon or malware activity

## Triage steps
1. Identify who performed the change (actor account)
2. Confirm whether change was approved (ticket/change)
3. Check if the new account logged in and from where
4. Review host for follow-on persistence or tooling
5. Escalate if actor is unusual or no change record exists

## MITRE ATT&CK mapping (optional)
- T1136 (Create Account)
- T1098 (Account Manipulation)
