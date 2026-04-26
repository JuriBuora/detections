# Detection Engineering Practice

Practice repository for detection engineering: KQL rules, tuning notes, triage checklists, and small validation samples.

This is a learning portfolio, not a production rule pack. Rules are intentionally documented with assumptions, expected false positives, tuning ideas, and triage steps so a reviewer can see the reasoning behind each detection.

## Structure

- `rules/kql/` - Microsoft Sentinel / Defender-style KQL detections
- `docs/` - detection write-ups, tuning notes, and response guidance
- `tests/` - lightweight validation notes and synthetic sample data

See `docs/validation.md` for the current validation standard and limitations.

## Current coverage

| ID | Detection | Status |
| --- | --- | --- |
| T0001 | SSH brute force | Draft, documented |
| T0002 | RDP brute force | Draft, documented |
| T0003 | Password spray | Draft, documented |
| T0004 | Suspicious PowerShell | Draft, documented |
| T0005 | New local admin | Draft, documented |
| T0005A | New user then privileged group add | Draft |
| T0006 | Service or scheduled task persistence | Draft, documented |
| T0007 | Impossible travel sign-in | Draft, documented |
| T0008 | Suspicious mail forwarding rule | Draft, documented |
| T0009 | Office spawning shell | Draft, documented |
| T0010 | Large outbound transfer | Draft, documented |

## How I review a detection

1. Identify the behavior and attacker technique.
2. Confirm the required data source and fields.
3. Write the first query as a readable draft.
4. Document expected false positives.
5. Add tuning ideas and triage steps.
6. Validate against synthetic or lab data when available.
7. Mark the detection as tested only after I can reproduce the signal.

## Naming

Use `tXXXX__short-desc.<ext>`, for example `t0001__ssh-bruteforce.kql`.
