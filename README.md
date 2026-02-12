# detections (JURI)

Detection engineering repo: KQL / Sigma rules + notes, test samples, and small playbooks.

## Structure
- `rules/kql/` — Microsoft Sentinel / Defender KQL detections
- `rules/sigma/` — Sigma rules (generic)
- `docs/` — references, tuning notes, false positive notes
- `playbooks/` — response playbooks / triage checklists
- `tests/samples/` — sample logs / test inputs

## Naming
Use: `tXXXX__short-desc.<ext>` (e.g., `t0001__ssh-bruteforce.kql`)
