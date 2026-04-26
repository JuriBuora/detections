# Detection Validation Notes

This folder contains lightweight synthetic data used to reason about draft detections.

The samples are not production telemetry and are not meant to prove that a rule is complete. Their purpose is to make the assumptions visible:

- What fields does the query expect?
- What should match?
- What should not match?
- Which threshold or tuning choice changes the result?

## Current samples

- `samples/syslog-ssh-bruteforce.csv` - Linux SSH failed-login patterns for `t0001__ssh-bruteforce.kql`
- `samples/windows-process-powershell.csv` - Windows process examples for `t0004__suspicious-powershell.kql`

## Validation checklist

1. Confirm that sample fields map to the data source documented in `docs/`.
2. Run or manually simulate the KQL grouping/filtering logic.
3. Record expected matches and expected non-matches.
4. Adjust thresholds only after documenting the false-positive trade-off.
5. Do not mark a detection as tested until it has been run against lab or SIEM data.
