# Detection: Suspicious PowerShell (encoded / download / IEX)

## Goal
Detect potentially malicious PowerShell usage including encoded commands and common “download & execute” patterns.

## Data sources required
- Endpoint process telemetry (e.g., Microsoft Defender for Endpoint `DeviceProcessEvents`) or equivalent EDR logs
- Fields needed: process name, full command line, user, device, parent process

## Detection logic (high level)
Attackers frequently use PowerShell because it is built-in and powerful enough to **download**, **decode**, and **execute** payloads.
This detection flags PowerShell executions that contain:
- Strong obfuscation signal: `-enc` / `-EncodedCommand` with a **long Base64 blob**
- Execution of strings as code: `IEX` / `Invoke-Expression`
- Web retrieval patterns: `Invoke-WebRequest`, `WebClient`, `DownloadString`, URLs
- Decode patterns: `FromBase64String`

We also capture **parent process** context, because Office → PowerShell is often higher risk than admin tooling → PowerShell.

## Query / Rule
See: `rules/kql/t0004__suspicious-powershell.kql`

## Thresholds
- Often alert per event (PowerShell command lines are “high information”)
- Consider severity increase if `SuspiciousParent == true` or if `HasLongEncoded == true`

## Expected false positives
- Legit admin automation scripts and deployment tools
- Security tools and IR scripts (especially if run by admins)
- Some IT management tooling that uses PowerShell under the hood

## Tuning ideas
- Allowlist known management tools or signed scripts (carefully)
- Prioritize alerts where parent is Office/script host (`winword.exe`, `excel.exe`, `wscript.exe`, etc.)
- Require supporting evidence near the same time window:
  - network indicators (new outbound connections / URL fetch)
  - file write indicators (dropping `.ps1/.exe/.dll` into Temp/AppData)
- Reduce noise by excluding known internal script runners (but avoid blind allowlisting)

## Triage steps
1. Inspect the full command line (look for `-enc`, URLs, decode + execute chains)
2. Check parent process and chain (Office → PowerShell is high risk)
3. Identify user context (admin vs normal user; expected behavior?)
4. Look for nearby network activity (downloads) and file writes (payload staging)
5. Escalate if encoded command + suspicious parent and/or any follow-on execution

## MITRE ATT&CK mapping (optional)
- T1059.001 (PowerShell)
- T1027 (Obfuscated/Compressed Files and Information) — for encoded commands
- T1105 (Ingress Tool Transfer) — for download patterns
