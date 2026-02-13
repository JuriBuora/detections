# Detection: Mail forwarding rule created (M365)

## Goal
Detect suspicious inbox/forwarding rules often used for email exfiltration and BEC.

## Data sources required
- Microsoft 365 audit logs (e.g., `OfficeActivity`)

## Detection logic (high level)
Attackers create inbox rules to forward email to external addresses or hide replies. We alert on rule creation/modification and inspect parameters.

## Query / Rule
See: `rules/kql/t0008__mail-forwarding-rule.kql`

## Expected false positives
- Legit user automation rules
- Shared mailbox management

## Tuning ideas
- Alert only when forwarding to external domains
- Focus on VIP/finance accounts
- Correlate with risky sign-in alerts

## Triage steps
1. Identify the rule details and destination address/domain
2. Check recent sign-ins for the user
3. Remove malicious rule and revoke sessions
4. Review mailbox for suspicious sent items
5. Escalate if finance/vendor payments involved

## MITRE ATT&CK mapping (optional)
- T1114 (Email Collection)
