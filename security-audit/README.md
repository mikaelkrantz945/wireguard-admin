# Security Audit — wireguard-admin

Security analysis of the wireguard-admin project. Findings, remediation tracking, and evidence.

## Work Areas

| # | Area | Status | Priority |
|---|------|--------|----------|
| 1 | [Network exposure](findings/01-network-exposure.md) | Open | Critical |
| 2 | [Integrations module](findings/02-integrations-review.md) | Open | High |
| 3 | [Portal XSS audit](findings/03-portal-xss.md) | Open | High |
| 4 | [Deployment secrets](findings/04-deployment-secrets.md) | Open | Medium |
| 5 | [Admin privilege separation](findings/05-admin-privileges.md) | Open | Medium |

## Severity Scale

| Level | Meaning |
|-------|---------|
| Critical | Exploitable from internet, data breach or RCE risk |
| High | Exploitable with some preconditions, credential theft or privilege escalation |
| Medium | Defense-in-depth gaps, misconfigurations |
| Low | Hardening recommendations, best practices |
| Info | Observations, no immediate risk |

## Process

1. Document finding in `findings/` with evidence
2. Update status in this table
3. Create fix in separate branch/PR
4. Mark as Resolved with PR reference
