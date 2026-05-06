# Security Audit — wireguard-admin

Security analysis of the wireguard-admin project. Findings, remediation tracking, and evidence.

## Work Areas

| # | Area | Status | Priority |
|---|------|--------|----------|
| 1 | [Network exposure](findings/01-network-exposure.md) | **Fixed** | Critical |
| 2 | [Integrations module](findings/02-integrations-review.md) | Open | High |
| 3 | [XSS audit (admin.html)](findings/03-portal-xss.md) | **Fixed** | Critical |
| 4 | [Deployment secrets](findings/04-deployment-secrets.md) | **Fixed** | Medium |
| 5 | [Admin privilege separation](findings/05-admin-privileges.md) | **Fixed** | Medium |
| 6 | [Missing auth checks](findings/06-missing-auth-checks.md) | **Fixed** | Critical |
| 7 | [Weak password hashing](findings/07-weak-password-hashing.md) | **Fixed** | Critical |
| 8 | [Activation expiry not enforced](findings/08-activation-expiry.md) | **Fixed** | Medium |
| 9 | [iptables state sync](findings/09-iptables-state-sync.md) | **Fixed** (via #10, #11) | Medium |
| 10 | [ACL enforcement state drift](findings/10-acl-enforcement-drift.md) | **Fixed** | Critical |
| 11 | [2FA multi-interface bugs](findings/11-2fa-multi-interface.md) | **Fixed** | High |

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
