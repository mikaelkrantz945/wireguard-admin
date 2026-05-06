# 03 — XSS Audit (admin.html + portal.html)

**Status:** Fix in progress
**Priority:** Critical (upgraded from High)
**Area:** XSS, Frontend Security

## Confirmed Findings

**portal.html:** SAFE — 3 innerHTML usages all use hardcoded HTML, no user data interpolation.
**captive.html:** SAFE — uses textContent only.
**admin.html:** 12 XSS vectors — 3 CRITICAL, 5 HIGH, 2 MEDIUM, 2 LOW.

### Critical — onclick attribute injection

| # | Line | Vector | PoC |
|---|------|--------|-----|
| 3 | ~644 | `onclick="showPeerConfig(id,'${p.name}')"` | Peer name: `');alert(document.cookie);//` |
| 4 | ~840 | `onclick="setupVpn2fa(id,'${peer.name}')"` | Same pattern |
| 12 | ~1092 | `onclick="showImportUsers(id,'${i.name}')"` | Integration name: same |

These allow JS execution through quote-breaking — no HTML tags needed, bypasses tag-only sanitization.

### High — innerHTML with user data

| # | Line | Data source |
|---|------|-------------|
| 1 | ~610 | Dashboard: `p.name` |
| 2 | ~634 | Peers table: `p.name`, `p.group_name`, `p.acl_profile_name` |
| 6 | ~767 | Logs table: `x.path`, `x.customer` (external attacker controlled) |
| 7 | ~773 | Users table: `x.firstname`, `x.lastname`, `x.email` |
| 10 | ~1178 | Import users: Google Workspace data (external) |
| 11 | ~874,933,1092 | Dropdowns: group/profile/integration names |

### Medium

| # | Line | Data source |
|---|------|-------------|
| 8 | ~1062 | Settings form: `value="${s.value}"` attribute breakout |

### Future risk

`portal_welcome_message` server setting says "HTML allowed" but is not yet rendered in portal.html. When implemented, it will be stored XSS unless sanitized with DOMPurify.

## Remediation

- Added `esc()` helper function for HTML entity escaping
- All user-controlled data wrapped with `esc()` in innerHTML
- onclick injection fixed with `encodeURIComponent`/`data-n` attributes
