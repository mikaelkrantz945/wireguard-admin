# 06 — Missing Auth Checks on Security-Sensitive Endpoints

**Status:** Fix implemented
**Priority:** Critical
**Area:** Authentication, Authorization

## Confirmed Findings

### 6.1 — `/portal/send-activation` lacks admin auth (CRITICAL)

- **File:** `app/portal.py:277`
- **Current auth:** NONE — `_require_admin` is imported inside function body but never called (dead code)
- **Impact:** Unauthenticated users can trigger activation emails AND disable active VPN peers
- **Activation reset bug:** `send_activation_email` (line 39) sets `activated=FALSE, enabled=FALSE`, disabling active peers

### 6.2 — VPN 2FA management endpoints lack auth (CRITICAL)

| Endpoint | File:Line | Auth | Impact |
|----------|-----------|------|--------|
| `POST /vpn-auth/setup/{peer_id}` | `vpn2fa_routes.py:50` | NONE | Generate TOTP secret for any peer |
| `POST /vpn-auth/enable/{peer_id}` | `vpn2fa_routes.py:59` | NONE | Set own TOTP on any peer (takeover) |
| `POST /vpn-auth/disable/{peer_id}` | `vpn2fa_routes.py:69` | NONE | Disable 2FA on any peer |

Public endpoints (captive portal) correctly remain unauthenticated:
- `GET /vpn-auth/captive` — OK
- `POST /vpn-auth/verify` — OK (IP-scoped)
- `GET /vpn-auth/status` — OK (IP-scoped)

## Remediation

1. Added `dependencies=[Depends(_require_admin)]` to `/portal/send-activation`
2. Added `dependencies=[Depends(_require_admin)]` to all 3 VPN 2FA management endpoints
3. Fixed activation reset: `send_activation_email` no longer sets `activated=FALSE, enabled=FALSE`
