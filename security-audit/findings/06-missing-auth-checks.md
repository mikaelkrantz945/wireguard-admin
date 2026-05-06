# 06 — Missing Auth Checks on Security-Sensitive Endpoints

**Status:** Open
**Priority:** Critical
**Area:** Authentication, Authorization

## Summary

Several high-privilege endpoints that control host networking, portal credentials, and VPN access lack proper authentication enforcement.

## Known Issues

### 6.1 — `/portal/send-activation` lacks admin auth

The endpoint is intended to be admin-only but does not enforce admin authentication. An unauthenticated or portal-authenticated user could trigger activation emails.

**Worse:** resending activation resets `activated = FALSE` and `enabled = FALSE`, meaning this endpoint can **disable an already active VPN peer**.

- **File:** `app/portal.py`
- **Impact:** Denial of service against active VPN users, unauthorized activation email sending

### 6.2 — VPN 2FA endpoints lack admin auth

Peer 2FA setup, enable, and disable endpoints are exposed without admin authentication checks. An attacker could disable 2FA on a peer or set up their own TOTP secret.

- **File:** `app/vpn2fa_routes.py`
- **Impact:** 2FA bypass, unauthorized peer access

## Investigation Steps

- [ ] Identify the auth decorator/dependency used on these endpoints
- [ ] List all endpoints in `portal.py` and `vpn2fa_routes.py` and their auth requirements
- [ ] Verify whether portal tokens can access admin-only endpoints
- [ ] Check if the activation reset (`activated=FALSE`, `enabled=FALSE`) is intentional or a bug

## Remediation

- [ ] Add admin auth check to `/portal/send-activation`
- [ ] Add admin auth checks to all VPN 2FA management endpoints
- [ ] Separate "resend activation" from "reset activation state" — resending should not disable active peers
