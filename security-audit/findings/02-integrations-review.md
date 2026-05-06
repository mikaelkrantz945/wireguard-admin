# 02 — Integrations Module Full Review

**Status:** Fixed
**Priority:** High
**Area:** Authentication, OAuth, User Provisioning

## Confirmed Findings (7 issues, all fixed)

### 2.1 — Missing OAuth state parameter (CRITICAL)
- No CSRF protection on OAuth flow
- **Fix:** Added `secrets.token_urlsafe(32)` state token, stored server-side, validated on callback (one-time use)

### 2.2 — Frontend not passing state back (CRITICAL)
- admin.html `doExchangeCode()` only sent `{code}`, not `{code, state}`
- **Fix:** Added `_oauthState` variable, saved from auth-url response, sent in callback POST

### 2.3 — Unvalidated redirect_uri in portal Google login (HIGH)
- `POST /portal/auth/google` accepted arbitrary redirect_uri
- **Fix:** Added `_validate_portal_redirect_uri()` — only allows URIs starting with `BASE_URL`

### 2.4 — No email domain validation in portal Google login (MEDIUM)
- Any Google account could attempt login, not just configured workspace domain
- **Fix:** Email must end with `@{domain}` when integration has domain configured

### 2.5 — No email format validation on user import (MEDIUM)
- Import accepted arbitrary email values
- **Fix:** Added `_validate_email()` regex check, invalid emails skipped

### 2.6 — Redirect URI consistency (LOW)
- **Fix:** Extracted `_build_redirect_uri()` helper used in both auth-url and callback

### 2.7 — Secret masking utility (IMPROVEMENT)
- **Fix:** Added `_mask_secret()` / `_mask_config()` for safe config display

## Verified as Secure

- All integration endpoints require admin auth (`Depends(_require_admin)`)
- Tokens not exposed in list/create responses (only id, provider, name, status)
- `client_id` exposure in `/portal/google-enabled` is intentional (public, needed by frontend)
- Token refresh handled properly in `_ensure_valid_token()`

## Follow-up (not in scope)

- Encrypt `client_secret` and OAuth tokens at rest (requires key management strategy)
