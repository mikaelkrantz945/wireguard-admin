# 08 — Portal Activation Expiry Not Enforced

**Status:** Fixed
**Priority:** Medium
**Area:** Authentication, Token Management

## Summary

The UI tells users activation links are valid for 7 days, but the backend does not store or enforce an activation token expiry for VPN peers. Activation tokens remain valid indefinitely.

## Impact

- Old activation links remain usable forever
- A leaked or intercepted activation email can be used months later
- No way to invalidate a pending activation without deleting the peer

## Files to Review

- [ ] `app/portal.py` — activation token generation and validation
- [ ] `app/users.py` — invite/activation flow
- [ ] Database schema — check for `activation_expires` or similar column

## Remediation

- [ ] Store `activation_expires_at` timestamp when generating activation token
- [ ] Reject activation attempts after expiry
- [ ] Match the stated 7-day window in the UI
- [ ] Add ability to manually invalidate/regenerate activation tokens
