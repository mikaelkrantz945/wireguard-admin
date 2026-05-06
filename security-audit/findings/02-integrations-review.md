# 02 — Integrations Module Full Review

**Status:** Open
**Priority:** High
**Area:** Authentication, OAuth, User Provisioning

## Summary

The integrations module (`app/integrations/`) handles OAuth2 flows with Google Workspace and user provisioning. This module is completely unreviewed and touches sensitive credentials (client_secret, access tokens) and user creation.

## Key Questions

- [ ] Are OAuth client_secret values stored securely (encrypted at rest)?
- [ ] Is the OAuth state parameter validated to prevent CSRF?
- [ ] Are access/refresh tokens stored securely?
- [ ] Can a non-admin trigger the OAuth flow or import users?
- [ ] Is the redirect_uri validated against an allowlist?
- [ ] Are imported users properly validated before peer creation?
- [ ] Can token refresh be exploited for persistent access?

## Files to Review

- `app/integrations/routes.py`
- `app/integrations/google_workspace.py`
- `app/integrations/base.py`
- `app/portal.py` (Google OAuth login)

## Findings

<!-- Document results here -->

## Remediation

<!-- Document fixes here -->
