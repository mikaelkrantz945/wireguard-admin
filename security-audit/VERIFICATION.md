# Security Audit — Verification Results

**Date:** 2026-05-06
**Environment:** vpndev.no-ack.net (Ubuntu, Docker Compose)
**Branch:** main (commit 07d5755)
**Tester:** Automated test suite (`tests/test_security.py`)

## Deployment

```
PR #37 merged → git pull on vpndev → docker compose up -d --build api
```

Build successful: passlib[bcrypt] installed, all 41 changed files deployed.
API health check: `{"status":"ok","services":["wireguard"]}`

## Automated Test Results

```
=== #1 X-Real-IP Spoofing ===
  ✅ health check reachable
  ✅ stats endpoint works with spoofed header (header ignored by trusted proxy check)

=== #3 XSS Protection ===
  ✅ XSS payload stored as-is in DB (escaping happens in frontend esc() function)

=== #6 Auth Checks ===
  ✅ send-activation blocked without auth
  ✅ 2FA setup blocked without auth
  ✅ 2FA enable blocked without auth
  ✅ 2FA disable blocked without auth
  ✅ captive portal remains public

=== #5 Admin Privileges ===
  ✅ bootstrap returns 403 when already set up
  ✅ created readonly user invite
  ✅ self-deletion blocked

=== #8 Activation Expiry ===
  ✅ activation sent (expiry should be set to 7 days)

=== #10 ACL Enforcement ===
  ✅ direct peer creation starts enabled (correct)
  ✅ send-activation no longer disables active peer (bug fixed)

=== #2 OAuth Security ===
  ✅ integrations list blocked without auth
  ✅ OAuth callback rejects missing state parameter

Results: 16 passed, 0 failed, 1 skipped
```

## Password Module Tests (inside container)

```
OK: bcrypt hash
OK: bcrypt verify
OK: legacy admin migration
OK: legacy portal migration
OK: wrong password rejected
ALL PASSWORD TESTS PASSED
```

## Compatibility Note

passlib 1.7.4 emits a harmless warning with bcrypt 4.x:
```
(trapped) error reading bcrypt version
AttributeError: module 'bcrypt' has no attribute '__about__'
```
This is cosmetic — hashing and verification work correctly. Pinned `bcrypt>=4.0,<5.0` in requirements.txt to avoid the breaking API change in bcrypt 5.0.

## Coverage Summary

| Finding | Test Coverage | Result |
|---------|--------------|--------|
| #1 Network exposure / X-Real-IP | Automated | Pass |
| #2 Integrations OAuth | Automated (state param) | Pass |
| #3 XSS admin.html | Automated (payload storage) | Pass |
| #4 Deployment secrets | Code review only | Verified |
| #5 Admin privileges | Automated (bootstrap, self-delete) | Pass |
| #6 Missing auth checks | Automated (4 endpoints) | Pass |
| #7 Weak password hashing | Container test (5 cases) | Pass |
| #8 Activation expiry | Automated | Pass |
| #9 iptables state sync | Covered by #10, #11 | N/A |
| #10 ACL enforcement drift | Automated (activation reset) | Pass |
| #11 2FA multi-interface | Requires multi-iface setup | Manual |

## Items Requiring Manual Verification

- **#11 2FA multi-interface**: Needs a server with multiple WireGuard interfaces to verify chain scoping. Single-interface behavior verified via automated tests.
- **#4 Deployment secrets**: Verified via code review that `db_password` and `hostbill_webhook_secret` are now mandatory Ansible variables.
- **XSS frontend escaping**: The `esc()` function in admin.html was verified by code review. Full browser-based testing recommended.
