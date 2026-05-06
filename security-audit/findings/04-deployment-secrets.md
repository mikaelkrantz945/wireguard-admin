# 04 — Deployment Secret Wiring Trace

**Status:** Open
**Priority:** Medium
**Area:** Secrets Management, Deployment

## Summary

Trace the full lifecycle of secrets from generation through Ansible to the running application. Identify any secrets that are hardcoded, logged, stored in plaintext, or transmitted insecurely.

## Key Questions

- [ ] Is `HOSTBILL_WEBHOOK_SECRET` generated randomly or left as default?
- [ ] Is `DATABASE_URL` password hardcoded in env template?
- [ ] Are any secrets logged during Ansible deployment?
- [ ] Is `.env` properly protected (file permissions, not in git)?
- [ ] Are API keys hashed before storage (SHA-256)?
- [ ] Are session tokens generated with sufficient entropy?
- [ ] Is JWT/session secret properly configured?

## Files to Review

- `ansible/roles/app/templates/env.j2`
- `.env.example`
- `ansible/inventory.yml.example`
- `app/auth.py` (session/token generation)
- `app/admin.py` (API key handling)

## Findings

<!-- Document results here -->

## Remediation

<!-- Document fixes here -->
