# 07 — Weak Password Hashing (SHA-256)

**Status:** Open
**Priority:** Critical
**Area:** Cryptography, Credential Storage

## Summary

Admin and portal passwords are hashed with plain SHA-256 plus a static string prefix/salt. This is insufficient for internet-facing authentication and vulnerable to offline brute-force attacks if the database is compromised.

## Problem

SHA-256 is a fast hash — modern GPUs can compute billions of SHA-256 hashes per second. Password hashing functions like bcrypt, scrypt, or argon2 are deliberately slow and include per-password salts, making brute-force infeasible.

A static prefix/salt means all users with the same password produce the same hash.

## Files to Review

- [ ] `app/users.py` — admin password hashing
- [ ] `app/portal.py` — portal password hashing
- [ ] Any password verification functions

## Remediation

- [ ] Replace SHA-256 with `bcrypt` (or `argon2id`)
- [ ] Use per-user random salt (bcrypt does this automatically)
- [ ] Add migration path: rehash on next successful login
- [ ] Dependency: add `bcrypt` or `passlib[bcrypt]` to requirements
