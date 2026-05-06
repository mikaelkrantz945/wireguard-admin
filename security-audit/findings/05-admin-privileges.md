# 05 — Admin Privilege Separation

**Status:** Open
**Priority:** Medium
**Area:** Authorization, Access Control

## Summary

Review the admin tier for proper privilege separation between admin roles (full vs readonly), and between admin and portal contexts.

## Key Questions

- [ ] Can readonly admins perform write operations?
- [ ] Are all write endpoints properly guarded with role checks?
- [ ] Can a portal session token be used against admin endpoints?
- [ ] Can an admin session token be used against portal endpoints?
- [ ] Is the bootstrap endpoint disabled after first use?
- [ ] Can API keys with `wireguard` scope access admin endpoints?
- [ ] Is there horizontal privilege escalation (admin A modifying admin B)?

## Files to Review

- `app/auth.py` (role enforcement)
- `app/admin.py` (admin endpoints + decorators)
- `app/portal.py` (portal endpoints)
- `app/users.py` (user/role management)

## Findings

<!-- Document results here -->

## Remediation

<!-- Document fixes here -->
