# 10 — ACL Enforcement State Drift

**Status:** Open
**Priority:** Critical
**Area:** Authorization, Firewall, State Consistency

## Summary

ACL profile resolution and firewall enforcement use different code paths, causing the database/UI to show one policy while the host enforces another. This is the central theme across multiple subsystems.

## Findings

### 10.1 — Default ACL fallback skipped in firewall enforcement

`get_profile_for_peer()` resolves the default ACL profile when a peer has no explicit `acl_profile_id`, but `apply_firewall_rules()` bypasses that helper and only loads a profile when `acl_profile_id` is explicitly set.

**Impact:** Peers using the default profile get restrictive client `AllowedIPs` in their config but no server-side `fw_rules` enforcement. Operators see split behavior between generated client config and actual firewall.

### 10.2 — Group ACL inheritance does not refresh live firewall

When a peer is moved into a group, the stored `acl_profile_id` is updated through inheritance, but `WG_ACL` iptables rules are not rebuilt unless the request explicitly sets `acl_profile_id`. The DB row updates immediately while the live firewall keeps the old policy.

**Impact:** Admin actions appear successful in UI/DB but effective network policy lags behind.

### 10.3 — Invite/import flow creates enabled peers then disables in DB only

Invite-style flows create peers as enabled and sync them into live WireGuard config. The activation helper then flips the DB row to disabled without performing a second WireGuard sync.

**Impact:** Unactivated peers are "disabled" in the DB but still present in the live WireGuard config until a later unrelated sync.

## Files to Review

- [ ] `app/acl.py` — `apply_firewall_rules()` vs `get_profile_for_peer()`
- [ ] `app/wireguard.py` — peer sync logic
- [ ] `app/portal.py` — invite/activation flow
- [ ] `app/admin.py` — group assignment, peer update endpoints

## Remediation (recommended order)

1. [ ] Make `apply_firewall_rules()` use `get_profile_for_peer()` for consistent profile resolution
2. [ ] Rebuild live ACL state on every effective policy change, including inherited group changes
3. [ ] Make invite/import flows create peers as disabled from the start — never sync an unactivated peer into live WireGuard
