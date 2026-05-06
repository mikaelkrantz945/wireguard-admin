# 09 — iptables State Sync Fragility

**Status:** Open
**Priority:** Medium
**Area:** Networking, Reliability

## Summary

ACL profiles and VPN 2FA are enforced via imperative `iptables` shell calls with best-effort error handling. Partial failures can leave database state and live firewall state out of sync — a peer may be "restricted" in the DB but have full access on the wire.

## Impact

- Failed iptables command leaves DB showing rules applied but no actual enforcement
- No reconciliation mechanism to detect or fix drift
- Server reboot clears iptables but DB still shows rules as active
- Multiple rapid ACL changes could leave orphaned rules

## Files to Review

- [ ] `app/acl.py` or equivalent — iptables rule application
- [ ] `app/vpn2fa.py` — 2FA iptables rules
- [ ] PostUp/PostDown scripts in WireGuard config
- [ ] Any startup reconciliation logic

## Remediation

- [ ] Add a reconciliation endpoint/task that rebuilds iptables from DB state
- [ ] Run reconciliation on application startup
- [ ] Use `iptables-restore` for atomic rule replacement instead of individual commands
- [ ] Log and alert on iptables command failures
- [ ] Consider `nftables` migration for transactional rule updates
