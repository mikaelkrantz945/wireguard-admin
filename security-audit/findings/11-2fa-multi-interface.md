# 11 — 2FA/Captive Portal Multi-Interface Bugs

**Status:** Open
**Priority:** High
**Area:** VPN 2FA, Firewall, Multi-Interface

## Summary

The VPN 2FA and captive portal implementation uses global iptables chains but rebuilds them per-interface with interface-specific assumptions, causing incorrect behavior on multi-interface deployments.

## Findings

### 11.1 — Global chains rebuilt per-interface

`WG_2FA` and `WG_2FA_NAT` chains are global, but the rebuild logic processes one interface at a time with that interface's server IP. The last interface processed overwrites captive-portal behavior for all interfaces.

**Impact:** NAT and exception rules can target the wrong server IP. Captive portal redirects break for non-last interfaces.

### 11.2 — Reconnect invalidation hardcoded to `wg0`

The reconnect detection logic reads endpoint and handshake data from `wg0` only. Peers on additional interfaces (`wg1`, `wg2`, etc.) are never evaluated against their actual WireGuard state.

**Impact:** `reauth_on_reconnect` silently fails for peers not on `wg0`. Reconnect-based 2FA invalidation only works on the default interface.

## Files to Review

- [ ] `app/vpn2fa.py` — chain rebuild logic, server IP assumptions
- [ ] `app/vpn2fa_routes.py` — reconnect detection
- [ ] Any `wg show` or `wg dump` calls that reference `wg0` directly

## Remediation

1. [ ] Redesign 2FA filter/NAT chains to be interface-scoped (e.g., `WG_2FA_wg0`, `WG_2FA_wg1`)
2. [ ] Remove `wg0` hardcoding from reconnect invalidation — resolve interface from peer's assigned interface
3. [ ] Rebuild chains per-interface atomically without affecting other interfaces
