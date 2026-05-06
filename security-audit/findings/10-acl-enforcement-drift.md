# 10 — ACL Enforcement State Drift

**Status:** Analyzed — fix pending
**Priority:** Critical
**Area:** Authorization, Firewall, State Consistency

## Confirmed Findings

### 10.1 — Default ACL fallback skipped in firewall enforcement

- `get_profile_for_peer()` (`acl.py:93-99`): Falls back to default profile
- `apply_firewall_rules()` (`acl.py:157-211`): Only loads profile when `peer["acl_profile_id"]` is explicitly set — **no fallback**
- Peers with no explicit profile get client AllowedIPs from default but zero server-side fw_rules

### 10.2 — Group assignment doesn't rebuild firewall

`update_peer()` (`peers.py:97-134`):
- When `group_id` is set, inherited `acl_profile_id` is written to DB
- But `_apply_acl()` only fires when the caller-supplied `acl_profile_id` parameter is not None
- Group inheritance sets the DB column but the Python parameter stays None → no iptables rebuild

Group ACL profile change (`groups.py:21-44` + `routes.py:420-435`):
- Updates all peers in DB ✓
- Calls `apply_firewall_rules` for all interfaces ✓
- But `apply_firewall_rules` still has the default-fallback bug from 10.1

### 10.3 — Invite/import creates enabled peers, then disables in DB only

Timeline:
1. `create_peer()` (`peers.py:39`): INSERT with `enabled = TRUE`
2. `_sync_config()` (`peers.py:49`): writes peer to WireGuard, runs `wg syncconf` — **PEER IS LIVE**
3. `send_activation_email()` (`portal.py:38-40`): UPDATE sets `enabled = FALSE` in DB
4. **No second `_sync_config()` call** — peer remains in live WireGuard config

Same pattern in Google Workspace import (`integrations/routes.py:197-205`).

### All wg sync call sites

| File | Line | Trigger |
|------|------|---------|
| `peers.py` | 49 | create peer |
| `peers.py` | 76 | delete peer |
| `peers.py` | 85 | enable peer |
| `peers.py` | 94 | disable peer |
| `peers.py` | 178 | ACL apply path |
| `routes.py` | 180 | update interface |
| `routes.py` | 131 | create interface (wg-quick up) |
| `portal.py` | 143 | activate with password |
| `portal.py` | 169 | activate with Google |
| `hostbill/routes.py` | 91 | HostBill create |

### All iptables call sites

- `acl.py`: 10 calls (WG_ACL chain management)
- `vpn2fa.py`: 17 calls (WG_2FA + WG_2FA_NAT chain management)

## Remediation (pending)

1. Make `apply_firewall_rules()` use `get_profile_for_peer()` for consistent resolution
2. Call `_apply_acl()` after group assignment, not just explicit acl_profile_id change
3. Create invite peers as `enabled = FALSE` from the start, sync AFTER disable
