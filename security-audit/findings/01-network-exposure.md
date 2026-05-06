# 01 — Network Exposure (Firewall / Port 8092)

**Status:** Fix implemented
**Priority:** Critical
**Area:** Network, Firewall

## Summary

The FastAPI application listens on port 8092 with `network_mode: host` bound to `0.0.0.0`. While UFW blocks external access, **VPN peers can always reach port 8092** on the WireGuard interface IP and spoof `X-Real-IP` headers.

## Confirmed Findings

### 1.1 — Port 8092 exposure

- `docker-compose.yml:61`: `network_mode: "host"`
- `Dockerfile:19`: uvicorn binds `0.0.0.0:8092`
- UFW does NOT allow 8092 (default deny) — external access blocked
- **But**: VPN peers on the WG tunnel can hit `<server-wg-ip>:8092` directly, bypassing nginx

### 1.2 — X-Real-IP spoofing (EXPLOITABLE TODAY)

Three locations trust `X-Real-IP` unconditionally:

| File | Line | Impact |
|------|------|--------|
| `app/auth.py` | 21 | API key IP ACL bypass |
| `app/vpn2fa_routes.py` | 30 | 2FA session hijack (verify) |
| `app/vpn2fa_routes.py` | 44 | 2FA session hijack (status) |

A VPN peer can spoof `X-Real-IP` to:
- Bypass API key `allowed_ips` restrictions
- Authenticate a 2FA session for a different peer's IP
- Check another peer's 2FA status

## Remediation

**Fix:** Created `app/utils.py` with `get_client_ip()` that only trusts `X-Real-IP` from `127.0.0.1`/`::1`. Updated all 3 call sites.
