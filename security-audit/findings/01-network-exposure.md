# 01 — Network Exposure (Firewall / Port 8092)

**Status:** Open
**Priority:** Critical
**Area:** Network, Firewall

## Summary

The FastAPI application listens on port 8092 with `network_mode: host`. If UFW or iptables does not block external access to port 8092, the API is directly reachable without going through nginx — bypassing TLS, rate limiting, and any nginx-level protections.

## Key Questions

- [ ] Is port 8092 accessible from outside the host?
- [ ] Does `X-Real-IP` / `X-Forwarded-For` spoofing bypass IP-based ACLs when accessing the API directly?
- [ ] Are API keys the only auth layer, or does nginx add anything?
- [ ] Is the captive portal endpoint (8092) exposed without auth?

## Investigation Steps

1. Check UFW rules: `sudo ufw status verbose`
2. Check iptables: `sudo iptables -L -n | grep 8092`
3. External port scan: `nmap -p 8092 <server-ip>`
4. Test direct API access: `curl http://<server-ip>:8092/health`
5. Test X-Real-IP spoofing: `curl -H "X-Real-IP: 1.2.3.4" http://<server-ip>:8092/wg/interfaces`

## Findings

<!-- Document results here -->

## Remediation

<!-- Document fixes here -->
