# CLAUDE.md

WireGuard VPN administration API with admin GUI. Manages VPN peers (create, delete, enable, disable) via a FastAPI middleware with HostBill script provisioning integration.

## Architecture

```
vpndev.no-ack.net
  Nginx (HTTPS) -> FastAPI (port 8092) -> WireGuard (host kernel)
  PostgreSQL (port 5432) for state
```

- API container runs with `network_mode: host` + `CAP_NET_ADMIN` to execute `wg`/`wg-quick` commands on host interfaces
- WireGuard configs stored in `/etc/wireguard/` (mounted from host)
- Client private keys stored in DB for config regeneration
- IPAM via PostgreSQL table

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
# Bootstrap first admin: POST /admin/bootstrap
# Open https://vpndev.no-ack.net/admin/ui
```

## Deployment

```bash
cd ansible
ansible-playbook -i inventory.yml site.yml   # Full server setup
ansible-playbook -i inventory.yml deploy.yml  # Quick redeploy
ansible-playbook -i inventory.yml certbot.yml # SSL certificate
```

## Stack

- FastAPI + Uvicorn (Python 3.12)
- PostgreSQL 16-alpine
- Docker Compose (host network mode)
- Vanilla HTML/CSS/JS SPA (admin GUI)
