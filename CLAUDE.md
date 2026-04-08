# CLAUDE.md

WireGuard VPN administration API with admin GUI. Manages VPN peers (create, delete, enable, disable) via a FastAPI middleware with HostBill script provisioning integration.

## Architecture

```
Nginx (HTTPS) -> FastAPI (port 8092) -> WireGuard (host kernel)
PostgreSQL (port 5432) for state
```

- API container runs with `network_mode: host` + `CAP_NET_ADMIN` to execute `wg`/`wg-quick` commands on host interfaces
- WireGuard configs stored in `/etc/wireguard/` (mounted from host)
- Client private keys stored in DB for config regeneration
- IPAM via PostgreSQL table

## Quick start

```bash
cp .env.example .env   # Edit with your settings
docker compose up -d --build
# Bootstrap first admin: POST /admin/bootstrap
# Open http://localhost:8092/admin/ui
```

## Deployment

```bash
cd ansible
cp inventory.yml.example inventory.yml  # Edit with your server details
ansible-playbook -i inventory.yml site.yml   # Full server setup
ansible-playbook -i inventory.yml deploy.yml  # Quick redeploy
ansible-playbook -i inventory.yml certbot.yml # SSL certificate
```

## Deployment rules — MANDATORY

1. **Every change MUST go through a pull request.** Never push directly to main.
2. **Create PR first, then deploy.** No deploy without a merged PR.
3. **Deploy command:** `cd ansible && ansible-playbook -i inventory.yml deploy.yml`
4. **Never commit** .env, inventory.yml, secrets, or production configs.
5. Copy *.example files and edit locally.

## Stack

- FastAPI + Uvicorn (Python 3.12)
- PostgreSQL 16-alpine
- Docker Compose (host network mode)
- Vanilla HTML/CSS/JS SPA (admin GUI)
