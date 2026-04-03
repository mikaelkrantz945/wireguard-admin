# WireGuard Admin

WireGuard VPN administration system with a web-based admin GUI, REST API, per-peer ACL profiles, and HostBill script provisioning integration.

Built for [No-Ack Hosting](https://noackhosting.se) to manage VPN customers through a centralized interface.

## Features

- **Admin GUI** — Dark-themed single-page application for managing peers, interfaces, ACL profiles, API keys, users, and request logs
- **Peer management** — Create, edit, enable/disable, and delete VPN peers with auto-generated keys and IP allocation
- **QR codes** — Scan-ready QR codes for instant WireGuard mobile client setup
- **ACL profiles** — Per-peer access control with client-side routing (AllowedIPs) and server-side iptables enforcement
- **IPAM** — Automatic IP address allocation from configurable subnets
- **API key auth** — Scoped API keys with IP ACL, SHA-256 hashed storage
- **2FA** — Optional Google Authenticator (TOTP) for admin accounts
- **HostBill integration** — Script provisioning webhook for automated Create/Suspend/Unsuspend/Terminate
- **Request logging** — All API requests logged to PostgreSQL with filtering and stats
- **Automated backups** — Daily pg_dump sidecar with 7-day retention

## Architecture

```
Internet
  |
  Nginx (HTTPS, Let's Encrypt)
  |   proxy_pass :8092
  |
  Docker Compose
  |-- wgadmin-api    FastAPI (Python 3.12), network_mode: host
  |     |-- mounts /etc/wireguard from host
  |     |-- runs wg/wg-quick commands with CAP_NET_ADMIN
  |-- wgadmin-db     PostgreSQL 16-alpine (localhost:5432)
  |-- wgadmin-backup pg_dump sidecar (daily 03:00 UTC)
  |
  WireGuard kernel module (host)
```

The API container runs with `network_mode: host` and `CAP_NET_ADMIN` so that `wg` and `wg-quick` commands directly affect the host's WireGuard interfaces. Config changes are applied live using `wg syncconf` for zero-downtime reloads.

## Quick start

```bash
git clone git@github.com:mikaelkrantz945/wireguard-admin.git
cd wireguard-admin
cp .env.example .env    # Edit with your settings
docker compose up -d --build

# Create first admin user
curl -X POST http://localhost:8092/admin/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"firstname":"Admin","lastname":"User","email":"admin@example.com","password":"changeme1"}'

# Open admin GUI
open http://localhost:8092/admin/ui
```

## Deployment with Ansible

Target: clean Ubuntu server with SSH access.

```bash
cd ansible

# Full server provisioning (packages, Docker, WireGuard, Nginx, app)
ansible-playbook -i inventory.yml site.yml

# SSL certificate
ansible-playbook -i inventory.yml certbot.yml

# Quick redeploy (git pull + rebuild)
ansible-playbook -i inventory.yml deploy.yml
```

### Ansible roles

| Role | What it does |
|------|-------------|
| common | Base packages, UFW (SSH, HTTP, HTTPS, WG/UDP), timezone |
| docker | Docker CE + Compose plugin, adds user to docker group |
| wireguard | wireguard-tools, IP forwarding (sysctl) |
| nginx | Reverse proxy vhost, reload handler |
| certbot | Let's Encrypt SSL certificate |
| app | Git clone, .env template, docker compose up, health check |

## Configuration

All settings via environment variables (`.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://wgadmin:wgadmin@127.0.0.1:5432/wgadmin` | PostgreSQL connection |
| `WG_CONFIG_DIR` | `/etc/wireguard` | WireGuard config directory |
| `WG_DEFAULT_DNS` | `195.47.238.46, 195.47.238.48` | DNS servers for client configs |
| `WG_DEFAULT_ENDPOINT` | `vpndev.no-ack.net` | Server endpoint for client configs |
| `WG_DEFAULT_SUBNET` | `10.0.0.0/24` | Default subnet for new interfaces |
| `WG_DEFAULT_PORT` | `51820` | Default WireGuard listen port |
| `HOSTBILL_WEBHOOK_SECRET` | | Shared secret for HostBill provisioning |
| `API_PORT` | `8092` | API listen port |
| `SMTP_HOST` | `mx.noackinfra.se` | SMTP server for invite emails |
| `SMTP_PORT` | `26` | SMTP port |
| `SMTP_FROM` | `noreply@no-ack.net` | From address for invite emails |
| `BASE_URL` | `https://vpndev.no-ack.net` | Base URL for invite links |

## ACL Profiles

ACL profiles control what each VPN peer can access, with two layers of enforcement:

1. **Client AllowedIPs** — Controls what traffic the client routes through the tunnel
2. **Firewall rules** — Server-side iptables enforcement via a custom `WG_ACL` chain

### Firewall rule format

Each rule: `destination[:ports[/protocol]]`, one per line or separated by semicolons.

| Rule | Meaning |
|------|---------|
| `10.0.0.0/8` | All traffic to 10.0.0.0/8 |
| `0.0.0.0/0:80,443` | TCP ports 80 and 443 to any destination |
| `0.0.0.0/0:80,443/tcp` | Same as above (tcp is default) |
| `8.8.8.8/32:53/udp` | UDP port 53 to 8.8.8.8 |
| `0.0.0.0/0:53/both` | TCP+UDP port 53 to anywhere |

### Profile examples

| Profile | Client AllowedIPs | Firewall rules | Effect |
|---------|-------------------|----------------|--------|
| Full Access | `0.0.0.0/0, ::/0` | *(empty)* | Full tunnel, unrestricted |
| Web Only | `0.0.0.0/0, ::/0` | `0.0.0.0/0:80,443`<br>`0.0.0.0/0:53/udp` | Full tunnel, only HTTP/HTTPS + DNS |
| Internal Only | `10.0.0.0/8` | `10.0.0.0/8` | Split tunnel, internal network only |
| Internal + Web | `0.0.0.0/0, ::/0` | `10.0.0.0/8`<br>`0.0.0.0/0:80,443`<br>`0.0.0.0/0:53/udp` | Full tunnel, internal unrestricted + web + DNS |

A default "Full Access" profile is created automatically on first startup.

---

# API Documentation

All API endpoints require authentication via `X-API-Key` header — either a session token (from admin GUI login) or an API key created in the admin panel.

**Base URL:** `https://vpndev.no-ack.net`

## Authentication & Users

### Login

```bash
curl -X POST /admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"mypassword"}'
```

Response:
```json
{
  "token": "session_token_here",
  "must_change_password": false,
  "user": {"id": 1, "firstname": "Admin", "lastname": "User", "email": "admin@example.com", "role": "admin", "totp_enabled": false}
}
```

If 2FA is enabled, first call returns `{"requires_totp": true}`. Retry with `totp_code`:

```bash
curl -X POST /admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"mypassword","totp_code":"123456"}'
```

### Logout

```bash
curl -X POST /admin/auth/logout \
  -H "X-API-Key: SESSION_TOKEN"
```

### Get current user

```bash
curl /admin/auth/me \
  -H "X-API-Key: SESSION_TOKEN"
```

### Change password

```bash
curl -X POST /admin/auth/change-password \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"newpassword123"}'
```

### Invite user

```bash
curl -X POST /admin/users/invite \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"firstname":"John","lastname":"Doe","email":"john@example.com","role":"readonly"}'
```

### List users

```bash
curl /admin/users \
  -H "X-API-Key: SESSION_TOKEN"
```

### Delete user

```bash
curl -X DELETE /admin/users/3 \
  -H "X-API-Key: SESSION_TOKEN"
```

### Setup 2FA

```bash
# Generate QR code
curl -X POST /admin/auth/totp/setup \
  -H "X-API-Key: SESSION_TOKEN"

# Enable with verification code
curl -X POST /admin/auth/totp/enable \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"secret":"BASE32SECRET","code":"123456"}'

# Disable
curl -X POST /admin/auth/totp/disable \
  -H "X-API-Key: SESSION_TOKEN"
```

## API Keys

### Create API key

```bash
curl -X POST /admin/keys \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"customer":"acme-hosting","scope":"wireguard","note":"Production key","allowed_ips":"203.0.113.10, 203.0.113.11"}'
```

Scopes: `wireguard`, `hostbill`, `all`

Response includes the raw key (shown only once):
```json
{
  "id": 1,
  "key": "a1b2c3d4e5f6...",
  "prefix": "a1b2c3d4...",
  "customer": "acme-hosting",
  "scope": "wireguard"
}
```

### List keys

```bash
curl /admin/keys \
  -H "X-API-Key: SESSION_TOKEN"

# Filter by customer
curl "/admin/keys?customer=acme-hosting" \
  -H "X-API-Key: SESSION_TOKEN"
```

### Revoke / delete key

```bash
# Revoke (soft delete — marks inactive)
curl -X DELETE /admin/keys/1 \
  -H "X-API-Key: SESSION_TOKEN"

# Delete permanently
curl -X DELETE /admin/keys/1/permanent \
  -H "X-API-Key: SESSION_TOKEN"
```

## WireGuard Interfaces

### List interfaces

```bash
curl /wg/interfaces \
  -H "X-API-Key: API_KEY"
```

Response:
```json
[
  {
    "id": 1, "name": "wg0", "address": "10.0.0.1/24", "subnet": "10.0.0.0/24",
    "listen_port": 51820, "endpoint": "vpndev.no-ack.net:51820",
    "is_up": true, "peer_count": 5
  }
]
```

### Create interface

```bash
curl -X POST /wg/interfaces \
  -H "X-API-Key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "wg0",
    "listen_port": 51820,
    "subnet": "10.0.0.0/24",
    "dns": "195.47.238.46, 195.47.238.48",
    "post_up": "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
    "post_down": "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
  }'
```

The interface is automatically started (`wg-quick up`) after creation.

### Update interface

```bash
curl -X PUT /wg/interfaces/1 \
  -H "X-API-Key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"dns":"1.1.1.1, 8.8.8.8","endpoint":"vpn.example.com:51820"}'
```

### Bring interface up / down

```bash
curl -X POST /wg/interfaces/1/up \
  -H "X-API-Key: API_KEY"

curl -X POST /wg/interfaces/1/down \
  -H "X-API-Key: API_KEY"
```

### Delete interface

```bash
curl -X DELETE /wg/interfaces/1 \
  -H "X-API-Key: API_KEY"
```

## WireGuard Peers

### List peers

```bash
curl /wg/interfaces/1/peers \
  -H "X-API-Key: API_KEY"
```

Response includes live status merged from `wg show`:
```json
[
  {
    "id": 1, "name": "johns-laptop", "allowed_ips": "10.0.0.2/32",
    "enabled": true, "acl_profile_id": 1, "acl_profile_name": "Full Access",
    "live_endpoint": "203.0.113.50:54321",
    "latest_handshake": 1712150400,
    "transfer_rx": 15728640, "transfer_tx": 8388608
  }
]
```

### Create peer

```bash
curl -X POST /wg/interfaces/1/peers \
  -H "X-API-Key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"johns-laptop","note":"John Doe personal device","acl_profile_id":1}'
```

Response includes the client config and QR code:
```json
{
  "peer": {"id": 1, "name": "johns-laptop", "allowed_ips": "10.0.0.2/32", ...},
  "client_config": "[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\n...",
  "qr_code": "data:image/png;base64,..."
}
```

### Get peer details

```bash
curl /wg/peers/1 \
  -H "X-API-Key: API_KEY"
```

### Update peer

```bash
curl -X PUT /wg/peers/1 \
  -H "X-API-Key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"johns-new-laptop","acl_profile_id":2,"note":"Upgraded device"}'
```

### Enable / disable peer

```bash
curl -X POST /wg/peers/1/enable \
  -H "X-API-Key: API_KEY"

curl -X POST /wg/peers/1/disable \
  -H "X-API-Key: API_KEY"
```

### Delete peer

```bash
curl -X DELETE /wg/peers/1 \
  -H "X-API-Key: API_KEY"
```

### Download client config

```bash
curl /wg/peers/1/config \
  -H "X-API-Key: API_KEY"
```

Response:
```json
{
  "config": "[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\nDNS = 195.47.238.46, 195.47.238.48\n\n[Peer]\nPublicKey = ...\nEndpoint = vpndev.no-ack.net:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
}
```

### Get QR code

```bash
curl /wg/peers/1/qr \
  -H "X-API-Key: API_KEY"
```

Response:
```json
{"qr_code": "data:image/png;base64,..."}
```

## ACL Profiles

### List profiles

```bash
curl /wg/acl-profiles \
  -H "X-API-Key: API_KEY"
```

Response:
```json
[
  {
    "id": 1, "name": "Full Access", "description": "Full tunnel",
    "allowed_ips": "0.0.0.0/0, ::/0", "fw_rules": "",
    "is_default": true, "peer_count": 3
  },
  {
    "id": 2, "name": "Web Only", "description": "HTTP/HTTPS + DNS only",
    "allowed_ips": "0.0.0.0/0, ::/0", "fw_rules": "0.0.0.0/0:80,443; 0.0.0.0/0:53/udp",
    "is_default": false, "peer_count": 1
  }
]
```

### Create profile

```bash
curl -X POST /wg/acl-profiles \
  -H "X-API-Key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Web Only",
    "description": "HTTP/HTTPS and DNS only",
    "allowed_ips": "0.0.0.0/0, ::/0",
    "fw_rules": "0.0.0.0/0:80,443; 0.0.0.0/0:53/udp"
  }'
```

### Create profile with full internal access + restricted external

```bash
curl -X POST /wg/acl-profiles \
  -H "X-API-Key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal + Web",
    "description": "Full internal access, external web only",
    "allowed_ips": "0.0.0.0/0, ::/0",
    "fw_rules": "10.0.0.0/8; 0.0.0.0/0:80,443; 0.0.0.0/0:53/udp"
  }'
```

### Update profile

```bash
curl -X PUT /wg/acl-profiles/2 \
  -H "X-API-Key: API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"fw_rules":"0.0.0.0/0:80,443; 0.0.0.0/0:53/both; 10.0.0.0/8"}'
```

Updating a profile re-applies iptables rules for all affected peers.

### Delete profile

```bash
curl -X DELETE /wg/acl-profiles/2 \
  -H "X-API-Key: API_KEY"
```

Cannot delete the default profile or a profile in use by peers.

## Live Status

### All interfaces

```bash
curl /wg/status \
  -H "X-API-Key: API_KEY"
```

### Specific interface

```bash
curl /wg/status/wg0 \
  -H "X-API-Key: API_KEY"
```

Response (parsed from `wg show wg0 dump`):
```json
{
  "interface": "wg0", "up": true,
  "public_key": "X0XZ3y...", "listen_port": 51820,
  "peers": [
    {
      "public_key": "abc123...",
      "endpoint": "203.0.113.50:54321",
      "allowed_ips": "10.0.0.2/32",
      "latest_handshake": 1712150400,
      "transfer_rx": 15728640,
      "transfer_tx": 8388608
    }
  ]
}
```

## HostBill Script Provisioning

Single endpoint for all provisioning actions. Authenticated via shared secret (not API key).

### Create (provision new VPN peer)

```bash
curl -X POST /hostbill/provision \
  -H "Content-Type: application/json" \
  -d '{
    "action": "Create",
    "secret": "your-webhook-secret",
    "service_id": 12345,
    "client_id": 678,
    "client_email": "customer@example.com",
    "client_name": "John Doe",
    "package": "vpn-basic"
  }'
```

Response:
```json
{
  "success": true, "action": "create",
  "service_id": 12345, "peer_id": 1,
  "client_config": "[Interface]\nPrivateKey = ...",
  "ip_address": "10.0.0.2/32"
}
```

### Suspend

```bash
curl -X POST /hostbill/provision \
  -H "Content-Type: application/json" \
  -d '{"action":"Suspend","secret":"your-webhook-secret","service_id":12345}'
```

### Unsuspend

```bash
curl -X POST /hostbill/provision \
  -H "Content-Type: application/json" \
  -d '{"action":"Unsuspend","secret":"your-webhook-secret","service_id":12345}'
```

### Terminate

```bash
curl -X POST /hostbill/provision \
  -H "Content-Type: application/json" \
  -d '{"action":"Terminate","secret":"your-webhook-secret","service_id":12345}'
```

### Health check

```bash
curl /hostbill/health
```

## Request Logs

### Get logs

```bash
curl "/admin/logs?limit=50&customer=acme&path=/wg" \
  -H "X-API-Key: SESSION_TOKEN"
```

### Get stats

```bash
curl /admin/stats \
  -H "X-API-Key: SESSION_TOKEN"
```

Response:
```json
{
  "total_requests": 1542,
  "today": 87,
  "today_errors": 3,
  "today_by_scope": {"wireguard": 45, "admin": 38, "hostbill": 4}
}
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI (Python 3.12), Uvicorn |
| Database | PostgreSQL 16-alpine |
| Frontend | Vanilla HTML/CSS/JS (single-file SPA) |
| Auth | SHA-256 hashed sessions + API keys, TOTP 2FA (pyotp) |
| VPN | WireGuard (kernel module + wireguard-tools) |
| Container | Docker Compose (host network mode) |
| Proxy | Nginx + Let's Encrypt (Certbot) |
| IaC | Ansible (6 roles) |
| Backup | pg_dump sidecar (daily, 7-day retention) |
