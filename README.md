# WireGuard Admin

WireGuard VPN administration system with a web-based admin GUI, REST API, per-peer ACL profiles, and HostBill script provisioning integration.

Open-source VPN management for hosting providers and teams.

**[Quickstart Guide](QUICKSTART.md)** — Get running on a fresh Ubuntu server in under 10 minutes.

## Screenshots

| | |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Peers](docs/screenshots/peers.png) |
| **Dashboard** — Active peers, traffic stats, interface status | **Peers** — Manage VPN peers with live status, ACL, groups |
| ![ACL Profiles](docs/screenshots/acl-profiles.png) | ![Interfaces](docs/screenshots/interfaces.png) |
| **ACL Profiles** — Firewall rule builder with port/protocol control | **Interfaces** — WireGuard server interfaces with up/down control |
| ![Groups](docs/screenshots/groups.png) | ![Request Logs](docs/screenshots/request-logs.png) |
| **Groups** — Organize peers with inherited ACL profiles | **Request Logs** — API request logging with filtering |
| ![API Keys](docs/screenshots/api-keys.png) | ![Login](docs/screenshots/login.png) |
| **API Keys** — Scoped keys with IP ACL | **Login** — Email + password + optional 2FA |

## Features

- **Admin GUI** — Dark-themed SPA for managing peers, interfaces, ACL profiles, groups, integrations, API keys, users, and request logs
- **User portal** — Self-service portal (`/portal/ui`) where VPN users view their config, scan QR codes, download `.conf` files
- **Peer management** — Create, edit, enable/disable, and delete VPN peers with auto-generated keys and IP allocation
- **QR codes** — Scan-ready QR codes for instant WireGuard mobile client setup
- **ACL profiles** — Per-peer access control with visual firewall rule builder (destination, protocol, ports, ACCEPT/DROP) and server-side iptables enforcement
- **Groups** — Organize peers into groups with inherited ACL profiles
- **Google Workspace integration** — Import users from Google Directory API with OAuth2, extensible provider framework for Azure AD/LDAP
- **Activation flow** — Email verification with two paths: set password or Google OAuth activation
- **Invite system** — Invite VPN users, admin (read-only), or admin (full) from the Users tab
- **IPAM** — Automatic IP address allocation from configurable subnets
- **API key auth** — Scoped API keys with IP ACL, SHA-256 hashed storage
- **2FA** — Optional Google Authenticator (TOTP) for admin accounts
- **HostBill integration** — Script provisioning webhook (Create/Suspend/Unsuspend/Terminate) with instant activation and welcome email
- **Request logging** — All API requests logged to PostgreSQL with filtering and stats
- **Automated backups** — Daily pg_dump sidecar with 7-day retention
- **Network tuning** — BBR congestion control, optimized buffers, irqbalance for multi-core throughput

## Architecture

```
Internet
  |
  Nginx (HTTPS, Let's Encrypt)        — or external reverse proxy
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

Two deployment modes are supported:
- **Local TLS** (`ssl_mode: local`) — Nginx + Certbot handles HTTPS directly (default)
- **Reverse proxy** (`ssl_mode: proxy`) — An external reverse proxy handles TLS, local Nginx runs HTTP only

## Quick start

```bash
sudo apt install -y git ansible
git clone https://github.com/mikaelkrantz945/wireguard-admin.git
cd wireguard-admin
./setup.sh                                                       # Answer questions
cd ansible && sudo ansible-playbook -i inventory.yml local.yml   # Install everything
sudo ansible-playbook -i inventory.yml certbot.yml               # SSL certificate
```

Then bootstrap your admin account and open the GUI:

```bash
curl -X POST http://localhost:8092/admin/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"firstname":"Admin","lastname":"User","email":"admin@example.com","password":"changeme1"}'
```

Open **https://your-domain/admin/ui** — done.

## Deployment

### Local server (recommended)

Run the interactive setup wizard — it asks for your domain, email, WireGuard settings and generates all config files:

```bash
./setup.sh

# Provision everything (Docker, WireGuard, Nginx, firewall, app)
cd ansible && sudo ansible-playbook -i inventory.yml local.yml

# SSL certificate
sudo ansible-playbook -i inventory.yml certbot.yml
```

See **[QUICKSTART.md](QUICKSTART.md)** for the full step-by-step guide.

### Remote server

If deploying to a remote server, edit `ansible/inventory.yml.example` with your SSH details:

```bash
cd ansible
cp inventory.yml.example inventory.yml  # Edit with your server details
ansible-playbook -i inventory.yml site.yml
ansible-playbook -i inventory.yml certbot.yml
```

### Behind an external reverse proxy

If another server handles TLS termination (e.g., a load balancer or separate nginx), set `ssl_mode: proxy` in your inventory:

```yaml
vars:
  ssl_mode: "proxy"
  base_url: "https://vpn.example.com"
  # listen_port: 8080        # Nginx listen port (default: 80)
  # trusted_proxy: 10.0.0.1  # Upstream proxy IP for real_ip_header
```

This skips Certbot, keeps Nginx on HTTP only, and trusts `X-Forwarded-Proto` / `X-Forwarded-For` headers from the upstream proxy. Configure your external proxy to pass these headers and proxy to this server's port 80.

### Quick redeploy

```bash
cd ansible && ansible-playbook -i inventory.yml deploy.yml
```

### Ansible roles

| Role | What it does |
|------|-------------|
| common | Base packages, UFW (SSH, HTTP, HTTPS, WG/UDP), timezone |
| docker | Docker CE + Compose plugin, adds user to docker group |
| wireguard | wireguard-tools, IP forwarding (sysctl) |
| nginx | Reverse proxy vhost, reload handler (HTTP-only in proxy mode) |
| certbot | Let's Encrypt SSL certificate (skipped in proxy mode) |
| app | Git clone, .env template, docker compose up, health check |

## Configuration

All settings via environment variables (`.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://wgadmin:wgadmin@127.0.0.1:5432/wgadmin` | PostgreSQL connection |
| `WG_CONFIG_DIR` | `/etc/wireguard` | WireGuard config directory |
| `WG_DEFAULT_DNS` | `1.1.1.1, 8.8.8.8` | DNS servers for client configs |
| `WG_DEFAULT_ENDPOINT` | `vpn.example.com` | Server endpoint for client configs |
| `WG_DEFAULT_SUBNET` | `10.0.0.0/24` | Default subnet for new interfaces |
| `WG_DEFAULT_PORT` | `51820` | Default WireGuard listen port |
| `HOSTBILL_WEBHOOK_SECRET` | | Shared secret for HostBill provisioning |
| `API_PORT` | `8092` | API listen port |
| `SMTP_HOST` | `localhost` | SMTP server for invite emails |
| `SMTP_PORT` | `25` | SMTP port |
| `SMTP_FROM` | `noreply@example.com` | From address for invite emails |
| `BASE_URL` | `https://vpn.example.com` | Base URL for invite links |

### Ansible inventory variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ssl_mode` | `local` | `local` = Certbot/Let's Encrypt on this server, `proxy` = external reverse proxy handles TLS |
| `base_url` | `https://{{domain}}` | Public URL (set explicitly in proxy mode) |
| `listen_port` | `80` | Nginx listen port (proxy mode only) |
| `trusted_proxy` | `0.0.0.0/0` | Upstream proxy IP for `set_real_ip_from` (proxy mode only) |

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

## Groups

Groups organize peers and assign ACL profiles collectively. When a peer is added to a group, it inherits the group's ACL profile automatically.

- Create groups in the **Groups** tab (e.g., "Customers", "Developers", "Admins")
- Assign an ACL profile to each group
- When creating or editing a peer, select a group — the ACL profile is inherited
- Changing a group's ACL profile updates all peers in that group

## User Portal

Self-service portal at `/portal/ui` where VPN users can:

- **Log in** with email + password (local credentials)
- **Log in with Google** (if a Google Workspace integration is configured)
- **View** their VPN configuration
- **Scan QR code** with the WireGuard mobile app
- **Download** `.conf` file

The portal is separate from the admin panel — VPN users never see the admin interface.

## Activation Flow

Peers require activation before VPN access is enabled. There are two paths depending on how the account was created:

### Invited or imported users

```
Admin creates peer → Activation email sent → User clicks link
  → Password method: Set password → Account activated → Peer enabled
  → Google method: Click activate → Account activated → Log in with Google
```

The peer is **disabled in WireGuard** until the user activates. This prevents unused peers from cluttering the config.

### HostBill-provisioned users

```
HostBill calls /hostbill/provision (Create) → Peer created as ACTIVE
  → Welcome email sent → User clicks link → Sets portal password
  → Can view config/QR in portal
```

HostBill peers are **active immediately** (paid service). The welcome email lets users set a portal password to access their config/QR code.

### Invite roles

The **+ Invite User** button in the Users tab supports three roles:

| Role | What happens |
|------|-------------|
| **VPN User** | Creates a WireGuard peer + sends activation email. Select group and activation method (password/Google) |
| **Admin (Read-only)** | Creates an admin panel user with view-only access |
| **Admin (Full)** | Creates an admin panel user with full write access |

## Integrations

Extensible identity provider framework for importing users from external systems.

### Google Workspace

Import users from Google Directory API:

1. Go to **Integrations** tab → **+ Add Integration**
2. Select **Google Workspace** and follow the setup instructions
3. Enter client_id, client_secret, and workspace domain
4. Complete the OAuth flow to connect
5. Click **Sync & Import** → select users → choose interface + group → peers created with activation emails

### Adding new providers

Implement `BaseProvider` in `app/integrations/`:

```python
class MyProvider(BaseProvider):
    provider_type = "my_provider"
    display_name = "My Provider"
    config_fields = [...]

    def get_auth_url(self, config, redirect_uri): ...
    def exchange_code(self, config, code, redirect_uri): ...
    def list_users(self, config, tokens): ...
```

Register in `PROVIDERS` dict in `app/integrations/routes.py`.

---

# API Documentation

All API endpoints require authentication via `X-API-Key` header — either a session token (from admin GUI login) or an API key created in the admin panel.

**Base URL:** `https://vpn.example.com`

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
    "listen_port": 51820, "endpoint": "vpn.example.com:51820",
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
    "dns": "1.1.1.1, 8.8.8.8",
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
  "config": "[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = ...\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
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

## User Portal

### Login (email + password)

```bash
curl -X POST /portal/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"mypassword"}'
```

### Login (Google OAuth)

```bash
curl -X POST /portal/auth/google \
  -H "Content-Type: application/json" \
  -d '{"integration_id":1,"code":"google_auth_code","redirect_uri":"https://vpn.example.com/portal/ui"}'
```

### Get my config / QR

```bash
curl /portal/config -H "X-API-Key: PORTAL_TOKEN"
curl /portal/qr -H "X-API-Key: PORTAL_TOKEN"
```

### Activate account (password method)

```bash
curl -X POST /portal/activate/password \
  -H "Content-Type: application/json" \
  -d '{"token":"activation_token_from_email","password":"newpassword"}'
```

### Send activation email (admin)

```bash
curl -X POST /portal/send-activation \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"peer_id":1,"method":"password"}'
```

## Integrations

### List providers

```bash
curl /integrations/providers -H "X-API-Key: SESSION_TOKEN"
```

### Create integration

```bash
curl -X POST /integrations \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google_workspace",
    "name": "Acme Corp Google",
    "config": {"client_id":"xxx","client_secret":"xxx","domain":"acme.com"}
  }'
```

### OAuth flow

```bash
# Get auth URL
curl /integrations/1/auth-url -H "X-API-Key: SESSION_TOKEN"

# Exchange code
curl -X POST /integrations/1/callback \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"google_auth_code"}'
```

### Sync and import users

```bash
# List users from provider
curl /integrations/1/users -H "X-API-Key: SESSION_TOKEN"

# Import selected users
curl -X POST /integrations/1/import \
  -H "X-API-Key: SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "interface_id": 1,
    "group_id": 2,
    "users": [
      {"email":"john@acme.com","firstname":"John","lastname":"Doe"},
      {"email":"jane@acme.com","firstname":"Jane","lastname":"Smith"}
    ]
  }'
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

## Client Installation Guide

### macOS (MacBook)

**Option A: App Store (recommended)**

1. Install **WireGuard** from the [Mac App Store](https://apps.apple.com/app/wireguard/id1451685025)
2. Open WireGuard → click **+** → **Add Empty Tunnel** or **Import tunnel(s) from file**
3. Paste your config or import the `.conf` file downloaded from the portal

**Option B: Homebrew**

```bash
brew install wireguard-tools

# Save your config
nano /usr/local/etc/wireguard/wg0.conf   # Paste config from portal

# Connect
sudo wg-quick up wg0

# Disconnect
sudo wg-quick down wg0

# Check status
sudo wg show
```

**Option C: QR code**

1. Install the WireGuard app on your iPhone/iPad
2. Open WireGuard → **+** → **Create from QR code**
3. Scan the QR code from the portal or admin GUI

### Linux (Ubuntu/Debian)

```bash
# Install
sudo apt update && sudo apt install -y wireguard

# Save config (paste from portal)
sudo nano /etc/wireguard/wg0.conf

# Connect
sudo wg-quick up wg0

# Disconnect
sudo wg-quick down wg0

# Auto-start on boot
sudo systemctl enable wg-quick@wg0

# Check status
sudo wg show
```

### Linux (Fedora/RHEL/CentOS)

```bash
# Install
sudo dnf install -y wireguard-tools

# Save config
sudo nano /etc/wireguard/wg0.conf

# Connect / disconnect
sudo wg-quick up wg0
sudo wg-quick down wg0

# Auto-start
sudo systemctl enable wg-quick@wg0
```

### Linux (Arch)

```bash
sudo pacman -S wireguard-tools
sudo nano /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

### Windows

1. Download WireGuard from [wireguard.com/install](https://www.wireguard.com/install/)
2. Open WireGuard → **Add Tunnel** → **Import tunnel(s) from file**
3. Import the `.conf` file downloaded from the portal
4. Click **Activate**

### Android / iOS

1. Install **WireGuard** from [Google Play](https://play.google.com/store/apps/details?id=com.wireguard.android) or [App Store](https://apps.apple.com/app/wireguard/id1441195209)
2. Open WireGuard → **+** → **Scan from QR code**
3. Scan the QR code from the portal — done

### Verify connection

After connecting, verify your VPN is working:

```bash
# Check WireGuard status
sudo wg show

# Verify your IP changed (should show VPN server IP)
curl ifconfig.me

# Test DNS resolution
nslookup example.com
```

## Contributing

1. Fork the repo and create a feature branch (`git checkout -b feature/my-change`)
2. Make your changes
3. Push and open a pull request against `main`
4. Wait for review and approval

**Rules:**
- All changes go through pull requests — direct pushes to `main` are blocked
- Never commit `.env`, `inventory.yml`, secrets, API keys, or production configs
- Copy `*.example` files and configure locally
- Keep the single-file SPA pattern (no build tools, no frameworks)

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI (Python 3.12), Uvicorn |
| Database | PostgreSQL 16-alpine |
| Frontend | Vanilla HTML/CSS/JS (single-file SPA) |
| Auth | SHA-256 hashed sessions + API keys, TOTP 2FA (pyotp) |
| VPN | WireGuard (kernel module + wireguard-tools) |
| Container | Docker Compose (host network mode) |
| Proxy | Nginx + Let's Encrypt (Certbot), or external reverse proxy |
| IaC | Ansible (6 roles) |
| Backup | pg_dump sidecar (daily, 7-day retention) |
