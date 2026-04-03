# Quickstart Guide

Get WireGuard Admin running on a fresh Ubuntu/Debian server in under 10 minutes.

## Requirements

- **Ubuntu 22.04+** or **Debian 12+** (fresh install)
- **Root access** (or sudo)
- **A domain name** pointed at your server's IP (for HTTPS)
- **Port 51820/UDP** open (WireGuard)

## Step 1: Install prerequisites

```bash
sudo apt update
sudo apt install -y git ansible
```

## Step 2: Clone the repo

```bash
git clone https://github.com/mikaelkrantz945/wireguard-admin.git
cd wireguard-admin
```

## Step 3: Run the setup wizard

The setup script asks for your domain, email, WireGuard settings, and generates all config files.

```bash
./setup.sh
```

It creates:
- `.env` — application environment config
- `ansible/inventory.yml` — Ansible inventory for local provisioning

Example session:
```
Domain name: vpn.mycompany.com
Admin email: admin@mycompany.com
WireGuard subnet [10.0.0.0/24]: ↵
WireGuard port [51820]: ↵
DNS servers [1.1.1.1, 8.8.8.8]: ↵
API port [8092]: ↵
SMTP host [localhost]: smtp.mycompany.com
SMTP port [25]: 587
SMTP from [noreply@vpn.mycompany.com]: ↵
HostBill webhook secret: ↵
```

## Step 4: Run the Ansible playbook

This installs everything: Docker, WireGuard, Nginx, firewall rules, network tuning, and starts the application.

```bash
cd ansible
sudo ansible-playbook -i inventory.yml local.yml
```

What it does:
- Installs Docker, WireGuard, Nginx, certbot, irqbalance
- Configures UFW firewall (SSH, HTTP, HTTPS, WireGuard)
- Tunes network stack (BBR, buffer sizes, conntrack)
- Enables IP forwarding and wg0 auto-start
- Sets up Nginx reverse proxy
- Builds and starts Docker containers (API + PostgreSQL + backup)
- Waits for the API to be healthy

## Step 5: Get HTTPS certificate

```bash
sudo ansible-playbook -i inventory.yml certbot.yml
```

## Step 6: Create your admin account

```bash
curl -X POST http://localhost:8092/admin/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "firstname": "Admin",
    "lastname": "User",
    "email": "admin@mycompany.com",
    "password": "changeme1"
  }'
```

## Step 7: Open the admin GUI

Go to **https://vpn.mycompany.com/admin/ui**

Log in with your email and password. You'll be asked to set a new password on first login.

## Step 8: Create your first VPN interface

In the admin GUI:
1. Go to **Interfaces** tab
2. Click **+ New Interface** (defaults are fine for most setups)
3. The interface starts automatically

## Step 9: Create VPN users

### Option A: Manual
1. Go to **Peers** tab → **+ New Peer**
2. Enter a name, select a group if desired
3. Set portal email + password for user self-service
4. The QR code appears — scan it with the WireGuard mobile app

### Option B: Invite
1. Go to **Users** tab → **+ Invite User**
2. Select **VPN User**, enter name + email, choose group
3. User receives activation email → sets password → VPN activated

### Option C: Google Workspace import
1. Go to **Integrations** tab → **+ Add Integration** → Google Workspace
2. Follow the OAuth setup wizard
3. Click **Sync & Import** → select users → choose group
4. Users receive activation emails

## Updating

```bash
cd wireguard-admin
git pull
cd ansible
sudo ansible-playbook -i inventory.yml local.yml
```

Or if using remote deployment:
```bash
cd ansible
ansible-playbook -i inventory.yml deploy.yml
```

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 22 | TCP | SSH |
| 80 | TCP | HTTP (redirects to HTTPS) |
| 443 | TCP | HTTPS (admin GUI + portal + API) |
| 51820 | UDP | WireGuard VPN |

## URLs

| URL | Purpose |
|-----|---------|
| `/admin/ui` | Admin panel (manage peers, groups, ACLs, integrations) |
| `/portal/ui` | User portal (view config, QR code, download .conf) |
| `/health` | Health check endpoint |
| `/docs` | FastAPI auto-generated API docs (Swagger) |

## Troubleshooting

### API not starting
```bash
docker logs wgadmin-api --tail 50
```

### WireGuard interface not up
```bash
sudo wg show
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

### Can't reach the admin GUI
```bash
# Check nginx
sudo nginx -t
sudo systemctl status nginx

# Check API is listening
curl http://localhost:8092/health
```

### Peers can't connect
```bash
# Check firewall
sudo ufw status

# Check WireGuard is running
sudo wg show wg0

# Check IP forwarding
sysctl net.ipv4.ip_forward
```
