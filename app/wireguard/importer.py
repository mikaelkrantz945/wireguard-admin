"""WireGuard config file parser and import logic."""

import os
import re
import ipaddress
from datetime import datetime
from .. import db
from . import ipam

def scan_configs(config_dir: str = "/etc/wireguard") -> list[dict]:
    """Scan for existing WireGuard config files. Returns list of parsed interfaces with their peers."""
    results = []
    if not os.path.isdir(config_dir):
        return results
    for fname in sorted(os.listdir(config_dir)):
        if not fname.endswith(".conf"):
            continue
        iface_name = fname[:-5]  # strip .conf
        path = os.path.join(config_dir, fname)
        try:
            parsed = parse_config(path, iface_name)
            if parsed:
                results.append(parsed)
        except Exception as e:
            results.append({"name": iface_name, "error": str(e)})
    return results


def parse_config(path: str, iface_name: str) -> dict:
    """Parse a WireGuard config file into interface + peers dict."""
    with open(path, "r") as f:
        content = f.read()

    # Split into sections
    sections = re.split(r'\n(?=\[)', content)

    interface = {"name": iface_name, "peers": []}

    for section in sections:
        section = section.strip()
        if not section:
            continue

        if section.startswith("[Interface]"):
            lines = section.split("\n")[1:]  # skip [Interface] header
            for line in lines:
                line = line.strip()
                if "=" not in line or line.startswith("#"):
                    continue
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()
                if key == "privatekey":
                    interface["private_key"] = value
                elif key == "address":
                    interface["address"] = value
                    # Derive subnet from address
                    try:
                        net = ipaddress.ip_interface(value.split(",")[0].strip())
                        interface["subnet"] = str(net.network)
                    except:
                        pass
                elif key == "listenport":
                    interface["listen_port"] = int(value)
                elif key == "postup":
                    interface["post_up"] = value
                elif key == "postdown":
                    interface["post_down"] = value

        elif section.startswith("[Peer]"):
            peer = {}
            comment_name = ""
            lines = section.split("\n")
            # Check line before [Peer] for comment name
            for i, line in enumerate(lines):
                line_stripped = line.strip()
                if line_stripped.startswith("# Peer:") or line_stripped.startswith("#Peer:"):
                    comment_name = line_stripped.split(":", 1)[1].strip()
                if "=" not in line_stripped or line_stripped.startswith("#"):
                    continue
                key, _, value = line_stripped.partition("=")
                key = key.strip().lower()
                value = value.strip()
                if key == "publickey":
                    peer["public_key"] = value
                elif key == "presharedkey":
                    peer["preshared_key"] = value
                elif key == "allowedips":
                    peer["allowed_ips"] = value
                elif key == "endpoint":
                    peer["endpoint"] = value
                elif key == "persistentkeepalive":
                    peer["persistent_keepalive"] = int(value)

            if peer.get("public_key"):
                peer["name"] = comment_name or f"imported-{peer['public_key'][:8]}"
                interface["peers"].append(peer)

    interface["peer_count"] = len(interface["peers"])
    return interface


def check_conflicts(parsed_interface: dict) -> dict:
    """Check if an interface or its peers already exist in the DB."""
    conflicts = {"interface_exists": False, "existing_peers": [], "new_peers": []}

    existing_iface = db.fetchone(
        "SELECT id, name FROM wg_interfaces WHERE name = %s", (parsed_interface["name"],)
    )
    if existing_iface:
        conflicts["interface_exists"] = True
        conflicts["interface_id"] = existing_iface["id"]

    for peer in parsed_interface.get("peers", []):
        existing = db.fetchone(
            "SELECT id, name FROM wg_peers WHERE public_key = %s", (peer["public_key"],)
        )
        if existing:
            conflicts["existing_peers"].append({**peer, "db_id": existing["id"], "db_name": existing["name"]})
        else:
            conflicts["new_peers"].append(peer)

    return conflicts


def execute_import(parsed_interface: dict, endpoint: str = "", skip_existing: bool = True) -> dict:
    """Import a parsed WireGuard interface and its peers into the database.

    - Interface created if not exists
    - Peers created with import_status='imported', enabled=True, activated=False
    - IPs registered in IPAM
    - Does NOT modify the live WireGuard config (it's already running)
    """
    now = datetime.utcnow().isoformat()
    result = {"interface": None, "imported_peers": [], "skipped_peers": [], "errors": []}

    # Check/create interface
    existing_iface = db.fetchone(
        "SELECT * FROM wg_interfaces WHERE name = %s", (parsed_interface["name"],)
    )

    if existing_iface:
        interface_id = existing_iface["id"]
        result["interface"] = {"id": interface_id, "name": parsed_interface["name"], "action": "existing"}
    else:
        # Need to generate public key from private key for DB
        private_key = parsed_interface.get("private_key", "")
        if private_key:
            import subprocess
            pub_result = subprocess.run(
                ["wg", "pubkey"], input=private_key + "\n",
                capture_output=True, text=True
            )
            public_key = pub_result.stdout.strip() if pub_result.returncode == 0 else ""
        else:
            public_key = ""

        address = parsed_interface.get("address", "")
        subnet = parsed_interface.get("subnet", "")
        listen_port = parsed_interface.get("listen_port", 51820)

        if not endpoint:
            from ..config import settings
            endpoint = f"{settings.wg_default_endpoint}:{listen_port}"

        iface_row = db.query(
            """INSERT INTO wg_interfaces
               (name, private_key, public_key, listen_port, address, subnet, dns,
                post_up, post_down, endpoint, enabled, created)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s)
               RETURNING *""",
            (parsed_interface["name"], private_key, public_key, listen_port,
             address, subnet, "",
             parsed_interface.get("post_up", ""), parsed_interface.get("post_down", ""),
             endpoint, now),
            fetchone=True, commit=True
        )
        interface_id = iface_row["id"] if iface_row else None
        if not interface_id:
            result["errors"].append("Failed to create interface")
            return result
        result["interface"] = {"id": interface_id, "name": parsed_interface["name"], "action": "created"}

    # Import peers
    for peer_data in parsed_interface.get("peers", []):
        try:
            # Check if peer already exists by public key
            existing = db.fetchone(
                "SELECT id, name FROM wg_peers WHERE public_key = %s", (peer_data["public_key"],)
            )
            if existing:
                if skip_existing:
                    result["skipped_peers"].append({
                        "name": existing["name"], "public_key": peer_data["public_key"],
                        "reason": "already exists"
                    })
                    continue

            # Extract IP from allowed_ips (e.g., "10.0.0.2/32" -> "10.0.0.2")
            allowed_ips = peer_data.get("allowed_ips", "")
            ip_addr = allowed_ips.split("/")[0].strip() if allowed_ips else ""

            # Insert peer - NO private key (we don't have it from server config)
            peer_row = db.query(
                """INSERT INTO wg_peers
                   (interface_id, name, private_key, public_key, preshared_key,
                    allowed_ips, persistent_keepalive, enabled, activated,
                    import_status, note, created)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, FALSE, 'imported', %s, %s)
                   RETURNING *""",
                (interface_id, peer_data.get("name", f"imported-{peer_data['public_key'][:8]}"),
                 "",  # No private key available from server config
                 peer_data["public_key"],
                 peer_data.get("preshared_key", ""),
                 allowed_ips,
                 peer_data.get("persistent_keepalive", 25),
                 f"Imported from {parsed_interface['name']}.conf", now),
                fetchone=True, commit=True
            )

            if peer_row:
                # Register IP in IPAM
                if ip_addr:
                    try:
                        db.execute(
                            """INSERT INTO wg_ip_allocations
                               (interface_id, ip_address, peer_id, allocated, allocated_at)
                               VALUES (%s, %s, %s, TRUE, %s)
                               ON CONFLICT DO NOTHING""",
                            (interface_id, ip_addr, peer_row["id"], now)
                        )
                    except Exception:
                        pass  # IP might already be tracked

                result["imported_peers"].append({
                    "id": peer_row["id"],
                    "name": peer_row["name"],
                    "allowed_ips": allowed_ips,
                    "public_key": peer_data["public_key"][:16] + "..."
                })
        except Exception as e:
            result["errors"].append(f"Peer {peer_data.get('name', '?')}: {str(e)}")

    return result
