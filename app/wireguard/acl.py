"""ACL profile management and iptables firewall enforcement."""

import subprocess
from datetime import datetime

from .. import db


def seed_default():
    """Create default ACL profile if none exist."""
    existing = db.fetchone("SELECT id FROM wg_acl_profiles LIMIT 1")
    if not existing:
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO wg_acl_profiles (name, description, allowed_ips, fw_rules, is_default, created) VALUES (%s,%s,%s,%s,TRUE,%s)",
            ("Full Access", "Full tunnel — all traffic routed through VPN", "0.0.0.0/0, ::/0", "", now),
        )


def create_profile(name: str, description: str = "", allowed_ips: str = "0.0.0.0/0, ::/0",
                   fw_rules: str = "", is_default: bool = False) -> dict:
    existing = db.fetchone("SELECT id FROM wg_acl_profiles WHERE name = %s", (name,))
    if existing:
        raise ValueError(f"Profile '{name}' already exists")
    if is_default:
        db.execute("UPDATE wg_acl_profiles SET is_default = FALSE WHERE is_default = TRUE")
    now = datetime.utcnow().isoformat()
    row = db.query(
        "INSERT INTO wg_acl_profiles (name, description, allowed_ips, fw_rules, is_default, created) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
        (name, description, allowed_ips, fw_rules, is_default, now),
        fetchone=True, commit=True,
    )
    return dict(db.fetchone("SELECT * FROM wg_acl_profiles WHERE id = %s", (row["id"],)))


def update_profile(profile_id: int, name: str = None, description: str = None,
                   allowed_ips: str = None, fw_rules: str = None, is_default: bool = None) -> dict:
    updates, params = [], []
    if name is not None:
        updates.append("name = %s")
        params.append(name)
    if description is not None:
        updates.append("description = %s")
        params.append(description)
    if allowed_ips is not None:
        updates.append("allowed_ips = %s")
        params.append(allowed_ips)
    if fw_rules is not None:
        updates.append("fw_rules = %s")
        params.append(fw_rules)
    if is_default is not None:
        if is_default:
            db.execute("UPDATE wg_acl_profiles SET is_default = FALSE WHERE is_default = TRUE")
        updates.append("is_default = %s")
        params.append(is_default)
    if not updates:
        raise ValueError("No fields to update")
    params.append(profile_id)
    db.execute(f"UPDATE wg_acl_profiles SET {', '.join(updates)} WHERE id = %s", tuple(params))
    return dict(db.fetchone("SELECT * FROM wg_acl_profiles WHERE id = %s", (profile_id,)))


def delete_profile(profile_id: int):
    profile = db.fetchone("SELECT * FROM wg_acl_profiles WHERE id = %s", (profile_id,))
    if not profile:
        raise ValueError("Profile not found")
    if profile["is_default"]:
        raise ValueError("Cannot delete the default profile")
    in_use = db.fetchone("SELECT id FROM wg_peers WHERE acl_profile_id = %s LIMIT 1", (profile_id,))
    if in_use:
        raise ValueError("Profile is in use by one or more peers")
    db.execute("DELETE FROM wg_acl_profiles WHERE id = %s", (profile_id,))


def list_profiles() -> list[dict]:
    profiles = db.fetchall("SELECT * FROM wg_acl_profiles ORDER BY is_default DESC, name")
    for p in profiles:
        count = db.fetchone("SELECT COUNT(*) as cnt FROM wg_peers WHERE acl_profile_id = %s", (p["id"],))
        p["peer_count"] = count["cnt"] if count else 0
    return profiles


def get_profile(profile_id: int) -> dict | None:
    row = db.fetchone("SELECT * FROM wg_acl_profiles WHERE id = %s", (profile_id,))
    return dict(row) if row else None


def get_default_profile() -> dict | None:
    row = db.fetchone("SELECT * FROM wg_acl_profiles WHERE is_default = TRUE")
    return dict(row) if row else None


def get_profile_for_peer(peer_id: int) -> dict | None:
    """Get the ACL profile for a peer, falling back to default."""
    peer = db.fetchone("SELECT acl_profile_id FROM wg_peers WHERE id = %s", (peer_id,))
    if not peer or not peer["acl_profile_id"]:
        return get_default_profile()
    profile = get_profile(peer["acl_profile_id"])
    return profile or get_default_profile()


# -- Rule parsing --

def parse_fw_rules(fw_rules: str) -> list[dict]:
    """Parse fw_rules string into structured rules.

    Format: destination[:ports[/protocol]]
    Separated by semicolons, commas (without ports), or newlines.

    Examples:
        "10.0.0.0/8"                       -> all traffic to 10.0.0.0/8
        "0.0.0.0/0:80,443"                 -> tcp 80,443 to anywhere
        "0.0.0.0/0:80,443/tcp"             -> tcp 80,443 to anywhere
        "8.8.8.8/32:53/udp"                -> udp 53 to 8.8.8.8
        "0.0.0.0/0:80,443; 10.0.0.0/8"    -> combined
    """
    rules = []
    # Split on semicolons and newlines first
    entries = []
    for part in fw_rules.replace("\n", ";").split(";"):
        part = part.strip()
        if part:
            entries.append(part)

    # If no semicolons were used, try comma-split but only for entries without ports
    if not entries:
        return rules
    if len(entries) == 1 and ":" not in entries[0] and "," in entries[0]:
        # Legacy format: comma-separated destinations without ports
        entries = [e.strip() for e in entries[0].split(",") if e.strip()]

    for entry in entries:
        if ":" in entry:
            dest, port_spec = entry.split(":", 1)
            dest = dest.strip()
            if "/" in port_spec and not port_spec.split("/")[0].replace(",", "").replace(" ", "").isdigit() is False:
                # Check if the / is protocol separator (e.g., "80,443/tcp") vs subnet mask
                parts = port_spec.rsplit("/", 1)
                if parts[-1] in ("tcp", "udp", "both"):
                    ports = parts[0].strip()
                    proto = parts[-1]
                else:
                    ports = port_spec.strip()
                    proto = "tcp"
            else:
                ports = port_spec.strip()
                proto = "tcp"
            rules.append({"dest": dest, "ports": ports, "proto": proto})
        else:
            rules.append({"dest": entry.strip(), "ports": "", "proto": ""})

    return rules


# -- iptables enforcement --

def apply_firewall_rules(interface_name: str = "wg0"):
    """Rebuild the WG_ACL iptables chain based on all peers and their ACL profiles.

    fw_rules format: destination[:ports[/protocol]] separated by semicolons.
    Examples:
        0.0.0.0/0:80,443       -> tcp ports 80,443 to any destination
        10.0.0.0/8              -> all traffic to 10.0.0.0/8
        8.8.8.8/32:53/udp      -> udp port 53 to 8.8.8.8
    """
    # Ensure chain exists
    subprocess.run(["iptables", "-N", "WG_ACL"], capture_output=True)

    # Flush existing rules
    subprocess.run(["iptables", "-F", "WG_ACL"], capture_output=True, check=True)

    # Ensure FORWARD jump to WG_ACL exists for this interface
    check = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", interface_name, "-j", "WG_ACL"],
        capture_output=True
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "FORWARD", "1", "-i", interface_name, "-j", "WG_ACL"],
            capture_output=True, check=True
        )

    # Get all enabled peers with their ACL profiles
    peers = db.fetchall("SELECT * FROM wg_peers WHERE enabled = TRUE")

    for peer in peers:
        peer_ip = peer["allowed_ips"].split("/")[0]
        profile = None
        if peer["acl_profile_id"]:
            profile = get_profile(peer["acl_profile_id"])

        if not profile or not profile.get("fw_rules", "").strip():
            # No restrictions — traffic passes through to normal FORWARD rules
            continue

        rules = parse_fw_rules(profile["fw_rules"])
        for rule in rules:
            cmd = ["iptables", "-A", "WG_ACL", "-s", peer_ip, "-d", rule["dest"]]
            if rule["ports"]:
                protos = ["tcp", "udp"] if rule["proto"] == "both" else [rule["proto"] or "tcp"]
                for proto in protos:
                    pcmd = cmd + ["-p", proto, "-m", "multiport", "--dports", rule["ports"], "-j", "ACCEPT"]
                    subprocess.run(pcmd, capture_output=True)
            else:
                subprocess.run(cmd + ["-j", "ACCEPT"], capture_output=True)

        # Default deny for this peer
        subprocess.run(
            ["iptables", "-A", "WG_ACL", "-s", peer_ip, "-j", "DROP"],
            capture_output=True
        )
