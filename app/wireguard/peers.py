"""Peer CRUD operations — database + WireGuard config sync."""

from datetime import datetime

from .. import db
from . import manager, ipam, acl


def create_peer(interface_id: int, name: str, note: str = "",
                dns: str = "", persistent_keepalive: int = 25,
                hostbill_service_id: int = 0, hostbill_client_id: int = 0,
                acl_profile_id: int = 0, group_id: int = 0,
                enabled: bool = True) -> dict:
    """Create a new peer: allocate IP, generate keys, write config."""
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (interface_id,))
    if not iface:
        raise ValueError("Interface not found")

    # If group is set and no explicit ACL, inherit from group
    if group_id and not acl_profile_id:
        from . import groups
        group = groups.get_group(group_id)
        if group and group.get("acl_profile_id"):
            acl_profile_id = group["acl_profile_id"]

    # Allocate IP
    ip = ipam.allocate_ip(interface_id, iface["subnet"])
    allowed_ips = f"{ip}/32"

    # Generate keys
    private_key, public_key = manager.generate_keypair()
    preshared_key = manager.generate_preshared_key()

    now = datetime.utcnow().isoformat()
    row = db.query(
        """INSERT INTO wg_peers
           (interface_id, name, private_key, public_key, preshared_key,
            allowed_ips, dns, persistent_keepalive, enabled,
            hostbill_service_id, hostbill_client_id, note, created, acl_profile_id, group_id)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (interface_id, name, private_key, public_key, preshared_key,
         allowed_ips, dns, persistent_keepalive, enabled,
         hostbill_service_id, hostbill_client_id, note, now, acl_profile_id, group_id),
        fetchone=True, commit=True,
    )
    peer_id = row["id"]
    ipam.link_peer(interface_id, ip, peer_id)

    # Regenerate and apply server config
    _sync_config(interface_id)

    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    profile = acl.get_profile_for_peer(peer_id)
    acl_ips = profile["allowed_ips"] if profile else ""
    client_config = manager.generate_client_config(dict(iface), dict(peer), acl_allowed_ips=acl_ips)
    qr_code = manager.generate_qr(client_config)

    return {
        "peer": dict(peer),
        "client_config": client_config,
        "qr_code": qr_code,
    }


def delete_peer(peer_id: int):
    """Delete a peer and release its IP."""
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    if not peer:
        raise ValueError("Peer not found")

    # Release IP
    ip = peer["allowed_ips"].split("/")[0]
    ipam.release_ip(peer["interface_id"], ip)

    interface_id = peer["interface_id"]
    db.execute("DELETE FROM wg_peers WHERE id = %s", (peer_id,))
    _sync_config(interface_id)


def enable_peer(peer_id: int):
    """Enable a peer."""
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    if not peer:
        raise ValueError("Peer not found")
    db.execute("UPDATE wg_peers SET enabled = TRUE WHERE id = %s", (peer_id,))
    _sync_config(peer["interface_id"])


def disable_peer(peer_id: int):
    """Disable a peer."""
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    if not peer:
        raise ValueError("Peer not found")
    db.execute("UPDATE wg_peers SET enabled = FALSE WHERE id = %s", (peer_id,))
    _sync_config(peer["interface_id"])


def update_peer(peer_id: int, name: str = None, note: str = None, dns: str = None,
                persistent_keepalive: int = None, acl_profile_id: int = None,
                group_id: int = None) -> dict:
    """Update peer metadata."""
    updates, params = [], []
    acl_changed = False
    if name is not None:
        updates.append("name = %s")
        params.append(name)
    if note is not None:
        updates.append("note = %s")
        params.append(note)
    if dns is not None:
        updates.append("dns = %s")
        params.append(dns)
    if persistent_keepalive is not None:
        updates.append("persistent_keepalive = %s")
        params.append(persistent_keepalive)
    if acl_profile_id is not None:
        updates.append("acl_profile_id = %s")
        params.append(acl_profile_id)
        acl_changed = True
    if group_id is not None:
        updates.append("group_id = %s")
        params.append(group_id)
        # Inherit ACL from group if no explicit ACL override
        if acl_profile_id is None and group_id:
            from . import groups
            group = groups.get_group(group_id)
            if group and group.get("acl_profile_id"):
                updates.append("acl_profile_id = %s")
                params.append(group["acl_profile_id"])
                acl_changed = True
    if not updates:
        raise ValueError("No fields to update")
    params.append(peer_id)
    db.execute(f"UPDATE wg_peers SET {', '.join(updates)} WHERE id = %s", tuple(params))
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    if acl_changed:
        _apply_acl(peer["interface_id"])
    return dict(peer)


def get_peer(peer_id: int) -> dict | None:
    row = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    return dict(row) if row else None


def list_peers(interface_id: int) -> list[dict]:
    return db.fetchall(
        "SELECT * FROM wg_peers WHERE interface_id = %s ORDER BY id",
        (interface_id,)
    )


def get_peer_config(peer_id: int) -> str:
    """Get the client config text for a peer."""
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    if not peer:
        raise ValueError("Peer not found")
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (peer["interface_id"],))
    profile = acl.get_profile_for_peer(peer_id)
    acl_ips = profile["allowed_ips"] if profile else ""
    return manager.generate_client_config(dict(iface), dict(peer), acl_allowed_ips=acl_ips)


def get_peer_qr(peer_id: int) -> str:
    """Get the QR code for a peer's client config."""
    config = get_peer_config(peer_id)
    return manager.generate_qr(config)


def _sync_config(interface_id: int):
    """Regenerate server config and apply it if the interface is up."""
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (interface_id,))
    if not iface:
        return
    peer_list = db.fetchall("SELECT * FROM wg_peers WHERE interface_id = %s", (interface_id,))
    manager.write_server_config(dict(iface), [dict(p) for p in peer_list])
    if manager.is_interface_up(iface["name"]):
        try:
            manager.apply_config(iface["name"])
        except RuntimeError:
            pass
    _apply_acl(interface_id)


def _apply_acl(interface_id: int):
    """Apply iptables ACL rules for the interface."""
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (interface_id,))
    if not iface:
        return
    try:
        acl.apply_firewall_rules(iface["name"])
    except Exception:
        pass
