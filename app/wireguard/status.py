"""Live WireGuard status from `wg show` command."""

import subprocess


def get_live_status(interface_name: str = "wg0") -> dict:
    """Parse `wg show <interface> dump` for live peer status."""
    result = subprocess.run(
        ["wg", "show", interface_name, "dump"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return {"interface": interface_name, "up": False, "peers": []}

    lines = result.stdout.strip().split("\n")
    if not lines:
        return {"interface": interface_name, "up": True, "peers": []}

    # First line: interface info (private_key, public_key, listen_port, fwmark)
    iface_fields = lines[0].split("\t")
    iface_info = {
        "public_key": iface_fields[1] if len(iface_fields) > 1 else "",
        "listen_port": int(iface_fields[2]) if len(iface_fields) > 2 else 0,
    }

    # Subsequent lines: peer info
    # Format: public_key  preshared_key  endpoint  allowed_ips  latest_handshake  transfer_rx  transfer_tx  persistent_keepalive
    peers = []
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) >= 8:
            peers.append({
                "public_key": fields[0],
                "endpoint": fields[2] if fields[2] != "(none)" else "",
                "allowed_ips": fields[3],
                "latest_handshake": int(fields[4]) if fields[4] != "0" else 0,
                "transfer_rx": int(fields[5]),
                "transfer_tx": int(fields[6]),
                "persistent_keepalive": fields[7] if fields[7] != "off" else "",
            })

    return {
        "interface": interface_name,
        "up": True,
        **iface_info,
        "peers": peers,
    }


def get_all_status(interface_names: list[str]) -> list[dict]:
    """Get live status for all interfaces."""
    return [get_live_status(name) for name in interface_names]
