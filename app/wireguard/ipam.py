"""IP Address Management — allocate and release IPs from a subnet."""

import ipaddress
from datetime import datetime

from .. import db


def allocate_ip(interface_id: int, subnet: str) -> str:
    """Allocate next free IP from subnet. Returns IP string like '10.0.0.2'."""
    network = ipaddress.ip_network(subnet, strict=False)
    all_hosts = list(network.hosts())  # .1 through .254 for /24
    server_ip = all_hosts[0]  # .1 is reserved for server

    allocated = db.fetchall(
        "SELECT ip_address FROM wg_ip_allocations WHERE interface_id = %s AND allocated = TRUE",
        (interface_id,)
    )
    allocated_set = {r["ip_address"] for r in allocated}
    allocated_set.add(str(server_ip))

    for host in all_hosts[1:]:  # start from .2
        if str(host) not in allocated_set:
            now = datetime.utcnow().isoformat()
            db.execute(
                "INSERT INTO wg_ip_allocations (interface_id, ip_address, allocated, allocated_at) VALUES (%s, %s, TRUE, %s)",
                (interface_id, str(host), now)
            )
            return str(host)

    raise ValueError("No free IP addresses in subnet")


def release_ip(interface_id: int, ip_address: str):
    """Release an allocated IP back to the pool."""
    db.execute(
        "UPDATE wg_ip_allocations SET allocated = FALSE, peer_id = NULL WHERE interface_id = %s AND ip_address = %s",
        (interface_id, ip_address)
    )


def link_peer(interface_id: int, ip_address: str, peer_id: int):
    """Link an IP allocation to a peer."""
    db.execute(
        "UPDATE wg_ip_allocations SET peer_id = %s WHERE interface_id = %s AND ip_address = %s",
        (peer_id, interface_id, ip_address)
    )


def get_allocated_count(interface_id: int) -> int:
    """Get the number of allocated IPs for an interface."""
    row = db.fetchone(
        "SELECT COUNT(*) as cnt FROM wg_ip_allocations WHERE interface_id = %s AND allocated = TRUE",
        (interface_id,)
    )
    return row["cnt"] if row else 0
