"""WireGuard API endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import verify_wireguard
from .. import db
from . import manager, ipam, peers, status

router = APIRouter(prefix="/wg", tags=["WireGuard"])


# -- Request models --

class CreateInterfaceRequest(BaseModel):
    name: str = "wg0"
    listen_port: int = 51820
    subnet: str = "10.0.0.0/24"
    dns: str = "195.47.238.46, 195.47.238.48"
    endpoint: str = ""
    post_up: str = "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
    post_down: str = "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"


class UpdateInterfaceRequest(BaseModel):
    dns: str | None = None
    endpoint: str | None = None
    post_up: str | None = None
    post_down: str | None = None


class CreatePeerRequest(BaseModel):
    name: str
    note: str = ""
    dns: str = ""
    persistent_keepalive: int = 25


class UpdatePeerRequest(BaseModel):
    name: str | None = None
    note: str | None = None
    dns: str | None = None
    persistent_keepalive: int | None = None


# -- Interface endpoints --

@router.get("/interfaces", dependencies=[Depends(verify_wireguard)])
async def list_interfaces():
    ifaces = db.fetchall("SELECT * FROM wg_interfaces ORDER BY id")
    result = []
    for iface in ifaces:
        d = dict(iface)
        d["is_up"] = manager.is_interface_up(iface["name"])
        d["peer_count"] = len(db.fetchall("SELECT id FROM wg_peers WHERE interface_id = %s", (iface["id"],)))
        result.append(d)
    return result


@router.post("/interfaces", status_code=201, dependencies=[Depends(verify_wireguard)])
async def create_interface(req: CreateInterfaceRequest):
    from ..config import settings
    existing = db.fetchone("SELECT id FROM wg_interfaces WHERE name = %s", (req.name,))
    if existing:
        raise HTTPException(400, f"Interface {req.name} already exists")

    private_key, public_key = manager.generate_keypair()

    import ipaddress
    network = ipaddress.ip_network(req.subnet, strict=False)
    server_ip = str(list(network.hosts())[0])
    address = f"{server_ip}/{network.prefixlen}"

    endpoint = req.endpoint or f"{settings.wg_default_endpoint}:{req.listen_port}"
    now = datetime.utcnow().isoformat()

    row = db.query(
        """INSERT INTO wg_interfaces
           (name, private_key, public_key, listen_port, address, subnet,
            dns, post_up, post_down, endpoint, enabled, created)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,TRUE,%s) RETURNING id""",
        (req.name, private_key, public_key, req.listen_port, address, req.subnet,
         req.dns, req.post_up, req.post_down, endpoint, now),
        fetchone=True, commit=True,
    )

    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (row["id"],))
    manager.write_server_config(dict(iface), [])
    return dict(iface)


@router.get("/interfaces/{iface_id}", dependencies=[Depends(verify_wireguard)])
async def get_interface(iface_id: int):
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (iface_id,))
    if not iface:
        raise HTTPException(404, "Interface not found")
    d = dict(iface)
    d["is_up"] = manager.is_interface_up(iface["name"])
    d["peer_count"] = len(db.fetchall("SELECT id FROM wg_peers WHERE interface_id = %s", (iface_id,)))
    d["allocated_ips"] = ipam.get_allocated_count(iface_id)
    return d


@router.put("/interfaces/{iface_id}", dependencies=[Depends(verify_wireguard)])
async def update_interface(iface_id: int, req: UpdateInterfaceRequest):
    updates, params = [], []
    if req.dns is not None:
        updates.append("dns = %s")
        params.append(req.dns)
    if req.endpoint is not None:
        updates.append("endpoint = %s")
        params.append(req.endpoint)
    if req.post_up is not None:
        updates.append("post_up = %s")
        params.append(req.post_up)
    if req.post_down is not None:
        updates.append("post_down = %s")
        params.append(req.post_down)
    if not updates:
        raise HTTPException(400, "No fields to update")
    params.append(iface_id)
    db.execute(f"UPDATE wg_interfaces SET {', '.join(updates)} WHERE id = %s", tuple(params))

    # Regenerate config
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (iface_id,))
    peer_list = db.fetchall("SELECT * FROM wg_peers WHERE interface_id = %s", (iface_id,))
    manager.write_server_config(dict(iface), [dict(p) for p in peer_list])
    if manager.is_interface_up(iface["name"]):
        manager.apply_config(iface["name"])
    return dict(iface)


@router.delete("/interfaces/{iface_id}", dependencies=[Depends(verify_wireguard)])
async def delete_interface(iface_id: int):
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (iface_id,))
    if not iface:
        raise HTTPException(404, "Interface not found")
    if manager.is_interface_up(iface["name"]):
        manager.interface_down(iface["name"])
    db.execute("DELETE FROM wg_interfaces WHERE id = %s", (iface_id,))
    return {"deleted": iface_id}


@router.post("/interfaces/{iface_id}/up", dependencies=[Depends(verify_wireguard)])
async def bring_interface_up(iface_id: int):
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (iface_id,))
    if not iface:
        raise HTTPException(404, "Interface not found")
    try:
        manager.interface_up(iface["name"])
        return {"status": "up", "interface": iface["name"]}
    except RuntimeError as e:
        raise HTTPException(500, str(e))


@router.post("/interfaces/{iface_id}/down", dependencies=[Depends(verify_wireguard)])
async def bring_interface_down(iface_id: int):
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (iface_id,))
    if not iface:
        raise HTTPException(404, "Interface not found")
    try:
        manager.interface_down(iface["name"])
        return {"status": "down", "interface": iface["name"]}
    except RuntimeError as e:
        raise HTTPException(500, str(e))


# -- Peer endpoints --

@router.get("/interfaces/{iface_id}/peers", dependencies=[Depends(verify_wireguard)])
async def list_interface_peers(iface_id: int):
    iface = db.fetchone("SELECT * FROM wg_interfaces WHERE id = %s", (iface_id,))
    if not iface:
        raise HTTPException(404, "Interface not found")
    peer_list = peers.list_peers(iface_id)

    # Merge with live status
    live = status.get_live_status(iface["name"])
    live_map = {p["public_key"]: p for p in live.get("peers", [])}

    result = []
    for p in peer_list:
        d = dict(p)
        live_peer = live_map.get(p["public_key"], {})
        d["live_endpoint"] = live_peer.get("endpoint", "")
        d["latest_handshake"] = live_peer.get("latest_handshake", 0)
        d["transfer_rx"] = live_peer.get("transfer_rx", 0)
        d["transfer_tx"] = live_peer.get("transfer_tx", 0)
        result.append(d)
    return result


@router.post("/interfaces/{iface_id}/peers", status_code=201, dependencies=[Depends(verify_wireguard)])
async def create_peer(iface_id: int, req: CreatePeerRequest):
    try:
        return peers.create_peer(
            interface_id=iface_id,
            name=req.name,
            note=req.note,
            dns=req.dns,
            persistent_keepalive=req.persistent_keepalive,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/peers/{peer_id}", dependencies=[Depends(verify_wireguard)])
async def get_peer(peer_id: int):
    peer = peers.get_peer(peer_id)
    if not peer:
        raise HTTPException(404, "Peer not found")
    return peer


@router.put("/peers/{peer_id}", dependencies=[Depends(verify_wireguard)])
async def update_peer(peer_id: int, req: UpdatePeerRequest):
    try:
        return peers.update_peer(peer_id, req.name, req.note, req.dns, req.persistent_keepalive)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/peers/{peer_id}", dependencies=[Depends(verify_wireguard)])
async def delete_peer(peer_id: int):
    try:
        peers.delete_peer(peer_id)
        return {"deleted": peer_id}
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/peers/{peer_id}/enable", dependencies=[Depends(verify_wireguard)])
async def enable_peer(peer_id: int):
    try:
        peers.enable_peer(peer_id)
        return {"enabled": peer_id}
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.post("/peers/{peer_id}/disable", dependencies=[Depends(verify_wireguard)])
async def disable_peer(peer_id: int):
    try:
        peers.disable_peer(peer_id)
        return {"disabled": peer_id}
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/peers/{peer_id}/config", dependencies=[Depends(verify_wireguard)])
async def get_peer_config(peer_id: int):
    try:
        config = peers.get_peer_config(peer_id)
        return {"config": config}
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/peers/{peer_id}/qr", dependencies=[Depends(verify_wireguard)])
async def get_peer_qr(peer_id: int):
    try:
        qr = peers.get_peer_qr(peer_id)
        return {"qr_code": qr}
    except ValueError as e:
        raise HTTPException(404, str(e))


# -- Status --

@router.get("/status", dependencies=[Depends(verify_wireguard)])
async def get_status():
    ifaces = db.fetchall("SELECT name FROM wg_interfaces ORDER BY id")
    return status.get_all_status([i["name"] for i in ifaces])


@router.get("/status/{interface_name}", dependencies=[Depends(verify_wireguard)])
async def get_interface_status(interface_name: str):
    return status.get_live_status(interface_name)
