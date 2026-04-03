"""HostBill Script Provisioning webhook endpoint."""

import hmac

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..config import settings
from .. import db
from ..wireguard import peers

router = APIRouter(prefix="/hostbill", tags=["HostBill"])


class ProvisionRequest(BaseModel):
    action: str
    secret: str
    service_id: int
    client_id: int = 0
    client_email: str = ""
    client_name: str = ""
    package: str = ""
    custom_fields: dict = {}


def _verify_secret(secret: str):
    if not settings.hostbill_webhook_secret:
        raise HTTPException(500, "Webhook secret not configured")
    if not hmac.compare_digest(secret, settings.hostbill_webhook_secret):
        raise HTTPException(403, "Invalid webhook secret")


@router.post("/provision")
async def provision(req: ProvisionRequest):
    """Handle HostBill Script Provisioning actions."""
    _verify_secret(req.secret)

    action = req.action.lower()

    if action == "create":
        return _create(req)
    elif action == "suspend":
        return _suspend(req)
    elif action == "unsuspend":
        return _unsuspend(req)
    elif action == "terminate":
        return _terminate(req)
    elif action == "changepackage":
        return _change_package(req)
    else:
        raise HTTPException(400, f"Unknown action: {req.action}")


def _create(req: ProvisionRequest) -> dict:
    """Create a new VPN peer for a HostBill service."""
    # Check if peer already exists for this service
    existing = db.fetchone(
        "SELECT id FROM wg_peers WHERE hostbill_service_id = %s",
        (req.service_id,)
    )
    if existing:
        raise HTTPException(400, f"Peer already exists for service {req.service_id}")

    # Use first available interface (wg0)
    iface = db.fetchone("SELECT * FROM wg_interfaces ORDER BY id LIMIT 1")
    if not iface:
        raise HTTPException(500, "No WireGuard interface configured")

    name = req.client_name or f"hostbill-{req.service_id}"
    result = peers.create_peer(
        interface_id=iface["id"],
        name=name,
        note=f"HostBill service #{req.service_id} ({req.client_email})",
        hostbill_service_id=req.service_id,
        hostbill_client_id=req.client_id,
    )

    return {
        "success": True,
        "action": "create",
        "service_id": req.service_id,
        "peer_id": result["peer"]["id"],
        "client_config": result["client_config"],
        "ip_address": result["peer"]["allowed_ips"],
    }


def _suspend(req: ProvisionRequest) -> dict:
    """Suspend (disable) a peer."""
    peer = db.fetchone(
        "SELECT id FROM wg_peers WHERE hostbill_service_id = %s",
        (req.service_id,)
    )
    if not peer:
        raise HTTPException(404, f"No peer found for service {req.service_id}")

    peers.disable_peer(peer["id"])
    return {"success": True, "action": "suspend", "service_id": req.service_id}


def _unsuspend(req: ProvisionRequest) -> dict:
    """Unsuspend (enable) a peer."""
    peer = db.fetchone(
        "SELECT id FROM wg_peers WHERE hostbill_service_id = %s",
        (req.service_id,)
    )
    if not peer:
        raise HTTPException(404, f"No peer found for service {req.service_id}")

    peers.enable_peer(peer["id"])
    return {"success": True, "action": "unsuspend", "service_id": req.service_id}


def _terminate(req: ProvisionRequest) -> dict:
    """Terminate (delete) a peer."""
    peer = db.fetchone(
        "SELECT id FROM wg_peers WHERE hostbill_service_id = %s",
        (req.service_id,)
    )
    if not peer:
        raise HTTPException(404, f"No peer found for service {req.service_id}")

    peers.delete_peer(peer["id"])
    return {"success": True, "action": "terminate", "service_id": req.service_id}


def _change_package(req: ProvisionRequest) -> dict:
    """Handle package change — update peer note with new package info."""
    peer = db.fetchone(
        "SELECT id FROM wg_peers WHERE hostbill_service_id = %s",
        (req.service_id,)
    )
    if not peer:
        raise HTTPException(404, f"No peer found for service {req.service_id}")

    peers.update_peer(peer["id"], note=f"HostBill service #{req.service_id} - {req.package}")
    return {"success": True, "action": "changepackage", "service_id": req.service_id}


@router.get("/health")
async def health():
    return {"status": "ok", "service": "hostbill-provisioning"}
