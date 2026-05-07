"""API endpoints for WireGuard config import."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from ..admin import _require_admin
from .. import db
from ..config import settings
from . import importer

router = APIRouter(prefix="/admin/import", tags=["import"])


@router.get("/detect", dependencies=[Depends(_require_admin)])
async def detect_configs():
    """Scan for existing WireGuard configs on the host."""
    configs = importer.scan_configs(settings.wg_config_dir)
    # Also check which interfaces are already in DB
    for cfg in configs:
        if "error" not in cfg:
            existing = db.fetchone(
                "SELECT id FROM wg_interfaces WHERE name = %s", (cfg["name"],)
            )
            cfg["in_database"] = existing is not None
            cfg["interface_id"] = existing["id"] if existing else None
    return {"configs": configs}


class ImportRequest(BaseModel):
    interface_name: str
    endpoint: str = ""
    skip_existing: bool = True

@router.post("/execute", dependencies=[Depends(_require_admin)])
async def execute_import(req: ImportRequest):
    """Import a detected WireGuard config into the database."""
    configs = importer.scan_configs(settings.wg_config_dir)
    target = next((c for c in configs if c.get("name") == req.interface_name), None)
    if not target:
        raise HTTPException(404, f"Config for {req.interface_name} not found")
    if "error" in target:
        raise HTTPException(400, f"Config has errors: {target['error']}")

    result = importer.execute_import(target, endpoint=req.endpoint, skip_existing=req.skip_existing)
    return result


class LinkEmailRequest(BaseModel):
    peer_id: int
    email: str
    send_activation: bool = False
    activation_method: str = "password"

@router.post("/link-email", dependencies=[Depends(_require_admin)])
async def link_email(req: LinkEmailRequest):
    """Assign an email to an imported peer, enabling portal access."""
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (req.peer_id,))
    if not peer:
        raise HTTPException(404, "Peer not found")

    if peer.get("import_status") not in ("imported", "linked", None):
        raise HTTPException(400, "Invalid import status")

    # Update peer with email and mark as linked
    db.execute(
        "UPDATE wg_peers SET portal_email = %s, import_status = 'linked' WHERE id = %s",
        (req.email, req.peer_id)
    )

    result = {"status": "linked", "peer_id": req.peer_id, "email": req.email}

    # Optionally send activation email
    if req.send_activation:
        from ..portal import send_activation_email
        try:
            peer = db.fetchone("SELECT name FROM wg_peers WHERE id = %s", (req.peer_id,))
            peer_name = peer["name"] if peer else ""
            send_activation_email(req.peer_id, req.email, peer_name, req.activation_method)
            result["activation_sent"] = True
        except Exception as e:
            result["activation_sent"] = False
            result["activation_error"] = str(e)

    return result


@router.get("/peers", dependencies=[Depends(_require_admin)])
async def list_imported_peers():
    """List all peers with import_status set."""
    peers = db.fetchall(
        """SELECT p.*, i.name as interface_name
           FROM wg_peers p
           JOIN wg_interfaces i ON p.interface_id = i.id
           WHERE p.import_status IS NOT NULL
           ORDER BY p.import_status, p.name"""
    )
    return {"peers": peers}
