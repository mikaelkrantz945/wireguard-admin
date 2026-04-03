"""Integration endpoints — provider management, OAuth, user sync, import."""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..admin import _require_admin
from .. import db
from ..wireguard import peers
from .google_workspace import GoogleWorkspaceProvider

router = APIRouter(prefix="/integrations", tags=["Integrations"])

# Provider registry — add new providers here
PROVIDERS = {
    "google_workspace": GoogleWorkspaceProvider(),
}


def _get_integration(integration_id: int) -> dict:
    row = db.fetchone("SELECT * FROM integrations WHERE id = %s", (integration_id,))
    if not row:
        raise HTTPException(404, "Integration not found")
    return dict(row)


def _parse_json(text: str) -> dict:
    try:
        return json.loads(text) if text else {}
    except json.JSONDecodeError:
        return {}


# -- CRUD --

class CreateIntegrationRequest(BaseModel):
    provider: str
    name: str
    config: dict = {}


class ImportUsersRequest(BaseModel):
    interface_id: int
    group_id: int = 0
    users: list[dict]


@router.get("/providers", dependencies=[Depends(_require_admin)])
async def list_providers():
    """List available identity providers."""
    return [
        {
            "type": p.provider_type,
            "name": p.display_name,
            "config_fields": p.config_fields,
            "setup_instructions": p.get_setup_instructions(),
        }
        for p in PROVIDERS.values()
    ]


@router.get("", dependencies=[Depends(_require_admin)])
async def list_integrations():
    rows = db.fetchall("SELECT id, provider, name, status, last_sync, created FROM integrations ORDER BY id")
    result = []
    for r in rows:
        d = dict(r)
        d["provider_name"] = PROVIDERS.get(r["provider"], None)
        d["provider_name"] = PROVIDERS[r["provider"]].display_name if r["provider"] in PROVIDERS else r["provider"]
        result.append(d)
    return result


@router.post("", status_code=201, dependencies=[Depends(_require_admin)])
async def create_integration(req: CreateIntegrationRequest):
    if req.provider not in PROVIDERS:
        raise HTTPException(400, f"Unknown provider: {req.provider}")
    now = datetime.utcnow().isoformat()
    row = db.query(
        "INSERT INTO integrations (provider, name, config, tokens, status, created) VALUES (%s,%s,%s,'{}','pending',%s) RETURNING id",
        (req.provider, req.name, json.dumps(req.config), now),
        fetchone=True, commit=True,
    )
    return dict(db.fetchone("SELECT id, provider, name, status, created FROM integrations WHERE id = %s", (row["id"],)))


@router.delete("/{integration_id}", dependencies=[Depends(_require_admin)])
async def delete_integration(integration_id: int):
    _get_integration(integration_id)
    db.execute("DELETE FROM integrations WHERE id = %s", (integration_id,))
    return {"deleted": integration_id}


# -- OAuth flow --

@router.get("/{integration_id}/auth-url", dependencies=[Depends(_require_admin)])
async def get_auth_url(integration_id: int, request: Request):
    integ = _get_integration(integration_id)
    provider = PROVIDERS.get(integ["provider"])
    if not provider:
        raise HTTPException(400, "Unknown provider")
    config = _parse_json(integ["config"])
    redirect_uri = str(request.base_url).rstrip("/") + f"/integrations/{integration_id}/callback"
    url = provider.get_auth_url(config, redirect_uri)
    return {"auth_url": url, "redirect_uri": redirect_uri}


@router.post("/{integration_id}/callback", dependencies=[Depends(_require_admin)])
async def oauth_callback(integration_id: int, request: Request):
    integ = _get_integration(integration_id)
    provider = PROVIDERS.get(integ["provider"])
    if not provider:
        raise HTTPException(400, "Unknown provider")
    config = _parse_json(integ["config"])

    body = await request.json()
    code = body.get("code", "")
    if not code:
        raise HTTPException(400, "Missing auth code")

    redirect_uri = str(request.base_url).rstrip("/") + f"/integrations/{integration_id}/callback"
    try:
        tokens = provider.exchange_code(config, code, redirect_uri)
    except Exception as e:
        db.execute("UPDATE integrations SET status = 'error' WHERE id = %s", (integration_id,))
        raise HTTPException(400, f"Token exchange failed: {e}")

    db.execute(
        "UPDATE integrations SET tokens = %s, status = 'connected' WHERE id = %s",
        (json.dumps(tokens), integration_id),
    )
    return {"status": "connected"}


# -- User sync & import --

@router.get("/{integration_id}/users", dependencies=[Depends(_require_admin)])
async def list_provider_users(integration_id: int):
    integ = _get_integration(integration_id)
    if integ["status"] != "connected":
        raise HTTPException(400, "Integration not connected. Complete OAuth first.")
    provider = PROVIDERS.get(integ["provider"])
    if not provider:
        raise HTTPException(400, "Unknown provider")

    config = _parse_json(integ["config"])
    tokens = _parse_json(integ["tokens"])

    try:
        users = provider.list_users(config, tokens)
    except Exception as e:
        raise HTTPException(502, f"Failed to fetch users: {e}")

    # Update tokens if they were refreshed
    db.execute(
        "UPDATE integrations SET tokens = %s, last_sync = %s WHERE id = %s",
        (json.dumps(tokens), datetime.utcnow().isoformat(), integration_id),
    )

    # Mark users that already have a peer (by email in note field)
    existing_notes = {r["note"] for r in db.fetchall("SELECT note FROM wg_peers")}
    for u in users:
        u["already_imported"] = u["email"] in existing_notes

    return users


@router.post("/{integration_id}/import", dependencies=[Depends(_require_admin)])
async def import_users(integration_id: int, req: ImportUsersRequest):
    integ = _get_integration(integration_id)
    if integ["status"] != "connected":
        raise HTTPException(400, "Integration not connected")

    iface = db.fetchone("SELECT id FROM wg_interfaces WHERE id = %s", (req.interface_id,))
    if not iface:
        raise HTTPException(400, "Interface not found")

    results = []
    for user in req.users:
        email = user.get("email", "")
        name = f"{user.get('firstname', '')} {user.get('lastname', '')}".strip() or email

        # Skip if already imported
        existing = db.fetchone("SELECT id FROM wg_peers WHERE note = %s", (email,))
        if existing:
            results.append({"email": email, "status": "skipped", "reason": "already exists"})
            continue

        try:
            result = peers.create_peer(
                interface_id=req.interface_id,
                name=name,
                note=email,
                group_id=req.group_id,
            )
            results.append({"email": email, "status": "created", "peer_id": result["peer"]["id"]})
        except Exception as e:
            results.append({"email": email, "status": "error", "reason": str(e)})

    return {"imported": len([r for r in results if r["status"] == "created"]), "results": results}
