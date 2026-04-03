"""Portal endpoints — VPN user self-service (view config, QR code)."""

import hashlib
import json
import secrets
from datetime import datetime, timedelta

import httpx
from fastapi import APIRouter, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from . import db
from .wireguard import peers as peer_ops, acl

router = APIRouter(prefix="/portal", tags=["Portal"])

_token_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _hash(s: str) -> str:
    return hashlib.sha256(f"wgportal:{s}".encode()).hexdigest()


# -- Portal sessions (separate from admin sessions) --

def _create_session(peer_id: int) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.utcnow().isoformat()
    expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    db.execute(
        "INSERT INTO sessions (token, user_id, created, expires) VALUES (%s,%s,%s,%s)",
        (_hash(token), -peer_id, now, expires),  # negative user_id = portal peer session
    )
    return token


def _verify_portal_session(token: str) -> dict | None:
    if not token:
        return None
    now = datetime.utcnow().isoformat()
    row = db.fetchone(
        "SELECT user_id FROM sessions WHERE token = %s AND expires > %s",
        (_hash(token), now),
    )
    if not row or row["user_id"] >= 0:
        return None
    peer_id = -row["user_id"]
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    return dict(peer) if peer else None


async def _require_portal_user(token: str = Security(_token_header)) -> dict:
    peer = _verify_portal_session(token)
    if not peer:
        raise HTTPException(401, "Not authenticated")
    return peer


# -- Auth --

class PortalLoginRequest(BaseModel):
    email: str
    password: str


class GoogleLoginRequest(BaseModel):
    integration_id: int
    code: str
    redirect_uri: str


@router.post("/auth/login")
async def portal_login(req: PortalLoginRequest):
    """Login with portal email + password."""
    peer = db.fetchone(
        "SELECT * FROM wg_peers WHERE portal_email = %s AND portal_password_hash != ''",
        (req.email,),
    )
    if not peer or peer["portal_password_hash"] != _hash(req.password):
        raise HTTPException(401, "Invalid email or password")
    if not peer["enabled"]:
        raise HTTPException(403, "Your VPN account is disabled")

    token = _create_session(peer["id"])
    return {
        "token": token,
        "peer": {"id": peer["id"], "name": peer["name"], "email": peer["portal_email"]},
    }


@router.post("/auth/google")
async def portal_google_login(req: GoogleLoginRequest):
    """Login with Google OAuth — matches email to peer."""
    integ = db.fetchone("SELECT * FROM integrations WHERE id = %s AND status = 'connected'", (req.integration_id,))
    if not integ:
        raise HTTPException(400, "Integration not found or not connected")

    config = json.loads(integ["config"]) if integ["config"] else {}

    # Exchange code for tokens and get user info
    try:
        token_resp = httpx.post("https://oauth2.googleapis.com/token", data={
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code": req.code,
            "grant_type": "authorization_code",
            "redirect_uri": req.redirect_uri,
        })
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        userinfo_resp = httpx.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()
    except Exception as e:
        raise HTTPException(400, f"Google auth failed: {e}")

    email = userinfo.get("email", "")
    if not email:
        raise HTTPException(400, "Could not get email from Google")

    # Find peer by portal_email or note (email stored during import)
    peer = db.fetchone("SELECT * FROM wg_peers WHERE portal_email = %s", (email,))
    if not peer:
        peer = db.fetchone("SELECT * FROM wg_peers WHERE note = %s", (email,))
    if not peer:
        raise HTTPException(404, f"No VPN account found for {email}")
    if not peer["enabled"]:
        raise HTTPException(403, "Your VPN account is disabled")

    token = _create_session(peer["id"])
    return {
        "token": token,
        "peer": {"id": peer["id"], "name": peer["name"], "email": email},
    }


@router.post("/auth/logout")
async def portal_logout(token: str = Security(_token_header)):
    if token:
        db.execute("DELETE FROM sessions WHERE token = %s", (_hash(token),))
    return {"ok": True}


# -- Self-service endpoints --

@router.get("/me")
async def portal_me(peer: dict = Security(_require_portal_user)):
    return {
        "id": peer["id"],
        "name": peer["name"],
        "email": peer.get("portal_email") or peer.get("note", ""),
        "allowed_ips": peer["allowed_ips"],
        "enabled": peer["enabled"],
    }


@router.get("/config")
async def portal_config(peer: dict = Security(_require_portal_user)):
    config = peer_ops.get_peer_config(peer["id"])
    return {"config": config}


@router.get("/qr")
async def portal_qr(peer: dict = Security(_require_portal_user)):
    qr = peer_ops.get_peer_qr(peer["id"])
    return {"qr_code": qr}


@router.get("/google-enabled")
async def google_enabled():
    """Check if any Google integration is available for portal login."""
    integ = db.fetchone("SELECT id, name, config FROM integrations WHERE provider = 'google_workspace' AND status = 'connected' LIMIT 1")
    if not integ:
        return {"enabled": False}
    config = json.loads(integ["config"]) if integ["config"] else {}
    return {
        "enabled": True,
        "integration_id": integ["id"],
        "client_id": config.get("client_id", ""),
    }
