"""Portal endpoints — VPN user self-service (activation, login, config, QR)."""

import hashlib
import json
import os
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText

import httpx
from fastapi import APIRouter, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from . import db
from .wireguard import peers as peer_ops, acl

router = APIRouter(prefix="/portal", tags=["Portal"])

_token_header = APIKeyHeader(name="X-API-Key", auto_error=False)

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@example.com")
BASE_URL = os.environ.get("BASE_URL", "https://vpn.example.com")


def _hash(s: str) -> str:
    return hashlib.sha256(f"wgportal:{s}".encode()).hexdigest()


# -- Activation --

def send_activation_email(peer_id: int, email: str, name: str, method: str = "password"):
    """Generate activation token and send email."""
    token = secrets.token_urlsafe(48)
    db.execute(
        "UPDATE wg_peers SET activation_token = %s, activation_method = %s, portal_email = %s, activated = FALSE, enabled = FALSE WHERE id = %s",
        (_hash(token), method, email, peer_id),
    )
    if method == "google":
        activate_url = f"{BASE_URL}/portal/ui#activate={token}&method=google"
    else:
        activate_url = f"{BASE_URL}/portal/ui#activate={token}&method=password"

    body = f"""Hi {name},

Your WireGuard VPN account has been created.

Click the link below to activate your account:

{activate_url}

{"You will be asked to set a password." if method == "password" else "You will sign in with your Google account."}

This link is valid for 7 days.

— WireGuard Admin
"""
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "Activate your WireGuard VPN account"
    msg["From"] = SMTP_FROM
    msg["To"] = email
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
    except Exception as e:
        print(f"[email] Failed to send activation to {email}: {e}")


# -- Portal sessions --

def _create_session(peer_id: int) -> str:
    token = secrets.token_urlsafe(48)
    now = datetime.utcnow().isoformat()
    expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    db.execute(
        "INSERT INTO portal_sessions (token, peer_id, created, expires) VALUES (%s,%s,%s,%s)",
        (_hash(token), peer_id, now, expires),
    )
    return token


def _verify_portal_session(token: str) -> dict | None:
    if not token:
        return None
    now = datetime.utcnow().isoformat()
    row = db.fetchone(
        "SELECT peer_id FROM portal_sessions WHERE token = %s AND expires > %s",
        (_hash(token), now),
    )
    if not row:
        return None
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (row["peer_id"],))
    return dict(peer) if peer else None


async def _require_portal_user(token: str = Security(_token_header)) -> dict:
    peer = _verify_portal_session(token)
    if not peer:
        raise HTTPException(401, "Not authenticated")
    return peer


# -- Activation endpoints --

class ActivatePasswordRequest(BaseModel):
    token: str
    password: str


class ActivateGoogleRequest(BaseModel):
    token: str


@router.post("/activate/password")
async def activate_with_password(req: ActivatePasswordRequest):
    """Activate account and set password. Also handles HostBill setup-password (already activated)."""
    token_hash = _hash(req.token)
    # Try inactive peer first (normal activation)
    peer = db.fetchone(
        "SELECT * FROM wg_peers WHERE activation_token = %s AND activated = FALSE",
        (token_hash,),
    )
    # Also try already-activated peer (HostBill setup-password flow)
    if not peer:
        peer = db.fetchone(
            "SELECT * FROM wg_peers WHERE activation_token = %s AND activated = TRUE",
            (token_hash,),
        )
    if not peer:
        raise HTTPException(400, "Invalid or expired activation link")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    db.execute(
        "UPDATE wg_peers SET portal_password_hash = %s, activated = TRUE, enabled = TRUE, activation_token = '' WHERE id = %s",
        (_hash(req.password), peer["id"]),
    )

    # Apply WG config since peer is now enabled
    peer_ops._sync_config(peer["interface_id"])

    session_token = _create_session(peer["id"])
    return {
        "status": "activated",
        "token": session_token,
        "peer": {"id": peer["id"], "name": peer["name"], "email": peer.get("portal_email", "")},
    }


@router.post("/activate/google")
async def activate_with_google(req: ActivateGoogleRequest):
    """Activate account via Google (just marks as activated)."""
    token_hash = _hash(req.token)
    peer = db.fetchone(
        "SELECT * FROM wg_peers WHERE activation_token = %s AND activated = FALSE",
        (token_hash,),
    )
    if not peer:
        raise HTTPException(400, "Invalid or expired activation link")

    db.execute(
        "UPDATE wg_peers SET activated = TRUE, enabled = TRUE, activation_token = '' WHERE id = %s",
        (peer["id"],),
    )

    peer_ops._sync_config(peer["interface_id"])

    session_token = _create_session(peer["id"])
    return {
        "status": "activated",
        "token": session_token,
        "peer": {"id": peer["id"], "name": peer["name"], "email": peer.get("portal_email", "")},
    }


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
    if not peer.get("activated"):
        raise HTTPException(403, "Account not yet activated. Check your email for the activation link.")
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

    peer = db.fetchone("SELECT * FROM wg_peers WHERE portal_email = %s", (email,))
    if not peer:
        peer = db.fetchone("SELECT * FROM wg_peers WHERE note = %s", (email,))
    if not peer:
        raise HTTPException(404, f"No VPN account found for {email}")
    if not peer.get("activated"):
        raise HTTPException(403, "Account not yet activated. Check your email for the activation link.")
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
        db.execute("DELETE FROM portal_sessions WHERE token = %s", (_hash(token),))
    return {"ok": True}


# -- Admin: send activation --

class SendActivationRequest(BaseModel):
    peer_id: int
    method: str = "password"  # "password" or "google"


@router.post("/send-activation")
async def send_activation(req: SendActivationRequest):
    """Admin endpoint: send activation email to a peer."""
    from .admin import _require_admin
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (req.peer_id,))
    if not peer:
        raise HTTPException(404, "Peer not found")
    email = peer.get("portal_email") or peer.get("note", "")
    if not email or "@" not in email:
        raise HTTPException(400, "Peer has no valid email. Set portal_email first.")
    name = peer["name"]
    send_activation_email(peer["id"], email, name, req.method)
    return {"sent": True, "email": email, "method": req.method}


# -- Self-service endpoints --

@router.get("/me")
async def portal_me(peer: dict = Security(_require_portal_user)):
    return {
        "id": peer["id"],
        "name": peer["name"],
        "email": peer.get("portal_email") or peer.get("note", ""),
        "allowed_ips": peer["allowed_ips"],
        "enabled": peer["enabled"],
        "activated": peer.get("activated", False),
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
