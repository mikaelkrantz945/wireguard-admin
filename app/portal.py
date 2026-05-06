"""Portal endpoints — VPN user self-service (activation, login, config, QR)."""

import hashlib
import json
import os
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText

import httpx
from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from . import db
from .admin import _require_admin
from .password import hash_password as _hash_portal_password, verify_password
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
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    db.execute(
        "UPDATE wg_peers SET activation_token = %s, activation_method = %s, portal_email = %s, activation_expires_at = %s WHERE id = %s",
        (_hash(token), method, email, expires_at, peer_id),
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
    if peer.get("activation_expires_at") and datetime.now(timezone.utc) > peer["activation_expires_at"]:
        raise HTTPException(400, "Activation link has expired")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    db.execute(
        "UPDATE wg_peers SET portal_password_hash = %s, activated = TRUE, enabled = TRUE, activation_token = '' WHERE id = %s",
        (_hash_portal_password(req.password), peer["id"]),
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
    if peer.get("activation_expires_at") and datetime.now(timezone.utc) > peer["activation_expires_at"]:
        raise HTTPException(400, "Activation link has expired")

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
    redirect_uri: str = ""  # Accepted for backwards compat but validated against allowlist


# Allowed redirect URI patterns for portal Google OAuth.
# The actual redirect_uri is validated against BASE_URL to prevent open redirect attacks.
def _validate_portal_redirect_uri(redirect_uri: str) -> str:
    """Validate and return a safe redirect_uri for portal Google OAuth.

    Only allows redirect URIs under the configured BASE_URL.
    If the provided URI is empty or invalid, returns the canonical portal OAuth URI.
    """
    canonical = BASE_URL.rstrip("/") + "/portal/ui"
    if not redirect_uri:
        return canonical
    # Only allow URIs that start with our BASE_URL
    base = BASE_URL.rstrip("/")
    if not redirect_uri.startswith(base + "/") and redirect_uri != base:
        return canonical
    return redirect_uri


@router.post("/auth/login")
async def portal_login(req: PortalLoginRequest):
    """Login with portal email + password."""
    peer = db.fetchone(
        "SELECT * FROM wg_peers WHERE portal_email = %s AND portal_password_hash != ''",
        (req.email,),
    )
    if not peer:
        raise HTTPException(401, "Invalid email or password")
    ok, needs_rehash = verify_password(req.password, peer["portal_password_hash"])
    if not ok:
        raise HTTPException(401, "Invalid email or password")
    if needs_rehash:
        db.execute("UPDATE wg_peers SET portal_password_hash = %s WHERE id = %s", (_hash_portal_password(req.password), peer["id"]))
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

    # Validate redirect_uri against allowlist — never pass arbitrary URIs to Google
    safe_redirect_uri = _validate_portal_redirect_uri(req.redirect_uri)

    try:
        token_resp = httpx.post("https://oauth2.googleapis.com/token", data={
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "code": req.code,
            "grant_type": "authorization_code",
            "redirect_uri": safe_redirect_uri,
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

    # Validate that the email belongs to the configured domain (if set)
    domain = config.get("domain", "")
    if domain and not email.lower().endswith("@" + domain.lower()):
        raise HTTPException(403, f"Email domain not allowed. Expected @{domain}")

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


@router.post("/send-activation", dependencies=[Depends(_require_admin)])
async def send_activation(req: SendActivationRequest):
    """Admin endpoint: send activation email to a peer."""
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
        "require_2fa": peer.get("require_2fa", False),
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
    """Check if any Google integration is available for portal login.

    Only exposes client_id (which is public) — never client_secret or tokens.
    """
    integ = db.fetchone("SELECT id, name, config FROM integrations WHERE provider = 'google_workspace' AND status = 'connected' LIMIT 1")
    if not integ:
        return {"enabled": False}
    config = json.loads(integ["config"]) if integ["config"] else {}
    return {
        "enabled": True,
        "integration_id": integ["id"],
        "client_id": config.get("client_id", ""),
        # Note: client_id is intentionally public — needed for OAuth redirect on frontend.
        # client_secret and tokens are NEVER returned in this response.
    }
