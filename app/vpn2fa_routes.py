"""VPN 2FA captive portal routes."""

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import vpn2fa, db
from .admin import _require_admin
from .portal import _require_portal_user
from .ratelimit import rate_limit_ip
from .utils import get_client_ip

router = APIRouter(prefix="/vpn-auth", tags=["VPN 2FA"])

_static_dir = os.path.join(os.path.dirname(__file__), "static")


@router.get("/captive", include_in_schema=False)
async def captive_page():
    """Serve the 2FA captive portal page."""
    return FileResponse(os.path.join(_static_dir, "captive.html"))


class VerifyRequest(BaseModel):
    code: str


@router.post("/verify")
async def verify_2fa(req: VerifyRequest, request: Request):
    """Verify TOTP code and open VPN access for the caller's IP."""
    rate_limit_ip(request)
    # Get the client's VPN IP (via WireGuard, this is the peer's tunnel IP)
    client_ip = get_client_ip(request)
    if not client_ip:
        raise HTTPException(400, "Cannot determine your IP")

    try:
        result = vpn2fa.verify_and_auth(client_ip, req.code)
        return result
    except ValueError as e:
        raise HTTPException(401, str(e))


@router.get("/status")
async def check_status(request: Request):
    """Check if the caller has an active 2FA session."""
    client_ip = get_client_ip(request)
    return vpn2fa.check_session(client_ip)


# -- Admin endpoints (for managing 2FA on peers) --

@router.post("/setup/{peer_id}", dependencies=[Depends(_require_admin)])
async def setup_peer_2fa(peer_id: int):
    """Generate TOTP secret and QR for a peer."""
    try:
        return vpn2fa.setup_totp(peer_id)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/enable/{peer_id}", dependencies=[Depends(_require_admin)])
async def enable_peer_2fa(peer_id: int, req: dict):
    """Enable 2FA for a peer after verifying TOTP code."""
    try:
        vpn2fa.enable_2fa(peer_id, req.get("secret", ""), req.get("code", ""))
        return {"ok": True, "require_2fa": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/disable/{peer_id}", dependencies=[Depends(_require_admin)])
async def disable_peer_2fa(peer_id: int):
    """Disable 2FA for a peer."""
    vpn2fa.disable_2fa(peer_id)
    return {"ok": True, "require_2fa": False}


# -- Portal self-service endpoints (user manages own 2FA) --

@router.post("/portal/setup")
async def portal_setup_2fa(peer: dict = Depends(_require_portal_user)):
    """Portal user: generate TOTP secret for own peer."""
    try:
        return vpn2fa.setup_totp(peer["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/portal/enable")
async def portal_enable_2fa(req: dict, peer: dict = Depends(_require_portal_user)):
    """Portal user: enable 2FA on own peer."""
    try:
        vpn2fa.enable_2fa(peer["id"], req.get("secret", ""), req.get("code", ""))
        return {"ok": True, "require_2fa": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/portal/disable")
async def portal_disable_2fa(peer: dict = Depends(_require_portal_user)):
    """Portal user: disable 2FA on own peer."""
    vpn2fa.disable_2fa(peer["id"])
    return {"ok": True, "require_2fa": False}
