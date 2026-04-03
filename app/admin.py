"""Admin endpoints — auth, user management, key management, logs."""

from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from . import keystore, logger, users

router = APIRouter(prefix="/admin", tags=["Admin"])

_token_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# -- Auth helpers --

async def _require_user(token: str = Security(_token_header)) -> dict:
    """Require any authenticated user (readonly or admin)."""
    if not token:
        raise HTTPException(401, "Not authenticated")
    user = users.verify_session(token)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    return user


async def _require_admin(token: str = Security(_token_header)) -> dict:
    """Require admin role."""
    if not token:
        raise HTTPException(401, "Not authenticated")
    user = users.verify_session(token)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    if user["role"] != "admin":
        raise HTTPException(403, "Admin role required")
    return user


# -- Auth endpoints --

class LoginRequest(BaseModel):
    email: str
    password: str
    totp_code: str = ""


class AcceptInviteRequest(BaseModel):
    token: str
    password: str


class ChangePasswordRequest(BaseModel):
    password: str


class EnableTotpRequest(BaseModel):
    secret: str
    code: str


@router.post("/auth/login")
async def login(req: LoginRequest):
    result = users.login(req.email, req.password, req.totp_code)
    if not result:
        raise HTTPException(401, "Invalid email, password, or 2FA code")
    return result


@router.post("/auth/logout")
async def logout(token: str = Security(_token_header)):
    if token:
        users.logout(token)
    return {"ok": True}


@router.post("/auth/accept-invite")
async def accept_invite(req: AcceptInviteRequest):
    try:
        return users.accept_invite(req.token, req.password)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/auth/me", dependencies=[Depends(_require_user)])
async def get_me(user: dict = Depends(_require_user)):
    return user


@router.post("/auth/change-password")
async def change_password(req: ChangePasswordRequest, user: dict = Depends(_require_user)):
    try:
        users.change_password(user["id"], req.password)
        return {"ok": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/auth/totp/setup")
async def totp_setup(user: dict = Depends(_require_user)):
    return users.setup_totp(user["id"])


@router.post("/auth/totp/enable")
async def totp_enable(req: EnableTotpRequest, user: dict = Depends(_require_user)):
    try:
        users.enable_totp(user["id"], req.secret, req.code)
        return {"ok": True, "totp_enabled": True}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/auth/totp/disable")
async def totp_disable(user: dict = Depends(_require_user)):
    users.disable_totp(user["id"])
    return {"ok": True, "totp_enabled": False}


# -- User management (admin only) --

class InviteRequest(BaseModel):
    firstname: str
    lastname: str
    email: str
    role: str = "readonly"
    group_id: int = 0
    activation_method: str = "password"  # "password" or "google"


class UpdateUserRequest(BaseModel):
    role: str | None = None
    active: int | None = None


@router.get("/users", dependencies=[Depends(_require_admin)])
async def list_all_users():
    return users.list_users()


@router.post("/users/invite", status_code=201, dependencies=[Depends(_require_admin)])
async def invite_user(req: InviteRequest):
    if req.role not in ("readonly", "admin", "vpn"):
        raise HTTPException(400, "Role must be 'readonly', 'admin', or 'vpn'")

    if req.role == "vpn":
        # Create a WireGuard peer instead of an admin user
        from . import db
        from .wireguard import peers
        from .portal import send_activation_email

        iface = db.fetchone("SELECT id FROM wg_interfaces ORDER BY id LIMIT 1")
        if not iface:
            raise HTTPException(400, "No WireGuard interface configured. Create one first.")

        name = f"{req.firstname} {req.lastname}".strip()
        try:
            result = peers.create_peer(
                interface_id=iface["id"],
                name=name,
                note=req.email,
                group_id=req.group_id,
            )
            peer_id = result["peer"]["id"]
            send_activation_email(peer_id, req.email, name, req.activation_method)
            return {
                "id": peer_id,
                "email": req.email,
                "firstname": req.firstname,
                "lastname": req.lastname,
                "role": "vpn",
                "invite_sent": True,
                "activation_method": req.activation_method,
            }
        except ValueError as e:
            raise HTTPException(400, str(e))

    try:
        return users.invite_user(req.firstname, req.lastname, req.email, req.role)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/users/{user_id}", dependencies=[Depends(_require_admin)])
async def update_user(user_id: int, req: UpdateUserRequest):
    if req.role and req.role not in ("readonly", "admin"):
        raise HTTPException(400, "Role must be 'readonly' or 'admin'")
    if users.update_user(user_id, req.role, req.active):
        return {"updated": user_id}
    raise HTTPException(404, "User not found")


@router.delete("/users/{user_id}", dependencies=[Depends(_require_admin)])
async def delete_user(user_id: int):
    if users.delete_user(user_id):
        return {"deleted": user_id}
    raise HTTPException(404, "User not found")


# -- Key management (admin only) --

class CreateKeyRequest(BaseModel):
    customer: str
    scope: str = "all"
    note: str = ""
    allowed_ips: str = ""


@router.post("/keys", status_code=201, dependencies=[Depends(_require_admin)])
async def create_key(req: CreateKeyRequest):
    if req.scope not in ("wireguard", "hostbill", "all"):
        raise HTTPException(400, "Invalid scope. Use: wireguard, hostbill, all")
    return keystore.create_key(req.customer, req.scope, req.note, allowed_ips=req.allowed_ips)


@router.get("/keys", dependencies=[Depends(_require_user)])
async def list_keys(customer: str = None):
    return keystore.list_keys(customer)


@router.delete("/keys/{key_id}", dependencies=[Depends(_require_admin)])
async def revoke_key(key_id: int):
    if keystore.revoke_key(key_id):
        return {"revoked": key_id}
    raise HTTPException(404, "Key not found")


@router.delete("/keys/{key_id}/permanent", dependencies=[Depends(_require_admin)])
async def delete_key(key_id: int):
    if keystore.delete_key(key_id):
        return {"deleted": key_id}
    raise HTTPException(404, "Key not found")


# -- Logs & stats --

@router.get("/logs", dependencies=[Depends(_require_user)])
async def get_logs(limit: int = 100, offset: int = 0, customer: str = None, path: str = None):
    return logger.get_logs(limit, offset, customer, path)


@router.get("/stats", dependencies=[Depends(_require_user)])
async def get_stats():
    return logger.get_stats()
