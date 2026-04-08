"""WireGuard Admin — VPN peer management API with admin GUI."""

import os
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .config import settings
from .admin import router as admin_router
from .wireguard.routes import router as wg_router
from .hostbill.routes import router as hostbill_router
from .integrations.routes import router as integrations_router
from .portal import router as portal_router
from .vpn2fa_routes import router as vpn2fa_router
from .middleware import RequestLogMiddleware
from . import users, db

app = FastAPI(
    title="WireGuard Admin",
    description="WireGuard VPN administration API with admin GUI and HostBill provisioning.",
    version="1.0.0",
)


@app.on_event("startup")
async def startup():
    db.init_schema()
    from .wireguard.acl import seed_default
    seed_default()
    from .server_settings import seed_defaults
    seed_defaults()
    # Start 2FA session cleanup background task
    import asyncio
    async def _2fa_cleanup_loop():
        await asyncio.sleep(30)  # Wait for startup
        while True:
            try:
                from .vpn2fa import cleanup_expired_sessions, apply_2fa_rules
                cleanup_expired_sessions()
                ifaces = db.fetchall("SELECT name FROM wg_interfaces")
                for iface in ifaces:
                    apply_2fa_rules(iface["name"])
            except Exception as e:
                print(f"[2fa-cleanup] {e}")
            await asyncio.sleep(60)
    asyncio.create_task(_2fa_cleanup_loop())


app.add_middleware(RequestLogMiddleware)
app.include_router(admin_router)
app.include_router(wg_router)
app.include_router(hostbill_router)
app.include_router(integrations_router)
app.include_router(portal_router)
app.include_router(vpn2fa_router)

# Serve admin UI
_static_dir = os.path.join(os.path.dirname(__file__), "static")


@app.get("/admin/ui", include_in_schema=False)
async def admin_ui():
    return FileResponse(os.path.join(_static_dir, "admin.html"))


@app.get("/portal/ui", include_in_schema=False)
async def portal_ui():
    return FileResponse(os.path.join(_static_dir, "portal.html"))


@app.get("/health")
async def health():
    services = ["wireguard"]
    if settings.hostbill_enabled:
        services.append("hostbill")
    return {"status": "ok", "services": services}


class BootstrapRequest(BaseModel):
    firstname: str
    lastname: str
    email: str
    password: str


@app.post("/admin/bootstrap")
async def bootstrap(req: BootstrapRequest):
    """Create the first admin user. Only works when no users exist."""
    existing = users.list_users()
    if existing:
        return {"error": "Users already exist. Use /admin/ui to manage."}
    if len(req.password) < 8:
        return {"error": "Password must be at least 8 characters"}
    now = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO users (firstname, lastname, email, password_hash, role, active, must_change_password, created, accepted) VALUES (%s,%s,%s,%s,'admin',TRUE,TRUE,%s,%s)",
        (req.firstname, req.lastname, req.email, users._hash_password(req.password), now, now),
    )
    return {"created": req.email, "role": "admin"}


# Catch-all: redirect unauthenticated VPN clients to captive portal
from fastapi.responses import RedirectResponse

@app.middleware("http")
async def captive_portal_redirect(request, call_next):
    """If a 2FA-required VPN client hits any page without a session, redirect to captive portal."""
    response = await call_next(request)
    # Only intercept 404s from VPN clients (not admin/portal/api)
    path = request.url.path
    if response.status_code == 404:
        client_ip = request.client.host if request.client else ""
        # Check if this IP belongs to a 2FA-required peer without active session
        if client_ip and not client_ip.startswith("127."):
            from . import vpn2fa
            peer = vpn2fa.get_peer_by_ip(client_ip)
            if peer and peer.get("require_2fa"):
                session = vpn2fa.check_session(client_ip)
                if not session.get("authenticated"):
                    return RedirectResponse(url="/vpn-auth/captive")
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.api_port)
