"""WireGuard Admin — VPN peer management API with admin GUI."""

import os
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .config import settings
from .ratelimit import rate_limit_ip
from .admin import router as admin_router
from .wireguard.routes import router as wg_router
from .hostbill.routes import router as hostbill_router
from .integrations.routes import router as integrations_router
from .portal import router as portal_router
from .vpn2fa_routes import router as vpn2fa_router
from .wireguard.import_routes import router as import_router
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
    # Auto-detect unimported WireGuard peers on startup
    _check_unimported_peers()
    # Start 2FA session cleanup background task
    import asyncio
    async def _2fa_cleanup_loop():
        await asyncio.sleep(30)  # Wait for startup
        while True:
            try:
                from .vpn2fa import cleanup_expired_sessions, apply_2fa_rules, check_reconnects, resolve_pending_preauths
                cleanup_expired_sessions()
                check_reconnects()
                resolve_pending_preauths()
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
app.include_router(import_router)

# Serve admin UI
_static_dir = os.path.join(os.path.dirname(__file__), "static")


@app.get("/admin/ui", include_in_schema=False)
async def admin_ui():
    return FileResponse(os.path.join(_static_dir, "admin.html"))


@app.get("/portal/ui", include_in_schema=False)
async def portal_ui():
    return FileResponse(os.path.join(_static_dir, "portal.html"))


@app.get("/branding")
async def get_branding():
    """Public endpoint: returns branding settings for login/portal pages."""
    from .server_settings import get as get_setting
    return {
        "title": get_setting("branding_title") or "WireGuard Admin",
        "logo_url": get_setting("branding_logo_url") or "",
        "logo_style": get_setting("branding_logo_style") or "none",
        "portal_title": get_setting("branding_portal_title") or "WireGuard VPN",
    }


@app.get("/health")
async def health():
    services = ["wireguard"]
    if settings.hostbill_enabled:
        services.append("hostbill")
    return {"status": "ok", "services": services}


def _check_unimported_peers():
    """On startup, check if live WireGuard has peers not in DB. Log warning if so."""
    import subprocess
    try:
        from .wireguard import importer
        configs = importer.scan_configs(settings.wg_config_dir)
        for cfg in configs:
            if "error" in cfg:
                continue
            iface_name = cfg["name"]
            # Check live peers
            result = subprocess.run(
                ["wg", "show", iface_name, "peers"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                continue
            live_keys = {k.strip() for k in result.stdout.strip().split("\n") if k.strip()}
            if not live_keys:
                continue
            # Check DB
            db_keys = {r["public_key"] for r in db.fetchall(
                "SELECT public_key FROM wg_peers"
            )}
            missing = live_keys - db_keys
            if missing:
                print(f"[startup] WARNING: {len(missing)} WireGuard peers on {iface_name} "
                      f"are NOT in the database. Config sync is BLOCKED for this interface "
                      f"until you import them via Admin → Import tab.")
    except Exception as e:
        print(f"[startup] Peer check skipped: {e}")


class BootstrapRequest(BaseModel):
    firstname: str
    lastname: str
    email: str
    password: str


@app.post("/admin/bootstrap")
async def bootstrap(req: BootstrapRequest, request: Request):
    """Create the first admin user. Only works when no users exist."""
    rate_limit_ip(request)
    # Only allow from localhost
    client_ip = request.client.host if request.client else ""
    if client_ip not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "Bootstrap only allowed from localhost")
    existing = users.list_users()
    if existing:
        raise HTTPException(403, "Already bootstrapped — users exist")
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    now = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO users (firstname, lastname, email, password_hash, role, active, must_change_password, created, accepted) VALUES (%s,%s,%s,%s,'admin',TRUE,TRUE,%s,%s)",
        (req.firstname, req.lastname, req.email, users.hash_password(req.password), now, now),
    )
    return {"created": req.email, "role": "admin"}


# Captive portal: redirect unauthenticated VPN clients
from fastapi.responses import RedirectResponse, PlainTextResponse, HTMLResponse

@app.middleware("http")
async def captive_portal_redirect(request, call_next):
    """Intercept all requests from unauthenticated 2FA VPN clients → captive portal."""
    path = request.url.path
    client_ip = request.client.host if request.client else ""

    # Skip internal paths (API, admin, portal, captive portal itself)
    if path.startswith(("/admin", "/portal", "/vpn-auth", "/wg", "/hostbill",
                        "/integrations", "/health", "/docs", "/openapi")):
        return await call_next(request)

    # Check if client is a VPN peer requiring 2FA
    if client_ip and not client_ip.startswith("127."):
        from . import vpn2fa
        peer = vpn2fa.get_peer_by_ip(client_ip)
        if peer and peer.get("require_2fa"):
            session = vpn2fa.check_session(client_ip)
            if not session.get("authenticated"):
                from . import db as _db
                _iface = _db.fetchone("SELECT address FROM wg_interfaces ORDER BY id LIMIT 1")
                _server_ip = _iface["address"].split("/")[0] if _iface else "172.19.1.1"
                captive_url = f"http://{_server_ip}:8092/vpn-auth/captive"
                # OS captive portal detection endpoints
                if "captive.apple.com" in request.headers.get("host", "") or path == "/hotspot-detect.html":
                    return HTMLResponse('<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>',
                                       status_code=302, headers={"Location": captive_url})
                if path == "/generate_204" or "connectivitycheck" in request.headers.get("host", ""):
                    return RedirectResponse(url=captive_url, status_code=302)
                if path == "/connecttest.txt" or "msftconnecttest" in request.headers.get("host", ""):
                    return RedirectResponse(url=captive_url, status_code=302)
                return RedirectResponse(url=captive_url, status_code=302)

    return await call_next(request)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.api_port)
