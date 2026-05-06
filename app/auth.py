"""API key authentication — supports API keys (with IP ACL) and user sessions."""

from fastapi import HTTPException, Security, Request
from fastapi.security import APIKeyHeader

from . import keystore, users
from .utils import get_client_ip

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _verify_scope(scope: str):
    """Return a dependency that verifies API key or session token, including IP ACL."""
    async def _check(request: Request, token: str = Security(_api_key_header)):
        if not token:
            raise HTTPException(401, "Missing API key")
        # Check if it's a user session (admin GUI)
        user = users.verify_session(token)
        if user:
            # Only admin-role users may access API-scoped endpoints via session
            if user["role"] != "admin":
                raise HTTPException(403, "Admin role required for API access")
            return {"customer": f"{user['firstname']} {user['lastname']}", "scope": "admin", "key_prefix": "session", "role": user["role"]}
        # Check API key with client IP
        client_ip = get_client_ip(request)
        info = keystore.verify_key(token, required_scope=scope, client_ip=client_ip)
        if not info:
            raise HTTPException(401, "Invalid API key or insufficient scope")
        if info.get("ip_denied"):
            raise HTTPException(
                403,
                f"Access denied: IP {info['client_ip']} not in allowed list. Update your API key ACL to add this IP."
            )
        return info
    return _check


verify_wireguard = _verify_scope("wireguard")
verify_hostbill = _verify_scope("hostbill")
verify_any = _verify_scope(None)
