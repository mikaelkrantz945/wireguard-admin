"""Shared utility helpers."""

from starlette.requests import Request

TRUSTED_PROXIES = {"127.0.0.1", "::1"}


def get_client_ip(request: Request) -> str:
    """Return true client IP. Only trust X-Real-IP when connection is from a trusted proxy."""
    peer = request.client.host if request.client else ""
    if peer in TRUSTED_PROXIES:
        return request.headers.get("x-real-ip", "") or peer
    return peer
