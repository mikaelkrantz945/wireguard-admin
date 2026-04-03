"""Request logging middleware."""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from . import logger, keystore


class RequestLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration_ms = int((time.time() - start) * 1000)

        path = request.url.path
        # Skip logging for static files and health checks
        if path.startswith("/admin/static") or path == "/health":
            return response

        # Try to identify the customer from API key
        key_prefix = ""
        customer = ""
        scope = ""
        api_key = request.headers.get("x-api-key", "")
        if api_key:
            info = keystore.verify_key(api_key)
            if info:
                key_prefix = info.get("key_prefix", "")
                customer = info.get("customer", "")
                scope = info.get("scope", "")

        # Determine scope from path if not from key
        if not scope:
            if path.startswith("/wg"):
                scope = "wireguard"
            elif path.startswith("/hostbill"):
                scope = "hostbill"
            elif path.startswith("/admin"):
                scope = "admin"

        logger.log_request(
            method=request.method,
            path=path,
            status=response.status_code,
            duration_ms=duration_ms,
            client_ip=request.client.host if request.client else "",
            key_prefix=key_prefix,
            customer=customer,
            scope=scope,
        )

        return response
