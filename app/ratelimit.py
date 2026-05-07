"""Simple in-memory rate limiter for auth endpoints."""

import time
from collections import defaultdict
from fastapi import HTTPException, Request

# {key: [(timestamp, ...], ...}
_attempts: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(key: str, max_attempts: int = 5, window_seconds: int = 300):
    """Check rate limit. Raises HTTPException(429) if exceeded."""
    now = time.time()
    # Clean old entries
    _attempts[key] = [t for t in _attempts[key] if now - t < window_seconds]
    if len(_attempts[key]) >= max_attempts:
        raise HTTPException(429, f"Too many attempts. Try again in {window_seconds // 60} minutes.")
    _attempts[key].append(now)


def rate_limit_ip(request: Request, max_attempts: int = 10, window_seconds: int = 300):
    """Rate limit by client IP."""
    from .utils import get_client_ip
    ip = get_client_ip(request)
    check_rate_limit(f"ip:{ip}", max_attempts, window_seconds)


def rate_limit_account(identifier: str, max_attempts: int = 5, window_seconds: int = 300):
    """Rate limit by account identifier (email, peer_id, etc)."""
    check_rate_limit(f"account:{identifier}", max_attempts, window_seconds)
