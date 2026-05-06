"""Shared password hashing module — bcrypt via passlib with legacy SHA-256 migration."""

import hashlib

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, stored_hash: str) -> tuple[bool, bool]:
    """Returns (is_valid, needs_rehash)."""
    if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
        return pwd_context.verify(password, stored_hash), False
    # Legacy SHA-256 admin
    legacy_admin = hashlib.sha256(f"wgadmin-salt:{password}".encode()).hexdigest()
    if stored_hash == legacy_admin:
        return True, True
    # Legacy SHA-256 portal
    legacy_portal = hashlib.sha256(f"wgportal:{password}".encode()).hexdigest()
    if stored_hash == legacy_portal:
        return True, True
    return False, False
