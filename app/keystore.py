"""API key management with PostgreSQL backend."""

import hashlib
import secrets
from datetime import datetime

from . import db


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_key(customer: str, scope: str = "all", note: str = "", user_id: int = 0, allowed_ips: str = "") -> dict:
    raw_key = secrets.token_hex(32)
    prefix = raw_key[:8]
    now = datetime.utcnow().isoformat()
    row = db.query(
        "INSERT INTO api_keys (key_hash, key_prefix, customer, scope, created, note, user_id, allowed_ips) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (_hash(raw_key), prefix, customer, scope, now, note, user_id, allowed_ips.strip()),
        fetchone=True, commit=True,
    )
    return {
        "id": row["id"],
        "key": raw_key,
        "prefix": prefix + "...",
        "customer": customer,
        "scope": scope,
        "created": now,
        "note": note,
        "user_id": user_id,
        "allowed_ips": allowed_ips.strip(),
    }


def verify_key(key: str, required_scope: str = None, client_ip: str = "") -> dict | None:
    row = db.fetchone("SELECT * FROM api_keys WHERE key_hash = %s AND active = TRUE", (_hash(key),))
    if not row:
        return None
    if required_scope and row["scope"] != "all" and row["scope"] != required_scope:
        return None
    # Check IP ACL
    allowed = (row["allowed_ips"] or "").strip()
    if allowed and client_ip:
        ip_list = [ip.strip() for ip in allowed.split(",") if ip.strip()]
        if ip_list and client_ip not in ip_list:
            result = dict(row)
            result["ip_denied"] = True
            result["client_ip"] = client_ip
            return result
    db.execute("UPDATE api_keys SET last_used = %s WHERE id = %s", (datetime.utcnow().isoformat(), row["id"]))
    return dict(row)


def list_keys(customer: str = None, user_id: int = None) -> list[dict]:
    if user_id is not None:
        return db.fetchall(
            "SELECT id, key_prefix, customer, scope, created, last_used, active, note, user_id, allowed_ips FROM api_keys WHERE user_id = %s ORDER BY created DESC",
            (user_id,),
        )
    if customer:
        return db.fetchall(
            "SELECT id, key_prefix, customer, scope, created, last_used, active, note, user_id, allowed_ips FROM api_keys WHERE customer = %s ORDER BY created DESC",
            (customer,),
        )
    return db.fetchall(
        "SELECT id, key_prefix, customer, scope, created, last_used, active, note, user_id, allowed_ips FROM api_keys ORDER BY created DESC"
    )


def update_key(key_id: int, note: str = None, scope: str = None, allowed_ips: str = None, user_id: int = None) -> bool:
    updates = []
    params = []
    if note is not None:
        updates.append("note = %s")
        params.append(note)
    if scope is not None:
        updates.append("scope = %s")
        params.append(scope)
    if allowed_ips is not None:
        updates.append("allowed_ips = %s")
        params.append(allowed_ips.strip())
    if not updates:
        return False
    query = f"UPDATE api_keys SET {', '.join(updates)} WHERE id = %s"
    params.append(key_id)
    if user_id is not None:
        query += " AND user_id = %s"
        params.append(user_id)
    return db.execute(query, tuple(params)) > 0


def revoke_key(key_id: int, user_id: int = None) -> bool:
    query = "UPDATE api_keys SET active = FALSE WHERE id = %s"
    params = [key_id]
    if user_id is not None:
        query += " AND user_id = %s"
        params.append(user_id)
    return db.execute(query, tuple(params)) > 0


def delete_key(key_id: int, user_id: int = None) -> bool:
    query = "DELETE FROM api_keys WHERE id = %s"
    params = [key_id]
    if user_id is not None:
        query += " AND user_id = %s"
        params.append(user_id)
    return db.execute(query, tuple(params)) > 0
