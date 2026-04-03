"""User management with PostgreSQL backend."""

import hashlib
import secrets
import os
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText

from . import db

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "25"))
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@example.com")
BASE_URL = os.environ.get("BASE_URL", "https://vpn.example.com")


def _hash_password(password: str) -> str:
    salt = "wgadmin-salt"
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def invite_user(firstname: str, lastname: str, email: str, role: str = "readonly") -> dict:
    existing = db.fetchone("SELECT id, active FROM users WHERE email = %s", (email,))
    if existing and existing["active"]:
        raise ValueError(f"User {email} already exists and is active")

    invite_token = secrets.token_urlsafe(48)
    now = datetime.utcnow().isoformat()
    expires = (datetime.utcnow() + timedelta(days=7)).isoformat()

    if existing:
        db.execute(
            "UPDATE users SET firstname=%s, lastname=%s, role=%s, invite_token=%s, invite_expires=%s, active=FALSE, password_hash='' WHERE id=%s",
            (firstname, lastname, role, _hash_token(invite_token), expires, existing["id"]),
        )
        user_id = existing["id"]
    else:
        row = db.query(
            "INSERT INTO users (firstname, lastname, email, role, invite_token, invite_expires, created) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (firstname, lastname, email, role, _hash_token(invite_token), expires, now),
            fetchone=True, commit=True,
        )
        user_id = row["id"]

    invite_url = f"{BASE_URL}/admin/ui#invite={invite_token}"
    _send_invite_email(email, firstname, role, invite_url)

    return {"id": user_id, "email": email, "firstname": firstname, "lastname": lastname, "role": role, "invite_sent": True}


def accept_invite(token: str, password: str) -> dict:
    token_hash = _hash_token(token)
    user = db.fetchone("SELECT * FROM users WHERE invite_token = %s AND active = FALSE", (token_hash,))
    if not user:
        raise ValueError("Invalid or expired invite token")
    if user["invite_expires"] < datetime.utcnow().isoformat():
        raise ValueError("Invite token has expired")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    now = datetime.utcnow().isoformat()
    db.execute(
        "UPDATE users SET password_hash=%s, active=TRUE, invite_token='', accepted=%s WHERE id=%s",
        (_hash_password(password), now, user["id"]),
    )
    return {"email": user["email"], "firstname": user["firstname"], "role": user["role"]}


def login(email: str, password: str, totp_code: str = "") -> dict | None:
    user = db.fetchone("SELECT * FROM users WHERE email = %s AND active = TRUE", (email,))
    if not user or user["password_hash"] != _hash_password(password):
        return None

    if user["totp_enabled"]:
        if not totp_code:
            return {"requires_totp": True}
        import pyotp
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(totp_code, valid_window=1):
            return None

    session_token = secrets.token_urlsafe(48)
    now = datetime.utcnow().isoformat()
    expires = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    db.execute(
        "INSERT INTO sessions (token, user_id, created, expires) VALUES (%s,%s,%s,%s)",
        (_hash_token(session_token), user["id"], now, expires),
    )
    db.execute("DELETE FROM sessions WHERE expires < %s", (now,))

    return {
        "token": session_token,
        "must_change_password": bool(user["must_change_password"]),
        "user": {
            "id": user["id"],
            "firstname": user["firstname"],
            "lastname": user["lastname"],
            "email": user["email"],
            "role": user["role"],
            "totp_enabled": bool(user["totp_enabled"]),
        },
    }


def verify_session(token: str) -> dict | None:
    now = datetime.utcnow().isoformat()
    row = db.fetchone("""
        SELECT u.id, u.firstname, u.lastname, u.email, u.role
        FROM sessions s JOIN users u ON s.user_id = u.id
        WHERE s.token = %s AND s.expires > %s AND u.active = TRUE
    """, (_hash_token(token), now))
    return dict(row) if row else None


def logout(token: str):
    db.execute("DELETE FROM sessions WHERE token = %s", (_hash_token(token),))


def setup_totp(user_id: int) -> dict:
    import pyotp, qrcode, io, base64
    user = db.fetchone("SELECT email FROM users WHERE id = %s", (user_id,))
    if not user:
        raise ValueError("User not found")
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["email"], issuer_name="WireGuard Admin")
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return {"secret": secret, "uri": uri, "qr_code": f"data:image/png;base64,{qr_b64}"}


def enable_totp(user_id: int, secret: str, code: str) -> bool:
    import pyotp
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise ValueError("Invalid verification code")
    db.execute("UPDATE users SET totp_secret = %s, totp_enabled = TRUE WHERE id = %s", (secret, user_id))
    return True


def disable_totp(user_id: int) -> bool:
    db.execute("UPDATE users SET totp_secret = '', totp_enabled = FALSE WHERE id = %s", (user_id,))
    return True


def change_password(user_id: int, new_password: str) -> bool:
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters")
    db.execute("UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE id = %s", (_hash_password(new_password), user_id))
    return True


def list_users() -> list[dict]:
    return db.fetchall("SELECT id, firstname, lastname, email, role, active, created, accepted FROM users ORDER BY created DESC")


def update_user(user_id: int, role: str = None, active: int = None) -> bool:
    updates, params = [], []
    if role is not None:
        updates.append("role = %s")
        params.append(role)
    if active is not None:
        updates.append("active = %s")
        params.append(bool(active))
    if not updates:
        return False
    params.append(user_id)
    return db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s", tuple(params)) > 0


def delete_user(user_id: int) -> bool:
    db.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    return db.execute("DELETE FROM users WHERE id = %s", (user_id,)) > 0


def _send_invite_email(to: str, firstname: str, role: str, invite_url: str):
    body = f"""Hi {firstname},

You've been invited to the WireGuard Admin panel as {role}.

Click the link below to set your password and activate your account:

{invite_url}

This link expires in 7 days.

— WireGuard Admin
"""
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = "WireGuard Admin — Invite"
    msg["From"] = SMTP_FROM
    msg["To"] = to
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
    except Exception as e:
        print(f"[email] Failed to send invite to {to}: {e}")
