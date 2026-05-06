"""Server settings stored in PostgreSQL — GUI-editable, with env fallbacks."""

from . import db
from .config import settings as env_settings

# Setting definitions: key -> {label, default_from_env, description}
SETTING_DEFS = {
    "branding_title": {
        "label": "Site Title",
        "default": "WireGuard Admin",
        "description": "Title shown in header, login page, and browser tab",
    },
    "branding_logo_url": {
        "label": "Logo URL",
        "default": "",
        "description": "URL to company logo image (displayed next to title, recommended max height 40px)",
    },
    "branding_logo_style": {
        "label": "Logo Background",
        "default": "none",
        "description": "Set to 'light' to add a white rounded background behind the logo (for dark logos on dark theme), or 'none' for transparent",
    },
    "branding_portal_title": {
        "label": "Portal Title",
        "default": "WireGuard VPN",
        "description": "Title shown on the user portal login and pages",
    },
    "dns_servers": {
        "label": "DNS Servers",
        "default": env_settings.wg_default_dns,
        "description": "Default DNS servers for VPN client configs (comma-separated)",
    },
    "endpoint": {
        "label": "Server Endpoint",
        "default": env_settings.wg_default_endpoint,
        "description": "Public hostname or IP for VPN client endpoint",
    },
    "default_subnet": {
        "label": "Default Subnet",
        "default": env_settings.wg_default_subnet,
        "description": "Default subnet for new WireGuard interfaces",
    },
    "default_port": {
        "label": "Default WireGuard Port",
        "default": str(env_settings.wg_default_port),
        "description": "Default listen port for new interfaces",
    },
    "default_keepalive": {
        "label": "Default PersistentKeepalive",
        "default": "25",
        "description": "Default keepalive interval (seconds) for new peers",
    },
    "vpn_2fa_session_hours": {
        "label": "VPN 2FA Session Duration (hours)",
        "default": "12",
        "description": "How long a VPN 2FA session lasts before re-authentication is required",
    },
    "vpn_2fa_reauth_on_reconnect": {
        "label": "Require 2FA re-auth on reconnect (global)",
        "default": "false",
        "description": "If true, 2FA sessions are invalidated when a peer disconnects and reconnects. Set to 'true' or 'false'",
    },
    "portal_welcome_message": {
        "label": "Portal Welcome Message",
        "default": "",
        "description": "Custom message shown on the user portal login page (HTML allowed)",
    },
    "email_invite_subject": {
        "label": "Admin Invite Email — Subject",
        "default": "WireGuard Admin — Invite",
        "description": "Subject line for admin user invite emails",
    },
    "email_invite_body": {
        "label": "Admin Invite Email — Body",
        "default": "Hi {firstname},\n\nYou've been invited to the WireGuard Admin panel as {role}.\n\nClick the link below to set your password and activate your account:\n\n{invite_url}\n\nThis link expires in 7 days.\n\n— WireGuard Admin",
        "description": "Body template for admin invite. Variables: {firstname}, {role}, {invite_url}",
    },
    "email_activation_subject": {
        "label": "VPN Activation Email — Subject",
        "default": "Activate your WireGuard VPN account",
        "description": "Subject line for VPN peer activation emails",
    },
    "email_activation_body": {
        "label": "VPN Activation Email — Body",
        "default": "Hi {name},\n\nYour WireGuard VPN account has been created.\n\nClick the link below to activate your account:\n\n{activate_url}\n\n{method_hint}\n\nThis link is valid for 7 days.\n\n— WireGuard Admin",
        "description": "Body template for VPN activation. Variables: {name}, {activate_url}, {method_hint}",
    },
    "email_welcome_subject": {
        "label": "HostBill Welcome Email — Subject",
        "default": "Your WireGuard VPN is ready",
        "description": "Subject line for HostBill provisioned welcome emails",
    },
    "email_welcome_body": {
        "label": "HostBill Welcome Email — Body",
        "default": "Hi {name},\n\nYour WireGuard VPN service is now active!\n\nYour VPN configuration is ready. Visit the portal to set your password and download your config:\n\n{portal_url}\n\nYou can also scan a QR code to set up WireGuard on your phone.\n\n— WireGuard Admin",
        "description": "Body template for HostBill welcome. Variables: {name}, {portal_url}",
    },
}


def seed_defaults():
    """Insert default settings if they don't exist."""
    for key, defn in SETTING_DEFS.items():
        existing = db.fetchone("SELECT key FROM settings WHERE key = %s", (key,))
        if not existing:
            db.execute(
                "INSERT INTO settings (key, value) VALUES (%s, %s)",
                (key, defn["default"]),
            )


def get(key: str) -> str:
    """Get a setting value, falling back to default."""
    row = db.fetchone("SELECT value FROM settings WHERE key = %s", (key,))
    if row and row["value"]:
        return row["value"]
    defn = SETTING_DEFS.get(key)
    return defn["default"] if defn else ""


def get_all() -> list[dict]:
    """Get all settings with metadata."""
    result = []
    for key, defn in SETTING_DEFS.items():
        row = db.fetchone("SELECT value FROM settings WHERE key = %s", (key,))
        result.append({
            "key": key,
            "value": row["value"] if row else defn["default"],
            "label": defn["label"],
            "description": defn["description"],
            "default": defn["default"],
        })
    return result


def update(key: str, value: str) -> dict:
    """Update a setting."""
    if key not in SETTING_DEFS:
        raise ValueError(f"Unknown setting: {key}")
    existing = db.fetchone("SELECT key FROM settings WHERE key = %s", (key,))
    if existing:
        db.execute("UPDATE settings SET value = %s WHERE key = %s", (value, key))
    else:
        db.execute("INSERT INTO settings (key, value) VALUES (%s, %s)", (key, value))
    return {"key": key, "value": value}
