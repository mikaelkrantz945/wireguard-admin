"""Server settings stored in PostgreSQL — GUI-editable, with env fallbacks."""

from . import db
from .config import settings as env_settings

# Setting definitions: key -> {label, default_from_env, description}
SETTING_DEFS = {
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
    "portal_welcome_message": {
        "label": "Portal Welcome Message",
        "default": "",
        "description": "Custom message shown on the user portal login page (HTML allowed)",
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
