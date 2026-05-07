"""WireGuard config generation, key management, and wg command execution."""

import re
import subprocess
import os
import io
import base64
import qrcode

from ..config import settings


_POSTUP_ALLOWED = re.compile(
    r'^(iptables|ip6tables)\s+-[ADI]\s+(FORWARD|POSTROUTING|INPUT)\b.*$'
)


def _safe_iface_name(name: str) -> str:
    """Validate interface name before use in paths/commands."""
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]{0,14}$', name):
        raise ValueError(f"Invalid interface name: {name}")
    return name


def _safe_post_script(script: str) -> str:
    """Defense-in-depth: validate PostUp/PostDown before writing to config."""
    if not script or not script.strip():
        return script
    commands = [cmd.strip() for cmd in script.split(";") if cmd.strip()]
    for cmd in commands:
        if not _POSTUP_ALLOWED.match(cmd):
            raise ValueError(f"Refusing to write disallowed command to config: {cmd[:80]}")
    return script


def generate_keypair() -> tuple[str, str]:
    """Generate WireGuard private/public key pair."""
    private = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
    public = subprocess.run(["wg", "pubkey"], input=private + "\n", capture_output=True, text=True, check=True).stdout.strip()
    return private, public


def generate_preshared_key() -> str:
    """Generate a preshared key."""
    return subprocess.run(["wg", "genpsk"], capture_output=True, text=True, check=True).stdout.strip()


def write_server_config(interface: dict, peers: list[dict]):
    """Write a complete wg config file for the given interface and its enabled peers."""
    _safe_iface_name(interface['name'])
    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {interface['private_key']}")
    lines.append(f"Address = {interface['address']}")
    lines.append(f"ListenPort = {interface['listen_port']}")
    if interface.get("post_up"):
        _safe_post_script(interface['post_up'])
        lines.append(f"PostUp = {interface['post_up']}")
    if interface.get("post_down"):
        _safe_post_script(interface['post_down'])
        lines.append(f"PostDown = {interface['post_down']}")
    lines.append("")

    for peer in peers:
        if not peer["enabled"]:
            continue
        lines.append(f"# Peer: {peer['name']}")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['public_key']}")
        if peer.get("preshared_key"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        lines.append(f"AllowedIPs = {peer['allowed_ips']}")
        lines.append("")

    config_path = os.path.join(settings.wg_config_dir, f"{interface['name']}.conf")
    with open(config_path, "w") as f:
        f.write("\n".join(lines))
    os.chmod(config_path, 0o600)


def generate_client_config(interface: dict, peer: dict, acl_allowed_ips: str = "") -> str:
    """Generate a client config string for download."""
    from ..server_settings import get as get_setting
    dns = peer.get("dns") or interface.get("dns") or get_setting("dns_servers")
    client_allowed_ips = acl_allowed_ips or "0.0.0.0/0, ::/0"
    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {peer['private_key']}")
    lines.append(f"Address = {peer['allowed_ips']}")
    if dns:
        lines.append(f"DNS = {dns}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {interface['public_key']}")
    if peer.get("preshared_key"):
        lines.append(f"PresharedKey = {peer['preshared_key']}")
    lines.append(f"Endpoint = {interface['endpoint']}")
    lines.append(f"AllowedIPs = {client_allowed_ips}")
    if peer.get("persistent_keepalive"):
        lines.append(f"PersistentKeepalive = {peer['persistent_keepalive']}")
    return "\n".join(lines) + "\n"


def generate_qr(config_text: str) -> str:
    """Return base64-encoded PNG QR code of the config."""
    qr = qrcode.make(config_text)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"


def apply_config(interface_name: str):
    """Apply config changes using wg syncconf for zero-downtime reload."""
    _safe_iface_name(interface_name)
    try:
        # wg-quick strip removes [Interface] section, keeping only peers
        strip_result = subprocess.run(
            ["wg-quick", "strip", interface_name],
            capture_output=True, text=True, check=True
        )
        stripped_path = f"/tmp/{interface_name}_stripped.conf"
        with open(stripped_path, "w") as f:
            f.write(strip_result.stdout)
        subprocess.run(
            ["wg", "syncconf", interface_name, stripped_path],
            capture_output=True, text=True, check=True
        )
        os.remove(stripped_path)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to apply config: {e.stderr}")


def interface_up(interface_name: str):
    """Bring a WireGuard interface up."""
    _safe_iface_name(interface_name)
    try:
        subprocess.run(
            ["wg-quick", "up", interface_name],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to bring up {interface_name}: {e.stderr}")


def interface_down(interface_name: str):
    """Bring a WireGuard interface down."""
    _safe_iface_name(interface_name)
    try:
        subprocess.run(
            ["wg-quick", "down", interface_name],
            capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to bring down {interface_name}: {e.stderr}")


def is_interface_up(interface_name: str) -> bool:
    """Check if a WireGuard interface is currently up."""
    result = subprocess.run(
        ["wg", "show", interface_name],
        capture_output=True, text=True
    )
    return result.returncode == 0
