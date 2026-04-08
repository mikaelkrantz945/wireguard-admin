"""VPN 2FA — captive portal authentication for WireGuard peers."""

import subprocess
from datetime import datetime, timedelta

import pyotp
import qrcode
import io
import base64

from . import db
from .server_settings import get as get_setting


def _session_hours() -> int:
    try:
        return int(get_setting("vpn_2fa_session_hours"))
    except (ValueError, TypeError):
        return 12


def setup_totp(peer_id: int) -> dict:
    """Generate TOTP secret and QR code for a peer."""
    peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (peer_id,))
    if not peer:
        raise ValueError("Peer not found")
    email = peer.get("portal_email") or peer.get("note") or peer["name"]
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="WireGuard VPN")
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return {"secret": secret, "uri": uri, "qr_code": f"data:image/png;base64,{qr_b64}"}


def enable_2fa(peer_id: int, secret: str, code: str) -> bool:
    """Verify TOTP code and enable 2FA for peer."""
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise ValueError("Invalid verification code")
    db.execute(
        "UPDATE wg_peers SET totp_secret = %s, require_2fa = TRUE WHERE id = %s",
        (secret, peer_id),
    )
    return True


def disable_2fa(peer_id: int):
    """Disable 2FA for a peer."""
    db.execute(
        "UPDATE wg_peers SET totp_secret = '', require_2fa = FALSE WHERE id = %s",
        (peer_id,),
    )
    # Remove any active sessions
    db.execute("DELETE FROM vpn_auth_sessions WHERE peer_id = %s", (peer_id,))


def verify_and_auth(peer_ip: str, code: str) -> dict:
    """Verify TOTP code for a peer identified by VPN IP. Creates auth session + opens iptables."""
    peer = db.fetchone(
        "SELECT * FROM wg_peers WHERE allowed_ips = %s AND require_2fa = TRUE AND enabled = TRUE",
        (peer_ip + "/32" if "/32" not in peer_ip else peer_ip,),
    )
    if not peer:
        raise ValueError("No 2FA-enabled peer found for this IP")
    if not peer["totp_secret"]:
        raise ValueError("2FA not configured for this peer. Set up TOTP first.")

    totp = pyotp.TOTP(peer["totp_secret"])
    if not totp.verify(code, valid_window=1):
        raise ValueError("Invalid 2FA code")

    # Create session
    now = datetime.utcnow().isoformat()
    expires = (datetime.utcnow() + timedelta(hours=_session_hours())).isoformat()
    ip = peer["allowed_ips"].split("/")[0]

    # Get current endpoint for reconnect detection
    endpoint = _get_peer_endpoint(ip)

    # Remove old sessions for this peer
    db.execute("DELETE FROM vpn_auth_sessions WHERE peer_id = %s", (peer["id"],))
    db.execute(
        "INSERT INTO vpn_auth_sessions (peer_id, peer_ip, expires, created, last_endpoint) VALUES (%s,%s,%s,%s,%s)",
        (peer["id"], ip, expires, now, endpoint),
    )

    # Open iptables for this peer
    _open_peer(ip)

    return {
        "authenticated": True,
        "peer_name": peer["name"],
        "expires": expires,
        "session_hours": _session_hours(),
    }


def check_session(peer_ip: str) -> dict:
    """Check if a peer has an active 2FA session."""
    ip = peer_ip.split("/")[0]
    now = datetime.utcnow().isoformat()
    session = db.fetchone(
        "SELECT * FROM vpn_auth_sessions WHERE peer_ip = %s AND expires > %s",
        (ip, now),
    )
    if session:
        return {"authenticated": True, "expires": session["expires"]}
    return {"authenticated": False}


def get_peer_by_ip(peer_ip: str) -> dict | None:
    """Get peer info from VPN IP."""
    ip = peer_ip if "/32" in peer_ip else peer_ip + "/32"
    row = db.fetchone("SELECT * FROM wg_peers WHERE allowed_ips = %s", (ip,))
    return dict(row) if row else None


# -- iptables management --

def _open_peer(peer_ip: str):
    """Add iptables ACCEPT rule for authenticated peer in WG_2FA chain."""
    # Ensure chain exists
    subprocess.run(["iptables", "-N", "WG_2FA"], capture_output=True)
    # Remove existing rules for this IP (avoid duplicates)
    while True:
        result = subprocess.run(
            ["iptables", "-D", "WG_2FA", "-s", peer_ip, "-j", "ACCEPT"],
            capture_output=True,
        )
        if result.returncode != 0:
            break
    # Add ACCEPT
    subprocess.run(
        ["iptables", "-I", "WG_2FA", "-s", peer_ip, "-j", "ACCEPT"],
        capture_output=True,
    )


def _block_peer(peer_ip: str):
    """Remove iptables ACCEPT rule for peer."""
    while True:
        result = subprocess.run(
            ["iptables", "-D", "WG_2FA", "-s", peer_ip, "-j", "ACCEPT"],
            capture_output=True,
        )
        if result.returncode != 0:
            break


def apply_2fa_rules(interface_name: str = "wg0"):
    """Build the WG_2FA iptables chain for all 2FA-required peers.

    Chain logic:
    - Peers WITHOUT require_2fa: RETURN (skip, handled by normal ACL)
    - Peers WITH require_2fa + active session: ACCEPT
    - Peers WITH require_2fa + no session: allow only access to VPN server, DROP rest
    """
    # Ensure chain exists
    subprocess.run(["iptables", "-N", "WG_2FA"], capture_output=True)
    # Flush
    subprocess.run(["iptables", "-F", "WG_2FA"], capture_output=True, check=True)

    # Ensure jump from FORWARD before WG_ACL
    check = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", interface_name, "-j", "WG_2FA"],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "FORWARD", "1", "-i", interface_name, "-j", "WG_2FA"],
            capture_output=True, check=True,
        )

    # Get 2FA-required peers
    peers_2fa = db.fetchall("SELECT * FROM wg_peers WHERE require_2fa = TRUE AND enabled = TRUE")
    if not peers_2fa:
        return

    now = datetime.utcnow().isoformat()
    active_sessions = db.fetchall("SELECT peer_ip FROM vpn_auth_sessions WHERE expires > %s", (now,))
    active_ips = {s["peer_ip"] for s in active_sessions}

    # Get VPN server IP for captive portal access
    iface = db.fetchone("SELECT address FROM wg_interfaces WHERE name = %s", (interface_name,))
    server_ip = iface["address"].split("/")[0] if iface else "172.19.1.1"

    for peer in peers_2fa:
        peer_ip = peer["allowed_ips"].split("/")[0]

        if peer_ip in active_ips:
            # Authenticated — ACCEPT all traffic
            subprocess.run(
                ["iptables", "-A", "WG_2FA", "-s", peer_ip, "-j", "ACCEPT"],
                capture_output=True,
            )
        else:
            # Not authenticated — only allow access to VPN server (portal + DNS)
            # Allow traffic to VPN server IP (for 2FA portal on any port)
            subprocess.run(
                ["iptables", "-A", "WG_2FA", "-s", peer_ip, "-d", server_ip, "-j", "ACCEPT"],
                capture_output=True,
            )
            # Allow DNS to resolve captive portal (UDP 53)
            subprocess.run(
                ["iptables", "-A", "WG_2FA", "-s", peer_ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                capture_output=True,
            )
            # Drop everything else
            subprocess.run(
                ["iptables", "-A", "WG_2FA", "-s", peer_ip, "-j", "DROP"],
                capture_output=True,
            )

    # Ensure NAT redirect: port 80 on VPN server → API port (for captive portal)
    api_port = get_setting("default_port") if False else "8092"  # hardcoded for now
    _ensure_captive_redirect(server_ip, api_port)


def _ensure_captive_redirect(server_ip: str, api_port: str):
    """Add iptables NAT redirect + INPUT allow for captive portal access."""
    # NAT: redirect port 80 on VPN IP to API port
    check = subprocess.run(
        ["iptables", "-t", "nat", "-C", "PREROUTING", "-d", server_ip, "-p", "tcp",
         "--dport", "80", "-j", "REDIRECT", "--to-port", api_port],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-d", server_ip, "-p", "tcp",
             "--dport", "80", "-j", "REDIRECT", "--to-port", api_port],
            capture_output=True,
        )

    # INPUT: allow all VPN clients to reach the server itself (for captive portal, DNS, etc.)
    check = subprocess.run(
        ["iptables", "-C", "INPUT", "-i", "wg0", "-d", server_ip, "-j", "ACCEPT"],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-i", "wg0", "-d", server_ip, "-j", "ACCEPT"],
            capture_output=True,
        )


def _get_peer_endpoint(peer_ip: str) -> str:
    """Get the current endpoint for a peer from wg show."""
    try:
        result = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True)
        for line in result.stdout.strip().split("\n")[1:]:
            fields = line.split("\t")
            if len(fields) >= 4 and peer_ip in fields[3]:
                return fields[2] if fields[2] != "(none)" else ""
    except Exception:
        pass
    return ""


def _get_peer_handshake(peer_ip: str) -> int:
    """Get latest handshake epoch for a peer from wg show."""
    try:
        result = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True)
        for line in result.stdout.strip().split("\n")[1:]:
            fields = line.split("\t")
            if len(fields) >= 5 and peer_ip in fields[3]:
                return int(fields[4]) if fields[4] != "0" else 0
    except Exception:
        pass
    return 0


def _should_reauth(peer: dict) -> bool:
    """Check if peer requires re-auth on reconnect."""
    # Per-peer override (NULL = use global)
    if peer.get("reauth_on_reconnect") is not None:
        return bool(peer["reauth_on_reconnect"])
    # Global setting
    return get_setting("vpn_2fa_reauth_on_reconnect").lower() == "true"


def check_reconnects():
    """Detect peers that disconnected and reconnected — invalidate their 2FA sessions.

    Detection methods:
    1. Endpoint changed (reconnect from different IP:port)
    2. Handshake stale >150s (WireGuard sends keepalive every 25s, so 150s = definitely gone)
    """
    import time
    now_epoch = int(time.time())
    sessions = db.fetchall("SELECT * FROM vpn_auth_sessions")
    invalidated = False

    for session in sessions:
        peer_ip = session["peer_ip"]
        peer = db.fetchone("SELECT * FROM wg_peers WHERE allowed_ips = %s", (peer_ip + "/32",))
        if not peer:
            continue
        if not _should_reauth(peer):
            continue

        current_endpoint = _get_peer_endpoint(peer_ip)
        stored_endpoint = session.get("last_endpoint", "")
        handshake = _get_peer_handshake(peer_ip)

        should_invalidate = False
        reason = ""

        # Method 1: Endpoint changed
        if stored_endpoint and current_endpoint and current_endpoint != stored_endpoint:
            should_invalidate = True
            reason = f"endpoint changed: {stored_endpoint} -> {current_endpoint}"

        # Method 2: Handshake stale (>150s = disconnected)
        if handshake > 0 and (now_epoch - handshake) > 150:
            should_invalidate = True
            reason = f"handshake stale: {now_epoch - handshake}s ago"

        # Method 3: No handshake at all (peer never connected or gone)
        if handshake == 0:
            should_invalidate = True
            reason = "no handshake"

        if should_invalidate:
            print(f"[2fa] Session invalidated for {peer_ip}: {reason}")
            db.execute("DELETE FROM vpn_auth_sessions WHERE id = %s", (session["id"],))
            invalidated = True

        # Update stored endpoint if it was empty
        elif current_endpoint and not stored_endpoint:
            db.execute(
                "UPDATE vpn_auth_sessions SET last_endpoint = %s WHERE id = %s",
                (current_endpoint, session["id"]),
            )

    return invalidated


def cleanup_expired_sessions():
    """Remove expired sessions and update iptables."""
    now = datetime.utcnow().isoformat()
    expired = db.fetchall("SELECT peer_ip FROM vpn_auth_sessions WHERE expires <= %s", (now,))
    for session in expired:
        _block_peer(session["peer_ip"])
    db.execute("DELETE FROM vpn_auth_sessions WHERE expires <= %s", (now,))
    if expired:
        # Rebuild 2FA rules
        ifaces = db.fetchall("SELECT name FROM wg_interfaces")
        for iface in ifaces:
            apply_2fa_rules(iface["name"])
