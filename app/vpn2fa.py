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

    # Resolve the interface this peer belongs to
    iface_row = db.fetchone(
        "SELECT i.name FROM wg_interfaces i JOIN wg_peers p ON p.interface_id = i.id WHERE p.id = %s",
        (peer["id"],),
    )
    iface_name = iface_row["name"] if iface_row else "wg0"

    # Get current endpoint for reconnect detection
    endpoint = _get_peer_endpoint(ip, iface_name)

    # Remove old sessions for this peer
    db.execute("DELETE FROM vpn_auth_sessions WHERE peer_id = %s", (peer["id"],))
    db.execute(
        "INSERT INTO vpn_auth_sessions (peer_id, peer_ip, expires, created, last_endpoint) VALUES (%s,%s,%s,%s,%s)",
        (peer["id"], ip, expires, now, endpoint),
    )

    # Open iptables for this peer (add ACCEPT, don't flush chain)
    _open_peer(ip, iface_name)

    # Schedule NAT rebuild + conntrack flush in background (after response is sent)
    import threading
    def _post_auth_cleanup():
        import time
        time.sleep(2)  # Wait for response to be sent
        # Rebuild NAT rules (removes DNAT for this now-authenticated peer)
        ifaces = db.fetchall("SELECT name FROM wg_interfaces")
        for iface in ifaces:
            apply_2fa_rules(iface["name"])
        # Flush conntrack so old NAT'd connections don't persist
        subprocess.run(["conntrack", "-D", "-s", ip], capture_output=True)
    threading.Thread(target=_post_auth_cleanup, daemon=True).start()

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

def _open_peer(peer_ip: str, interface_name: str = "wg0"):
    """Add iptables ACCEPT rule for authenticated peer in interface-scoped WG_2FA chain."""
    chain = f"WG_2FA_{interface_name}"
    # Ensure chain exists
    subprocess.run(["iptables", "-N", chain], capture_output=True)
    # Remove existing rules for this IP (avoid duplicates)
    while True:
        result = subprocess.run(
            ["iptables", "-D", chain, "-s", peer_ip, "-j", "ACCEPT"],
            capture_output=True,
        )
        if result.returncode != 0:
            break
    # Add ACCEPT
    subprocess.run(
        ["iptables", "-I", chain, "-s", peer_ip, "-j", "ACCEPT"],
        capture_output=True,
    )


def _block_peer(peer_ip: str, interface_name: str = "wg0"):
    """Remove iptables ACCEPT rule for peer from interface-scoped WG_2FA chain."""
    chain = f"WG_2FA_{interface_name}"
    while True:
        result = subprocess.run(
            ["iptables", "-D", chain, "-s", peer_ip, "-j", "ACCEPT"],
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
    chain = f"WG_2FA_{interface_name}"
    # Ensure chain exists
    subprocess.run(["iptables", "-N", chain], capture_output=True)
    # Flush only this interface's chain
    subprocess.run(["iptables", "-F", chain], capture_output=True, check=True)

    # Ensure jump from FORWARD before WG_ACL
    check = subprocess.run(
        ["iptables", "-C", "FORWARD", "-i", interface_name, "-j", chain],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "FORWARD", "1", "-i", interface_name, "-j", chain],
            capture_output=True, check=True,
        )

    # Check if this interface has 2FA enabled
    iface_row = db.fetchone("SELECT require_2fa FROM wg_interfaces WHERE name = %s", (interface_name,))
    if iface_row and not iface_row.get("require_2fa", True):
        # Interface has 2FA disabled — no rules needed
        return

    # Get 2FA-required peers on this specific interface
    peers_2fa = db.fetchall(
        """SELECT p.* FROM wg_peers p
           JOIN wg_interfaces i ON p.interface_id = i.id
           WHERE p.require_2fa = TRUE AND p.enabled = TRUE AND i.require_2fa = TRUE
             AND i.name = %s""",
        (interface_name,),
    )
    if not peers_2fa:
        return

    now = datetime.utcnow().isoformat()
    active_sessions = db.fetchall("SELECT peer_ip FROM vpn_auth_sessions WHERE expires > %s", (now,))
    active_ips = {s["peer_ip"] for s in active_sessions}

    # Get VPN server IP for captive portal access
    iface = db.fetchone("SELECT address FROM wg_interfaces WHERE name = %s", (interface_name,))
    server_ip = iface["address"].split("/")[0] if iface else "172.19.1.1"

    # Check 2FA mode: 'captive' (default) or 'portal'
    tfa_mode = get_setting("vpn_2fa_mode") or "captive"

    unauth_ips = []
    for peer in peers_2fa:
        peer_ip = peer["allowed_ips"].split("/")[0]

        if peer_ip in active_ips:
            # Authenticated — ACCEPT all traffic
            subprocess.run(
                ["iptables", "-A", chain, "-s", peer_ip, "-j", "ACCEPT"],
                capture_output=True,
            )
        else:
            unauth_ips.append(peer_ip)
            # Allow traffic to VPN server IP (for captive portal / API access)
            subprocess.run(
                ["iptables", "-A", chain, "-s", peer_ip, "-d", server_ip, "-j", "ACCEPT"],
                capture_output=True,
            )
            # Allow DNS (so browser can resolve, then gets redirected)
            subprocess.run(
                ["iptables", "-A", chain, "-s", peer_ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                capture_output=True,
            )
            if tfa_mode == "captive":
                # Captive mode: allow HTTP/HTTPS outbound (will be NAT-redirected to captive portal)
                subprocess.run(
                    ["iptables", "-A", chain, "-s", peer_ip, "-p", "tcp", "--dport", "80", "-j", "ACCEPT"],
                    capture_output=True,
                )
                subprocess.run(
                    ["iptables", "-A", chain, "-s", peer_ip, "-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
                    capture_output=True,
                )
            # Portal mode: no HTTP/HTTPS ACCEPT needed — user authenticates via portal before VPN connect
            # REJECT everything else (fast fail, not timeout)
            subprocess.run(
                ["iptables", "-A", chain, "-s", peer_ip, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
                capture_output=True,
            )

    if tfa_mode == "captive":
        # NAT: redirect HTTP from unauthenticated peers to captive portal
        api_port = "8092"
        _ensure_captive_nat(server_ip, api_port, unauth_ips, interface_name)
    else:
        # Portal mode: ensure NAT chain is flushed (no DNAT redirects needed)
        nat_chain = f"WG_2FA_NAT_{interface_name}"
        subprocess.run(["iptables", "-t", "nat", "-N", nat_chain], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F", nat_chain], capture_output=True)


def _ensure_captive_nat(server_ip: str, api_port: str, unauth_ips: list[str], interface_name: str):
    """NAT redirect all HTTP from unauthenticated peers to captive portal."""
    nat_chain = f"WG_2FA_NAT_{interface_name}"
    # Ensure interface-scoped NAT chain exists in nat table
    subprocess.run(["iptables", "-t", "nat", "-N", nat_chain], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-F", nat_chain], capture_output=True)

    # Ensure jump from PREROUTING
    check = subprocess.run(
        ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", interface_name, "-j", nat_chain],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", interface_name, "-j", nat_chain],
            capture_output=True,
        )

    # For each unauthenticated peer: redirect HTTP + HTTPS to captive portal
    # EXCLUDE traffic already going to VPN server (captive portal API calls)
    for peer_ip in unauth_ips:
        subprocess.run(
            ["iptables", "-t", "nat", "-A", nat_chain, "-s", peer_ip,
             "!", "-d", server_ip, "-p", "tcp", "--dport", "80",
             "-j", "DNAT", "--to-destination", f"{server_ip}:{api_port}"],
            capture_output=True,
        )
        subprocess.run(
            ["iptables", "-t", "nat", "-A", nat_chain, "-s", peer_ip,
             "!", "-d", server_ip, "-p", "tcp", "--dport", "443",
             "-j", "DNAT", "--to-destination", f"{server_ip}:443"],
            capture_output=True,
        )

    # INPUT: allow VPN clients to reach the server
    check = subprocess.run(
        ["iptables", "-C", "INPUT", "-i", interface_name, "-d", server_ip, "-j", "ACCEPT"],
        capture_output=True,
    )
    if check.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-i", interface_name, "-d", server_ip, "-j", "ACCEPT"],
            capture_output=True,
        )


def _resolve_interface_for_ip(peer_ip: str) -> str:
    """Look up which WireGuard interface a peer IP belongs to."""
    ip = peer_ip if "/32" in peer_ip else peer_ip + "/32"
    row = db.fetchone(
        "SELECT i.name FROM wg_interfaces i JOIN wg_peers p ON p.interface_id = i.id WHERE p.allowed_ips = %s",
        (ip,),
    )
    return row["name"] if row else "wg0"


def _get_peer_endpoint(peer_ip: str, interface_name: str | None = None) -> str:
    """Get the current endpoint for a peer from wg show."""
    iface = interface_name or _resolve_interface_for_ip(peer_ip)
    try:
        result = subprocess.run(["wg", "show", iface, "dump"], capture_output=True, text=True)
        for line in result.stdout.strip().split("\n")[1:]:
            fields = line.split("\t")
            if len(fields) >= 4 and peer_ip in fields[3]:
                return fields[2] if fields[2] != "(none)" else ""
    except Exception:
        pass
    return ""


def _get_peer_handshake(peer_ip: str, interface_name: str | None = None) -> int:
    """Get latest handshake epoch for a peer from wg show."""
    iface = interface_name or _resolve_interface_for_ip(peer_ip)
    try:
        result = subprocess.run(["wg", "show", iface, "dump"], capture_output=True, text=True)
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

        # Resolve the interface this peer belongs to
        iface_name = _resolve_interface_for_ip(peer_ip)

        current_endpoint = _get_peer_endpoint(peer_ip, iface_name)
        stored_endpoint = session.get("last_endpoint", "")
        handshake = _get_peer_handshake(peer_ip, iface_name)

        should_invalidate = False
        reason = ""

        # Method 1: Endpoint changed
        # Compare only the IP part (port changes are normal for mobile/NAT)
        stored_ip = stored_endpoint.split(":")[0] if stored_endpoint else ""
        current_ip = current_endpoint.split(":")[0] if current_endpoint else ""
        if stored_ip and current_ip and stored_ip != current_ip:
            should_invalidate = True
            reason = f"endpoint IP changed: {stored_ip} -> {current_ip}"

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


def resolve_pending_preauths():
    """Match pending pre-auth sessions to connected VPN peers and open iptables."""
    pending = db.fetchall(
        "SELECT * FROM vpn_auth_sessions WHERE peer_ip = 'pending' AND expires > %s",
        (datetime.utcnow().isoformat(),),
    )
    for session in pending:
        peer = db.fetchone("SELECT * FROM wg_peers WHERE id = %s", (session["peer_id"],))
        if not peer:
            continue
        peer_ip = peer["allowed_ips"].split("/")[0]

        # Check if this peer is currently connected to WireGuard
        iface_row = db.fetchone(
            "SELECT i.name FROM wg_interfaces i WHERE i.id = %s", (peer["interface_id"],)
        )
        iface_name = iface_row["name"] if iface_row else "wg0"

        endpoint = _get_peer_endpoint(peer_ip, iface_name)
        if not endpoint:
            continue  # Peer not connected yet

        # Peer is connected! Update session with real IP and open iptables
        db.execute(
            "UPDATE vpn_auth_sessions SET peer_ip = %s, last_endpoint = %s WHERE id = %s",
            (peer_ip, endpoint, session["id"]),
        )
        _open_peer(peer_ip, iface_name)
        print(f"[2fa-preauth] Resolved pending session for peer {peer['name']} ({peer_ip})")


def cleanup_expired_sessions():
    """Remove expired sessions and update iptables."""
    now = datetime.utcnow().isoformat()
    expired = db.fetchall("SELECT peer_ip FROM vpn_auth_sessions WHERE expires <= %s", (now,))
    for session in expired:
        iface_name = _resolve_interface_for_ip(session["peer_ip"])
        _block_peer(session["peer_ip"], iface_name)
    db.execute("DELETE FROM vpn_auth_sessions WHERE expires <= %s", (now,))
    if expired:
        # Rebuild 2FA rules
        ifaces = db.fetchall("SELECT name FROM wg_interfaces")
        for iface in ifaces:
            apply_2fa_rules(iface["name"])
