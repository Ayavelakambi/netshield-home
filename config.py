"""NetShield Home — central configuration.

Responsibilities:
  * detect the local subnet (assumed /24 home LAN, overridable via env),
  * detect the gateway IP (never a valid control target),
  * own the persistent secret key (generated ONCE and stored in data/secret_key
    so session cookies survive restarts — regenerating it every restart would
    invalidate every session),
  * define the interval constants used by the background services.
"""
from __future__ import annotations

import ipaddress
import os
import secrets
import socket
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
BLOCKLIST_DIR = os.path.join(DATA_DIR, "blocklist")
DB_PATH = os.path.join(DATA_DIR, "netshield.db")
SECRET_KEY_FILE = os.path.join(DATA_DIR, "secret_key")
OUI_PATH = os.path.join(DATA_DIR, "oui.json")
LOG_FILE = os.path.join(DATA_DIR, "netshield.log")

for _d in (DATA_DIR, BLOCKLIST_DIR):
    os.makedirs(_d, exist_ok=True)

# ---------------------------------------------------------------------------
# Interval constants (seconds)
# ---------------------------------------------------------------------------
DEVICE_SCAN_INTERVAL = 60              # device poller cadence
HISTORY_INTERVAL = 60                  # bandwidth sampling cadence
SCHEDULER_INTERVAL = 60                # schedule-rule ("bedtime") evaluation
BLOCKLIST_REFRESH_INTERVAL = 24 * 3600 # daily StevenBlack blocklist refresh
RETENTION_PURGE_INTERVAL = 24 * 3600   # history retention purger cadence
ARP_REPOISON_INTERVAL = 3              # ARP re-poisoning interval per session
PORT_SCAN_TIMEOUT = 0.8                # per-port connect timeout (seconds)
PORT_SCAN_WORKERS = 32                 # thread pool size for port scans

DEFAULT_SCAN_INTERVAL = 60             # device poller interval (setting)
DEFAULT_RETENTION_DAYS = 90            # history retention (setting)
DEFAULT_DATA_THRESHOLD_MB = 0          # per-device daily data alert threshold; 0 = off


def _load_or_create_secret_key() -> str:
    """Persistent secret key — created once, reused forever."""
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as fh:
            key = fh.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w", encoding="utf-8") as fh:
        fh.write(key)
    try:
        os.chmod(SECRET_KEY_FILE, 0o600)
    except OSError:
        pass
    return key


SECRET_KEY = _load_or_create_secret_key()


def detect_host_ip() -> str:
    """Local interface IP via the UDP connect trick (no packets leave the host)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))  # connect() never sends data for UDP
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "0.0.0.0":
            return ip
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def current_network() -> ipaddress.IPv4Network:
    """The local network object.

    Priority: NETSHIELD_SUBNET override → the actual interface subnet
    (ip+netmask from Scapy's interface table, so non-/24 home LANs and
    any router's subnet are handled) → host-IP /24 fallback.
    """
    override = os.environ.get("NETSHIELD_SUBNET", "").strip()
    if override:
        try:
            return ipaddress.ip_network(override, strict=False)
        except ValueError:
            pass
    # try the real interface subnet (handles any router's subnet, not just /24)
    try:
        from scapy.all import conf
        host = detect_host_ip()
        candidates = []
        for i in conf.ifaces.values():
            ip = getattr(i, "ip", None) or ""
            mask = getattr(i, "netmask", None)
            if not ip or not mask or ip.startswith("127.") or ip == "0.0.0.0":
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except ValueError:
                continue
            if not net.is_private or net.prefixlen < 16:
                continue
            candidates.append(net)
            if ip == host:
                return net  # exact match on the detected host IP
        if candidates:
            return candidates[0]
    except Exception:
        pass
    host = detect_host_ip()
    if host.startswith("127."):
        return ipaddress.ip_network("192.168.1.0/24")
    return ipaddress.ip_network(f"{host}/24", strict=False)


_resolved_gateway: str | None = None


def set_resolved_gateway(ip: str) -> None:
    """Pin the gateway IP after LAN detection (called by the scanner).

    The safety gate and traffic control read gateway_ip(), so pinning the
    REAL router (WiFi or LAN) here means it can never be scanned, cut or
    throttled — even when the OS default route points at a VPN.
    """
    global _resolved_gateway
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return
    if addr.is_private and not addr.is_multicast:
        _resolved_gateway = str(addr)


def gateway_ip() -> str:
    """Gateway IP: resolved by detection first, then OS routing tables."""
    if _resolved_gateway:
        return _resolved_gateway
    override = os.environ.get("NETSHIELD_GATEWAY", "").strip()
    if override:
        return override
    try:  # Linux / macOS
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    try:  # Windows: `route print -4`, default route line:
        #   0.0.0.0   0.0.0.0   <gateway>   <iface>   <metric>
        out = subprocess.run(
            ["route", "print", "-4"], capture_output=True, text=True,
            timeout=5,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and \
                    parts[1] == "0.0.0.0" and "." in parts[2]:
                return parts[2]
    except Exception:
        pass
    try:  # generic fallback
        out = subprocess.run(
            ["route", "-n"], capture_output=True, text=True, timeout=3,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) > 2 and parts[0] == "0.0.0.0" and "." in parts[1]:
                return parts[1]
    except Exception:
        pass
    net = current_network()
    hosts = list(net.hosts())
    return str(hosts[1] if len(hosts) > 1 else hosts[0])
