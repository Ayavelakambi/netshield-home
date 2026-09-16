"""Host privileges & packet-capture capability — and Windows self-elevation.

NetShield Home's packet-level features (ARP scanning, DNS sniffing, traffic
control) need elevated privileges: Administrator on Windows (plus Npcap), or
root on Linux/macOS. This module reports exactly what the host has, detects
Npcap, and can relaunch the app elevated on Windows with a single UAC prompt
so the scanning host runs as admin and can do everything.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys

logger = logging.getLogger("netshield.privileges")


def is_elevated() -> bool:
    """True when the process has Administrator (Windows) / root (POSIX)."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
        try:  # fallback: `net session` requires admin
            out = subprocess.run(["net", "session"],
                                 capture_output=True, text=True, timeout=5)
            return out.returncode == 0
        except Exception:
            return True  # cannot tell — runtime errors will surface
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def npcap_installed() -> bool | None:
    """True/False on Windows; None on other platforms (not applicable)."""
    if os.name != "nt":
        return None
    for path in (r"C:\Windows\System32\Npcap\wpcap.dll",
                 r"C:\Windows\System32\wpcap.dll"):
        if os.path.exists(path):
            return True
    try:
        out = subprocess.run(["sc", "query", "npcap"],
                             capture_output=True, text=True, timeout=5)
        return out.returncode == 0  # service exists = driver installed
    except Exception:
        return False


def scapy_available() -> bool:
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False


def privilege_status() -> dict:
    """One dict with everything the UI needs about host capabilities."""
    elev = is_elevated()
    npcap = npcap_installed()
    scapy = scapy_available()
    full = scapy and elev and (npcap if os.name == "nt" else True)
    return {
        "os": sys.platform,
        "elevated": elev,
        "npcap": npcap,
        "scapy": scapy,
        "full_capture": full,
        "windows": os.name == "nt",
    }


def relaunch_as_admin(port: int = 5000) -> tuple[bool, str]:
    """Relaunch this app elevated via a UAC prompt (Windows only).

    The new process is started with NETSHIELD_ELEVATE_RELAUNCH=1 so run.py
    waits for the current instance to release the port instead of refusing
    to start. Returns (ok, message).
    """
    if is_elevated():
        return True, "Already running with administrator privileges."
    if os.name != "nt":
        return False, ("Self-elevation is Windows-only. On Linux/macOS start "
                       "with: sudo python run.py")

    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = os.path.join(project_root, "run.py")
    if not os.path.exists(script):  # running from a different layout
        script = os.path.abspath(sys.argv[0] if sys.argv else "run.py")
    python = sys.executable
    args = f'"{script}" --port {int(port)}'

    ps = (
        "Start-Process -FilePath '{python}' -ArgumentList '{args}' "
        "-Verb RunAs -WorkingDirectory '{cwd}'"
    ).format(
        python=python.replace("'", "''"),
        args=args.replace("'", "''"),
        cwd=os.getcwd().replace("'", "''"),
    )
    env = dict(os.environ)
    env["NETSHIELD_ELEVATE_RELAUNCH"] = "1"
    try:
        subprocess.Popen(["powershell", "-NoProfile", "-Command", ps], env=env)
        return True, ("Elevation prompt shown — approve it to restart "
                      "NetShield Home as Administrator.")
    except Exception as exc:  # pragma: no cover
        return False, f"Could not launch elevation: {exc}"
