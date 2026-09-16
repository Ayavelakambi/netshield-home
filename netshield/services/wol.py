"""Wake-on-LAN — send a magic packet to wake a sleeping device (PC, NAS…).

Magic packet: 6x 0xFF followed by the target MAC repeated 16 times, sent as
a UDP broadcast to port 9 (and 7) on the LAN. PACKET-LEVEL NOTE: this is an
admin convenience — it only WAKES a device that already has WoL enabled in
its firmware/OS; it cannot power on a device that lacks WoL support.
"""
from __future__ import annotations

import socket

from netshield.services import mac_intel


def wake_on_lan(mac: str, broadcast_ip: str | None = None) -> bool:
    """Send the WoL magic packet for a MAC. Returns True on success."""
    mac = mac_intel.normalize_mac(mac)
    if not mac:
        return False
    mac_bytes = bytes.fromhex(mac.replace(":", ""))
    payload = b"\xff" * 6 + mac_bytes * 16
    ok = False
    for port in (9, 7):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(1)
            s.sendto(payload, (broadcast_ip or "255.255.255.255", port))
            s.close()
            ok = True
        except OSError:
            continue
    return ok
