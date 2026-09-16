"""OUI vendor lookup + private/randomised MAC detection.

Ships a compact built-in table of common home-LAN prefixes. If a larger
``data/oui.json`` exists (e.g. the full IEEE OUI database exported as
{"AA:BB:CC": "Vendor Name", ...}), it is loaded and takes precedence.
MACs with the locally-administered bit set are flagged as randomised/private
so the UI shows a distinct label instead of a wrong vendor.
"""
from __future__ import annotations

import json
import os
import re

import config

# ---------------------------------------------------------------------------
# Compact built-in table of common prefixes (OUI = first 3 bytes of the MAC).
# ---------------------------------------------------------------------------
BUILTIN_OUI = {
    "00:1B:63": "Apple", "3C:22:FB": "Apple", "AC:BC:32": "Apple",
    "F0:18:98": "Apple", "F4:0F:24": "Apple", "A8:5C:2C": "Apple",
    "F0:D1:A9": "Apple", "A4:83:E7": "Apple", "D0:E1:40": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "3C:5A:B4": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "D8:BB:C1": "Dell", "F8:BC:12": "Dell", "14:58:D0": "Intel",
    "00:1F:29": "Intel", "00:1A:8C": "HP", "3C:D9:2B": "HP",
    "CC:2D:8C": "Huawei", "A4:9B:CD": "Huawei", "FC:48:EF": "Huawei",
    "18:59:36": "Cisco", "64:16:66": "Cisco", "00:26:AB": "Cisco-Linksys",
    "00:1E:58": "Cisco-Linksys", "C0:56:27": "TP-Link", "50:C7:BF": "TP-Link",
    "F4:F2:6D": "TP-Link", "D4:6E:0C": "TP-Link", "EC:08:6B": "TP-Link",
    "74:DA:38": "TP-Link", "58:6D:8F": "TP-Link", "DC:FE:18": "TP-Link",
    "90:2B:34": "Asus", "00:1B:FC": "Asus", "B0:C5:54": "Asus",
    "94:D9:B3": "Xiaomi", "78:11:DC": "Xiaomi", "A0:CE:C8": "Xiaomi",
    "8C:DE:F9": "Samsung", "5C:0A:5B": "Samsung", "3C:BD:3E": "Samsung",
    "9C:D2:1B": "Samsung", "FC:03:9F": "Samsung", "10:68:3F": "Samsung",
    "F4:5C:89": "Sony", "AC:7A:4D": "Sony", "00:1F:90": "Sony",
    "C4:6E:1F": "Sony", "04:C5:A4": "LG", "A0:63:91": "Google",
    "18:65:90": "Google", "94:EB:2C": "Google", "D8:6C:63": "Google",
    "F4:F5:D8": "Google", "94:DB:C9": "Google", "74:75:48": "Amazon",
    "F0:27:2D": "Amazon", "68:37:E9": "Amazon", "AC:63:BE": "Amazon",
    "FC:65:DE": "Amazon", "DC:44:6D": "Roku", "04:26:65": "Roku",
    "6C:56:97": "Netgear", "20:4E:7F": "Netgear", "C0:3F:0E": "Netgear",
    "A0:40:A0": "Netgear", "28:C6:8E": "Netgear", "F4:6D:04": "Netgear",
    "B0:39:56": "Netgear", "00:24:B2": "Netgear", "10:DA:43": "Belkin",
    "94:44:52": "Belkin", "E8:94:F6": "Belkin", "00:22:48": "Motorola",
    "00:25:9E": "Motorola", "08:00:0E": "IBM", "3C:97:0E": "IBM",
    "A4:8C:DB": "HTC", "00:9A:CD": "HTC", "D0:23:DB": "OnePlus",
    "00:17:88": "Nokia", "04:4B:ED": "Nokia", "98:03:9B": "Nokia",
    "BC:6A:29": "Nest", "18:B4:30": "Nest", "5C:8A:FD": "Ubiquiti",
    "24:A4:3C": "Ubiquiti", "04:18:D6": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "78:8A:20": "Ubiquiti", "48:8F:5A": "Ubiquiti", "C4:12:F5": "Zyxel",
    "54:25:EA": "Zyxel", "00:1C:C4": "Zyxel", "00:1A:2B": "Garmin",
    "00:1E:52": "Sonos", "B8:E9:37": "Sonos", "D0:6F:4A": "Sonos",
    "CC:F3:A5": "Sonos", "C4:8E:8F": "Sonos", "C8:5B:76": "TP-Link",
    "D4:3A:2C": "Espressif", "24:0A:C4": "Espressif", "18:FE:34": "Espressif",
    "5C:CF:7F": "Espressif", "60:01:94": "Espressif", "24:6F:28": "Espressif",
    "30:AE:A4": "Espressif", "A4:CF:12": "Espressif", "EC:FA:BC": "Espressif",
    "F4:CF:A2": "Espressif", "00:1F:3B": "QNAP", "00:24:8C": "Synology",
    "00:11:32": "Synology", "90:09:D0": "Synology", "00:13:33": "Hikvision",
    "44:19:B6": "Hikvision", "BE:5E:0C": "Ring", "38:83:45": "Ring",
    "AC:CC:8E": "Ring", "E4:FA:ED": "Ring", "64:16:F0": "D-Link",
    "00:1B:11": "D-Link", "1C:7E:C5": "D-Link", "14:D6:4D": "D-Link",
    "C8:3A:35": "D-Link", "28:10:7B": "D-Link", "F8:E4:E3": "D-Link",
    "50:9A:4C": "D-Link", "00:1D:7E": "Cisco", "3C:CE:73": "Cisco",
    "00:23:04": "Cisco", "F8:7B:20": "Cisco", "54:BF:64": "Sierra Wireless",
}

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})")

_extra_oui: dict[str, str] | None = None


def _load_extra_oui() -> dict[str, str]:
    """Load data/oui.json if present (larger table, takes precedence)."""
    global _extra_oui
    if _extra_oui is None:
        _extra_oui = {}
        if os.path.exists(config.OUI_PATH):
            try:
                with open(config.OUI_PATH, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    _extra_oui = {str(k).upper(): str(v) for k, v in data.items()}
            except (OSError, ValueError):
                _extra_oui = {}
    return _extra_oui


def normalize_mac(mac: str) -> str:
    """Normalise to uppercase AA:BB:CC:DD:EE:FF; returns '' if invalid.

    Accepts every format scanners produce: "aa:bb:cc:dd:ee:ff" (Scapy,
    /proc/net/arp, ip neigh), "3C-22-FB-12-34-01" (Windows arp -a),
    "aabb.ccdd.eeff" (Cisco) and bare "AABBCCDDEEFF". Separators are
    stripped first, then the 12 hex digits are regrouped into octets.
    """
    if not mac:
        return ""
    clean = mac.strip().upper().replace("-", "").replace(":", "").replace(".", "")
    if len(clean) != 12:
        return ""
    try:
        int(clean, 16)  # must be valid hex
    except ValueError:
        return ""
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def lookup_vendor(mac: str) -> str | None:
    """Vendor from OUI prefix (extra table first, then the built-in table)."""
    mac = normalize_mac(mac)
    if not mac:
        return None
    prefix = mac[:8]  # "AA:BB:CC"
    extra = _load_extra_oui()
    vendor = extra.get(prefix) or BUILTIN_OUI.get(prefix)
    if vendor:
        return vendor
    # a couple of generic OUI families as a last resort
    if mac.startswith("02:") or mac.startswith("06:"):
        return None  # randomised — do NOT guess
    return None


def is_private_mac(mac: str) -> bool:
    """True when the locally-administered bit is set (randomised/private MAC)."""
    mac = normalize_mac(mac)
    if not mac:
        return False
    first_octet = int(mac[:2], 16)
    return bool(first_octet & 0x02)  # bit 1 of the first octet
