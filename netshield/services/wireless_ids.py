"""WiFi scanning via OS tooling.

Windows: `netsh wlan show networks mode=Bssid` — one record per BSSID so
multiple APs broadcasting the same SSID stay individually visible.
Linux:   best-effort `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list`.
Others:  return a clear "unsupported on this platform" status — never crash.

Wireless IDS (de-duplicated by a stable key so the same finding does not
re-fire every scan cycle):
  * evil-twin:   same SSID observed from more than one distinct BSSID
  * open network: Open (no auth) or WEP encryption detected
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import sys

import config
from netshield.extensions import db
from netshield.models.models import WifiNetwork, utcnow

logger = logging.getLogger("netshield.wifi")

_UNSUPPORTED = {"status": "unsupported",
                "message": "WiFi scanning is unsupported on this platform. "
                           "NetShield Home scans via `netsh wlan show networks "
                           "mode=Bssid` on Windows (nmcli on Linux)."}


def wifi_scan() -> dict:
    """Scan once; upsert WifiNetwork rows by BSSID; return a status dict."""
    if os.name == "nt":
        networks, status, message = _netsh_scan()
    elif sys.platform.startswith("linux"):
        networks, status, message = _nmcli_scan()
    else:
        return _UNSUPPORTED

    if status != "ok":
        return {"status": status, "message": message, "networks": []}

    now = utcnow()
    seen = set()
    for n in networks:
        row = WifiNetwork.query.filter_by(bssid=n["bssid"]).first()
        if row is None:
            row = WifiNetwork(bssid=n["bssid"])
            db.session.add(row)
        row.ssid = n.get("ssid")
        row.channel = n.get("channel")
        row.band = n.get("band")
        row.signal_strength = n.get("signal_strength")
        row.encryption = n.get("encryption")
        row.last_seen = now
        seen.add(n["bssid"])
    db.session.commit()
    return {"status": status, "message": message, "networks": networks}


def current_networks() -> list[WifiNetwork]:
    """All observed networks from the database (one row per BSSID)."""
    return (WifiNetwork.query.order_by(WifiNetwork.band,
                                       WifiNetwork.channel).all())


def security_audit() -> list[dict]:
    """Aircrack-ng-style wireless security audit for YOUR OWN networks.

    Analyzes each observed network (encryption, band, channel, multiple APs)
    and produces a security score + plain-language hardening advice. This is
    the defensive counterpart to Wi-Fi auditing — it never touches passwords
    or handshakes; it only reads what the WiFi scan already captures.
    """
    networks = current_networks()
    by_ssid: dict[str, list[WifiNetwork]] = {}
    for n in networks:
        if n.ssid:
            by_ssid.setdefault(n.ssid, []).append(n)

    findings: list[dict] = []
    for ssid, aps in by_ssid.items():
        issues: list[str] = []
        score = 100
        encs = {ap.encryption for ap in aps}
        channels = {ap.channel for ap in aps}
        if "Open" in encs:
            issues.append("No encryption (Open) — anyone can join and read "
                          "all traffic. Enable WPA2/WPA3.")
            score -= 60
        elif "WEP" in encs:
            issues.append("WEP is broken and can be cracked in minutes. "
                          "Upgrade to WPA2/WPA3.")
            score -= 50
        elif "WPA" in encs and "WPA2" not in encs and "WPA3" not in encs:
            issues.append("Legacy WPA (TKIP) — upgrade to WPA2/WPA3.")
            score -= 20
        if "WPA3" not in encs and any(e not in ("WPA3",) for e in encs):
            if not issues:
                issues.append("WPA2 is OK, but WPA3 would resist offline "
                              "handshake cracking (PMF, SAE).")
                score -= 5
        if len(aps) > 1 and len(channels) == 1:
            issues.append(f"{len(aps)} access points share the same channel "
                          f"{next(iter(channels))} — congested; split "
                          "channels (1/6/11).")
            score -= 5
        if len(aps) > 1:
            issues.append(f"{len(aps)} APs broadcast this name — verify they "
                          "are all yours (evil-twin check).")
            score -= 10
        findings.append({
            "ssid": ssid,
            "ap_count": len(aps),
            "encryptions": sorted(encs),
            "channels": sorted(c for c in channels if c),
            "score": max(score, 0),
            "issues": issues,
            "ok": score >= 85,
        })
    findings.sort(key=lambda f: f["score"])
    return findings


def _band_for_channel(channel: int | None) -> str:
    if channel is None:
        return "?"
    return "5" if channel >= 36 else "2.4"


def _encryption_label(auth: str) -> str:
    a = (auth or "").lower()
    if "open" in a:
        return "Open"
    if "wep" in a:
        return "WEP"
    if "wpa3" in a:
        return "WPA3"
    if "wpa2" in a:
        return "WPA2"
    if "wpa" in a:
        return "WPA"
    return auth or "?"


# ---------------------------------------------------------------------------
# Windows netsh parser — one row per BSSID
# ---------------------------------------------------------------------------
def _netsh_scan():
    try:
        out = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return [], "error", f"netsh failed: {exc}"

    networks = []
    ssid = None
    bssid = None
    channel = None
    signal = None
    auth = None
    bssid_re = re.compile(r"BSSID\s*\d*\s*:\s*([0-9a-fA-F:\-]+)")
    ssid_re = re.compile(r"SSID\s*\d*\s*:\s*(.*)")
    channel_re = re.compile(r"Channel\s*:\s*(\d+)")
    signal_re = re.compile(r"Signal\s*:\s*(\d+)%")
    auth_re = re.compile(r"Authentication\s*:\s*(.*)")

    def _flush():
        if bssid:
            networks.append({
                "ssid": ssid,
                "bssid": bssid.upper().replace("-", ":"),
                "channel": channel,
                "band": _band_for_channel(channel),
                "signal_strength": signal,
                "encryption": _encryption_label(auth),
            })

    for line in out.splitlines():
        m = ssid_re.match(line.strip())
        if m:
            _flush()
            ssid, bssid, channel, signal, auth = m.group(1).strip(), None, None, None, None
            continue
        m = bssid_re.match(line.strip())
        if m:
            _flush()
            bssid = m.group(1)
            continue
        m = channel_re.search(line)
        if m and bssid:
            channel = int(m.group(1))
        m = signal_re.search(line)
        if m and bssid:
            signal = int(m.group(1))
        m = auth_re.search(line)
        if m and bssid:
            auth = m.group(1).strip()
    _flush()
    return networks, "ok", "netsh"


# ---------------------------------------------------------------------------
# Linux nmcli best-effort parser
# ---------------------------------------------------------------------------
def _nmcli_scan():
    try:
        out = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY",
             "dev", "wifi", "list"],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return [], "unsupported", (
            "WiFi scanning needs `nmcli` (NetworkManager) on Linux; "
            "`netsh` is used on Windows. Scanning is disabled here.")
    networks = []
    for line in out.splitlines():
        if not line.strip():
            continue
        # nmcli -t escapes colons as \: ; split on unescaped colons only
        fields = re.split(r"(?<!\\):", line)
        if len(fields) < 4:
            continue
        ssid, bssid, chan, signal = fields[0], fields[1], fields[2], fields[3]
        security = fields[4] if len(fields) > 4 else ""
        try:
            ch = int(chan) if chan.isdigit() else None
        except ValueError:
            ch = None
        try:
            sig = int(signal.replace("%", "")) if signal else None
        except ValueError:
            sig = None
        networks.append({
            "ssid": ssid.replace("\\:", ":"),
            "bssid": bssid.upper().replace("-", ":") if bssid else None,
            "channel": ch,
            "band": _band_for_channel(ch),
            "signal_strength": sig,
            "encryption": _encryption_label(security),
        })
    return networks, "ok", "nmcli"


# ---------------------------------------------------------------------------
# Wireless IDS analysis (evil twin / insecure network)
# ---------------------------------------------------------------------------
def analyze() -> list[dict]:
    """Findings from the current network table.

    Each finding carries a stable key (type + SSID/BSSIDs + encryption) so
    the caller can de-duplicate against existing active alerts — the same
    finding never re-fires every scan cycle.
    """
    networks = current_networks()
    findings: list[dict] = []

    by_ssid: dict[str, list[WifiNetwork]] = {}
    for n in networks:
        if n.ssid:
            by_ssid.setdefault(n.ssid, []).append(n)

    for ssid, aps in by_ssid.items():
        bssids = sorted({ap.bssid for ap in aps})
        if len(bssids) > 1:
            findings.append({
                "key": f"evil_twin:{ssid}:{','.join(bssids)}",
                "type": "evil_twin",
                "severity": "high",
                "message": (f"Possible evil-twin: SSID '{ssid}' is broadcast by "
                            f"{len(bssids)} different access points "
                            f"({', '.join(bssids)}). A lookalike AP may be "
                            f"intercepting traffic."),
            })

    for n in networks:
        if n.encryption in ("Open", "WEP"):
            findings.append({
                "key": f"open_network:{n.bssid}:{n.encryption}",
                "type": "open_network",
                "severity": "medium",
                "message": (f"Insecure network '{n.ssid or '(hidden)'}' "
                            f"({n.bssid}, {n.channel}) uses {n.encryption} — "
                            f"traffic is not encrypted and can be intercepted."),
            })
    return findings


def rf_recommendations() -> dict:
    """Delegate to the rf_optimizer (kept as a separate service module)."""
    from netshield.services.rf_optimizer import recommend
    return recommend(current_networks())
