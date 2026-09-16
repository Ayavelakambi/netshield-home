"""Defensive packet guards — the protective counterparts to common LAN
attacks. This project deliberately contains NO attack/cracking tooling
(no WPA handshake capture, no password brute-forcing). These guards WATCH
for attacks instead:

  * ARP-spoofing detection — flags anyone (other than this host, which is
    the app's own control sessions) answering ARP requests for the gateway
    with a different MAC. That is the exact technique NetCut-style tools
    use to intercept traffic.
  * Deauth-attack detection — flags a device flooding the air with 802.11
    deauthentication frames (the way someone knocks devices off Wi-Fi).
    Needs an interface that can capture 802.11 frames (monitor mode on
    Linux); on setups that can't, the guard retries quietly and the rest
    of the app is unaffected.

Both fire alerts + activity-log entries, de-duplicated per attacker MAC.
"""
from __future__ import annotations

import logging
import threading
import time

import config
from netshield.services import mac_intel
from netshield.services.network_scanner import detect_gateway_mac, host_mac

logger = logging.getLogger("netshield.guard")


def start_arp_guard(app) -> None:
    """Watch ARP replies claiming to be the gateway.

    PACKET-LEVEL NOTE: passive listener only — reads ARP op=2 replies,
    never injects anything. Our own control sessions answer for the
    gateway with OUR mac, which is explicitly skipped.
    """

    def loop():
        gw = config.gateway_ip()
        our = mac_intel.normalize_mac(host_mac() or "")
        real_gw = None
        last_alert: dict[str, float] = {}

        def handler(pkt):
            nonlocal real_gw
            try:
                if not pkt.haslayer("ARP") or pkt.op != 2:
                    return
                if str(pkt.psrc) != gw:
                    return  # only gateway impersonation matters
                hwsrc = mac_intel.normalize_mac(str(pkt.hwsrc))
                if not hwsrc or (our and hwsrc == our):
                    return  # our own poison / invalid
                if real_gw is None:
                    real_gw = mac_intel.normalize_mac(
                        detect_gateway_mac(gw) or "")
                if real_gw and hwsrc == real_gw:
                    return  # the genuine router answering
                now = time.time()
                if last_alert.get(hwsrc) and now - last_alert[hwsrc] < 600:
                    return  # already alerted for this attacker recently
                last_alert[hwsrc] = now
                with app.app_context():
                    from netshield.audit import log_activity
                    from netshield.services.alerts_dispatch import create_alert
                    vendor = mac_intel.lookup_vendor(hwsrc)
                    msg = (f"ARP spoofing detected: the gateway {gw} is being "
                           f"impersonated by {hwsrc}"
                           + (f" ({vendor})" if vendor else "")
                           + " — another device is claiming to be your "
                             "router; traffic may be intercepted.")
                    create_alert("arp_spoof", msg, "high")
                    log_activity("system", f"ARP spoofing detected from {hwsrc}")
            except Exception:
                pass

        while True:
            try:
                from scapy.all import sniff
                sniff(store=False, prn=handler, filter="arp and arp op 2",
                      timeout=1)
            except Exception as exc:
                logger.debug("arp guard unavailable (%s) — retrying in 60s",
                             exc)
                time.sleep(60)

    threading.Thread(target=loop, daemon=True, name="arp-guard").start()


def start_deauth_guard(app) -> None:
    """Watch for 802.11 deauthentication floods (Wi-Fi knock-off attacks).

    PACKET-LEVEL NOTE: passive listener only. Requires a capture setup
    that sees 802.11 management frames (monitor mode on Linux; Npcap on
    Windows usually can't) — the guard retries quietly otherwise.
    """

    def loop():
        counts: dict[str, list[float]] = {}
        alerted: dict[str, float] = {}

        def handler(pkt):
            try:
                from scapy.all import Dot11
                if not pkt.haslayer(Dot11):
                    return
                if pkt.type != 0 or pkt.subtype != 12:  # mgmt / deauth
                    return
                src = (pkt.addr2 or "").upper().replace("-", ":")
                if not src or src == "FF:FF:FF:FF:FF:FF":
                    return
                now = time.time()
                q = counts.setdefault(src, [])
                q.append(now)
                counts[src] = [t for t in q if now - t < 60]
                if len(counts[src]) >= 20 and \
                        now - alerted.get(src, 0) > 600:
                    alerted[src] = now
                    with app.app_context():
                        from netshield.audit import log_activity
                        from netshield.services.alerts_dispatch import create_alert
                        n = len(counts[src])
                        msg = (f"Possible Wi-Fi deauth attack: {src} sent "
                               f"{n} deauthentication frames in 60s — "
                               "devices are being knocked off the network.")
                        create_alert("deauth_attack", msg, "high")
                        log_activity("system",
                                     f"deauth flood detected from {src}")
            except Exception:
                pass

        while True:
            try:
                from scapy.all import sniff
                sniff(store=False, prn=handler,
                      filter="wlan type mgt subtype deauth", timeout=1)
            except Exception as exc:
                logger.debug("deauth guard unavailable (%s) — retrying in "
                             "60s", exc)
                time.sleep(60)

    threading.Thread(target=loop, daemon=True, name="deauth-guard").start()
