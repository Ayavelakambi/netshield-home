"""Unified per-device traffic-control sessions (ARP spoof + software relay).

ONE session per targeted device that can simultaneously:
  * CUT       — ARP-spoof both directions and drop everything (no forwarding),
  * THROTTLE  — ARP-spoof and forward through a token-bucket rate limiter,
  * CATEGORY-BLOCK — drop (and black-hole respond to) DNS queries for blocked
                categories / allowlist enforcement,
  * MONITOR   — "full DNS capture": ARP-spoof ALL devices and relay their
                traffic transparently while logging every DNS query they
                make into the history pipeline. This is how per-device
                domain history is captured for every device on the network
                (passive sniffing only sees traffic that happens to cross
                this host's interface).

Every public entry point validates the target through netshield.safety
(inside the local /24, not the gateway, not this host) BEFORE touching the
wire. If Scapy or the required privileges are unavailable, sessions raise
TrafficControlUnavailable and the UI shows a clear error + degraded banner.

Effectiveness: each session reports whether it is actually seeing the
target's traffic (pkts_seen > 0 after the warm-up window). A session that
is not seeing packets is surfaced as "ineffective" in the UI with hints —
no more silent no-ops.

--------------------------------------------------------------------------
PACKET-LEVEL AUDIT TRAIL (read this before reviewing the code)
--------------------------------------------------------------------------
Poisoning (per session, re-sent every ARP_REPOISON_INTERVAL seconds):
  1. to the TARGET:  "gateway-IP is at OUR-mac"
     -> the target sends all its Internet-bound frames to us.
  2. to the GATEWAY: "target-IP is at OUR-mac"
     -> the gateway sends the target's return traffic to us.
Relay (only when NOT in cut mode):
  3. sniff frames to/from the target IP,
  4. rewrite only the Ethernet destination (we are the poisoned next hop),
     leaving IP/TCP/UDP payloads untouched (checksums are end-to-end),
  5. DNS queries (UDP 53, client side): ALWAYS record the queried domain
     into the history pipeline (this is the captured "search history"),
     then drop/black-hole them if they match a blocked category or fail
     the allowlist,
  6. pass them through the token bucket when throttling, and drop them when
     cutting,
Restore:
  7. on stop, send correct ARP announcements in both directions a few times
     so the target and gateway immediately relearn the real MACs. Also
     registered via atexit so a crashed/stopped app heals the network.
--------------------------------------------------------------------------
NOTE: IPv6 (NDP) is not intercepted — a device with working IPv6 could
bypass cut/block rules. This tool operates on the IPv4 LAN as specified.
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time

import config
from netshield.safety import SafetyViolation, assert_safe_target
from netshield.services import dns_categories, history, mac_intel
from netshield.services.hostname_resolver import (extract_query_name,
                                                  parse_dns_response)

logger = logging.getLogger("netshield.traffic")

# Known encrypted-DNS endpoints (DoH over 443, DoT over 853, DoH3/QUIC over
# UDP 443). When ANY blocking is active for a device, connections to these
# are dropped so the device CANNOT bypass the block via encrypted DNS — it
# is forced back to plain DNS, which the relay sees, logs and filters.
DOH_SERVER_IPS = {
    "8.8.8.8", "8.8.4.4",              # Google
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220",# OpenDNS
    "76.76.2.0", "76.76.10.0",         # NextDNS
    "185.228.168.9", "185.228.169.9",  # CleanBrowsing
}

RESOLVE_INTERVAL = 60        # seconds between eager blocked-domain re-resolves
EAGER_RESOLVE_LIMIT = 500    # max domains eagerly resolved per cycle

# DoH/DoT hostnames (SNI) — when ANY blocking is active, TLS connections to
# these are dropped even if the resolver IP is custom/unknown. This closes
# the "custom encrypted-DNS server" bypass.
DOH_SNI_HOSTS = {
    "dns.google", "dns.google.com", "cloudflare-dns.com",
    "one.one.one.one", "dns.quad9.net", "resolver.opendns.com",
    "doh.opendns.com", "doh.nextdns.io", "dns.nextdns.io",
    "family.adguard-dns.com", "dns.adguard.com", "doh.cleanbrowsing.org",
    "dns.mullvad.net", "doh.mullvad.net",
}


class TrafficControlUnavailable(Exception):
    """Raised when packet capture / spoofing cannot operate here."""


def _scapy():
    try:
        from scapy.all import (ARP, Ether, IP, Raw, TCP, UDP, conf,
                               get_if_hwaddr, send, sendp, sniff)
        return (ARP, Ether, IP, Raw, TCP, UDP, conf, get_if_hwaddr, send,
                sendp, sniff)
    except ImportError as exc:
        raise TrafficControlUnavailable(
            "Scapy is not installed — traffic control (cut/throttle/block) "
            "is unavailable.") from exc


def _require_capability() -> None:
    from netshield.services.network_scanner import packet_capability_available
    if not packet_capability_available():
        raise TrafficControlUnavailable(
            "Packet capture unavailable (install Npcap on Windows and run as "
            "Administrator, or run as root on Linux/macOS) — ARP-based "
            "cut/throttle and DNS blocking are disabled.")


def _lan_iface():
    """The interface that routes to the gateway (where all targets live).

    On multi-adapter hosts Scapy's default interface is frequently the
    wrong one; poisoning/relaying must go out the LAN adapter or nothing
    is seen or spoofed.
    """
    try:
        from netshield.services.network_scanner import lan_interface
        return lan_interface()
    except Exception:
        return None


def _resolve_mac(ip: str, iface=None) -> str | None:
    """Resolve a MAC for an IP: Scapy ARP, OS table, then ping + re-read."""
    try:
        from scapy.all import getmacbyip
        mac = getmacbyip(ip)
        if mac:
            norm = mac_intel.normalize_mac(mac)
            if norm:
                return norm
    except Exception:
        pass
    try:
        from netshield.services.network_scanner import read_arp_table
        raw = read_arp_table().get(ip)
        if raw:
            norm = mac_intel.normalize_mac(raw)
            if norm:
                return norm
    except Exception:
        pass
    try:  # wake the gateway so it answers ARP, then re-read the table
        from netshield.services.network_scanner import ping_host, read_arp_table
        ping_host(ip)
        time.sleep(0.5)
        raw = read_arp_table().get(ip)
        if raw:
            norm = mac_intel.normalize_mac(raw)
            if norm:
                return norm
    except Exception:
        pass
    return None


class _TokenBucket:
    """Simple token bucket used to rate-limit forwarded bytes."""

    def __init__(self, kbps: int | None):
        self.rate = (kbps or 0) * 1024 / 8.0  # bytes per second
        self.capacity = max(self.rate * 2, 4096)
        self.tokens = self.capacity
        self.updated = time.monotonic()

    def allow(self, nbytes: int) -> bool:
        if self.rate <= 0:
            return True
        now = time.monotonic()
        self.tokens = min(self.capacity,
                          self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= nbytes:
            self.tokens -= nbytes
            return True
        return False


class DeviceSession:
    """One ARP-spoof + relay session bound to one target device (by MAC)."""

    def __init__(self, device_mac: str, target_ip: str, monitor: bool = False):
        # HARD SAFETY GATE — single shared enforcement point (safety.py).
        assert_safe_target(target_ip)
        self.device_mac = mac_intel.normalize_mac(device_mac) or device_mac
        self.target_ip = target_ip
        self.target_mac = self.device_mac
        self.gateway_ip = config.gateway_ip()
        self.gateway_mac: str | None = None
        self.iface = _lan_iface()          # explicit LAN interface
        self.monitor = monitor             # full DNS-capture relay

        self.cut = False
        self.speed_limit_kbps: int | None = None
        self.blocked_domains: set[str] = set()   # base domains / "=host" rules
        self.dns_allowlist: set[str] | None = None  # None = no allowlist mode
        # IPs that host blocked domains, learned from DNS — connections to
        # these are dropped at the IP layer so cached DNS / DoH / already
        # open streams cannot bypass the block
        self.blocked_ips: set[str] = set()
        # top servers contacted by the target (dest ip:port -> count) and
        # (server ip:port -> count) for responses — live "who is this device
        # talking to" data, capped so memory stays tiny
        self.top_servers: dict[str, int] = {}
        self._top_lock = threading.Lock()
        self._sni_blocked = 0
        # Wireshark-style packet ring buffer (last N captured packets)
        self.packet_log: list[dict] = []
        self._packet_lock = threading.Lock()
        # protocol counters for the breakdown panel
        self.proto_counts: dict[str, int] = {}

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._bucket = _TokenBucket(None)
        self._bypass_domains: set[str] = set()
        self._bypass_resolver: str = "1.1.1.1"
        # eager resolver: resolves blocked domains' IPs in the background so
        # cached-DNS access is cut even before the device queries again
        self._resolver_thread: threading.Thread | None = None
        self._resolver_stop: threading.Event | None = None
        # DNS-bypass cache: domain -> (ipv4 list, expiry) for domains the
        # relay answers itself via a public resolver (router-blocked domains)
        self._public_cache: dict[str, tuple[list[str], float]] = {}
        self.stats = {
            "pkts_seen": 0, "pkts_forwarded": 0, "pkts_dropped": 0,
            "dns_blocked": 0, "dns_logged": 0, "ip_blocked": 0,
            "doh_blocked": 0, "sni_blocked": 0, "dns_bypassed": 0,
            "quic_blocked": 0, "started_at": None,
        }

    # ------------------------------------------------------------------
    def configure(self, *, cut: bool, kbps: int | None,
                  blocked_domains: set[str],
                  dns_allowlist: set[str] | None,
                  monitor: bool = False) -> bool:
        """Update session parameters. Returns True when something changed."""
        with self._lock:
            cfg = (cut, kbps, frozenset(blocked_domains or set()),
                   frozenset(dns_allowlist or set()) if dns_allowlist else None,
                   monitor)
            cur = (self.cut, self.speed_limit_kbps,
                   frozenset(self.blocked_domains),
                   frozenset(self.dns_allowlist) if self.dns_allowlist else None,
                   self.monitor)
            if cfg == cur:
                return False
            self.cut = cut
            self.speed_limit_kbps = kbps
            self.blocked_domains = set(blocked_domains or set())
            self.dns_allowlist = (set(dns_allowlist) if dns_allowlist else None)
            self.monitor = monitor
            self._bucket = _TokenBucket(kbps)
            # cache the DNS-bypass list + resolver here (called from routes/
            # scheduler which hold an app context) so the relay thread never
            # touches the DB
            try:
                from netshield.models.models import Setting as _S3
                self._bypass_domains = set(
                    _S3.get("global_dns_bypass_domains", []) or [])
                self._bypass_resolver = str(
                    _S3.get("dns_bypass_resolver", "1.1.1.1"))
            except Exception:
                pass
            # blocking removed entirely -> forget learned IPs so the device's
            # normal traffic flows again immediately
            if not self.blocked_domains and self.dns_allowlist is None:
                self.blocked_ips.clear()
            # keep the eager resolver in step with the current block list
            if self.blocked_domains and self.dns_allowlist is None:
                self._restart_resolver()
            else:
                self._stop_resolver()
            return True

    # ------------------------------------------------------------------
    def start(self) -> None:
        """Begin poisoning + relay threads (idempotent).

        A session is "running" when its threads exist and _stop is NOT set.
        A fresh session has no threads, so it MUST start — the old guard
        (`if not self._stop.is_set(): return`) returned immediately for new
        sessions, so cut/throttle/monitor never actually ran. That is fixed
        here: we only skip when threads are already alive.
        """
        if self._threads and not self._stop.is_set():
            return  # already running
        _require_capability()
        # refresh the cached DNS-bypass list/resolver (start() always runs
        # in the app-context flow via apply())
        try:
            from netshield.models.models import Setting as _S4
            self._bypass_domains = set(
                _S4.get("global_dns_bypass_domains", []) or [])
            self._bypass_resolver = str(_S4.get("dns_bypass_resolver",
                                                "1.1.1.1"))
        except Exception:
            pass
        ARP, Ether, IP, Raw, TCP, UDP, conf, get_if_hwaddr, send, sendp, \
            sniff = _scapy()

        self.gateway_mac = _resolve_mac(self.gateway_ip, self.iface)
        if self.gateway_mac:
            self.gateway_mac = mac_intel.normalize_mac(self.gateway_mac)
        if not self.gateway_mac:
            raise TrafficControlUnavailable(
                f"Could not resolve the gateway MAC for {self.gateway_ip}. "
                "Traffic control cannot be applied — verify the gateway is "
                "reachable (ping it) and that you are running as "
                "Administrator/root.")

        # our MAC on the LAN interface — via Scapy's ifaces table (works on
        # Windows where get_if_hwaddr fails with the raw NPF path)
        try:
            from netshield.services.network_scanner import host_mac
            self.our_mac = host_mac(self.iface)
        except Exception:
            self.our_mac = None
        if not self.our_mac:
            raise TrafficControlUnavailable(
                "Could not determine this host's MAC address on the active "
                f"interface ({self.iface or 'default'}) — traffic control "
                "cannot be applied.")
        self.our_mac_upper = (self.our_mac or "").upper()

        self._stop.clear()
        self.stats["started_at"] = time.time()
        self.stats.update(pkts_seen=0, pkts_forwarded=0, pkts_dropped=0,
                          dns_blocked=0, dns_logged=0, ip_blocked=0,
                          doh_blocked=0, sni_blocked=0, dns_bypassed=0,
                          quic_blocked=0, relay_bytes_up=0,
                          relay_bytes_down=0)

        poison = threading.Thread(target=self._poison_loop,
                                  args=(ARP, Ether, sendp),
                                  daemon=True, name=f"poison-{self.device_mac}")
        relay = threading.Thread(target=self._relay_loop,
                                 args=(ARP, Ether, IP, Raw, TCP, UDP, send,
                                       sendp, sniff),
                                 daemon=True, name=f"relay-{self.device_mac}")
        self._threads = [poison, relay]
        poison.start()
        relay.start()
        # eager IP learning: resolve the blocked domains NOW (and every
        # RESOLVE_INTERVAL) so cached-DNS connections are cut immediately,
        # without waiting for the device to issue a fresh lookup
        if self.blocked_domains and self.dns_allowlist is None:
            self._restart_resolver()

    # ------------------------------------------------------------------
    def _poison_loop(self, ARP, Ether, sendp) -> None:
        """Re-send the two spoofed ARP replies every few seconds so the
        poisoned entries never age out (ARP cache entries expire). Sent out
        the LAN interface explicitly, with a fallback to Scapy's default
        interface if the resolved name is rejected."""
        iface = self.iface
        while not self._stop.is_set():
            try:
                # target <- "gateway is at our MAC"
                sendp(Ether(dst=self.target_mac) /
                      ARP(psrc=self.gateway_ip, pdst=self.target_ip,
                          hwsrc=self.our_mac, op=2), verbose=0, iface=iface)
                # gateway <- "target is at our MAC"
                sendp(Ether(dst=self.gateway_mac) /
                      ARP(psrc=self.target_ip, pdst=self.gateway_ip,
                          hwsrc=self.our_mac, op=2), verbose=0, iface=iface)
            except Exception as exc:
                if iface:
                    logger.warning("ARP poison send failed on %s (%s) — "
                                   "retrying on default interface",
                                   iface, exc)
                    iface = None
                else:
                    logger.warning("ARP poison send failed for %s: %s",
                                   self.target_ip, exc)
            self._stop.wait(config.ARP_REPOISON_INTERVAL)

    # ------------------------------------------------------------------
    def _relay_loop(self, ARP, Ether, IP, Raw, TCP, UDP, send, sendp,
                    sniff) -> None:
        """Sniff frames to/from the target and forward (or drop) them."""
        iface = self.iface
        our_mac = self.our_mac_upper
        # exclude frames WE emit (incl. forwarded copies) so nothing we
        # send is ever re-captured and re-relayed
        bpf = f"host {self.target_ip}"
        if our_mac:
            bpf += f" and not ether src {our_mac}"

        def _handler(pkt):
            self.stats["pkts_seen"] += 1
            try:
                if not pkt.haslayer(Ether):
                    return
                # quick protocol classification for the packet log
                try:
                    if pkt.haslayer("DNS"):
                        proto = "DNS"
                        qd = pkt.getlayer("DNS").qd
                        info = qd.qname.decode(errors="ignore")[:60] \
                            if qd and qd.qname else ""
                    elif pkt.haslayer("TCP"):
                        proto = "TCP"
                        info = f"{pkt[IP].sport}->{pkt[IP].dport} " \
                               f"flags={pkt[TCP].flags}"
                    elif pkt.haslayer("UDP"):
                        proto = "UDP"
                        info = f"{pkt[IP].sport}->{pkt[IP].dport}"
                    elif pkt.haslayer("ICMP"):
                        proto = "ICMP"
                        info = str(pkt[ICMP].type)
                    else:
                        proto = "IP"
                        info = ""
                except Exception:
                    proto, info = "IP", ""
                self._log_packet(pkt, proto, info)
                # packet MACs are lowercase; registry MACs are uppercase —
                # compare case-insensitively
                src = (pkt[Ether].src or "").upper().replace("-", ":")
                dst = (pkt[Ether].dst or "").upper().replace("-", ":")
                if our_mac and src == our_mac:
                    # a frame WE emitted — the original was already
                    # delivered; never relay our own sends
                    return
                if src == self.target_mac:
                    # target -> (poisoned) us -> real gateway
                    direction, other = "up", self.gateway_mac
                elif src == self.gateway_mac:
                    # gateway -> (poisoned) us -> real target.
                    # NOTE: these frames have Ether dst = OUR mac (the
                    # gateway was told the target lives at our MAC), so
                    # matching on dst==target_mac would NEVER match and
                    # all downlink traffic would be silently dropped —
                    # that bug made every session kill the device's
                    # internet. Match on the sender instead.
                    direction, other = "down", self.target_mac
                else:
                    return  # not our target's traffic

                # ---- encrypted-DNS enforcement (DoH/DoT) ---------------
                # When ANY blocking is active, cut the device's access to
                # known encrypted-DNS endpoints so it cannot bypass the
                # block — it is forced back to plain DNS, which the relay
                # sees, logs and filters.
                if self._blocking_active() and pkt.haslayer(IP) \
                        and direction == "up":
                    if pkt.haslayer(TCP):
                        dport = pkt[TCP].dport
                    elif pkt.haslayer(UDP):
                        dport = pkt[UDP].dport
                    else:
                        dport = None
                    if dport in (443, 853) and pkt[IP].dst in DOH_SERVER_IPS:
                        self.stats["doh_blocked"] += 1
                        return

                # ---- QUIC / HTTP3: browsers bypass filters over UDP 443 ----
                # While ANY blocking is active, drop QUIC entirely — the
                # standard approach used by filtering routers. Without this,
                # Chrome/Firefox (which use QUIC for YouTube, Facebook, ...)
                # would keep loading blocked sites even with DNS+TCP blocked.
                if self._blocking_active() and pkt.haslayer(UDP) \
                        and pkt[UDP].dport == 443 and direction == "up":
                    self.stats["quic_blocked"] += 1
                    self._log_packet(pkt, "QUIC", "blocked (HTTP/3 disabled "
                                                   "while blocking)")
                    return

                # ---- TLS SNI: block by hostname even when DNS is hidden ----
                # Every HTTPS connection carries the destination hostname in
                # the plaintext ClientHello (SNI). If that hostname is
                # blocked (or is a DoH server), cut the connection here —
                # this works regardless of cached DNS, encrypted DNS, or any
                # resolver. ECH would hide it; it is still rare.
                if pkt.haslayer(TCP) and pkt[TCP].dport == 443 \
                        and pkt.haslayer(IP) and direction == "up":
                    raw = bytes(pkt[TCP].payload)
                    if raw:
                        from netshield.services.tls_sni import extract_sni
                        sni = extract_sni(raw[:2048])
                        if sni:
                            # count the server for the top-servers panel
                            self._note_server(pkt[IP].dst, 443)
                            if self._blocking_active() and \
                                    sni in DOH_SNI_HOSTS:
                                self.stats["doh_blocked"] += 1
                                self._reset_conn(pkt, IP, TCP, send)
                                return
                            if self._domain_blocked(sni):
                                self.stats["sni_blocked"] += 1
                                self._reset_conn(pkt, IP, TCP, send)
                                return
                elif pkt.haslayer(IP) and direction == "up" and \
                        pkt.haslayer(TCP):
                    self._note_server(pkt[IP].dst, pkt[TCP].dport)
                elif pkt.haslayer(IP) and direction == "down" and \
                        pkt.haslayer(TCP):
                    self._note_server(pkt[IP].src, pkt[TCP].sport)
                elif pkt.haslayer(IP) and direction == "up" and \
                        pkt.haslayer(UDP):
                    self._note_server(pkt[IP].dst, pkt[UDP].dport)

                # ---- DNS: queries (client -> resolver) + responses ----
                if pkt.haslayer(UDP) and pkt.haslayer(IP):
                    if pkt[UDP].dport == 53 and pkt[IP].src == self.target_ip:
                        # a QUERY from the target
                        qname = extract_query_name(bytes(pkt[UDP].payload))
                        if qname:
                            # ALWAYS record the observed query into history —
                            # this is the per-device "search history"
                            # captured via the ARP relay (DNS-layer truth,
                            # nothing inferred about page content).
                            try:
                                from netshield.models.models import utcnow as _now
                                history.record_query(self.device_mac, qname,
                                                     _now())
                                self.stats["dns_logged"] += 1
                            except Exception:
                                pass
                            # DNS bypass: this domain is on the bypass list
                            # (router/firewall blocks it) — answer it
                            # ourselves via the public resolver, so the
                            # device reaches it regardless of the router's
                            # DNS filter.
                            if self._domain_is_bypassed(qname):
                                self.stats["dns_bypassed"] += 1
                                if self._answer_from_public(
                                        pkt, qname, ARP, Ether, IP, Raw, UDP,
                                        send):
                                    return  # answered — drop the original
                            if self._domain_blocked(qname):
                                self.stats["dns_blocked"] += 1
                                # learn the blocked domain's IPs and block
                                # them at the connection level (defeats
                                # cached DNS, DoH and open streams)
                                self._learn_ips_for(qname)
                                self._send_blackhole(pkt, ARP, Ether, IP, Raw,
                                                     UDP, send)
                                return  # drop the real query
                    elif pkt[UDP].sport == 53 and pkt[IP].dst == self.target_ip:
                        # a RESPONSE to the target — learn IPs of blocked
                        # domains from it (covers other devices' plain-DNS
                        # lookups being relayed, and pre-block lookups)
                        self._learn_from_response(bytes(pkt[UDP].payload))

                if self.cut:
                    # CUT mode: absorb the frame, never forward it
                    self.stats["pkts_dropped"] += 1
                    return

                # ---- connection-level blocking of learned IPs ----------
                if self.blocked_ips and pkt.haslayer(IP):
                    if (direction == "up" and pkt[IP].dst in self.blocked_ips) \
                            or (direction == "down"
                                and pkt[IP].src in self.blocked_ips):
                        self.stats["ip_blocked"] += 1
                        self._reset_conn(pkt, IP, TCP, send)
                        return  # drop the connection to a blocked domain

                if self.speed_limit_kbps and not self._bucket.allow(len(pkt)):
                    self.stats["pkts_dropped"] += 1
                    return  # throttled: no tokens left

                # Forward: rewrite ONLY the Ether addresses. dst -> the
                # real next hop; src -> OUR mac, so the switch never
                # re-learns the victim's MAC at our port (MAC stealing
                # silently killed the device's traffic before), the ARP
                # state on both victims stays consistent with the poison,
                # and our own sniffer never re-captures the forwarded
                # frame into an infinite relay loop. IP/TCP/UDP layers are
                # untouched, so checksums stay valid (end-to-end).
                frame = pkt.copy()
                frame[Ether].dst = other
                frame[Ether].src = self.our_mac
                sendp(frame, verbose=0, iface=iface)
                self.stats["pkts_forwarded"] += 1
                # account the exact forwarded bytes per direction — this is
                # what feeds per-device usage (relay accounting)
                if direction == "up":
                    self.stats["relay_bytes_up"] = self.stats.get(
                        "relay_bytes_up", 0) + len(frame)
                else:
                    self.stats["relay_bytes_down"] = self.stats.get(
                        "relay_bytes_down", 0) + len(frame)
            except Exception as exc:
                logger.debug("relay handler error: %s", exc)

        def _stopped(_pkt):
            return self._stop.is_set()

        try:
            while not self._stop.is_set():
                try:
                    sniff(store=False, prn=_handler, filter=bpf,
                          stop_filter=_stopped, timeout=1, iface=iface)
                except Exception as exc:
                    # interface rejected (e.g. stale NPF name) — retry on
                    # Scapy's default interface instead of dying
                    if iface:
                        logger.warning("sniff failed on %s (%s) — using "
                                       "default interface", iface, exc)
                        iface = None
                    else:
                        raise
        except Exception as exc:
            if not self._stop.is_set():
                logger.warning("relay sniff ended: %s", exc)

    # ------------------------------------------------------------------
    def _send_blackhole(self, pkt, ARP, Ether, IP, Raw, UDP, send) -> None:
        """Forge a DNS response pointing the blocked domain at 0.0.0.0.

        The client asked for the domain through us (we are its poisoned
        gateway), so we can answer on its behalf with a minimal crafted
        response: same query ID, QR|RD|RA flags, one A answer 0.0.0.0.
        """
        try:
            q = bytes(pkt[UDP].payload)
            if len(q) < 12:
                return
            query_id = struct.unpack(">H", q[:2])[0]
            # question section = qname + 4 bytes (type+class)
            name_end = 12
            while name_end < len(q) and q[name_end] != 0:
                name_end += 1 + q[name_end]
            name_end += 1  # trailing zero byte
            question = q[:name_end + 4] if name_end + 4 <= len(q) else None
            if question is None:
                return
            header = struct.pack(">HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
            answer = struct.pack(">HHHlH", 0xC00C, 1, 1, 60, 4) + bytes(
                [0, 0, 0, 0])
            resp = header + question + answer
            forged = (IP(src=pkt[IP].dst, dst=self.target_ip) /
                      UDP(sport=53, dport=pkt[UDP].sport) / Raw(resp))
            send(forged, verbose=0, iface=self.iface)
        except Exception as exc:
            logger.debug("blackhole response failed: %s", exc)

    # ------------------------------------------------------------------
    def _log_packet(self, pkt, proto: str, info: str) -> None:
        """Append one packet to the Wireshark-style ring buffer."""
        try:
            import time as _t
            entry = {
                "ts": round(_t.time(), 3),
                "src": pkt[IP].src if pkt.haslayer("IP") else "?",
                "dst": pkt[IP].dst if pkt.haslayer("IP") else "?",
                "proto": proto,
                "len": len(pkt),
                "info": info[:120],
            }
            with self._packet_lock:
                self.packet_log.append(entry)
                if len(self.packet_log) > 300:
                    del self.packet_log[:len(self.packet_log) - 300]
                self.proto_counts[proto] = self.proto_counts.get(proto, 0) + 1
        except Exception:
            pass

    def _note_server(self, ip: str, port: int) -> None:
        """Count one contact with a server (ip:port) for the top-servers
        panel on the device page."""
        try:
            key = f"{ip}:{port}"
            with self._top_lock:
                self.top_servers[key] = self.top_servers.get(key, 0) + 1
                if len(self.top_servers) > 400:
                    # drop the least-seen entries to bound memory
                    for k in sorted(self.top_servers,
                                    key=self.top_servers.get)[:100]:
                        del self.top_servers[k]
        except Exception:
            pass

    def _domain_is_bypassed(self, qname: str) -> bool:
        """True when the queried domain is on the DNS-bypass list (access
        DNS blocked by the router/firewall via a public resolver)."""
        q = (qname or "").strip().lower().rstrip(".")
        if not q:
            return False
        bypass = getattr(self, "_bypass_domains", None)
        if not bypass:
            return False
        base = dns_categories.base_domain(q)
        return base in bypass or q in bypass

    def _answer_from_public(self, pkt, qname, ARP, Ether, IP, Raw, UDP,
                            send) -> bool:
        """Resolve a bypassed domain via the public resolver and forge the
        device a DNS answer with the real IPs. Returns True on success."""
        try:
            now = time.time()
            cached = self._public_cache.get(qname)
            if cached and cached[1] > now:
                ips = cached[0]
            else:
                from netshield.services.hostname_resolver import \
                    public_resolve_a
                ips = public_resolve_a(qname, self._bypass_resolver)
                if not ips:
                    return False
                self._public_cache[qname] = (ips, now + 300)
            # forge the response: same query id, QR|RD|RA, one A per IP
            q = bytes(pkt[UDP].payload)
            query_id = struct.unpack(">H", q[:2])[0]
            name_end = 12
            while name_end < len(q) and q[name_end] != 0:
                name_end += 1 + q[name_end]
            name_end += 1
            question = q[:name_end + 4] if name_end + 4 <= len(q) else None
            if question is None:
                return False
            header = struct.pack(">HHHHHH", query_id, 0x8180, 1, len(ips),
                                 0, 0)
            answers = b""
            for ip in ips[:4]:
                try:
                    rdata = socket.inet_aton(ip)
                except OSError:
                    continue
                answers += struct.pack(">HHHlH", 0xC00C, 1, 1, 300, 4) + rdata
            if not answers:
                return False
            forged = (IP(src=pkt[IP].dst, dst=self.target_ip) /
                      UDP(sport=53, dport=pkt[UDP].sport) /
                      Raw(header + question + answers))
            send(forged, verbose=0, iface=self.iface)
            return True
        except Exception:
            return False

    def _domain_blocked(self, qname: str) -> bool:
        """Blocked? base-domain match, or exact/subdomain '=host' rule."""
        q = (qname or "").strip().lower().rstrip(".")
        if not q:
            return False
        if self._domain_is_bypassed(q):
            return False  # bypassed domains are never blocked
        if getattr(self, "device_bypass", False):
            return False  # unrestricted device — nothing is blocked
        # global allowlist (quick "Allow this domain" from history) — exempts
        # the domain from ALL blocking, everywhere
        try:
            from netshield.models.models import Setting
            global_allow = set(Setting.get("global_allow_domains", []) or [])
            if dns_categories.base_domain(q) in global_allow or \
                    q in global_allow:
                return False
        except Exception:
            pass
        if self.dns_allowlist is not None:
            # allowlist mode: only listed domains pass
            return dns_categories.base_domain(q) not in self.dns_allowlist
        base = dns_categories.base_domain(q)
        if base in self.blocked_domains:
            return True
        for rule in self.blocked_domains:
            if rule.startswith("="):
                host = rule[1:].strip().lower()
                if q == host or q.endswith("." + host):
                    return True
        return False

    def _learn_ips_for(self, qname: str) -> None:
        """Resolve a blocked domain and remember its IPv4 addresses so any
        connection to them is dropped (cached DNS / DoH / open streams)."""
        try:
            addrs = set()
            try:
                infos = socket.getaddrinfo(qname, None, socket.AF_INET)
                addrs.update(info[4][0] for info in infos if len(info[4]) >= 1)
            except Exception:
                pass
            if addrs:
                with self._lock:
                    self.blocked_ips.update(addrs)
        except Exception:
            pass

    def _learn_from_response(self, payload: bytes) -> None:
        """Parse a DNS response; remember IPs of blocked-domain answers."""
        try:
            parsed = parse_dns_response(payload)
            for name, rtype, _ttl, rdata in parsed.get("answers", []):
                if rtype == 1 and len(rdata) == 4 and \
                        self._domain_blocked(name):
                    try:
                        ip = socket.inet_ntoa(rdata)
                        with self._lock:
                            self.blocked_ips.add(ip)
                    except OSError:
                        pass
        except Exception:
            pass

    def _reset_conn(self, pkt, IP, TCP, send) -> None:
        """Send a TCP RST to both sides of a blocked connection so open
        streams die immediately instead of silently hanging."""
        try:
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                # RST to the sender (tells it the connection is dead)
                send(IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                     TCP(sport=tcp.dport, dport=tcp.sport, flags="R",
                         seq=tcp.ack),
                     verbose=0, iface=self.iface)
        except Exception as exc:
            logger.debug("RST failed: %s", exc)

    # ------------------------------------------------------------------
    def _blocking_active(self) -> bool:
        """True when this session filters (category block or allowlist)."""
        return bool(self.blocked_domains) or self.dns_allowlist is not None

    def _restart_resolver(self) -> None:
        """(Re)start the eager blocked-domain IP resolver."""
        try:
            self._stop_resolver()
        except Exception:
            pass
        self._resolver_stop = threading.Event()
        t = threading.Thread(target=self._resolver_loop, daemon=True,
                             name=f"resolver-{self.device_mac}")
        self._resolver_thread = t
        t.start()

    def _stop_resolver(self) -> None:
        try:
            if self._resolver_thread and self._resolver_thread.is_alive():
                if self._resolver_stop:
                    self._resolver_stop.set()
                self._resolver_thread.join(timeout=2)
        except Exception:
            pass
        self._resolver_thread = None
        self._resolver_stop = None

    def _resolver_loop(self) -> None:
        """Resolve every blocked domain and remember its IPv4 addresses.

        Runs immediately on block and repeats every RESOLVE_INTERVAL (IPs
        rotate on CDNs). Capped at EAGER_RESOLVE_LIMIT domains so huge sets
        (e.g. the StevenBlack adult list) are handled by query/response
        learning instead of thousands of lookups.
        """
        while True:
            try:
                with self._lock:
                    doms = list(self.blocked_domains)
                    allowlist_mode = self.dns_allowlist is not None
                if not doms or allowlist_mode:
                    break  # no domains to resolve anymore
                targets = []
                for d in doms[:EAGER_RESOLVE_LIMIT]:
                    targets.append(d[1:] if d.startswith("=") else d)
                ips: set[str] = set()
                for host in targets:
                    try:
                        for info in socket.getaddrinfo(
                                host, None, socket.AF_INET):
                            if len(info[4]) >= 1:
                                ips.add(info[4][0])
                    except Exception:
                        continue
                if ips:
                    with self._lock:
                        self.blocked_ips.update(ips)
            except Exception:
                pass
            if self._resolver_stop is not None and \
                    self._resolver_stop.wait(RESOLVE_INTERVAL):
                break  # stopped

    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Stop threads and restore the victims' ARP entries to reality."""
        self._stop.set()
        self._stop_resolver()
        for t in self._threads:
            t.join(timeout=5)
        self._threads = []
        self._restore_arp()

    def _restore_arp(self) -> None:
        """Unsolicited, CORRECT ARP replies so the target and gateway
        immediately relearn the real MACs after we withdraw."""
        try:
            ARP, Ether, *_rest = _scapy()  # first two are ARP, Ether
            sendp = _rest[6]
            if not (self.gateway_mac and self.our_mac):
                return
            for _ in range(3):
                sendp(Ether(dst=self.target_mac) /
                      ARP(psrc=self.gateway_ip, pdst=self.target_ip,
                          hwsrc=self.gateway_mac, op=2), verbose=0,
                      iface=self.iface)
                sendp(Ether(dst=self.gateway_mac) /
                      ARP(psrc=self.target_ip, pdst=self.gateway_ip,
                          hwsrc=self.target_mac, op=2), verbose=0,
                      iface=self.iface)
                time.sleep(0.4)
        except Exception as exc:
            logger.warning("ARP restore failed for %s: %s", self.target_ip, exc)

    # ------------------------------------------------------------------
    def effectiveness(self) -> str:
        """'stopped' | 'warming' | 'effective' | 'ineffective'.

        A session that has been running long enough but has seen ZERO of
        the target's packets is NOT working (wrong interface, client
        isolation, ARP validation on the target/gateway, ...). Surface it
        instead of silently pretending.
        """
        started = self.stats.get("started_at")
        if not started or self._stop.is_set():
            return "stopped"
        elapsed = time.time() - started
        if elapsed < 8:
            return "warming"
        return "effective" if self.stats.get("pkts_seen", 0) > 0 \
            else "ineffective"

    # ------------------------------------------------------------------
    def info(self) -> dict:
        with self._lock:
            try:
                blocked_categories = dns_categories.categories_for_bases(
                    set(self.blocked_domains))
            except Exception:
                blocked_categories = {}
            return {
                "mac": self.device_mac,
                "ip": self.target_ip,
                "cut": self.cut,
                "speed_limit_kbps": self.speed_limit_kbps,
                "blocked_domains": len(self.blocked_domains),
                "blocked_categories": blocked_categories,
                "blocked_ips": len(self.blocked_ips),
                "doh_blocked": self.stats.get("doh_blocked", 0),
                "doh_enforced": self._blocking_active(),
                "dns_allowlist": (len(self.dns_allowlist)
                                  if self.dns_allowlist is not None else None),
                "monitor": self.monitor,
                "iface": self.iface,
                "effective": self.effectiveness(),
                "stats": dict(self.stats),
                "running": not self._stop.is_set(),
                "sni_blocked": self.stats.get("sni_blocked", 0),
                "quic_blocked": self.stats.get("quic_blocked", 0),
                "top_servers": dict(self.top_servers),
                "proto_counts": dict(self.proto_counts),
                "packets": list(self.packet_log),
            }


# ---------------------------------------------------------------------------
# Controller — the single place blueprints/scheduler talk to
# ---------------------------------------------------------------------------
class TrafficController:
    def __init__(self):
        self._sessions: dict[str, DeviceSession] = {}
        self._lock = threading.Lock()
        self.monitor_all = False   # full DNS capture: ARP-spoof every device
        self.monitor_macs: set[str] = set()  # per-device DNS capture (no cut)

    def set_monitor_all(self, enabled: bool) -> None:
        """Enable/disable full DNS capture (ARP-spoof ALL devices)."""
        self.monitor_all = bool(enabled)

    def set_monitor_macs(self, macs) -> None:
        """Per-device DNS capture set (ARP-spoof just those devices)."""
        from netshield.services import mac_intel
        self.monitor_macs = {mac_intel.normalize_mac(m) for m in macs}
        self.monitor_macs.discard("")

    # ------------------------------------------------------------------
    def _effective_config(self, device) -> dict:
        """Compute the DESIRED session config for a device from:
          - device.control_state / speed_limit_kbps / blocked_categories
          - group defaults + group bedtime window
          - active schedule rules (allowlist or category modes)
          - monitor_all (full DNS capture) as the fallback reason to run
            a session for every device
        """
        # BYPASS device: unrestricted — never cut, throttled or blocked,
        # even by network-wide rules. (It can still get a monitor session
        # for DNS capture / DNS bypass.)
        device_bypass = bool(getattr(device, "bypass", False))

        cut = device.control_state == "cut"
        kbps = (device.speed_limit_kbps
                if device.control_state == "throttled" else None)
        categories = list(device.effective_blocked_categories())
        allowlist: set[str] = set()
        allowlist_active = False
        group = device.group
        if device_bypass:
            cut = False
            kbps = None
            categories = []
            allowlist_active = False

        from netshield.models.models import ScheduleRule, utcnow
        rules = (ScheduleRule.query.filter_by(active=True).all()
                 if ScheduleRule.query.count() else [])
        now = utcnow()
        for rule in rules:
            if rule.target_type == "device" and rule.target_id != device.mac:
                continue
            if rule.target_type == "group" and not (
                    group and rule.target_id == str(group.id)):
                continue
            if not _time_in_window(rule.start_time, rule.end_time, now):
                continue
            if rule.days_of_week and now.weekday() not in rule.days_of_week:
                continue
            if rule.mode == "block_all_except_allowlist":
                allowlist_active = True
                allowlist.update(rule.allowlist_domains or [])
            elif rule.mode == "block_categories":
                categories.extend(rule.blocked_categories or [])

        # group bedtime window -> full cut (no Internet during bedtime)
        if group and group.bedtime_start and group.bedtime_end:
            if _time_in_window(group.bedtime_start, group.bedtime_end, now):
                if not group.bedtime_days or now.weekday() in group.bedtime_days:
                    cut = True

        blocked = dns_categories.effective_blocked_domains(categories)
        # network-wide blocking: categories blocked for EVERY device on the
        # network (including devices that join later) — merged here so both
        # existing and new sessions enforce them
        try:
            from netshield.models.models import Setting
            global_cats = list(Setting.get("global_blocked_categories",
                                           []) or [])
            global_doms = list(Setting.get("global_block_domains", []) or [])
        except Exception:
            global_cats = []
            global_doms = []
        if global_cats and not device_bypass:
            blocked |= dns_categories.effective_blocked_domains(global_cats)
        # quick "Block this domain" rules from the history table (network-wide)
        if not device_bypass:
            blocked |= {str(d).strip().lower() for d in global_doms
                        if str(d).strip()}

        # SAFE MODE: allowlist-only internet for this device (block everything
        # except the domains in its allowlist) — skipped for bypass devices
        safe_mode = bool(getattr(device, "safe_mode", False)) and not device_bypass
        if safe_mode:
            allowlist_active = True
            allowlist.update(getattr(device, "allowlist_domains", None) or [])
            if not allowlist:
                # safe mode with empty allowlist = block everything
                cut = True

        # INTERNET WINDOW: if the device has a window during which internet
        # is allowed, anything outside that window is a full cut
        win_start = getattr(device, "internet_start", None)
        win_end = getattr(device, "internet_end", None)
        if win_start and win_end and not device_bypass:
            from netshield.models.models import utcnow as _utcnow
            if not _time_in_window(win_start, win_end, _utcnow()):
                cut = True

        active = cut or kbps or bool(blocked) or allowlist_active
        monitor = False
        # NOTE: DNS bypass does NOT auto-enable capture anymore (removed per
        # request). Bypass works only for devices that already have a session
        # (per-device capture / full capture / control).
        monitor_capture = (self.monitor_all or device.mac in self.monitor_macs)
        if not active and monitor_capture:
            # no control needed, but capture requested -> monitor session
            active = True
            monitor = True
        return {
            "active": active,
            "cut": cut,
            "kbps": kbps,
            "blocked_domains": blocked,
            "dns_allowlist": (allowlist if allowlist_active else None),
            "monitor": monitor,
            "safe_mode": safe_mode,
            "internet_window": bool(win_start and win_end),
        }

    # ------------------------------------------------------------------
    def apply(self, device) -> dict | None:
        """Reconcile the live session with the device's desired config.

        Idempotent — callable every scheduler tick; only acts on change.
        Raises TrafficControlUnavailable when packet capability is missing
        (callers surface the error; the DB state stays untouched).
        """
        if not device.current_ip:
            return None
        # HARD SAFETY GATE — re-validated on EVERY apply, even from the
        # scheduler thread, so a stale/bad IP can never be poisoned.
        assert_safe_target(device.current_ip)

        cfg = self._effective_config(device)
        with self._lock:
            session = self._sessions.get(device.mac)

            if not cfg["active"]:
                if session is not None:
                    session.stop()
                    del self._sessions[device.mac]
                return None

            if session is None:
                session = DeviceSession(device.mac, device.current_ip,
                                        monitor=cfg["monitor"])
                self._sessions[device.mac] = session
            session.device_bypass = bool(getattr(device, "bypass", False))
            if session.target_ip != device.current_ip:
                # DHCP re-lease: rebuild the session against the new IP
                session.stop()
                session = DeviceSession(device.mac, device.current_ip,
                                        monitor=cfg["monitor"])
                self._sessions[device.mac] = session

            changed = session.configure(
                cut=cfg["cut"], kbps=cfg["kbps"],
                blocked_domains=cfg["blocked_domains"],
                dns_allowlist=cfg["dns_allowlist"],
                monitor=cfg["monitor"])
            if session._stop.is_set() or changed:
                try:
                    session.start()
                except TrafficControlUnavailable:
                    # session failed to start — remove the dead session so
                    # the UI does not show a "stopped" ghost, then surface
                    # the real reason to the user
                    session.stop()
                    if self._sessions.get(device.mac) is session:
                        del self._sessions[device.mac]
                    raise
                except Exception as exc:
                    session.stop()
                    if self._sessions.get(device.mac) is session:
                        del self._sessions[device.mac]
                    # never let an unexpected session failure surface as a 500
                    raise TrafficControlUnavailable(
                        f"Session failed to start: {exc}") from exc
            return session.info()

    # ------------------------------------------------------------------
    def cut(self, device) -> dict | None:
        assert_safe_target(device.current_ip)
        device.control_state = "cut"
        return self.apply(device)

    def throttle(self, device, kbps: int) -> dict | None:
        assert_safe_target(device.current_ip)
        device.control_state = "throttled"
        device.speed_limit_kbps = max(int(kbps), 1)
        return self.apply(device)

    def restore(self, device) -> dict | None:
        assert_safe_target(device.current_ip)
        device.control_state = "none"
        device.speed_limit_kbps = None
        return self.apply(device)

    def set_categories(self, device, categories: list[str]) -> dict | None:
        assert_safe_target(device.current_ip)
        device.blocked_categories = [c for c in categories if c]
        return self.apply(device)

    # ------------------------------------------------------------------
    def sessions(self) -> list[dict]:
        with self._lock:
            return [s.info() for s in self._sessions.values()]

    def session_for(self, mac: str) -> dict | None:
        with self._lock:
            s = self._sessions.get(mac)
            return s.info() if s else None

    def stop_all(self) -> None:
        with self._lock:
            for s in self._sessions.values():
                try:
                    s.stop()
                except Exception as exc:
                    logger.warning("stop failed for %s: %s", s.device_mac, exc)
            self._sessions.clear()


controller = TrafficController()


def _time_in_window(start: str, end: str, now) -> bool:
    """True when 'now' falls inside [start, end) — supports overnight windows
    (e.g. 22:00 -> 06:00)."""
    try:
        sh, sm = (int(x) for x in start.split(":"))
        eh, em = (int(x) for x in end.split(":"))
    except (ValueError, AttributeError):
        return False
    cur = now.hour * 60 + now.minute
    s = sh * 60 + sm
    e = eh * 60 + em
    if s == e:
        return False
    if s < e:
        return s <= cur < e
    return cur >= s or cur < e  # overnight window
