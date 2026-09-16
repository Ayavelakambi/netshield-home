"""Hostname resolution with the EXACT fallback chain required by the spec:

    1. user nickname        (from the device registry)
    2. NetBIOS name query   (UDP 137 — classic Windows hostname discovery)
    3. mDNS reverse PTR     (multicast UDP 5353 — no admin rights required)
    4. reverse DNS          (PTR via the system resolver)
    5. fall back to the IP

Also contains the minimal hand-rolled DNS message builder/parser used by the
traffic-control relay (to read query names out of intercepted DNS packets)
and by the mDNS/NetBIOS lookups. Kept dependency-free on purpose.
"""
from __future__ import annotations

import logging
import random
import socket
import struct
import threading
import time

logger = logging.getLogger("netshield.hostname")

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
NETBIOS_PORT = 137

# ---------------------------------------------------------------------------
# Minimal DNS wire-format helpers (shared with the traffic-control relay).
# ---------------------------------------------------------------------------

def encode_qname(name: str) -> bytes:
    """'www.example.com' -> b'\\x03www\\x07example\\x03com\\x00'"""
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii", errors="ignore")
    return out + b"\x00"


def parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    pos = offset
    jumped = False
    end = offset
    jumps = 0
    while True:
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            if not jumped:
                end = pos + 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            pos = pointer
            jumped = True
            jumps += 1
            if jumps > 10:  # loop protection
                break
            continue
        if pos + 1 + length > len(data):
            break
        labels.append(data[pos + 1:pos + 1 + length].decode("ascii", errors="ignore"))
        pos += 1 + length
    return ".".join(labels), end


def build_dns_query(qname: str, qtype: int = 12, qclass: int = 1,
                    query_id: int | None = None) -> bytes:
    """Build a minimal DNS query. qtype 12 = PTR (used by mDNS)."""
    qid = query_id if query_id is not None else random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0000, 1, 0, 0, 0)
    return header + encode_qname(qname) + struct.pack(">HH", qtype, qclass)


def parse_dns_response(data: bytes) -> dict:
    """Parse the answer section of a DNS response.

    Returns {id, flags, answers: [(name, rtype, ttl, rdata_bytes), ...]}.
    """
    if len(data) < 12:
        return {"id": 0, "flags": 0, "answers": []}
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    answers: list[tuple[str, int, int, bytes]] = []
    offset = 12
    for _ in range(qd):  # skip question section
        _, offset = parse_qname(data, offset)
        offset += 4
    for _ in range(an + ns + ar):
        if offset + 10 > len(data):
            break
        name, offset = parse_qname(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        answers.append((name, rtype, ttl, rdata))
    return {"id": qid, "flags": flags, "answers": answers}


def extract_query_name(dns_payload: bytes) -> str | None:
    """Pull the first question's qname out of a DNS query payload (UDP 53)."""
    try:
        if len(dns_payload) < 12:
            return None
        _, _, qd, _, _, _ = struct.unpack(">HHHHHH", dns_payload[:12])
        if qd == 0:
            return None
        name, _ = parse_qname(dns_payload, 12)
        return name or None
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Resolution chain
# ---------------------------------------------------------------------------

_cache: dict[str, tuple[str, float]] = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 60.0

# per-MAC attempt bookkeeping so failed lookups are retried occasionally,
# not hammered every poller pass
_attempts: dict[str, float] = {}
_attempts_lock = threading.Lock()
RESOLVE_RETRY_SECONDS = 6 * 3600


def resolve_hostname(device) -> str:
    """Full fallback chain: nickname → NetBIOS → mDNS → reverse DNS → IP."""
    if device.nickname:
        return device.nickname
    ip = device.current_ip
    if not ip:
        return device.mac
    if device.hostname:
        return device.hostname

    with _cache_lock:
        hit = _cache.get(ip)
        if hit and time.time() - hit[1] < _CACHE_TTL:
            return hit[0]

    name = resolve_hostname_chain(ip)

    result = name or ip
    with _cache_lock:
        _cache[ip] = (result, time.time())
    if name:
        try:
            device.hostname = name[:255]
        except Exception:
            pass
    return result


def resolve_hostname_chain(ip: str) -> str | None:
    """NetBIOS → mDNS → reverse DNS. Returns None when all fail."""
    for fn in (netbios_name, mdns_name, rdns_name):
        try:
            name = fn(ip)
        except Exception as exc:  # any resolver failure -> try the next
            logger.debug("resolver %s failed for %s: %s", fn.__name__, ip, exc)
            name = None
        if name:
            return name
    return None


def should_attempt(mac: str, hostname: str | None, force: bool = False) -> bool:
    """True when we should try resolving this device's hostname now."""
    if hostname:
        return False  # already known
    if force:
        return True
    with _attempts_lock:
        last = _attempts.get(mac, 0.0)
    return (time.time() - last) > RESOLVE_RETRY_SECONDS


def mark_attempt(mac: str) -> None:
    with _attempts_lock:
        _attempts[mac] = time.time()


def resolve_device_hostname(device, force: bool = False) -> str | None:
    """Resolve + persist one device's hostname (respects retry cooldown)."""
    if device.hostname:
        return device.hostname
    if not device.current_ip:
        return None
    if not should_attempt(device.mac, device.hostname, force):
        return None
    mark_attempt(device.mac)
    try:
        name = resolve_hostname_chain(device.current_ip)
    except Exception:
        return None
    if name and name != device.current_ip:
        device.hostname = name[:255]
        return name
    return None


def background_hostname_resolver(app) -> None:
    """Periodically resolve hostnames for devices that don't have one yet
    (or whose old resolution failed). Runs in a thread pool with short
    per-host timeouts so the LAN is never flooded; emits a Socket.IO
    'hostname' event so open pages update live."""
    from concurrent.futures import ThreadPoolExecutor
    from netshield.extensions import db, socketio
    from netshield.models.models import Device, utcnow

    while True:
        time.sleep(30)
        try:
            with app.app_context():
                now = utcnow()
                candidates = []
                for d in Device.query.all():
                    if not d.current_ip or d.hostname:
                        continue
                    if not should_attempt(d.mac, None):
                        continue
                    # only bother with recently-seen (online-ish) devices
                    if (now - d.last_seen).total_seconds() > 15 * 60:
                        continue
                    candidates.append(d)
                if not candidates:
                    continue
                with ThreadPoolExecutor(max_workers=8) as pool:
                    futures = {
                        pool.submit(resolve_hostname_chain, d.current_ip): d
                        for d in candidates[:30]
                    }
                    for fut, d in futures.items():
                        try:
                            name = fut.result()
                        except Exception:
                            name = None
                        if name and name != d.current_ip:
                            d.hostname = name[:255]
                            try:
                                socketio.emit("hostname",
                                              {"mac": d.mac,
                                               "hostname": d.hostname})
                            except Exception:
                                pass
                db.session.commit()
        except Exception as exc:
            logger.warning("hostname resolver error: %s", exc)


def force_resolve_names(app) -> None:
    """Resolve names for every hostname-less device right now (used by the
    'Scan now' button so names appear immediately, not after the next tick)."""
    from concurrent.futures import ThreadPoolExecutor
    from netshield.extensions import db, socketio
    from netshield.models.models import Device

    def _run():
        with app.app_context():
            candidates = [d for d in Device.query.all()
                          if d.current_ip and not d.hostname]
            if not candidates:
                return
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {
                    pool.submit(resolve_hostname_chain, d.current_ip): d
                    for d in candidates[:30]
                }
                for fut, d in futures.items():
                    try:
                        name = fut.result()
                    except Exception:
                        name = None
                    if name and name != d.current_ip:
                        d.hostname = name[:255]
                        try:
                            socketio.emit("hostname",
                                          {"mac": d.mac, "hostname": d.hostname})
                        except Exception:
                            pass
            db.session.commit()

    threading.Thread(target=_run, daemon=True, name="hostname-force").start()


def netbios_name(ip: str, timeout: float = 1.2) -> str | None:
    """NetBIOS NBSTAT query for '*' sent to UDP 137 (no admin required)."""
    try:
        # 12-byte NBNS header: id, flags(0x0010 = query, broadcast), qd=1
        header = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0010, 1, 0, 0, 0)
        # question: special '*' name (single byte 0x2A), type NBSTAT (0x21)
        question = b"\x2a" + struct.pack(">HH", 0x0021, 0x0001)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(header + question, (ip, NETBIOS_PORT))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if len(data) < 12:
            return None
        qd, an = struct.unpack(">HH", data[4:8])
        offset = 12
        for _ in range(qd):
            _, offset = parse_qname(data, offset)
            offset += 4
        for _ in range(an):
            if offset + 10 > len(data):
                return None
            _, offset = parse_qname(data, offset)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            if rtype == 0x0021 and len(rdata) >= 3:  # NBSTAT
                num_names = rdata[0]
                if num_names == 0 or len(rdata) < 1 + num_names * 18 + 6:
                    continue
                # pick the first workstation (type 0x00) name entry
                for i in range(num_names):
                    entry = rdata[1 + i * 18: 1 + (i + 1) * 18]
                    name = entry[:16].decode("ascii", errors="ignore").strip(" \x00")
                    ntype = entry[16]
                    if ntype in (0x00, 0x03) and name:
                        return name
        return None
    except (socket.timeout, OSError):
        return None


def mdns_name(ip: str, timeout: float = 1.5) -> str | None:
    """mDNS reverse-PTR query (multicast 224.0.0.251:5353); unicast retry."""
    reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = build_dns_query(reverse, qtype=12, query_id=0)  # mDNS uses id=0
    for target, addr in ((MDNS_ADDR, MDNS_ADDR), (ip, ip)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (target, MDNS_PORT))
            data, _ = sock.recvfrom(4096)
            sock.close()
            parsed = parse_dns_response(data)
            for name, rtype, _ttl, rdata in parsed["answers"]:
                if rtype == 12 and rdata:  # PTR -> target name bytes
                    ptr, _ = parse_qname(rdata, 0)
                    if ptr:
                        return ptr
        except (socket.timeout, OSError):
            continue
    return None


def rdns_name(ip: str, timeout: float = 2.0) -> str | None:
    """Reverse DNS lookup via the system resolver."""
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            name = socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(old)
        if name and not name.rstrip(".").isdigit():
            return name.rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        pass
    return None
