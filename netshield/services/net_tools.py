"""Network toolbelt — Linux-style tools that work on Windows, plus
Wireshark-style analysis helpers. All graceful (never crash the app when a
tool isn't available or the OS lacks the command)."""

from __future__ import annotations

import datetime
import ipaddress
import os
import re
import socket
import struct
import subprocess
import time

from netshield.services.hostname_resolver import (build_dns_query,
                                                  parse_dns_response)


def run_cmd(cmd: list[str], timeout: float = 6.0) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout)
        return (out.stdout or out.stderr).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def traceroute(ip: str, max_hops: int = 15) -> list[dict]:
    """traceroute/tracert — returns hops [{hop, ip, rtt_ms, hostname}]."""
    hops: list[dict] = []
    if os.name == "nt":
        out = run_cmd(["tracert", "-d", "-h", str(max_hops), ip], timeout=30)
        if not out:
            return hops
        for line in out.splitlines():
            m = re.search(r"^\s*(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+"
                          r"(\d+)\s+ms\s+([0-9.]+)", line)
            if m:
                hops.append({"hop": int(m.group(1)), "ip": m.group(5),
                             "rtt_ms": int(m.group(2)),
                             "hostname": None})
        return hops
    out = run_cmd(["traceroute", "-n", "-m", str(max_hops), "-w", "1", ip],
                  timeout=30)
    if not out:
        return hops
    for line in out.splitlines()[1:]:
        m = re.match(r"\s*(\d+)\s+([0-9.]+|\*)\s+([0-9.]+|\*)\s*ms", line)
        if m:
            ip_ = m.group(2)
            hops.append({"hop": int(m.group(1)),
                         "ip": ip_ if ip_ != "*" else None,
                         "rtt_ms": float(m.group(3)) if m.group(3) != "*"
                         else None,
                         "hostname": None})
    return hops


def dig(domain: str, resolver: str = "8.8.8.8", qtype: int = 1,
        timeout: float = 3.0) -> dict:
    """dig-style lookup against any resolver. Returns parsed answers."""
    domain = (domain or "").strip().lower()
    if not domain or not re.match(r"^[a-z0-9.\-]+$", domain):
        return {"error": "invalid domain", "answers": []}
    try:
        query = build_dns_query(domain, qtype=qtype)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(query, (resolver, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        parsed = parse_dns_response(data)
        answers = []
        rtype_names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX",
                       16: "TXT", 28: "AAAA", 6: "SOA"}
        for name, rtype, _ttl, rdata in parsed.get("answers", []):
            if rtype == 1 and len(rdata) == 4:
                val = socket.inet_ntoa(rdata)
            elif rtype == 28 and len(rdata) == 16:
                val = str(ipaddress.ip_address(rdata))
            elif rtype in (2, 5, 12, 15):
                val, _ = _parse_name(rdata)
            elif rtype == 16:
                val = rdata.decode(errors="ignore").strip('"')
            else:
                val = rdata.hex()
            answers.append({"name": name, "type": rtype_names.get(rtype,
                                                                  str(rtype)),
                            "value": val})
        return {"domain": domain, "resolver": resolver,
                "answers": answers,
                "flags": parsed.get("flags", 0)}
    except OSError as exc:
        return {"error": str(exc), "answers": []}


def _parse_name(data: bytes):
    """Parse a possibly-compressed name (for dig MX/NS/CNAME answers)."""
    from netshield.services.hostname_resolver import parse_qname
    return parse_qname(data, 0)


def rdap_lookup(ip: str, timeout: float = 6.0) -> dict | None:
    """whois-style RDAP lookup for an IP (needs internet; graceful)."""
    try:
        import requests
        r = requests.get(f"https://rdap.org/ip/{ip}", timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
        out = {"ip": ip}
        for e in data.get("entities", []):
            for h in e.get("vcardArray", [[], []])[1]:
                if h[0] == "fn":
                    out["name"] = h[3]
        for e in data.get("entities", []):
            for h in e.get("vcardArray", [[], []])[1]:
                if h[0] == "org":
                    out["org"] = h[3]
        out["network"] = data.get("handle", "")
        for n in data.get("links", []):
            if n.get("rel") == "self":
                out["url"] = n.get("href")
        return out or None
    except Exception:
        return None


def traffic_matrix(devices) -> dict:
    """Who-talks-to-whom across all active sessions (Wireshark-style)."""
    from netshield.services.traffic_control import controller
    rows = []
    for s in controller.sessions():
        dev_name = next((d.display_name for d in devices
                         if d.mac == s["mac"]), s["mac"])
        for srv, cnt in list(s.get("top_servers", {}).items())[:20]:
            ip, _, port = srv.rpartition(":")
            rows.append({"device": dev_name, "server_ip": ip, "port": port,
                         "count": cnt})
    rows.sort(key=lambda r: -r["count"])
    return rows[:60]


def pcap_bytes(packets: list[dict]) -> bytes:
    """Write captured packet metadata as a minimal pcap file (Wireshark can
    open it). Each entry becomes a fake Ethernet frame with the IP layer."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for p in packets:
        try:
            src = socket.inet_aton(p.get("src", "0.0.0.0"))
            dst = socket.inet_aton(p.get("dst", "0.0.0.0"))
        except OSError:
            continue
        proto = 17 if p.get("proto") == "UDP" else (
            1 if p.get("proto") == "ICMP" else 6)
        ihl = 5
        total_len = 20 + 8 + 20  # IP + UDP + padding
        iph = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64,
                          proto, 0, src, dst)
        udp = struct.pack(">HHHH", 53, 53, 8, 0)
        body = iph + udp + b"\x00" * 20
        ts = p.get("ts", time.time())
        out += struct.pack("<IIII", int(ts), 0, len(body), len(body))
        out += body
    return bytes(out)


def live_speed_mbps(device_mac: str, window_seconds: int = 120) -> float:
    """Approximate current download speed from recent bandwidth samples."""
    from netshield.extensions import db
    from netshield.models.models import BandwidthSample, utcnow
    cutoff = utcnow() - datetime.timedelta(seconds=window_seconds)
    try:
        rows = (BandwidthSample.query
                .filter(BandwidthSample.device_mac == device_mac,
                        BandwidthSample.timestamp >= cutoff).all())
        total = sum(r.bytes_down for r in rows)
        return round(total * 8 / window_seconds / 1_000_000, 2)
    except Exception:
        return 0.0


def heatmap_today() -> list[dict]:
    """Device x hour matrix (queries per hour) for today — a heat table."""
    from netshield.extensions import db
    from netshield.models.models import Device, DnsQueryLog, utcnow
    day = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        rows = (db.session.query(DnsQueryLog.device_mac,
                                 db.func.strftime("%H", DnsQueryLog.timestamp),
                                 db.func.sum(DnsQueryLog.count))
                .filter(DnsQueryLog.timestamp >= day)
                .group_by(DnsQueryLog.device_mac, "strftime('%H', "
                          "dns_query_log.timestamp)").all())
        dev_names = {d.mac: d.display_name for d in Device.query.all()}
        out = []
        for mac, hour, cnt in rows:
            out.append({"mac": mac, "name": dev_names.get(mac, mac),
                        "hour": int(hour), "count": int(cnt)})
        return out
    except Exception:
        return []


def iface_info() -> list[dict]:
    """ifconfig-style interface listing (IP, netmask, MAC, flags)."""
    out = []
    try:
        from scapy.all import conf
        for i in conf.ifaces.values():
            out.append({
                "name": getattr(i, "name", "?"),
                "ip": getattr(i, "ip", None) or None,
                "netmask": getattr(i, "netmask", None) or None,
                "mac": (getattr(i, "mac", None) or "").upper(),
                "flags": getattr(i, "flags", None) or 0,
            })
    except Exception:
        pass
    return out


def route_table() -> list[dict]:
    """route-style default-route listing from the OS."""
    routes = []
    try:
        from netshield.services.network_scanner import _os_gateway_candidates
        for c in _os_gateway_candidates():
            routes.append({"iface": c.get("iface"), "gateway": c["gateway"],
                           "source": c["source"]})
    except Exception:
        pass
    return routes
