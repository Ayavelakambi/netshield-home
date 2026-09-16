"""Device discovery — rebuilt for real-world networks.

Detection strategy:
  1. Enumerate EVERY private network this host has an interface on (from
     Scapy's interface table: ip + netmask, plus config fallbacks). This
     matters on machines with Wi-Fi + Ethernet + VPN/virtual adapters —
     the old single-guess approach could pick the wrong subnet and then
     filter out every real host.
  2. ARP-broadcast scan each candidate network, on the interface Scapy
     routes to it. The network with the most ARP replies (and the gateway
     among them) is the real LAN and wins.
  3. Merge in the OS neighbour/ARP table (`arp -a` on Windows,
     /proc/net/arp + `ip neigh` on Linux/macOS) — authoritative MACs.
  4. Parallel ping sweep of the chosen network — wakes sleepy hosts and
     yields TTLs for OS fingerprinting.

Every candidate is validated before it becomes a device:
  * must be a private unicast address inside the CHOSEN network,
  * not the network/broadcast/multicast address, the gateway, or this host,
  * MAC must normalize (colon / hyphen / Cisco-dot formats) — otherwise the
    entry is skipped and counted, never silently corrupting the registry.

A discovery REPORT (per-method counts + network + interface + duration) is
kept in LAST_REPORT, logged at INFO, and shown on the Devices page and
Settings diagnostics so detection health is always visible.

OS fingerprinting is heuristic: ping-reply TTL (Windows ~128, Linux/macOS
~64, network gear ~255) combined with open-service hints (135/139/445 =>
Windows, 22 => Linux/macOS).
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import config
from netshield.services import mac_intel

logger = logging.getLogger("netshield.scanner")

_capability_cache: bool | None = None

# last detection run's per-method counts (shown in the UI)
LAST_REPORT: dict = {}


def packet_capability_available() -> bool:
    """Scapy importable AND we have the privileges raw L2 needs."""
    global _capability_cache
    if _capability_cache is None:
        _capability_cache = _check_capability()
    return _capability_cache


def refresh_capability() -> bool:
    """Re-run the capability check (e.g. after the user regains admin)."""
    global _capability_cache
    _capability_cache = _check_capability()
    return _capability_cache


def _check_capability() -> bool:
    try:
        import scapy  # noqa: F401
    except ImportError:
        return False
    if os.name == "nt":
        try:  # Windows: require an elevated shell
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return True  # cannot tell — let the runtime errors surface
    try:
        return os.geteuid() == 0  # POSIX: raw sockets need root
    except AttributeError:
        return True


# ---------------------------------------------------------------------------
# Interface / network selection — the ARP broadcast must go out the LAN
# adapter, and the subnet must be the REAL LAN subnet, not a VPN guess.
# ---------------------------------------------------------------------------
def lan_interface() -> str | None:
    """Return a Scapy-accepted interface name for the LAN (gateway-routed).

    On Windows the route table can expose the RAW Npcap device path
    (``\\Device\\NPF_{GUID}``) which Scapy's sendp/sniff/get_if_hwaddr
    cannot use — that silently killed sessions (they showed 0 packets,
    "stopped"). This resolves the route's interface against conf.ifaces
    and returns the friendly name Scapy understands. Returns None to let
    Scapy pick when nothing matches.
    """
    try:
        from scapy.all import conf
        route = conf.route.route(config.gateway_ip())
        iface = route[0]
        if not iface or str(iface).lower() in ("", "lo", "loopback",
                                               "none", "null"):
            return None
        try:
            iface_l = str(iface).lower()
            for i in conf.ifaces.values():
                cands = {
                    str(getattr(i, "name", "")),
                    str(getattr(i, "network_name", "")),
                    str(getattr(i, "winpcap_name", "")),
                    str(getattr(i, "description", "")),
                }
                if iface_l in {c.lower() for c in cands if c}:
                    name = getattr(i, "name", None)
                    return str(name) if name else iface
        except Exception:
            pass
        return iface
    except Exception as exc:
        logger.debug("interface selection failed: %s", exc)
    return None


def host_mac(iface: str | None = None) -> str | None:
    """This host's MAC on the given interface (or the default one).

    Tries Scapy's get_if_hwaddr first, then reads the MAC straight from
    conf.ifaces (which needs no raw sockets and works on Windows where
    get_if_hwaddr can fail with the raw NPF path).
    """
    try:
        from scapy.all import conf, get_if_hwaddr
        try:
            mac = get_if_hwaddr(iface or conf.iface)
            norm = mac_intel.normalize_mac(str(mac))
            if norm:
                return norm
        except Exception:
            pass
        try:
            target = conf.ifaces[iface] if iface else conf.iface
            mac = getattr(target, "mac", None)
            norm = mac_intel.normalize_mac(str(mac)) if mac else None
            if norm:
                return norm
        except Exception:
            pass
    except Exception as exc:
        logger.debug("host MAC lookup failed: %s", exc)
    return None


def _candidate_networks() -> list[ipaddress.IPv4Network]:
    """Every plausible private LAN network this host has an interface on.

    Sources: Scapy's interface table (ip + netmask per adapter), a /24
    fallback per adapter IP, and config.current_network() as a final
    fallback. Multi-adapter / VPN hosts produce several candidates — the
    detector scans each and keeps the one with the most ARP replies.
    """
    nets: list[ipaddress.IPv4Network] = []
    seen: set[ipaddress.IPv4Network] = set()

    def add(net) -> None:
        if net is None:
            return
        try:
            net = ipaddress.ip_network(str(net), strict=False)
        except ValueError:
            return
        if net in seen:
            return
        if not net.is_private or net.prefixlen < 16:
            return
        seen.add(net)
        nets.append(net)

    try:
        from scapy.all import conf
        for iface in conf.ifaces.values():
            ip = getattr(iface, "ip", None) or ""
            if not ip or ip == "0.0.0.0":
                continue
            netmask = getattr(iface, "netmask", None)
            if netmask:
                add(f"{ip}/{netmask}")
            add(f"{ip}/24")
    except Exception as exc:
        logger.debug("interface enumeration failed: %s", exc)
    add(config.current_network())
    return nets


def _select_network(candidates: list, gw: str):
    """ARP-scan each candidate network; return the one that is the real LAN.

    The real LAN is the candidate that yields the most ARP replies (with
    the gateway among them if gateway detection is sane). Scanning stops
    early once a candidate returns a healthy number of hosts, so a normal
    single-LAN machine only ever scans one network.
    """
    best_net: ipaddress.IPv4Network | None = None
    best_hosts: dict[str, str] = {}
    best_iface: str | None = None
    best_src: str | None = None

    for net in candidates:
        try:
            hosts = _scapy_arp_scan(net)
            logger.info("ARP scan of %s found %d hosts", net, len(hosts))
        except Exception as exc:
            logger.warning("ARP scan of %s failed: %s", net, exc)
            continue
        if len(hosts) > len(best_hosts):
            best_net, best_hosts = net, hosts
            try:  # interface + source IP Scapy would use for this network
                from scapy.all import conf
                probe = str(next(net.hosts()))
                iface, src, _gw = conf.route.route(probe)
                if src and ipaddress.ip_address(src) in net:
                    best_iface, best_src = iface, src
            except Exception:
                pass
        if len(hosts) >= 5 and (not gw or gw in hosts):
            break  # healthy LAN found — no need to scan the rest

    if best_net is None:
        best_net = config.current_network()
    if best_src is None:
        best_src = config.detect_host_ip()
    return best_net, best_hosts, best_iface, best_src


# ---------------------------------------------------------------------------
# Method: Scapy ARP broadcast
# ---------------------------------------------------------------------------
def _scapy_arp_scan(network, iface: str | None = None) -> dict[str, str]:
    """ARP-scan the subnet with Scapy. Returns {ip: mac}.

    PACKET-LEVEL NOTE (audit trail): this sends a broadcast Ether/ARP
    "who-has" request and collects the replies. It is a passive-intent
    discovery technique — it never spoofs, never targets the gateway, and
    touches every host equally.
    """
    from scapy.all import ARP, Ether, srp
    kwargs = {"iface": iface} if iface else {}
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                 timeout=2, retry=1, verbose=0, **kwargs)
    return {rcv.psrc: rcv.hwsrc for _snd, rcv in ans}


# ---------------------------------------------------------------------------
# Method: OS ARP / neighbour table
# ---------------------------------------------------------------------------
def read_arp_table() -> dict[str, str]:
    """Read the OS ARP/neighbour table. Returns {ip: mac}."""
    entries: dict[str, str] = {}
    mac_re = re.compile(r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                        r"[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})")
    if sys.platform.startswith("linux") and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        entries[parts[0]] = parts[3]
        except OSError:
            pass
        if entries:
            return entries
    for cmd in (["ip", "neigh", "show"], ["arp", "-a"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=5).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*?(" +
                              r"[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-]"
                              r"[0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
                              line)
                if m and "incomplete" not in line.lower():
                    entries[m.group(1)] = m.group(2)
        except (OSError, subprocess.SubprocessError):
            continue
        if entries:
            return entries
    return entries


# ---------------------------------------------------------------------------
# Method: parallel ping sweep (wakes hosts, yields TTLs)
# ---------------------------------------------------------------------------
def ping_host(ip: str) -> tuple[bool, int | None]:
    """Ping one host; return (reachable, ttl_or_None)."""
    ttl = None
    try:
        if os.name == "nt":
            out = subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
        else:
            out = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                 capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
        return m is not None, ttl
    except (OSError, subprocess.SubprocessError):
        return False, None


def subnet_ping_sweep(network) -> dict[str, int | None]:
    """Parallel ping sweep. Returns {ip: ttl} for responders."""
    results: dict[str, int | None] = {}
    hosts = [str(h) for h in network.hosts()]
    with ThreadPoolExecutor(max_workers=64) as pool:
        for ip, (ok, ttl) in zip(hosts, pool.map(ping_host, hosts)):
            if ok:
                results[ip] = ttl
    return results


def ping_latency_ms(ip: str) -> float | None:
    """Round-trip latency for one host (single ping), or None if no reply."""
    try:
        if os.name == "nt":
            out = subprocess.run(["ping", "-n", "1", "-w", "2000", ip],
                                 capture_output=True, text=True,
                                 timeout=4).stdout
            m = (re.search(r"time[=<](\d+)ms", out, re.I)
                 or re.search(r"Average = (\d+)ms", out, re.I))
        else:
            out = subprocess.run(["ping", "-c", "1", "-W", "2", ip],
                                 capture_output=True, text=True,
                                 timeout=4).stdout
            m = re.search(r"time=(\d+(?:\.\d+)?)\s*ms", out)
        if m:
            return float(m.group(1))
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def ttl_os_guess(ttl: int | None, hints: dict[int, bool] | None = None) -> str | None:
    """Heuristic OS guess from TTL (+ optional open-port hints)."""
    hints = hints or {}
    if hints.get(445) or hints.get(139) or hints.get(135):
        return "Windows"
    if ttl is None:
        if hints.get(22):
            return "Linux/macOS"
        return None
    if 110 <= ttl <= 140:
        return "Windows"
    if 55 <= ttl <= 70:
        return "Linux/macOS"
    if 235 <= ttl <= 255:
        return "Network device (router/switch)"
    if 25 <= ttl <= 45:
        return "Embedded/Unix (low TTL)"
    return None


# ---------------------------------------------------------------------------
# Gateway resolution — the WiFi/LAN router's IP, per OS routing tables.
# The resolved gateway is pushed into config (set_resolved_gateway) so the
# safety gate and traffic control ALWAYS exclude the real router, even when
# the default route points at a VPN.
# ---------------------------------------------------------------------------
def _parse_route_print(text: str) -> list[dict]:
    """Parse Windows `route print -4` -> [{iface, gateway, source}]."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "0.0.0.0" and \
                parts[1] == "0.0.0.0":
            gw = parts[2]
            if gw.lower() == "on-link":
                gw = parts[3]  # interface itself is the gateway
            try:
                socket.inet_aton(gw)
            except OSError:
                continue
            out.append({"iface": parts[3], "gateway": gw,
                        "source": "route print -4"})
    return out


def _parse_netsh_config(text: str) -> list[dict]:
    """Parse `netsh interface ipv4 show config` -> [{iface, gateway}]."""
    out = []
    iface = None
    for line in text.splitlines():
        m = re.match(r'Configuration for interface "([^"]+)"', line.strip())
        if m:
            iface = m.group(1)
            continue
        if iface and "Default Gateway" in line:
            gw = line.split(":", 1)[-1].strip()
            try:
                socket.inet_aton(gw)
            except OSError:
                continue
            out.append({"iface": iface, "gateway": gw,
                        "source": "netsh interface ipv4"})
    return out


def _parse_proc_net_route(text: str) -> list[dict]:
    """Parse Linux /proc/net/route -> [{iface, gateway}] (hex, LE)."""
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000":  # dest 0.0.0.0
            try:
                gw = socket.inet_ntoa(struct.pack("<I", int(parts[2], 16)))
            except (ValueError, struct.error, OSError):
                continue
            out.append({"iface": parts[0], "gateway": gw,
                        "source": "/proc/net/route"})
    return out


def _parse_ip_route_default(text: str) -> list[dict]:
    """Parse `ip route show default` -> [{iface, gateway}]."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if "via" not in parts:
            continue
        try:
            gw = parts[parts.index("via") + 1]
            socket.inet_aton(gw)
        except (ValueError, OSError, IndexError):
            continue
        iface = None
        if "dev" in parts:
            try:
                iface = parts[parts.index("dev") + 1]
            except IndexError:
                pass
        out.append({"iface": iface, "gateway": gw, "source": "ip route"})
    return out


def _os_gateway_candidates() -> list[dict]:
    """Gateway candidates from the OS routing tables (per interface)."""
    cands: list[dict] = []
    try:
        if os.name == "nt":
            try:
                out = subprocess.run(["route", "print", "-4"],
                                     capture_output=True, text=True,
                                     timeout=8).stdout
                cands += _parse_route_print(out)
            except (OSError, subprocess.SubprocessError):
                pass
            try:
                out = subprocess.run(["netsh", "interface", "ipv4",
                                      "show", "config"],
                                     capture_output=True, text=True,
                                     timeout=8).stdout
                cands += _parse_netsh_config(out)
            except (OSError, subprocess.SubprocessError):
                pass
        elif sys.platform.startswith("linux"):
            try:
                with open("/proc/net/route", "r", encoding="utf-8") as fh:
                    cands += _parse_proc_net_route(fh.read())
            except OSError:
                pass
            if not cands:
                try:
                    out = subprocess.run(["ip", "route", "show", "default"],
                                         capture_output=True, text=True,
                                         timeout=5).stdout
                    cands += _parse_ip_route_default(out)
                except (OSError, subprocess.SubprocessError):
                    pass
        elif sys.platform == "darwin":
            try:
                out = subprocess.run(["route", "-n", "get", "default"],
                                     capture_output=True, text=True,
                                     timeout=5).stdout
                for line in out.splitlines():
                    if line.strip().startswith("gateway:"):
                        gw = line.split(":", 1)[-1].strip()
                        try:
                            socket.inet_aton(gw)
                        except OSError:
                            continue
                        cands.append({"iface": None, "gateway": gw,
                                      "source": "route -n get default"})
            except (OSError, subprocess.SubprocessError):
                pass
    except Exception as exc:
        logger.debug("gateway enumeration failed: %s", exc)
    return cands


def _ip_in_net(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _wifi_like_iface(name: str | None) -> bool | None:
    """True if the interface name looks like Wi-Fi; None when unknown."""
    if not name:
        return None
    return bool(re.search(r"(wi-?fi|wireless|wlan|^wl\d)", name, re.I))


def resolve_gateway(net, own_ip: str) -> dict:
    """Best gateway for the chosen LAN, in priority order:

      1. NETSHIELD_GATEWAY env override (if inside the LAN)
      2. OS routing tables (per-interface default routes inside the LAN)
      3. config fallback (if inside the LAN)
      4. first usable host of the subnet
    """
    env_gw = os.environ.get("NETSHIELD_GATEWAY", "").strip()
    if env_gw and _ip_in_net(env_gw, net):
        return {"ip": env_gw, "iface": None, "source": "env",
                "is_wifi": None}
    for cand in _os_gateway_candidates():
        if _ip_in_net(cand["gateway"], net):
            return {"ip": cand["gateway"], "iface": cand.get("iface"),
                    "source": cand["source"],
                    "is_wifi": _wifi_like_iface(cand.get("iface"))}
    cfg = config.gateway_ip()
    if _ip_in_net(cfg, net):
        return {"ip": cfg, "iface": None, "source": "config-fallback",
                "is_wifi": None}
    hosts = list(net.hosts())
    return {"ip": str(hosts[1] if len(hosts) > 1 else hosts[0]),
            "iface": None, "source": "first-host", "is_wifi": None}


def detect_gateway_mac(gw_ip: str) -> str | None:
    """Gateway MAC via an ARP lookup, with OS-table fallback."""
    try:
        from scapy.all import getmacbyip
        mac = getmacbyip(gw_ip)
        if mac:
            norm = mac_intel.normalize_mac(mac)
            if norm:
                return norm
    except Exception:
        pass
    try:
        raw = read_arp_table().get(gw_ip)
        if raw:
            norm = mac_intel.normalize_mac(raw)
            if norm:
                return norm
    except Exception:
        pass
    return None


def gateway_info() -> dict:
    """Current gateway identity (from the last discovery run, else config)."""
    rep_gw = (LAST_REPORT or {}).get("gateway") or {}
    if rep_gw.get("ip"):
        return rep_gw
    gw = config.gateway_ip()
    return {"ip": gw, "mac": None, "vendor": None, "iface": None,
            "is_wifi": None, "source": "config-fallback"}


# ---------------------------------------------------------------------------
# Internet reachability (host -> outside) — cached 30s
# ---------------------------------------------------------------------------
_internet_cache: dict = {"ts": 0.0, "data": None}


def internet_status(force: bool = False) -> dict:
    """Quick outbound check from this host: is there Internet, what's the
    RTT to 1.1.1.1:443, and does the system resolver work?"""
    global _internet_cache
    if not force and _internet_cache["data"] and \
            time.time() - _internet_cache["ts"] < 30:
        return _internet_cache["data"]
    data = {"reachable": False, "rtt_ms": None, "dns_ok": False,
            "checked_at": None}
    from datetime import datetime
    data["checked_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M") + " UTC"
    t0 = time.time()
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=3)
        s.close()
        data["reachable"] = True
        data["rtt_ms"] = round((time.time() - t0) * 1000)
    except OSError:
        pass
    try:
        socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        data["dns_ok"] = True
    except OSError:
        pass
    _internet_cache = {"ts": time.time(), "data": data}
    return data


def host_ips() -> set[str]:
    """All IPv4 addresses of THIS machine (every interface). Used to make
    sure the app's own traffic (DNS queries from the admin PC) is never
    recorded in history — the host is not a target device."""
    ips = {config.detect_host_ip()}
    try:
        from scapy.all import conf
        for i in conf.ifaces.values():
            ip = getattr(i, "ip", None)
            if ip and ip != "0.0.0.0":
                ips.add(str(ip))
    except Exception:
        pass
    return {ip for ip in ips if ip and not ip.startswith("127.")}


def _candidate_ok(ip: str, net, own_ip: str, gw: str) -> tuple[bool, str]:
    """Validate one discovered IP before it can become a device."""
    if ip == gw:
        return False, "gateway"
    if ip == own_ip:
        return False, "self"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "invalid"
    if not addr.is_private or addr.is_multicast or addr.is_loopback:
        return False, "not-private"
    if addr not in net:
        return False, "outside-subnet"
    if addr == net.network_address:
        return False, "network-addr"
    if addr == net.broadcast_address:
        return False, "broadcast"
    return True, ""


def discover_devices() -> list[dict]:
    """Discover devices on the LAN by merging three methods.

    Returns list of dicts: {ip, mac, vendor, is_private_mac, os_guess, ttl}
    with MACs normalized to AA:BB:CC:DD:EE:FF. Gateway, this host, and
    non-unicast addresses are excluded. Per-method counts land in
    LAST_REPORT (shown in the UI and logged).
    """
    global LAST_REPORT
    start = time.time()

    gw = config.gateway_ip()

    # --- choose the REAL LAN network + interface (multi-adapter safe) ----
    candidates = _candidate_networks()
    net, arp_hosts, iface, own_ip = _select_network(candidates, gw)
    logger.info("selected network %s (iface %s, src %s) from %d candidate(s)",
                net, iface or "auto", own_ip, len(candidates))

    # --- resolve the gateway for THIS network and pin it in config -------
    gw_info = resolve_gateway(net, own_ip)
    config.set_resolved_gateway(gw_info["ip"])
    gw = gw_info["ip"]
    gw_mac = detect_gateway_mac(gw)
    gw_info["mac"] = gw_mac
    gw_info["vendor"] = (mac_intel.lookup_vendor(gw_mac) if gw_mac else None)
    logger.info("gateway for %s: %s (mac %s, iface %s, source %s)",
                net, gw, gw_mac or "?", gw_info.get("iface") or "?",
                gw_info["source"])

    # --- merge in the OS neighbour table --------------------------------
    try:
        table_hosts = read_arp_table()
    except Exception:
        table_hosts = {}
    logger.info("neighbour table: %d entries", len(table_hosts))

    hosts: dict[str, str] = {}
    for ip, mac in table_hosts.items():   # table first (authoritative)
        hosts[ip] = mac
    for ip, mac in arp_hosts.items():     # ARP scan fills the gaps
        hosts.setdefault(ip, mac)

    # --- ping sweep the chosen network (wakes hosts + TTL evidence) -----
    ttl_map: dict[str, int | None] = {}
    try:
        ttl_map = subnet_ping_sweep(net)
    except Exception as exc:
        logger.warning("ping sweep failed: %s", exc)
    if len(hosts) < 8:  # thin table — re-read after the sweep woke hosts
        try:
            for ip, mac in read_arp_table().items():
                hosts.setdefault(ip, mac)
        except Exception:
            pass

    # --- validate + build ------------------------------------------------
    devices: list[dict] = []
    skipped = {"gateway": 0, "self": 0, "bad_mac": 0, "other": 0}
    for ip, mac in hosts.items():
        ok, reason = _candidate_ok(ip, net, own_ip, gw)
        if not ok:
            skipped[reason if reason in skipped else "other"] += 1
            continue
        norm = mac_intel.normalize_mac(mac)
        if not norm:
            skipped["bad_mac"] += 1
            logger.debug("skipping %s: unparseable MAC %r", ip, mac)
            continue
        devices.append({
            "ip": ip,
            "mac": norm,
            "vendor": mac_intel.lookup_vendor(norm),
            "is_private_mac": mac_intel.is_private_mac(norm),
            "os_guess": ttl_os_guess(ttl_map.get(ip)),
            "ttl": ttl_map.get(ip),
        })

    # dedupe by MAC (a MAC seen on two IPs = it moved; keep the last)
    by_mac: dict[str, dict] = {}
    for d in devices:
        by_mac[d["mac"]] = d
    devices = list(by_mac.values())

    LAST_REPORT = {
        "iface": iface,
        "network": str(net),
        "host_ip": own_ip,
        "candidates": len(candidates),
        "arp_broadcast": len(arp_hosts),
        "neighbor_table": len(table_hosts),
        "ping_sweep": len(ttl_map),
        "unique": len(devices),
        "gateway": gw_info,
        "skipped": skipped,
        "elapsed_s": round(time.time() - start, 2),
    }
    logger.info("discovery report: %s", LAST_REPORT)
    return devices


def sync_discovered_devices(found: list[dict]) -> dict:
    """Upsert discovered devices into the registry (idempotent).

    Shared by the background poller AND the manual "Scan now" button, so a
    manual scan populates the Devices page immediately. Fires Socket.IO
    join events, new-device alerts and activity entries only for MACs that
    were genuinely never seen before; refreshes last_seen/current_ip for
    everyone else. One bad device can never abort the whole pass — each
    device is committed/isolated on its own.
    """
    from netshield.audit import log_activity
    from netshield.extensions import db, socketio
    from netshield.models.models import Device, utcnow
    from netshield.services.alerts_dispatch import create_alert
    from netshield.services.traffic_control import controller

    now = utcnow()
    new_macs: list[str] = []
    updated_macs: list[str] = []
    for info in found:
        mac = info.get("mac")
        norm = mac_intel.normalize_mac(mac) if mac else ""
        if not norm:
            continue
        try:
            device = db.session.get(Device, norm)
            is_new = device is None
            hostname_hint = info.get("hostname")
            if device is None:
                device = Device(
                    mac=norm, current_ip=info.get("ip"),
                    vendor=info.get("vendor"),
                    is_private_mac=bool(info.get("is_private_mac")),
                    os_guess=info.get("os_guess"),
                    hostname=hostname_hint,
                    first_seen=now, last_seen=now)
                db.session.add(device)
                new_macs.append(norm)
            else:
                changed = (device.current_ip != info.get("ip")
                           or device.os_guess != info.get("os_guess"))
                device.current_ip = info.get("ip")
                device.vendor = info.get("vendor") or device.vendor
                device.is_private_mac = bool(info.get("is_private_mac"))
                device.os_guess = info.get("os_guess") or device.os_guess
                if hostname_hint and not device.hostname:
                    device.hostname = hostname_hint
                device.last_seen = now
                if changed:
                    updated_macs.append(norm)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            logger.warning("could not persist device %s: %s", mac, exc)
            continue

        try:
            payload = {
                "mac": norm, "ip": info.get("ip"),
                "vendor": device.vendor, "nickname": device.nickname,
        "display_name": device.display_name,
        "hostname": device.hostname,
        "os_guess": device.os_guess,
                "control_state": device.control_state,
                "is_new": is_new,
            }
            socketio.emit("device_join", payload)
        except Exception:
            pass
        if is_new:
            try:
                create_alert(
                    alert_type="new_device",
                    message=(f"New device joined: "
                             f"{device.display_name} ({norm}) at "
                             f"{info.get('ip')}"),
                    severity="info", device_mac=norm)
                log_activity("system",
                             f"new device discovered {norm} ({info.get('ip')})")
            except Exception as exc:
                logger.debug("new-device alert failed: %s", exc)
        # DHCP re-lease with an active session -> rebuild session
        if device.control_state != "none" and device.current_ip:
            try:
                controller.apply(device)
            except Exception:
                pass
    return {"new": new_macs, "updated": updated_macs,
            "total": len(found)}
