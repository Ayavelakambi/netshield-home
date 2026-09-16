# NetShield Home

A self-hosted home / small-office network security & parental-control web
app. It merges two feature sets into one product:

1. **LAN monitoring & parental control** — device discovery, per-device
   traffic control (cut / throttle / category block), DNS-based domain
   history with top-domain leaderboards, "bedtime" scheduling.
2. **A lightweight XDR-style security console** — port scanning with risk
   scoring, a static vulnerability advisory database, threat-intelligence
   panels with remediation guidance, WiFi IDS (evil-twin / open-network
   detection) and an RF channel optimizer.

Everything runs on your LAN from one machine. **No cloud services are
required** — SQLite file storage, zero external databases.

> ⚠️ **Scope boundaries (stated plainly)**
> - **No TLS/HTTPS interception.** NetShield Home has no fake root CA and
>   does not MITM encrypted traffic. It sees *which domains* devices query
>   (via DNS), **not** search terms, page content, or anything inside
>   HTTPS. The UI and code state this explicitly — nothing is inferred or
>   fabricated from the DNS layer.
> - **No exploitation.** The vulnerability database is a static, read-only
>   advisory table. NetShield Home never attempts to exploit a finding.
> - **No action outside your local /24.** Every control-plane action
>   (port scan, ARP spoof, cut, throttle) validates its target through the
>   shared safety gate: inside the local /24, not the gateway, not the
>   host itself. Violations are rejected and logged (see *Safety model*).

---

## Features

| Area | What you get |
|---|---|
| **Devices** | ARP-based discovery (Scapy), OS ARP-table + ping-sweep fallback, TTL-based OS fingerprinting, MAC-keyed registry (survives DHCP re-leases), OUI vendor lookup with randomised-MAC flagging, **automatic device names** (nickname → NetBIOS → mDNS → reverse DNS → IP; resolved in the background, stored, shown everywhere, live-updated), inline-SVG topology graph, device groups (Kids / Guests / IoT / Trusted seeded, fully editable). **NetCut-style one-click controls**: per-row Cut/Restore buttons, red tint for cut devices, and Cut all / Restore all — cuts persist across reconnects. |
| **Traffic control** | One ARP-spoof + software-relay session per device that can **cut** (drop all), **throttle** (token-bucket rate limit), and **category-block** (DNS black-hole) simultaneously. Sessions now actually run (a startup-guard bug previously prevented threads from launching), operate on the gateway-routed interface, and report **effectiveness** (warming / effective / ineffective) so a silent no-op is impossible. Schedule rules ("bedtime mode") evaluated every minute. |
| **DNS history** | Hourly-rolled-up `DnsQueryLog` (no per-query row explosion), top-domains leaderboard (today / 7 days / 30 days, network-wide or per device), searchable/filterable/paginated history table, CSV export. **Full DNS capture mode**: ARP-spoofs ALL devices and records every device's DNS queries through the relay, so per-device domain history works on any network — not just traffic that passively crosses this host's interface. The real resolved domain is always shown in plain text — category badges are tags next to it, never a replacement. |
| **XDR console** | Thread-pool TCP-connect port scans of the common-port list, five-level risk scoring, static vulnerability advisories (well-known CVEs such as EternalBlue, BlueKeep, Heartbleed, regreSSHion…), plain-language threat-intel panels with concrete remediation ("Disable Telnet", "Replace FTP with SFTP"). |
| **WiFi** | One record per BSSID (netsh on Windows, nmcli on Linux; "unsupported on this platform" elsewhere), evil-twin + open/WEP detection de-duplicated by stable keys, RF channel optimizer (2.4 GHz: only 1/6/11 are non-overlapping; 5 GHz scored independently). |
| **Bandwidth** | Per-device up/down byte counters sampled periodically, daily + weekly SVG charts (no external chart library). |
| **Alerts & reporting** | New-device / high-risk-port / evil-twin / open-network / data-threshold alerts with live push; weekly CSV (zero dependencies) and PDF (optional reportlab) reports with a title page; full admin activity log. |
| **Realtime** | Socket.IO pushes device join/leave, new alerts, control-state changes and scan completion to open pages without a refresh. |
| **Privileges & gateway** | The host's admin/root status, Npcap presence and Scapy availability are checked and shown in the UI, with a one-click **Restart as Administrator** (Windows UAC) — `python run.py --elevate` does the same from the console. The **WiFi/LAN gateway is resolved from the OS routing tables** (`route print -4` + `netsh interface ipv4 show config` on Windows, `/proc/net/route` + `ip route` on Linux, `route -n get default` on macOS), pinned into the safety gate so the router can never be scanned or controlled, and shown with its MAC + vendor on the WiFi page and dashboard. An **internet reachability check** (host → 1.1.1.1:443 + resolver test) shows whether the network's path to the outside is up. |

---

## Requirements

- **Python 3.11+**
- **Windows:** [Npcap](https://npcap.com) (the packet-capture driver Scapy
  uses) — install it separately, then **run NetShield Home as
  Administrator**.
- **Linux/macOS:** run as **root** (raw sockets). On Linux, WiFi scanning
  additionally needs NetworkManager's `nmcli`.

Without these privileges the app **still runs** — it degrades gracefully:
discovery falls back to the OS ARP/neighbour table and a subnet ping sweep,
and the UI shows a clear banner:

> *Packet capture unavailable — showing degraded discovery*

and disables the features that need capture: port scanning, ARP-spoof-based
cut/throttle, DNS sniffing, and WiFi BSSID scanning.

---

## Setup

```bash
# 1. create + activate a virtualenv (recommended)
python -m venv venv
# Windows: venv\Scripts\activate     Linux/macOS: source venv/bin/activate

# 2. install dependencies
pip install -r requirements.txt

# 3. (optional) PDF reports
pip install reportlab          # CSV export works without it

# 4. initialise the database and create the admin account
python create_db.py            # prompts for username + password
# or: python create_db.py --auto                     (random password, printed once)
# or: python create_db.py --username admin --password secret123

# 5. run (as Administrator / root)
python run.py                  # http://localhost:5000
```

**First run without `create_db.py`:** if the database is empty, `run.py`
auto-generates an `admin` account with a random password, prints it **once**
to the console, and forces a password change on first login.

### Environment variables

| Variable | Purpose |
|---|---|
| `NETSHIELD_HOST` / `NETSHIELD_PORT` | bind address / port (defaults `0.0.0.0:5000`) |
| `NETSHIELD_SUBNET` | override detected subnet, e.g. `192.168.1.0/24` |
| `NETSHIELD_GATEWAY` | override gateway IP detection |
| `NETSHIELD_DEBUG=1` | Flask debug mode |

There is no demo/simulation mode: everything shown in the app is real data
from your network.

---

## Safety model

Every function that can scan ports, ARP-spoof, cut or throttle a target
must first pass the target through **`netshield/safety.py`** — the *single*
shared enforcement module (never re-implemented per caller). A target is
rejected (with an audit + log entry) unless it is:

- (a) inside the detected local /24,
- (b) **not** the gateway IP,
- (c) **not** the host machine's own IP,

plus network/broadcast/loopback/multicast exclusions. The gate is enforced
inside the service functions themselves, so it also protects the scheduler
thread and any future caller — not just HTTP routes. `run.py` prints the
detected subnet/gateway/host at startup for transparency.

## Packet-level code — audit trail

All packet manipulation lives in two services, both heavily commented:

- `services/network_scanner.py` — ARP discovery (`srp(Ether/ARP(pdst))`),
  TTL fingerprinting, OS ARP-table + ping-sweep fallbacks.
- `services/traffic_control.py` — the ARP-spoof + relay engine:
  - **Poisoning** (re-sent every 3 s): "gateway is at our MAC" to the
    target, "target is at our MAC" to the gateway.
  - **Relay**: sniff frames to/from the target, rewrite only the Ethernet
    destination (payloads and checksums untouched), pass through a token
    bucket when throttling, drop when cutting.
  - **DNS blocking**: UDP/53 queries are inspected; blocked domains get a
    forged `0.0.0.0` answer (client fails fast instead of hanging).
  - **Restore**: correct ARP announcements in both directions when a
    session stops, so the network heals immediately.
- `services/history.py` — passive DNS sniffer (reads only; never injects).
- `services/bandwidth.py` — passive per-MAC byte accounting.

When the process exits, poisoning stops and the ARP cache re-learns the
real MACs within seconds.

## Blocklist (adult-content category)

The adult category is **fetched at runtime, never hardcoded**, from the
actively-maintained [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
project: the `fakenews-gambling-porn` alternates file first, falling back
to the base `hosts` file. `0.0.0.0 domain.tld` lines are parsed into a
domain set, cached to `data/blocklist/stevenblack.json` with a fetch
timestamp (works offline), and refreshed on a daily schedule plus a manual
"Refresh now" button on the Settings page. Category matching is by
**registrable (base) domain**, so `m.youtube.com` matches `youtube.com`.

## Roles & permissions

| Action | admin | standard |
|---|---|---|
| Dashboard, devices, reports, history (read) | ✅ | ✅ |
| User management, activity log, settings | ✅ | ❌ (403 + flash) |
| Port scans | ✅ | ❌ |
| Traffic control (cut / throttle / block), schedule rules | ✅ | ❌ |
| WiFi scan trigger | ✅ | ❌ (view only) |
| Alert acknowledge / clear | ✅ | ❌ |

Passwords are PBKDF2-SHA256 with a per-user random salt (200k iterations),
never stored or logged in plaintext. Session cookies are signed with a
persistent key stored in `data/secret_key` (created once — sessions survive
restarts), `HttpOnly` + `SameSite=Lax`.

## Project layout

```
netshield-home/
├── run.py                     # entrypoint (banner, socketio.run)
├── create_db.py               # schema + first admin (interactive/--auto/--reset)
├── config.py                  # subnet/gateway detection, intervals, secret key
├── requirements.txt
├── data/                      # runtime: netshield.db, secret_key, oui.json,
│                              #          blocklist cache (auto-created)
└── netshield/
    ├── __init__.py            # app factory, background threads, first-run admin
    ├── extensions.py          # db / login_manager / socketio
    ├── safety.py              # ★ the shared safety gate
    ├── security.py            # PBKDF2 hashing, admin_required
    ├── audit.py               # activity-log writer
    ├── models/models.py       # all SQLAlchemy models
    ├── services/              # framework-agnostic logic
    │   ├── network_scanner.py # ARP discovery + fallbacks + capability check
    │   ├── port_scanner.py    # TCP-connect scan, alerts
    │   ├── risk_analyzer.py   # 5-level port/status risk scoring
    │   ├── vulnerability_db.py# static advisory table (read-only)
    │   ├── threat_intelligence.py
    │   ├── dns_categories.py  # categories + StevenBlack fetch/cache
    │   ├── traffic_control.py # unified cut/throttle/block sessions
    │   ├── wireless_ids.py    # netsh/nmcli scan + evil-twin/open detection
    │   ├── rf_optimizer.py    # channel congestion scoring
    │   ├── hostname_resolver.py  # nickname→NetBIOS→mDNS→rDNS→IP
    │   ├── mac_intel.py       # OUI lookup + randomised-MAC detection
    │   ├── bandwidth.py       # sampling engine + daily/weekly rollups
    │   ├── history.py         # DNS sniffing, hourly rollups, leaderboards
    │   ├── scheduler.py       # bedtime rules, once a minute
    │   ├── alerts_dispatch.py # alerts + webhook/Discord/Telegram
    │   └── reports.py         # CSV (stdlib) + PDF (reportlab, optional)
    ├── blueprints/            # auth, dashboard, devices, wifi, traffic,
    │                          # alerts, reports, activity_logs, users, settings
    ├── templates/             # Jinja2, SVG charts/topology, no SPA
    └── static/                # style.css, app.js (Socket.IO client)
```

## OUI vendor data

A compact built-in OUI table covers common home-LAN vendors. To use a
larger database, drop a JSON file at `data/oui.json` with the format
`{"AA:BB:CC": "Vendor Name", ...}` (e.g. export the IEEE OUI list); it is
loaded automatically and takes precedence. MACs with the locally-administered
bit set are flagged as **randomised/private** in the UI instead of showing
a wrong vendor.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Banner "Packet capture unavailable…" | Install Npcap (Windows) or run as root (Linux/macOS), then restart. The app keeps working degraded meanwhile. |
| Port scan returns everything Filtered | A firewall is dropping probes; that is the correct, safe answer. |
| Traffic control says "cannot be applied" | Requires capture privileges (same as above). Desired states are saved and enforced automatically once capture is available. |
| WiFi page shows "unsupported on this platform" | Scanning uses `netsh wlan` (Windows) or `nmcli` (Linux/NetworkManager); other platforms get a clean status, not a crash. |
| `data/netshield.db` deleted? | `python create_db.py` recreates everything; device registry rebuilds from the next discovery pass. |
| No DNS history | DNS sniffing needs capture privileges (see above). Also note: the sniffer only sees DNS queries that pass through the interface the host can hear. If NetShield runs on a wired PC while phones/tablets are on Wi-Fi, the access point handles client→router queries internally and the wired host won't see them. The Traffic page shows a live **DNS capture** status box (queries seen / domains logged) so you can tell immediately whether traffic is visible. To capture Wi-Fi clients' queries, run NetShield on a machine that acts as the LAN's DNS server (e.g. run `dnsmasq` there and set the router's DHCP DNS option to its IP), or use a switch port mirror. ARP-based discovery is unaffected — it uses broadcasts, which every host sees. |

## Security notes for a home tool

- Run it on a machine you trust; it has admin/root-level LAN capabilities.
- It listens on `0.0.0.0` by default so other LAN devices can open it —
  bind it to localhost (`--host 127.0.0.1`) if you only need it locally.
- It ships without HTTPS; it is designed for a trusted home network.
  (A reverse proxy with TLS in front of it works fine.)
