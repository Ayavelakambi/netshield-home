"""Local port scanner — thread-pool TCP connect against a fixed common-port list.

No raw sockets are needed for the connect scan itself, so it does not require
privileges beyond what discovery already has. The target is validated through
netshield.safety BEFORE anything happens (inside local /24, not the gateway,
not this host).

Common-port list per spec: 20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
443, 445, 3306, 3389, 5900, 8080, 8443, plus RTSP (554). (No further ports
were used by any prior source project, so the list ends there.)
"""
from __future__ import annotations

import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

import config
from netshield.audit import log_activity
from netshield.extensions import db
from netshield.models.models import PortResult, Scan, utcnow
from netshield.safety import SafetyViolation, assert_safe_target
from netshield.services import risk_analyzer, vulnerability_db
from netshield.services.alerts_dispatch import create_alert

logger = logging.getLogger("netshield.portscan")

COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                554, 3306, 3389, 5900, 8080, 8443]

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS-SSN", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 554: "RTSP", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def _check_port(ip: str, port: int, timeout: float) -> str:
    """TCP connect test. Open = accepted; Filtered = timeout (firewall drop);
    Closed = refused."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect((ip, port))
            return "Open"
        except socket.timeout:
            return "Filtered"
        except (ConnectionRefusedError, ConnectionResetError, OSError):
            return "Closed"
    finally:
        sock.close()


def scan_device(device) -> int:
    """Scan one device (validated via the safety gate). Returns the Scan id.

    Alerts: old active high-risk-port alerts for this device are cleared
    FIRST, then fresh ones are created for anything High/Critical — so a
    re-scan replaces stale findings instead of accumulating duplicates.

    The heavy lifting runs in a worker thread which re-fetches its own
    Device/Scan rows inside a fresh app context — ORM instances created in
    the request thread's session must never be touched from another thread.
    """
    ip = device.current_ip
    mac = device.mac
    if not ip:
        raise ValueError("device has no current IP")
    # HARD SAFETY GATE — the single shared enforcement point (see safety.py).
    assert_safe_target(ip)

    scan = Scan(device_ip=ip, status="running")
    db.session.add(scan)
    db.session.commit()

    # capture the app in THIS thread (the worker thread has no context)
    from flask import current_app, has_app_context
    _app = current_app._get_current_object() if has_app_context() else None

    def _run():
        ctx = _app.app_context() if _app is not None else None
        if ctx is not None:
            ctx.push()
        try:
            # fresh ORM objects bound to THIS thread's session
            from netshield.models.models import Alert, Device
            dev = db.session.get(Device, mac)
            scan_row = db.session.get(Scan, scan.id)
            if dev is None or scan_row is None:
                return
            dev_ip = dev.current_ip or ip

            results = []
            with ThreadPoolExecutor(max_workers=config.PORT_SCAN_WORKERS) as pool:
                    futures = {pool.submit(_check_port, dev_ip, p,
                                           config.PORT_SCAN_TIMEOUT): p
                               for p in COMMON_PORTS}
                    for fut in futures:
                        port = futures[fut]
                        status = fut.result()
                        risk = risk_analyzer.risk_for(port, status)
                        vulns = vulnerability_db.advisories_for_port(port)
                        entry = {
                            "port": port,
                            "service_name": SERVICES.get(port),
                            "status": status,
                            "risk_level": risk,
                            "cve_id": (vulns[0]["cve"] if vulns else None),
                            "cvss": (vulns[0]["cvss"] if vulns else None),
                            "description": (vulns[0]["description"] if vulns
                                            else None),
                            "recommendation": (vulns[0]["recommendation"]
                                               if vulns else None),
                        }
                        results.append(entry)

            # clear stale active findings for this device, then write fresh ones
            stale = Alert.query.filter_by(device_mac=mac, active=True,
                                          type="high_risk_port").all()
            for a in stale:
                a.active = False

            for r in sorted(results, key=lambda x: x["port"]):
                db.session.add(PortResult(scan_id=scan_row.id, **r))

            scan_row.status = "complete"
            scan_row.completed_at = utcnow()
            db.session.commit()

            for r in results:
                if r["status"] == "Open" and r["risk_level"] in (
                        "High", "Critical"):
                    create_alert(
                        alert_type="high_risk_port",
                        message=(f"{dev.display_name} ({dev_ip}) has an open "
                                 f"{r['service_name'] or r['port']} port — "
                                 f"{r['risk_level']} risk"
                                 + (f" ({r['cve_id']})" if r["cve_id"] else "")),
                        severity=r["risk_level"].lower(),
                        device_mac=mac,
                    )

            open_count = sum(1 for r in results if r["status"] == "Open")
            from netshield.extensions import socketio
            socketio.emit("scan_complete", {
                "scan_id": scan_row.id,
                "device_ip": dev_ip,
                "device_mac": mac,
                "open_count": open_count,
                "high_risk": sum(1 for r in results
                                 if r["risk_level"] in ("High", "Critical")),
            })
        except SafetyViolation:
            try:
                scan_row = db.session.get(Scan, scan.id)
                scan_row.status = "error"
                db.session.commit()
            except Exception:
                pass
            raise
        except Exception as exc:
            logger.exception("port scan failed for %s", ip)
            try:
                scan_row = db.session.get(Scan, scan.id)
                scan_row.status = "error"
                db.session.commit()
            except Exception:
                pass
        finally:
            if ctx is not None:
                ctx.pop()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return scan.id
