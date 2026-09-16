"""Threat-intelligence panel — plain-language explainers per open port.

Combines the risk analyzer and the static advisory table into a readable
"what is this + how do I fix it" card for each open port. Read-only: this
service only explains findings, it never acts on them.
"""
from __future__ import annotations

from netshield.services import risk_analyzer, vulnerability_db

_SERVICE_HINT = {
    21: "File Transfer Protocol", 22: "Secure Shell", 23: "Telnet",
    25: "SMTP mail", 53: "DNS", 80: "HTTP web", 110: "POP3 mail",
    135: "Windows RPC", 139: "NetBIOS file sharing", 143: "IMAP mail",
    443: "HTTPS web", 445: "SMB file sharing", 554: "RTSP streaming",
    3306: "MySQL database", 3389: "Remote Desktop", 5900: "VNC remote desktop",
    8080: "HTTP (alternate)", 8443: "HTTPS (alternate)",
}


def panel_for(port: int, service_name: str, status: str) -> dict:
    """One advisory panel for a single scanned port."""
    risk = risk_analyzer.risk_for(port, status)
    vulns = vulnerability_db.advisories_for_port(port) if status == "Open" else []
    service = service_name or _SERVICE_HINT.get(port, f"port {port}")

    if status == "Open":
        plain = (
            f"Port {port} ({service}) is accepting connections on this device. "
            f"Every open port is an attack surface; it is rated {risk} risk."
        )
        if not vulns:
            plain += " No specific known issue is mapped for this port."
        remediation = "Close the port if the service is not required; otherwise " \
                      "update, configure and restrict it (see recommendations)."
    elif status == "Filtered":
        plain = f"Port {port} ({service}) did not respond — a firewall is " \
                "likely filtering it. No direct exposure."
        remediation = "No action needed; keep the firewall rule in place."
    else:
        plain = f"Port {port} ({service}) is closed. No exposure."
        remediation = "No action needed."

    return {
        "port": port,
        "service_name": service_name,
        "status": status,
        "risk_level": risk,
        "risk_score": risk_analyzer.risk_score(risk),
        "plain_language": plain,
        "remediation": remediation,
        "advisories": vulns,
    }


def panel_for_scan(port_results) -> list[dict]:
    """Panels for every result of a finished scan (open ports first)."""
    panels = [panel_for(r.port, r.service_name, r.status) for r in port_results]
    panels.sort(key=lambda p: (-p["risk_score"], p["port"]))
    return panels
