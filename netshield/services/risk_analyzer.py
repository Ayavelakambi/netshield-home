"""Risk scoring per port/status combination — five levels.

None (closed/filtered), Low, Medium, High, Critical.
Examples per spec: Telnet(23) open = Critical, FTP(21) open = High,
SSH(22) open = Medium, DNS(53) open = Low.
"""
from __future__ import annotations

# risk level for an OPEN port, keyed by port number
RISK_BY_PORT: dict[int, str] = {
    20: "Low",        # FTP-data
    21: "High",       # FTP — cleartext creds, backdoors
    22: "Medium",     # SSH — patching risk, brute force
    23: "Critical",   # Telnet — cleartext, ancient
    25: "Low",        # SMTP
    53: "Low",        # DNS
    80: "Low",        # HTTP
    110: "Low",       # POP3
    135: "Medium",    # MSRPC
    139: "Medium",    # NetBIOS
    143: "Low",       # IMAP
    443: "Low",       # HTTPS
    445: "High",      # SMB — EternalBlue family
    554: "Medium",    # RTSP — camera firmware
    3306: "Medium",   # MySQL
    3389: "High",     # RDP — BlueKeep, brute force
    5900: "High",     # VNC — weak auth history
    8080: "Medium",   # HTTP alt — often admin panels
    8443: "Medium",   # HTTPS alt
}

LEVEL_ORDER = ["None", "Low", "Medium", "High", "Critical"]

LEVEL_SCORE = {level: i for i, level in enumerate(LEVEL_ORDER)}

LEVEL_COLOR = {
    "None": "#6b7280",
    "Low": "#3b82f6",
    "Medium": "#f0a742",
    "High": "#ef7d3b",
    "Critical": "#e05252",
}


def risk_for(port: int, status: str) -> str:
    """Risk level for a (port, status) pair."""
    if status != "Open":
        return "None"
    return RISK_BY_PORT.get(port, "Medium")


def risk_score(level: str) -> int:
    return LEVEL_SCORE.get(level, 0)
