"""SQLAlchemy schema — all NetShield Home models.

Field names/types follow the project spec exactly. JSON columns are stored as
SQLite TEXT via SQLAlchemy's JSON type. Timestamps are naive UTC datetimes
(converted to local time in templates via the ``localtime`` filter).
"""
from __future__ import annotations

from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import (
    JSON, BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer,
    String, Text,
)

from netshield.extensions import db


def utcnow() -> datetime:
    """Naive UTC 'now' used for every timestamp column."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)   # PBKDF2-SHA256 hex
    salt = Column(String(32), nullable=False)            # per-user random salt
    role = Column(String(16), nullable=False, default="standard")  # admin|standard
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime, nullable=True)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.username} ({self.role})>"


class Group(db.Model):
    """Device group with shared default controls (Kids, Guests, IoT, Trusted...)."""
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    default_blocked_categories = Column(JSON, default=list)   # category names
    default_speed_limit_kbps = Column(Integer, nullable=True)
    bedtime_start = Column(String(5), nullable=True)          # "HH:MM"
    bedtime_end = Column(String(5), nullable=True)            # "HH:MM"
    bedtime_days = Column(JSON, default=list)                 # weekday ints 0-6


class Device(db.Model):
    """Persistent device registry — keyed by MAC so identity survives DHCP.

    The MAC is the primary key; the current IP is just the latest lease.
    """
    __tablename__ = "devices"
    mac = Column(String(17), primary_key=True)
    nickname = Column(String(64), nullable=True)
    hostname = Column(String(255), nullable=True)  # NetBIOS/mDNS/rDNS resolved
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    current_ip = Column(String(45), nullable=True)
    vendor = Column(String(64), nullable=True)      # OUI lookup
    is_private_mac = Column(Boolean, default=False) # locally-administered bit
    os_guess = Column(String(32), nullable=True)    # TTL + open-port heuristics
    blocked_categories = Column(JSON, default=list) # per-device category names
    speed_limit_kbps = Column(Integer, nullable=True)
    control_state = Column(String(16), nullable=False, default="none")
    # ^ none | cut | throttled
    safe_mode = Column(Boolean, default=False)        # allowlist-only internet
    allowlist_domains = Column(JSON, default=list)    # safe-mode allowlist
    data_cap_mb = Column(Integer, nullable=True)      # daily data cap (MB)
    internet_start = Column(String(5), nullable=True) # internet allowed window
    internet_end = Column(String(5), nullable=True)
    bypass = Column(Boolean, default=False)           # unrestricted device:
    # ^ exempt from ALL blocking (even network-wide) — never cut/throttled

    group = db.relationship("Group", backref="devices")

    ONLINE_WINDOW_SECONDS = 5 * 60

    @property
    def display_name(self) -> str:
        # nickname (user-set) > resolved hostname > IP > MAC
        return self.nickname or self.hostname or self.current_ip or self.mac

    @property
    def is_online(self) -> bool:
        if not self.last_seen:
            return False
        return (utcnow() - self.last_seen).total_seconds() < self.ONLINE_WINDOW_SECONDS

    def effective_blocked_categories(self) -> list[str]:
        """Device categories + group defaults, de-duplicated, order preserved."""
        cats: list[str] = list(self.blocked_categories or [])
        if self.group and self.group.default_blocked_categories:
            for c in self.group.default_blocked_categories:
                if c not in cats:
                    cats.append(c)
        return cats


class DnsQueryLog(db.Model):
    """One row per device+domain+hour bucket with an incrementing counter.

    Rolled up per hour on purpose — a per-query row per DNS request would
    explode the table on a busy LAN.
    """
    __tablename__ = "dns_query_log"
    id = Column(Integer, primary_key=True)
    device_mac = Column(String(17), ForeignKey("devices.mac"), nullable=True,
                        index=True)
    domain = Column(String(255), nullable=False, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)  # hour bucket start
    count = Column(Integer, nullable=False, default=0)


class BandwidthSample(db.Model):
    """Periodic per-device byte counters (delta since the previous sample)."""
    __tablename__ = "bandwidth_samples"
    id = Column(Integer, primary_key=True)
    device_mac = Column(String(17), ForeignKey("devices.mac"), nullable=False,
                        index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    bytes_up = Column(BigInteger, nullable=False, default=0)
    bytes_down = Column(BigInteger, nullable=False, default=0)


class Scan(db.Model):
    """A completed/in-progress port scan of one device IP."""
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    device_ip = Column(String(45), nullable=False)
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(16), nullable=False, default="running")
    # ^ running | complete | error

    results = db.relationship("PortResult", backref="scan", lazy="selectin")


class PortResult(db.Model):
    __tablename__ = "port_results"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    service_name = Column(String(32), nullable=True)
    status = Column(String(16), nullable=False)  # Open | Closed | Filtered
    risk_level = Column(String(16), nullable=True)  # None|Low|Medium|High|Critical
    cve_id = Column(String(32), nullable=True)
    cvss = Column(Float, nullable=True)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)


class Alert(db.Model):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    type = Column(String(32), nullable=False, index=True)
    # ^ new_device | high_risk_port | evil_twin | open_network | data_threshold ...
    device_mac = Column(String(17), ForeignKey("devices.mac"), nullable=True,
                        index=True)
    message = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False, default="info", index=True)
    # ^ info | low | medium | high | critical
    created_at = Column(DateTime, default=utcnow, index=True)
    active = Column(Boolean, nullable=False, default=True)

    device = db.relationship("Device")


class ActivityLog(db.Model):
    __tablename__ = "activity_log"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), nullable=False, index=True)
    action = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=utcnow, index=True)


class WifiNetwork(db.Model):
    """One row per BSSID (not per SSID) so multiple APs with the same SSID
    (evil twins, mesh nodes) stay individually visible."""
    __tablename__ = "wifi_networks"
    id = Column(Integer, primary_key=True)
    ssid = Column(String(64), nullable=True)  # None for hidden networks
    bssid = Column(String(17), unique=True, nullable=False)
    channel = Column(Integer, nullable=True)
    band = Column(String(8), nullable=True)   # 2.4 | 5
    signal_strength = Column(Integer, nullable=True)  # percent 0-100
    encryption = Column(String(16), nullable=True)    # Open|WEP|WPA2|WPA3
    last_seen = Column(DateTime, default=utcnow)


class ScheduleRule(db.Model):
    """Scheduler ("bedtime mode") rule: time window + optional weekdays."""
    __tablename__ = "schedule_rules"
    id = Column(Integer, primary_key=True)
    target_type = Column(String(8), nullable=False)  # device | group
    # target_id: device MAC ("AA:BB:..") when target_type=device, else the
    # group id as a string — stored as text so both fit the same column
    target_id = Column(String(64), nullable=False)
    name = Column(String(64), nullable=False)
    start_time = Column(String(5), nullable=False)   # "HH:MM"
    end_time = Column(String(5), nullable=False)     # "HH:MM"
    days_of_week = Column(JSON, default=list)        # weekday ints 0-6; [] = every day
    mode = Column(String(32), nullable=False)
    # ^ block_all_except_allowlist | block_categories
    allowlist_domains = Column(JSON, nullable=True)  # for block_all mode
    blocked_categories = Column(JSON, nullable=True) # for block_categories mode
    active = Column(Boolean, nullable=False, default=True)


class Setting(db.Model):
    """Simple key/value store for user-configurable settings."""
    __tablename__ = "settings"
    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False, default="null")  # JSON-encoded

    @classmethod
    def get(cls, key: str, default=None):
        import json
        row = db.session.get(cls, key)
        if row is None:
            return default
        try:
            return json.loads(row.value)
        except ValueError:
            return default

    @classmethod
    def set(cls, key: str, value) -> None:
        import json
        row = db.session.get(cls, key)
        if row is None:
            row = cls(key=key, value=json.dumps(value))
            db.session.add(row)
        else:
            row.value = json.dumps(value)
        db.session.commit()
