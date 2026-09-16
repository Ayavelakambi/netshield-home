"""NetShield Home — Flask application factory.

Starts the background services (device poller, capture engine, scheduler,
blocklist refresher, retention purger) and handles the first-run admin
account: with an empty database the app auto-generates a random admin
password, prints it ONCE to the console, and forces a password change on
first login (create_db.py is the explicit alternative for choosing a
password up front).
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from logging.handlers import RotatingFileHandler

from flask import Flask, request
from flask_login import current_user

import config
from netshield.extensions import db, login_manager, socketio

# ---------------------------------------------------------------------------
# Logging setup — never log passwords or session cookies
# ---------------------------------------------------------------------------
def _setup_logging(app: Flask) -> None:
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    root = logging.getLogger()
    root.addHandler(stream)
    root.setLevel(logging.INFO)
    try:
        fh = RotatingFileHandler(config.LOG_FILE, maxBytes=1_000_000,
                                 backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass
    app.logger.setLevel(logging.INFO)


def _init_sqlite_pragmas() -> None:
    """WAL mode + busy timeout for sane multi-threaded SQLite access."""
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "connect")
    def _set_pragma(dbapi_connection, _record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=10000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
        except Exception:
            pass


def _register_blueprints(app: Flask) -> None:
    from netshield.blueprints.activity_logs import bp as activity_bp
    from netshield.blueprints.alerts import bp as alerts_bp
    from netshield.blueprints.auth import bp as auth_bp
    from netshield.blueprints.dashboard import bp as dashboard_bp
    from netshield.blueprints.devices import bp as devices_bp
    from netshield.blueprints.reports import bp as reports_bp
    from netshield.blueprints.settings import bp as settings_bp
    from netshield.blueprints.tools import bp as tools_bp
    from netshield.blueprints.traffic import bp as traffic_bp
    from netshield.blueprints.users import bp as users_bp
    from netshield.blueprints.wifi import bp as wifi_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(wifi_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(activity_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(tools_bp)


def _register_template_helpers(app: Flask) -> None:
    from netshield.services import dns_categories, network_scanner

    @app.template_filter("localtime")
    def localtime_filter(dt):
        """Stored timestamps are naive UTC — convert to local wall-clock."""
        if dt is None:
            return ""
        import datetime
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        try:
            return dt.astimezone().strftime("%Y-%m-%d %H:%M")
        except (ValueError, OSError):
            return str(dt)

    @app.template_filter("weekdays")
    def weekdays_filter(days):
        """[0,1,5] -> 'Mon, Tue, Sat'; empty list -> 'every day'."""
        names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        if not days:
            return "every day"
        return ", ".join(names[i] for i in days if 0 <= i < 7)

    @app.template_filter("fmt_bytes")
    def fmt_bytes(n):
        try:
            n = int(n or 0)
        except (TypeError, ValueError):
            return "—"
        size = float(n)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{size:.0f} B"
            size /= 1024
        return f"{n} B"

    @app.context_processor
    def inject_globals():
        from netshield.version import VERSION
        return {
            "packet_capable": network_scanner.packet_capability_available(),
            "category_labels": {
                k: v["label"] for k, v in dns_categories.get_categories().items()
            },
            "active_nav": request.blueprint or "",
            "app_version": VERSION,
            "priv": _privilege_status_global(),
            "full_capture_active": _full_capture_active(),
            "scoped": True,
        }


def _full_capture_active() -> bool:
    """Cheap read of the full-DNS-capture flag (no DB access)."""
    try:
        from netshield.services.traffic_control import controller
        return controller.monitor_all
    except Exception:
        return False


_priv_cache: dict = {"ts": 0.0, "data": None}


def _privilege_status_global():
    """Privilege status for the banner — cached 5s, never blocks a page."""
    import time
    global _priv_cache
    now = time.time()
    if _priv_cache["data"] and now - _priv_cache["ts"] < 5:
        return _priv_cache["data"]
    try:
        from netshield.services import privileges
        _priv_cache = {"ts": now, "data": privileges.privilege_status()}
    except Exception:
        _priv_cache = {"ts": now, "data": {}}
    return _priv_cache["data"]


# ---------------------------------------------------------------------------
# First-run admin
# ---------------------------------------------------------------------------
def _ensure_first_run_admin(app: Flask) -> None:
    """No users yet -> create 'admin' with a random password, print ONCE,
    force a change on first login."""
    from netshield.models.models import Setting, User, utcnow
    if User.query.count() > 0:
        return
    from netshield.security import hash_password
    password = secrets.token_urlsafe(10)
    digest, salt = hash_password(password)
    admin = User(username="admin", password_hash=digest, salt=salt,
                 role="admin", created_at=utcnow())
    db.session.add(admin)
    db.session.commit()
    Setting.set("pending_pw_change", "admin")
    app.config["FIRST_RUN_ADMIN"] = {"username": "admin", "password": password}
    print("=" * 62)
    print("  NetShield Home — FIRST RUN")
    print("  Auto-generated administrator account (password change forced on")
    print("  first login):")
    print(f"      username : admin")
    print(f"      password : {password}")
    print("=" * 62)


# ---------------------------------------------------------------------------
# Background service threads
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Network-change handling: when the host connects to a DIFFERENT Wi-Fi/router,
# everything from the previous network (devices, DNS history, bandwidth,
# device alerts) is wiped once, then the new network is discovered fresh.
# ---------------------------------------------------------------------------
def _current_network_id() -> str:
    try:
        net = config.current_network()
        gw = config.gateway_ip()
        return f"{net}|{gw}"
    except Exception:
        return ""


def reset_network_data() -> dict:
    """Wipe everything tied to the previous network. Users, groups and
    settings (preferences) are kept — only network-observed data is cleared.
    Sessions for the old devices are stopped and their ARP state restored."""
    from netshield.audit import log_activity
    from netshield.models.models import (Alert, BandwidthSample, Device,
                                         DnsQueryLog, Setting)
    from netshield.services.history import set_relay_capture
    from netshield.services.traffic_control import controller

    controller.stop_all()
    n_dns = DnsQueryLog.query.delete(synchronize_session=False)
    n_bw = BandwidthSample.query.delete(synchronize_session=False)
    Alert.query.filter(Alert.device_mac.isnot(None)).update(
        {"device_mac": None}, synchronize_session=False)
    n_dev = Device.query.delete(synchronize_session=False)
    Setting.set("dns_capture_macs", [])
    controller.set_monitor_macs([])
    set_relay_capture(controller.monitor_all)
    db.session.commit()
    log_activity("system",
                 f"network change detected — cleared {n_dev} device(s), "
                 f"{n_dns} DNS row(s), {n_bw} bandwidth row(s)")
    return {"devices": n_dev, "dns": n_dns, "bandwidth": n_bw}


def check_network_change(app: Flask, emit: bool = True) -> bool:
    """Compare the current network identity against the stored one; reset all
    network data when they differ. Returns True when a reset happened."""
    from netshield.models.models import Setting
    net_id = _current_network_id()
    if not net_id:
        return False
    known = Setting.get("net_id")
    if known and known != net_id:
        app.logger.warning("network changed (%s -> %s) — resetting network "
                           "data", known, net_id)
        counts = reset_network_data()
        if emit:
            try:
                socketio.emit("network_reset",
                              {"network": str(config.current_network()),
                               **counts})
            except Exception:
                pass
        Setting.set("net_id", net_id)
        return True
    if not known:
        Setting.set("net_id", net_id)
    return False


def _device_poller_loop(app: Flask) -> None:
    """Rescan, upsert into the registry, fire join/leave events, write
    alerts + activity entries for new devices. Runs forever."""
    from netshield.extensions import socketio as sio
    from netshield.models.models import Setting
    from netshield.services import network_scanner

    online: set[str] = set()
    first_pass = True
    while True:
        try:
            with app.app_context():
                check_network_change(app)
                interval = int(Setting.get("scan_interval",
                                           config.DEFAULT_SCAN_INTERVAL) or 60)
        except Exception:
            interval = config.DEFAULT_SCAN_INTERVAL

        time.sleep(interval if not first_pass else 3)
        first_pass = False
        try:
            with app.app_context():
                found = network_scanner.discover_devices()
                seen = {d["mac"] for d in found if d.get("mac")}
                network_scanner.sync_discovered_devices(found)

                for mac in (online - seen):
                    try:
                        sio.emit("device_leave", {"mac": mac})
                    except Exception:
                        pass
                    try:
                        from netshield.audit import log_activity
                        log_activity("system", f"device left network {mac}")
                    except Exception:
                        pass
                online = seen
        except Exception as exc:
            app.logger.exception("device poller error: %s", exc)


def _blocklist_refresher(app: Flask) -> None:
    """Keep the StevenBlack-derived blocklist fresh on a daily schedule
    (and once shortly after startup when the cache is stale/absent)."""
    from netshield.models.models import Setting, utcnow
    from netshield.services.dns_categories import blocklist_status, fetch_stevenblack
    first = True
    while True:
        if first:
            time.sleep(20)
            first = False
        try:
            with app.app_context():
                status = blocklist_status()
                stale = (not status.get("last_fetch") or
                         (utcnow() - _parse_iso(status["last_fetch"])).total_seconds()
                         > config.BLOCKLIST_REFRESH_INTERVAL)
                if stale:
                    fetch_stevenblack()
        except Exception as exc:
            app.logger.warning("blocklist refresher error: %s", exc)
        time.sleep(config.BLOCKLIST_REFRESH_INTERVAL)


def _parse_iso(iso: str | None):
    from datetime import datetime
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        return None


def _retention_purger(app: Flask) -> None:
    from netshield.models.models import Setting
    from netshield.services.history import purge
    while True:
        time.sleep(config.RETENTION_PURGE_INTERVAL)
        try:
            with app.app_context():
                days = int(Setting.get("history_retention_days",
                                       config.DEFAULT_RETENTION_DAYS) or 90)
                purge(days)
        except Exception as exc:
            app.logger.warning("retention purge error: %s", exc)


def _migrate_schema() -> None:
    """Lightweight migration: add columns that newer models have but existing
    SQLite databases don't (db.create_all() never alters existing tables).
    The user's existing data/netshield.db must keep working after an update."""
    from sqlalchemy import text
    _ADD_COLUMNS = {
        "devices": [
            ("hostname", "VARCHAR(255)"),
            ("safe_mode", "BOOLEAN"),
            ("allowlist_domains", "JSON"),
            ("data_cap_mb", "INTEGER"),
            ("internet_start", "VARCHAR(5)"),
            ("internet_end", "VARCHAR(5)"),
            ("bypass", "BOOLEAN"),
        ],
    }
    try:
        for table, cols in _ADD_COLUMNS.items():
            try:
                existing = {c["name"]
                            for c in db.inspect(db.engine).get_columns(table)}
            except Exception:
                continue
            for col, ctype in cols:
                if col not in existing:
                    db.session.execute(text(
                        f"ALTER TABLE {table} ADD COLUMN {col} {ctype}"))
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        app_logger = logging.getLogger("netshield")
        app_logger.warning("schema migration failed: %s", exc)


# MAC addresses used by the old demo/simulation mode (now removed from the
# project). Purged once on startup so previously-simulated devices can never
# show up as real devices in the user's registry.
_LEGACY_DEMO_MACS = {
    "3C:22:FB:12:34:01", "F8:BC:12:AB:CD:01", "94:D9:B3:11:22:33",
    "B8:27:EB:AA:BB:01", "FC:03:9F:44:55:66", "AC:63:BE:77:88:99",
    "DC:44:6D:01:02:03", "02:7A:9B:DE:AD:01", "DC:A6:32:5E:5E:5E",
    "10:68:3F:99:88:77",
}


def _purge_legacy_demo_devices() -> None:
    """Delete any device rows that came from the removed demo mode, along
    with their bandwidth samples; detach their alerts/DNS logs (kept, but
    no longer attributed to a fake device)."""
    from netshield.models.models import (Alert, BandwidthSample, Device,
                                         DnsQueryLog)
    removed = 0
    for mac in _LEGACY_DEMO_MACS:
        try:
            BandwidthSample.query.filter_by(device_mac=mac).delete(
                synchronize_session=False)
            Alert.query.filter_by(device_mac=mac).update(
                {"device_mac": None}, synchronize_session=False)
            DnsQueryLog.query.filter_by(device_mac=mac).update(
                {"device_mac": None}, synchronize_session=False)
            removed += Device.query.filter_by(mac=mac).delete(
                synchronize_session=False)
        except Exception as exc:
            db.session.rollback()
            app_logger = logging.getLogger("netshield")
            app_logger.warning("demo-device purge failed for %s: %s",
                               mac, exc)
    if removed:
        try:
            db.session.commit()
            app_logger = logging.getLogger("netshield")
            app_logger.info("removed %d legacy simulated device(s) from "
                            "the registry", removed)
        except Exception as exc:
            db.session.rollback()
            app_logger = logging.getLogger("netshield")
            app_logger.warning("demo-device purge commit failed: %s", exc)


def _purge_noise_history() -> None:
    """Delete already-recorded noise rows (reverse-DNS lookups and
    connectivity-check domains) so the user's existing history is cleaned
    once; new noise is filtered at capture time."""
    from netshield.models.models import DnsQueryLog
    from netshield.services.history import NOISE_DOMAINS, NOISE_SUFFIXES
    app_logger = logging.getLogger("netshield")
    removed = 0
    try:
        for suffix in NOISE_SUFFIXES:
            removed += DnsQueryLog.query.filter(
                DnsQueryLog.domain.like("%" + suffix)).delete(
                synchronize_session=False)
        for entry in NOISE_DOMAINS:
            removed += DnsQueryLog.query.filter(
                DnsQueryLog.domain.like("%" + entry)).delete(
                synchronize_session=False)
        if removed:
            db.session.commit()
            app_logger.info("purged %d noise history row(s) (reverse-DNS / "
                            "connectivity checks)", removed)
        else:
            db.session.rollback()
    except Exception as exc:
        db.session.rollback()
        app_logger.warning("noise-history purge failed: %s", exc)


def _start_background_services(app: Flask) -> None:
    from netshield.services import bandwidth, history, scheduler
    from netshield.services.hostname_resolver import background_hostname_resolver

    socketio.start_background_task(_device_poller_loop, app)
    socketio.start_background_task(_blocklist_refresher, app)
    socketio.start_background_task(_retention_purger, app)
    socketio.start_background_task(background_hostname_resolver, app)
    scheduler.start_scheduler(app)

    captured = bandwidth.engine.start(app)
    if captured:
        history.start_dns_sniffer(app)
        # defensive packet guards (ARP-spoof, deauth, port-scan, ICMP flood,
        # DNS tunnel)
        try:
            from netshield.services.guard import (start_arp_guard,
                                                  start_deauth_guard,
                                                  start_dns_tunnel_guard,
                                                  start_icmp_guard,
                                                  start_scan_guard)
            start_arp_guard(app)
            start_deauth_guard(app)
            start_scan_guard(app)
            start_icmp_guard(app)
            start_dns_tunnel_guard(app)
        except Exception as exc:
            app.logger.warning("attack guards failed to start: %s", exc)
    app.config["CAPTURE_ENGINE_ACTIVE"] = captured


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def create_app(test_config: dict | None = None, auto_admin: bool = True,
               start_background: bool = True) -> Flask:
    """App factory.

    auto_admin:        when True (default), an empty database gets an
                       auto-generated 'admin' account printed once to the
                       console (password change forced at first login).
                       create_db.py passes False — it owns admin creation.
    start_background:  when True (default), start poller/scheduler/capture.
    """
    app = Flask(__name__)
    _setup_logging(app)
    _init_sqlite_pragmas()

    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{config.DB_PATH}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={
            "connect_args": {"check_same_thread": False, "timeout": 15},
        },
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=4 * 1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)

    from netshield.models.models import Setting, User
    with app.app_context():
        db.create_all()
        _migrate_schema()
        _purge_legacy_demo_devices()
        _purge_noise_history()
        # if the host is on a DIFFERENT network than the last run, wipe the
        # old network's data before anything is shown
        check_network_change(app, emit=False)
        _seed_defaults()
        if auto_admin:
            _ensure_first_run_admin(app)
        # restore the persisted DNS-capture modes (full + per-device)
        try:
            from netshield.services.history import set_relay_capture
            from netshield.services.traffic_control import controller
            monitor = bool(Setting.get("full_dns_capture", False))
            macs = Setting.get("dns_capture_macs", []) or []
            controller.set_monitor_all(monitor)
            controller.set_monitor_macs(macs)
            set_relay_capture(monitor or bool(macs))
        except Exception:
            pass

    _register_blueprints(app)
    _register_template_helpers(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.errorhandler(403)
    def forbidden(_e):
        from flask import flash, redirect, url_for
        flash("That action is restricted to administrators.", "warning")
        return redirect(url_for("dashboard.index"))

    if start_background:
        _start_background_services(app)

    # heal the network on exit: every ARP-spoofed device gets its real
    # gateway/target MACs restored when the app stops or crashes
    import atexit

    def _cleanup_arp():
        try:
            from netshield.services.traffic_control import controller
            controller.stop_all()
        except Exception:
            pass

    atexit.register(_cleanup_arp)
    return app


def _seed_defaults() -> None:
    """Seed the default groups (Kids, Guests, IoT, Trusted — fully editable)."""
    from netshield.models.models import Group
    defaults = [
        ("Kids", ["youtube", "tiktok", "gaming"], None, "21:00", "06:30",
         [0, 1, 2, 3, 4]),
        ("Guests", [], None, None, None, []),
        ("IoT", [], None, None, None, []),
        ("Trusted", [], None, None, None, []),
    ]
    for name, cats, kbps, start, end, days in defaults:
        if not Group.query.filter_by(name=name).first():
            db.session.add(Group(
                name=name, default_blocked_categories=cats,
                default_speed_limit_kbps=kbps, bedtime_start=start,
                bedtime_end=end, bedtime_days=days))
    db.session.commit()
