"""Settings — category domain lists, blocklist refresh, notification
channels, scan interval, history retention, data threshold, plus the
user-management section (admin-only controls; standard users see a
read-only page)."""
from __future__ import annotations

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

import config
from netshield.audit import log_activity
from netshield.extensions import db
from netshield.models.models import Device, Group, Setting, User
from netshield.security import admin_required
from netshield.services import dns_categories, network_scanner
from netshield.services.alerts_dispatch import send_test_notification

bp = Blueprint("settings", __name__)


@bp.route("/settings")
@login_required
def index():
    from netshield.version import BUILD_DATE, VERSION
    from netshield.services import history as history_svc
    from netshield.services import network_scanner, privileges
    categories = dns_categories.get_categories()
    blocklist = dns_categories.blocklist_status()
    users = User.query.order_by(User.username).all() if current_user.is_admin \
        else []
    groups = Group.query.order_by(Group.name).all()
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template(
        "settings.html",
        categories=categories,
        blocklist=blocklist,
        users=users,
        groups=groups,
        devices=devices,
        app_version=VERSION,
        build_date=BUILD_DATE,
        last_report=network_scanner.LAST_REPORT,
        dns_stats=history_svc.dns_capture_status(),
        device_count=Device.query.count(),
        online_count=sum(1 for d in devices if d.is_online),
        scan_interval=Setting.get("scan_interval",
                                  config.DEFAULT_SCAN_INTERVAL),
        retention_days=Setting.get("history_retention_days",
                                   config.DEFAULT_RETENTION_DAYS),
        data_threshold_mb=Setting.get("data_threshold_mb",
                                      config.DEFAULT_DATA_THRESHOLD_MB),
        webhook_url=Setting.get("webhook_url", ""),
        discord_webhook=Setting.get("discord_webhook", ""),
        telegram_token=Setting.get("telegram_token", ""),
        telegram_chat_id=Setting.get("telegram_chat_id", ""),
        notify_new_device=Setting.get("notify_new_device", False),
        notify_wireless=Setting.get("notify_wireless", False),
        notify_data_threshold=Setting.get("notify_data_threshold", False),
        packet_capable=network_scanner.packet_capability_available(),
        subnet=str(config.current_network()),
        gateway=config.gateway_ip(),
        host_ip=config.detect_host_ip(),
        priv=privileges.privilege_status(),
        gateway_info=network_scanner.gateway_info(),
        internet=network_scanner.internet_status(),
        full_capture=Setting.get("full_dns_capture", False),
        monitored_devices=_monitored_count(),
        speedtest_result=Setting.get("speedtest_result"),
    )


def _monitored_count() -> int:
    try:
        from netshield.services.traffic_control import controller
        return sum(1 for s in controller.sessions() if s.get("monitor"))
    except Exception:
        return 0


@bp.route("/settings/dns-capture", methods=["POST"])
@admin_required
def dns_capture():
    """Toggle full DNS capture: ARP-spoof EVERY device and log their DNS
    queries through the relay (per-device search history for all devices,
    not just traffic that passively crosses this host's interface)."""
    enabled = "enabled" in request.form
    Setting.set("full_dns_capture", enabled)
    from netshield.services.history import set_relay_capture
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    controller.set_monitor_all(enabled)
    set_relay_capture(enabled)
    log_activity(current_user.username,
                 f"{'enabled' if enabled else 'disabled'} full DNS capture "
                 f"(ARP-spoof all devices)")

    # apply monitor sessions to every device RIGHT NOW (not waiting for the
    # next scheduler tick); surface per-device failures so nothing is silent
    failures = []
    for dev in Device.query.all():
        if not dev.current_ip:
            continue
        try:
            controller.apply(dev)
        except TrafficControlUnavailable as exc:
            failures.append(f"{dev.display_name}: {exc}")
        except Exception:
            failures.append(dev.display_name)
    if enabled:
        if failures:
            flash(f"Full DNS capture enabled — sessions started for "
                  f"{Device.query.count() - len(failures)} device(s); "
                  f"failed for: {'; '.join(failures[:3])}", "warning")
        else:
            flash("Full DNS capture enabled — every device is now "
                  "ARP-spoofed and its DNS queries are recorded.", "success")
    else:
        flash("Full DNS capture disabled — falling back to passive "
              "sniffing of this interface only.", "info")
    return redirect(url_for("settings.index"))


@bp.route("/settings/relaunch-admin", methods=["POST"])
@admin_required
def relaunch_admin():
    """Restart NetShield Home as Administrator (Windows UAC)."""
    import threading
    from netshield.services import privileges
    port = current_app.config.get("WEB_PORT", 5000)
    ok, msg = privileges.relaunch_as_admin(port=port)
    flash(msg, "success" if ok else "warning")
    if ok:
        # the current (non-elevated) instance must release the port so the
        # elevated one (started with NETSHIELD_ELEVATE_RELAUNCH=1) can bind
        def _shutdown():
            import time
            time.sleep(3)
            try:
                from netshield.extensions import socketio
                socketio.stop()
            except Exception:
                pass
        threading.Thread(target=_shutdown, daemon=True).start()
        flash("Approve the UAC prompt — NetShield Home will restart as "
              "Administrator and pick up where it left off.", "info")
    return redirect(url_for("settings.index"))


@bp.route("/settings/categories", methods=["POST"])
@admin_required
def save_categories():
    overrides: dict[str, list[str]] = {}
    for name in dns_categories.CURATED_CATEGORIES:
        text = request.form.get(f"cat_{name}") or ""
        overrides[name] = [d.strip().lower() for d in text.splitlines()
                           if d.strip()]
    dns_categories.save_category_overrides(overrides)
    log_activity(current_user.username, "updated category domain lists")
    flash("Category domain lists updated.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/settings/categories/reset", methods=["POST"])
@admin_required
def reset_categories():
    dns_categories.reset_category_overrides()
    log_activity(current_user.username, "reset category domain lists to "
                                        "defaults")
    flash("Category lists reset to built-in defaults.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/settings/blocklist/refresh", methods=["POST"])
@admin_required
def refresh_blocklist():
    result = dns_categories.fetch_stevenblack(force=True)
    log_activity(current_user.username, "refreshed StevenBlack blocklist")
    if result.get("error"):
        flash(f"Blocklist refresh issue: {result['error']}", "warning")
    else:
        flash(f"Blocklist refreshed — {result['count']} domains from "
              f"{result['source'].split('/')[2]}.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/settings/notifications", methods=["POST"])
@admin_required
def save_notifications():
    Setting.set("webhook_url", (request.form.get("webhook_url") or "").strip())
    Setting.set("discord_webhook",
                (request.form.get("discord_webhook") or "").strip())
    Setting.set("telegram_token",
                (request.form.get("telegram_token") or "").strip())
    Setting.set("telegram_chat_id",
                (request.form.get("telegram_chat_id") or "").strip())
    Setting.set("notify_new_device", "notify_new_device" in request.form)
    Setting.set("notify_wireless", "notify_wireless" in request.form)
    Setting.set("notify_data_threshold",
                "notify_data_threshold" in request.form)
    log_activity(current_user.username, "updated notification settings")
    flash("Notification settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/settings/notifications/test", methods=["POST"])
@admin_required
def test_notifications():
    msg = send_test_notification()
    log_activity(current_user.username, "sent test notification")
    flash(msg, "success")
    return redirect(url_for("settings.index"))


@bp.route("/settings/speedtest", methods=["POST"])
@admin_required
def speedtest():
    """Download speed test from the host to the internet (10 MB)."""
    import time
    import requests as _requests
    from netshield.models.models import utcnow as _utcnow
    url = "https://speed.cloudflare.com/__down?bytes=10000000"
    try:
        t0 = time.time()
        total = 0
        with _requests.get(url, stream=True, timeout=30) as resp:
            for chunk in resp.iter_content(65536):
                total += len(chunk)
        secs = time.time() - t0
        mbps = (total * 8 / secs) / 1_000_000 if secs > 0 else 0
        Setting.set("speedtest_result",
                    {"mbps": round(mbps, 1), "at": _utcnow().isoformat()})
        log_activity(current_user.username, "ran internet speed test")
        flash(f"Speed test: {mbps:.1f} Mbps download ({total // 1048576} MB "
              f"in {secs:.1f}s).", "success")
    except Exception as exc:
        flash(f"Speed test failed: {exc}", "danger")
    return redirect(url_for("settings.index"))


@bp.route("/settings/backup.db")
@admin_required
def backup_db():
    """Download a full backup of the database (devices, history, settings,
    users)."""
    from flask import send_file
    log_activity(current_user.username, "downloaded database backup")
    return send_file(config.DB_PATH, as_attachment=True,
                     download_name="netshield-backup.db")


@bp.route("/settings/scan-interval", methods=["POST"])
@admin_required
def save_scan_interval():
    seconds = max(request.form.get("scan_interval", 60, type=int), 15)
    Setting.set("scan_interval", seconds)
    log_activity(current_user.username, f"set scan interval to {seconds}s")
    flash(f"Device scan interval set to {seconds} seconds.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/settings/retention", methods=["POST"])
@admin_required
def save_retention():
    days = max(request.form.get("retention_days", 90, type=int), 7)
    Setting.set("history_retention_days", days)
    log_activity(current_user.username,
                 f"set history retention to {days} days")
    flash(f"History retention set to {days} days.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/settings/data-threshold", methods=["POST"])
@admin_required
def save_data_threshold():
    mb = max(request.form.get("data_threshold_mb", 0, type=int), 0)
    Setting.set("data_threshold_mb", mb)
    log_activity(current_user.username,
                 f"set per-device data threshold to {mb} MB/day")
    flash("Data threshold saved (0 disables the check).", "success")
    return redirect(url_for("settings.index"))
