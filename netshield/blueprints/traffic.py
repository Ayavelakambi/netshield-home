"""Traffic / History — control overview, schedule rules ("bedtime mode"),
top-domains leaderboard, and the searchable/paginated/exportable query
history table."""
from __future__ import annotations

import csv
import io

from flask import (Blueprint, Response, abort, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from netshield.audit import log_activity
from netshield.extensions import db, socketio
from netshield.models.models import Device, Group, ScheduleRule, Setting
from netshield.safety import SafetyViolation
from netshield.security import admin_required
from netshield.services import dns_categories, history
from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                controller)

bp = Blueprint("traffic", __name__)


@bp.route("/traffic")
@login_required
def index():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    groups = db.session.query(Group).order_by(Group.name).all()
    groups_names = {str(g.id): g.name for g in groups}
    sessions = controller.sessions()
    rules = ScheduleRule.query.order_by(ScheduleRule.name).all()
    device_names = {d.mac: d.display_name for d in devices}
    range_days = request.args.get("range", "1", type=int)
    range_days = range_days if range_days in (1, 7, 30) else 1
    dev_filter = request.args.get("device") or None
    top = history.top_domains(days=range_days, device_mac=dev_filter,
                              limit=25)
    page = max(request.args.get("page", 1, type=int), 1)
    q = (request.args.get("q") or "").strip()
    hist = history.history_rows(page=page, per_page=25, q=q,
                                device_mac=dev_filter)
    return render_template(
        "traffic.html", devices=devices, sessions=sessions, rules=rules,
        device_names=device_names, groups_names=groups_names, top=top,
        range_days=range_days, dev_filter=dev_filter, hist=hist, q=q,
        categories=dns_categories.get_categories(),
        scope_note=history.SCOPE_NOTE,
        dns_status=_dns_status_full(),
        packet_capable=current_user.is_authenticated
        and _capture_flag(),
        global_block_doms=set(Setting.get("global_block_domains", []) or []),
        global_allow_doms=set(Setting.get("global_allow_domains", []) or []),
        dns_bypass_doms=set(Setting.get("global_dns_bypass_domains", []) or []),
    )


def _dns_status_full() -> dict:
    """Capture status + relay-mode info for the Traffic page."""
    data = history.dns_capture_status()
    data["relayed_devices"] = sum(
        1 for s in controller.sessions() if s.get("monitor"))
    data["ineffective"] = sum(
        1 for s in controller.sessions() if s.get("effective") == "ineffective")
    return data


def _capture_flag() -> bool:
    from netshield.services import network_scanner
    return network_scanner.packet_capability_available()


@bp.route("/traffic/api/dns-status")
@login_required
def dns_status_api():
    """Live DNS-capture health for the Traffic page status box."""
    return jsonify(_dns_status_full())


# ---------------------------------------------------------------------------
# Unified control (also used from the Devices page)
# ---------------------------------------------------------------------------
@bp.route("/traffic/control/<mac>/<action>", methods=["POST"])
@admin_required
def control(mac, action):
    device = db.session.get(Device, mac)
    if device is None:
        abort(404)
    previous_state = device.control_state
    try:
        if action == "cut":
            device.control_state = "cut"
            msg = f"{device.display_name} set to cut."
        elif action == "throttle":
            kbps = max(request.form.get("kbps", 256, type=int), 16)
            device.control_state = "throttled"
            device.speed_limit_kbps = kbps
            msg = f"{device.display_name} throttled to {kbps} kbps."
        elif action == "restore":
            device.control_state = "none"
            device.speed_limit_kbps = None
            msg = f"{device.display_name} restored."
        else:
            flash("Unknown action.", "danger")
            return redirect(url_for("traffic.index"))
        db.session.commit()
        try:
            controller.apply(device)
            db.session.commit()
            flash(msg, "success")
        except TrafficControlUnavailable as exc:
            flash(f"{msg} Saved, but not enforced right now: {exc}",
                  "warning")
        log_activity(current_user.username,
                     f"{action} device {device.current_ip} ({mac})")
        try:
            socketio.emit("control_state", {
                "mac": device.mac,
                "control_state": device.control_state,
                "speed_limit_kbps": device.speed_limit_kbps,
            })
        except Exception:
            pass
    except SafetyViolation as exc:
        device.control_state = previous_state
        db.session.commit()
        flash(str(exc), "danger")
    except ValueError as exc:
        device.control_state = previous_state
        db.session.commit()
        flash(str(exc), "danger")
    return redirect(request.referrer or url_for("traffic.index"))


# ---------------------------------------------------------------------------
# History export
# ---------------------------------------------------------------------------
@bp.route("/traffic/clear-history", methods=["POST"])
@admin_required
def clear_history():
    """Clear ALL device history (DNS query log + bandwidth samples)."""
    from netshield.models.models import BandwidthSample, DnsQueryLog
    n_dns = DnsQueryLog.query.delete(synchronize_session=False)
    n_bw = BandwidthSample.query.delete(synchronize_session=False)
    db.session.commit()
    log_activity(current_user.username,
                 f"cleared all device history ({n_dns} DNS rows, "
                 f"{n_bw} bandwidth rows)")
    flash(f"All device history cleared ({n_dns} DNS rows, {n_bw} bandwidth "
          f"rows).", "success")
    return redirect(url_for("traffic.index"))


@bp.route("/traffic/api/live-dns")
@login_required
def live_dns():
    """Latest observed DNS queries (last 60) for the live feed widget."""
    from netshield.models.models import DnsQueryLog
    rows = (DnsQueryLog.query.order_by(DnsQueryLog.timestamp.desc(),
                                       DnsQueryLog.id.desc())
            .limit(60).all())
    dev_names = {d.mac: d.display_name for d in Device.query.all()}
    out = []
    for r in rows:
        out.append({
            "device": dev_names.get(r.device_mac, "unknown"),
            "mac": r.device_mac,
            "domain": r.domain,
            "count": r.count,
            "when": r.timestamp.isoformat() if r.timestamp else None,
        })
    return jsonify(out)


@bp.route("/traffic/block-domain", methods=["POST"])
@admin_required
def block_domain_quick():
    """Quick block of a domain from the history table (network-wide)."""
    from netshield.models.models import Setting
    from netshield.services.traffic_control import controller
    domain = (request.form.get("domain") or "").strip().lower()
    if not domain:
        flash("No domain given.", "warning")
        return redirect(url_for("traffic.index"))
    doms = list(Setting.get("global_block_domains", []) or [])
    if domain not in doms:
        doms.append(domain)
    Setting.set("global_block_domains", doms)
    allow = list(Setting.get("global_allow_domains", []) or [])
    if domain in allow:
        allow.remove(domain)
        Setting.set("global_allow_domains", allow)
    for dev in Device.query.all():
        try:
            controller.apply(dev)
        except Exception:
            pass
    db.session.commit()
    log_activity(current_user.username,
                 f"network-wide block of domain {domain} (from history)")
    flash(f"'{domain}' blocked network-wide.", "success")
    return redirect(url_for("traffic.index"))


@bp.route("/traffic/allow-domain", methods=["POST"])
@admin_required
def allow_domain_quick():
    """Quick allow of a domain from the history table (exempt from blocks)."""
    from netshield.models.models import Setting
    from netshield.services.traffic_control import controller
    domain = (request.form.get("domain") or "").strip().lower()
    if not domain:
        flash("No domain given.", "warning")
        return redirect(url_for("traffic.index"))
    doms = list(Setting.get("global_block_domains", []) or [])
    if domain in doms:
        doms.remove(domain)
        Setting.set("global_block_domains", doms)
    allow = list(Setting.get("global_allow_domains", []) or [])
    if domain not in allow:
        allow.append(domain)
    Setting.set("global_allow_domains", allow)
    for dev in Device.query.all():
        try:
            controller.apply(dev)
        except Exception:
            pass
    db.session.commit()
    log_activity(current_user.username,
                 f"network-wide allow of domain {domain} (from history)")
    flash(f"'{domain}' allowed everywhere.", "success")
    return redirect(url_for("traffic.index"))


@bp.route("/traffic/bypass-domain", methods=["POST"])
@admin_required
def bypass_domain_quick():
    """Quick 'Bypass' from history: add a domain to the DNS-bypass list so
    it is answered via the public resolver (router-blocked domains become
    reachable)."""
    from netshield.models.models import Setting
    from netshield.services.traffic_control import controller
    domain = (request.form.get("domain") or "").strip().lower()
    if not domain:
        flash("No domain given.", "warning")
        return redirect(url_for("traffic.index"))
    bypass = list(Setting.get("global_dns_bypass_domains", []) or [])
    if domain not in bypass:
        bypass.append(domain)
    Setting.set("global_dns_bypass_domains", bypass)
    doms = list(Setting.get("global_block_domains", []) or [])
    if domain in doms:
        doms.remove(domain)
        Setting.set("global_block_domains", doms)
    for dev in Device.query.all():
        try:
            controller.apply(dev)
        except Exception:
            pass
    db.session.commit()
    log_activity(current_user.username,
                 f"DNS bypass added for domain {domain}")
    flash(f"'{domain}' added to DNS bypass — reachable even if the router "
          f"blocks it.", "success")
    return redirect(url_for("traffic.index"))


@bp.route("/traffic/cut-timer", methods=["POST"])
@admin_required
def cut_timer():
    """Kill-switch timer: cut ALL devices for N minutes, then auto-restore."""
    from netshield.models.models import Setting as _S
    from netshield.services.traffic_control import controller
    minutes = max(request.form.get("minutes", 30, type=int), 1)
    import time as _t
    until = _t.time() + minutes * 60
    _S.set("cut_all_until", until)
    _S.set("cut_all_minutes", minutes)
    failures = 0
    for dev in Device.query.all():
        if not dev.current_ip:
            continue
        try:
            controller.cut(dev)
            db.session.commit()
        except Exception:
            failures += 1
    log_activity(current_user.username,
                 f"kill-switch: cut ALL devices for {minutes} minutes")
    flash(f"ALL devices cut for {minutes} minutes — they will be restored "
          f"automatically.", "success")
    return redirect(url_for("traffic.index"))


@bp.route("/traffic/history/export.csv")
@login_required
def export_history():
    q = (request.args.get("q") or "").strip()
    dev = request.args.get("device") or None
    rows = history.history_export_rows(q=q, device_mac=dev)
    device_names = {d.mac: d.display_name for d in Device.query.all()}

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["domain", "device_mac", "device", "first_seen", "last_seen",
                "count"])
    for mac, domain, first, last, total in rows:
        w.writerow([domain, mac or "", device_names.get(mac, ""),
                    first, last, total])
    filename = "netshield-history.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename={filename}"})


# ---------------------------------------------------------------------------
# Schedule rules ("bedtime mode")
# ---------------------------------------------------------------------------
@bp.route("/traffic/schedule", methods=["POST"])
@admin_required
def create_rule():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Rule name required.", "danger")
        return redirect(url_for("traffic.index"))
    rule = ScheduleRule(
        target_type=request.form.get("target_type", "device"),
        target_id=(request.form.get("target_id") or "").strip(),
        name=name,
        start_time=request.form.get("start_time") or "22:00",
        end_time=request.form.get("end_time") or "06:00",
        days_of_week=[int(x) for x in request.form.getlist("days")],
        mode=request.form.get("mode", "block_categories"),
        allowlist_domains=[d.strip().lower() for d in
                           (request.form.get("allowlist") or "").splitlines()
                           if d.strip()],
        blocked_categories=request.form.getlist("categories"),
        active=True,
    )
    db.session.add(rule)
    db.session.commit()
    log_activity(current_user.username, f"created schedule rule {name}")
    flash(f"Schedule rule '{name}' created — applied within a minute.",
          "success")
    return redirect(url_for("traffic.index"))


@bp.route("/traffic/schedule/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    rule = db.session.get(ScheduleRule, rule_id)
    if rule is None:
        abort(404)
    rule.active = not rule.active
    db.session.commit()
    log_activity(current_user.username,
                 f"{'activated' if rule.active else 'deactivated'} "
                 f"schedule rule {rule.name}")
    flash(f"Rule '{rule.name}' {'enabled' if rule.active else 'disabled'}.",
          "success")
    return redirect(url_for("traffic.index"))


@bp.route("/traffic/schedule/<int:rule_id>/delete", methods=["POST"])
@admin_required
def delete_rule(rule_id):
    rule = db.session.get(ScheduleRule, rule_id)
    if rule is None:
        abort(404)
    name = rule.name
    db.session.delete(rule)
    db.session.commit()
    log_activity(current_user.username, f"deleted schedule rule {name}")
    flash(f"Rule '{name}' deleted.", "success")
    return redirect(url_for("traffic.index"))
