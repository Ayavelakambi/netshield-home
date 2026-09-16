"""Devices — registry, detail page (controls, scans, charts, history),
groups, topology, and all per-device admin actions."""
from __future__ import annotations

import markupsafe

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

import config
from netshield.audit import log_activity
from netshield.extensions import db, socketio
from netshield.models.models import (Alert, Device, Group, Scan, Setting,
                                     utcnow)
from netshield.safety import SafetyViolation
from netshield.security import admin_required
from netshield.services import bandwidth, port_scanner, threat_intelligence
from netshield.services.alerts_dispatch import create_alert
from netshield.services.hostname_resolver import resolve_hostname
from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                controller)

bp = Blueprint("devices", __name__)


# ---------------------------------------------------------------------------
# List + topology
# ---------------------------------------------------------------------------
@bp.route("/devices")
@login_required
def list_devices():
    from netshield.services import dns_categories, network_scanner
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    groups = Group.query.order_by(Group.name).all()
    sessions = {s["mac"]: s for s in controller.sessions()}
    cut_count = sum(1 for d in devices if d.control_state == "cut")
    return render_template("devices.html", devices=devices, groups=groups,
                           sessions=sessions,
                           categories=dns_categories.get_categories(),
                           last_report=network_scanner.LAST_REPORT,
                           cut_count=cut_count,
                           topology=render_topology(devices, groups))


def render_topology(devices, groups) -> str:
    """Inline-SVG topology: gateway node at centre, devices radiating out,
    edges coloured by active control state (cut=red, throttled=orange,
    normal=gray). No external graphing library."""
    width, height = 900, 460
    cx, cy = width / 2, height / 2
    radius = 180
    parts = [f'<svg id="topo" viewBox="0 0 {width} {height}" class="topology" '
             f'role="img" aria-label="Network topology">']
    # gateway node
    parts.append(
        f'<g><circle cx="{cx}" cy="{cy}" r="30" fill="#334155" '
        f'stroke="#64748b" stroke-width="2"/>'
        f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" fill="#e2e8f0" '
        f'font-size="11" font-weight="600">Gateway</text></g>')
    online = [d for d in devices if d.is_online]
    offline = [d for d in devices if not d.is_online]
    ordered = online + offline
    n = len(ordered)
    if n == 0:
        parts.append(f'<text x="{cx}" y="{cy + 70}" text-anchor="middle" '
                     f'fill="#94a3b8" font-size="13">No devices discovered '
                     f'yet</text>')
    edge_colors = {"cut": "#e05252", "throttled": "#f0a742", "none": "#475569"}
    import math
    for i, d in enumerate(ordered):
        angle = (2 * math.pi * i) / max(n, 1) - math.pi / 2
        x = cx + radius * 0.9 * math.cos(angle)
        y = cy + radius * 0.62 * math.sin(angle)
        color = edge_colors.get(d.control_state, "#475569")
        parts.append(
            f'<line id="edge-{markupsafe.escape(d.mac)}" '
            f'x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" '
            f'stroke="{color}" stroke-width="2" '
            f'stroke-dasharray="{6 if d.is_online else 3}"/>')
        fill = "#1e293b" if d.is_online else "#0f172a"
        stroke = "#38bdf8" if d.is_online else "#475569"
        label = markupsafe.escape(d.display_name[:16])
        parts.append(
            f'<g id="node-{markupsafe.escape(d.mac)}" class="topo-node" '
            f'data-mac="{markupsafe.escape(d.mac)}" '
            f'data-ip="{markupsafe.escape(d.current_ip or "")}" '
            f'data-name="{markupsafe.escape(d.display_name)}" '
            f'data-vendor="{markupsafe.escape(d.vendor or "")}" '
            f'data-state="{markupsafe.escape(d.control_state)}" '
            f'data-online="{"1" if d.is_online else "0"}" '
            f'tabindex="0"><circle cx="{x:.1f}" cy="{y:.1f}" r="22" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
            f'<text class="topo-label" data-mac="{markupsafe.escape(d.mac)}" '
            f'x="{x:.1f}" y="{y + 3:.1f}" text-anchor="middle" '
            f'fill="#e2e8f0" font-size="7.5">{label}</text></g>')
    parts.append(
        '<g font-size="10"><rect x="20" y="20" width="240" height="64" rx="6" '
        'fill="#0f172a" stroke="#334155"/><text x="34" y="38" fill="#e2e8f0">'
        'Edges — active control state</text>'
        '<line x1="34" y1="52" x2="54" y2="52" stroke="#e05252" '
        'stroke-width="3"/><text x="62" y="56" fill="#94a3b8">cut</text>'
        '<line x1="96" y1="52" x2="116" y2="52" stroke="#f0a742" '
        'stroke-width="3"/><text x="124" y="56" fill="#94a3b8">throttled</text>'
        '<line x1="182" y1="52" x2="202" y2="52" stroke="#475569" '
        'stroke-width="3"/><text x="210" y="56" fill="#94a3b8">normal</text>'
        '</g>')
    parts.append('<text x="20" y="452" font-size="10" fill="#64748b">'
                 'drag devices to rearrange &middot; scroll / buttons to zoom '
                 '&middot; double-click a device to open it</text>')
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Detail page
# ---------------------------------------------------------------------------
@bp.route("/devices/<mac>")
@login_required
def detail(mac):
    device = db.session.get(Device, mac)
    if device is None:
        abort(404)
    page = max(request.args.get("page", 1, type=int), 1)
    q = (request.args.get("q") or "").strip()
    from netshield.services.history import history_rows
    hist = history_rows(page=page, per_page=20, q=q, device_mac=mac)
    latest_scan = (Scan.query.filter_by(device_ip=device.current_ip)
                   .order_by(Scan.started_at.desc()).first()
                   if device.current_ip else None)
    scan = None
    if latest_scan:
        scan = (Scan.query.filter_by(id=latest_scan.id).first())
    panels = []
    if scan and scan.status == "complete":
        panels = threat_intelligence.panel_for_scan(scan.results)
    alerts = (Alert.query.filter_by(device_mac=mac, active=True)
              .order_by(Alert.created_at.desc()).limit(20).all())
    from netshield.services import dns_categories
    groups = Group.query.order_by(Group.name).all()
    capture_on = (device.mac in controller.monitor_macs
                  or controller.monitor_all)
    screen_time = _screen_time_by_category(mac)
    session = controller.session_for(mac)
    from netshield.services.net_tools import live_speed_mbps
    top_servers = []
    daily_usage = bandwidth.totals_by_day(mac, 7)
    today_up = daily_usage[-1]["up"] if daily_usage else 0
    today_down = daily_usage[-1]["down"] if daily_usage else 0
    live_mbps = live_speed_mbps(mac)
    if session and session.get("top_servers"):
        top_servers = sorted(session["top_servers"].items(),
                             key=lambda kv: -kv[1])[:12]
    return render_template(
        "device_detail.html", device=device, groups=groups,
        categories=dns_categories.get_categories(),
        hostname=device.hostname or resolve_hostname(device), hist=hist, q=q,
        capture_on=capture_on,
        screen_time=screen_time,
        top_servers=top_servers,
        daily_usage=daily_usage,
        today_up=today_up, today_down=today_down,
        live_mbps=live_mbps,
        device_bypass=bool(device.bypass),
        dns_bypass_doms=set(Setting.get("global_dns_bypass_domains", []) or []),
        global_block_doms=set(Setting.get("global_block_domains", []) or []),
        global_allow_doms=set(Setting.get("global_allow_domains", []) or []),
        scan=scan, panels=panels, alerts=alerts,
        daily=bandwidth.totals_by_day(mac, 7),
        weekly=bandwidth.totals_by_week(mac, 8),
        top30=_top_domains_for_device(mac),
        session=controller.session_for(mac),
        admin=current_user.is_admin,
    )


def _top_domains_for_device(mac: str):
    from netshield.services.history import top_domains
    return top_domains(days=30, device_mac=mac, limit=15)


def _screen_time_by_category(mac: str, days: int = 7) -> list[dict]:
    """Query-count per category for one device over N days — 'screen time'
    by category (DNS-volume proxy), sorted desc."""
    from netshield.services.dns_categories import classify
    from netshield.services.history import top_domains
    totals: dict[str, int] = {}
    for d in top_domains(days=days, device_mac=mac, limit=100):
        cats = classify(d["domain"])
        key = cats[0] if cats else "other"
        totals[key] = totals.get(key, 0) + d["count"]
    out = [{"category": k, "label": category_labels_global().get(k, k),
            "count": v} for k, v in sorted(totals.items(),
                                           key=lambda kv: -kv[1])]
    return out[:10]


def category_labels_global() -> dict:
    from netshield.services.dns_categories import get_categories
    return {k: v["label"] for k, v in get_categories().items()}


# ---------------------------------------------------------------------------
# Admin actions
# ---------------------------------------------------------------------------
@bp.route("/devices/refresh", methods=["POST"])
@login_required
def refresh():
    """Force an immediate discovery pass AND persist the results into the
    registry (same upsert the background poller performs), so the Devices
    page fills in right away. The flash shows the per-method detection
    report so you can see exactly what the scanner found."""
    from netshield.services import network_scanner
    try:
        from netshield import check_network_change
        from flask import current_app
        check_network_change(current_app._get_current_object(), emit=True)
        found = network_scanner.discover_devices()
        result = network_scanner.sync_discovered_devices(found)
        # resolve device names in the background so they appear immediately
        try:
            from flask import current_app
            from netshield.services.hostname_resolver import force_resolve_names
            force_resolve_names(current_app._get_current_object())
        except Exception:
            pass
        rep = network_scanner.LAST_REPORT or {}
        skip = rep.get("skipped", {}) or {}
        flash(
            f"Discovery: {len(found)} device(s) seen — "
            f"ARP {rep.get('arp_broadcast', '?')} · neighbour table "
            f"{rep.get('neighbor_table', '?')} · ping "
            f"{rep.get('ping_sweep', '?')} · iface {rep.get('iface') or 'auto'} — "
            f"{len(result['new'])} new in registry "
            f"({skip.get('gateway', 0)} gateway, {skip.get('self', 0)} self, "
            f"{skip.get('bad_mac', 0)} bad MACs skipped).",
            "success")
    except Exception as exc:
        flash(f"Discovery failed: {exc}", "danger")
    return redirect(request.referrer or url_for("devices.list_devices"))


@bp.route("/devices/cut-all", methods=["POST"])
@admin_required
def cut_all():
    """NetCut-style: cut EVERY device on the network at once.

    Each device is handled independently (one failure never aborts the
    rest); desired states persist even when packet capture is unavailable,
    so the cuts apply automatically the moment privileges are available.
    """
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    devices = Device.query.all()
    cut_count = 0
    enforced = 0
    failed: list[str] = []
    for device in devices:
        if not device.current_ip or device.control_state == "cut":
            continue
        try:
            controller.cut(device)
            db.session.commit()
            cut_count += 1
            enforced += 1
            _emit_control_state(device)
        except SafetyViolation as exc:
            failed.append(f"{device.display_name}: {exc}")
        except TrafficControlUnavailable:
            # state already persisted by controller.cut -> will apply later
            db.session.commit()
            cut_count += 1
        except Exception as exc:
            db.session.rollback()
            failed.append(f"{device.display_name}: {exc}")
    if cut_count:
        log_activity(current_user.username,
                     f"cut ALL devices ({cut_count} devices)")
        if enforced == cut_count:
            flash(f"Cut {cut_count} device(s) off the network.", "success")
        else:
            flash(f"Cut {cut_count} device(s) — {enforced} enforced now; the "
                  f"rest are saved and will apply automatically (packet "
                  f"capture unavailable).", "warning")
    else:
        flash("No devices to cut.", "info")
    if failed:
        flash("Skipped: " + "; ".join(failed[:3]), "warning")
    return redirect(url_for("devices.list_devices"))


@bp.route("/devices/restore-all", methods=["POST"])
@admin_required
def restore_all():
    """NetCut-style: restore EVERY device at once."""
    from netshield.services.traffic_control import controller
    devices = Device.query.all()
    restored = 0
    for device in devices:
        if device.control_state == "none":
            continue
        try:
            controller.restore(device)
            db.session.commit()
            restored += 1
            _emit_control_state(device)
        except SafetyViolation as exc:
            flash(f"{device.display_name}: {exc}", "warning")
        except Exception:
            db.session.rollback()
    if restored:
        log_activity(current_user.username,
                     f"restored ALL devices ({restored} devices)")
        flash(f"Restored {restored} device(s).", "success")
    else:
        flash("No devices were cut.", "info")
    return redirect(url_for("devices.list_devices"))


def _get_device(mac: str) -> Device:
    device = db.session.get(Device, mac)
    if device is None:
        abort(404)
    return device


def _emit_control_state(device: Device) -> None:
    try:
        socketio.emit("control_state", {
            "mac": device.mac,
            "control_state": device.control_state,
            "speed_limit_kbps": device.speed_limit_kbps,
        })
    except Exception:
        pass


@bp.route("/devices/<mac>/clear-history", methods=["POST"])
@admin_required
def clear_device_history(mac):
    """Clear one device's history (DNS + bandwidth) — without disconnecting
    it; capture continues."""
    from netshield.models.models import BandwidthSample, DnsQueryLog
    device = _get_device(mac)
    n_dns = DnsQueryLog.query.filter_by(device_mac=mac).delete(
        synchronize_session=False)
    n_bw = BandwidthSample.query.filter_by(device_mac=mac).delete(
        synchronize_session=False)
    db.session.commit()
    log_activity(current_user.username,
                 f"cleared history for {device.display_name} ({mac})")
    flash(f"History cleared for {device.display_name} — "
          f"{n_dns} DNS rows, {n_bw} bandwidth rows. Capture continues.",
          "success")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/dns-capture", methods=["POST"])
@admin_required
def dns_capture_toggle(mac):
    """Toggle per-device DNS capture (ARP-spoof JUST this device, no cut):
    history is recorded live while the device keeps working normally."""
    from netshield.models.models import Setting
    from netshield.services.history import set_relay_capture
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    device = _get_device(mac)
    macs = list(Setting.get("dns_capture_macs", []) or [])
    turning_on = device.mac not in macs
    if turning_on:
        macs.append(device.mac)
    else:
        macs = [m for m in macs if m != device.mac]
    Setting.set("dns_capture_macs", macs)
    controller.set_monitor_macs(macs)
    set_relay_capture(controller.monitor_all or bool(macs))
    try:
        controller.apply(device)
        db.session.commit()
        flash(f"DNS capture {'ON' if turning_on else 'OFF'} for "
              f"{device.display_name} — history records live, device keeps "
              f"working.", "success")
    except TrafficControlUnavailable as exc:
        flash(f"Capture saved, but not active right now: {exc}", "warning")
    log_activity(current_user.username,
                 f"{'enabled' if turning_on else 'disabled'} DNS capture "
                 f"for {mac}")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/ping", methods=["POST"])
@admin_required
def ping_test(mac):
    """Latency test for one device (no privileges needed)."""
    from netshield.services.network_scanner import ping_latency_ms
    device = _get_device(mac)
    if not device.current_ip:
        flash("Device has no current IP.", "warning")
        return redirect(url_for("devices.detail", mac=mac))
    ms = ping_latency_ms(device.current_ip)
    if ms is None:
        flash(f"{device.display_name} did not answer ping.", "warning")
    else:
        flash(f"{device.display_name} replied in {ms:.0f} ms.", "success")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/bypass", methods=["POST"])
@admin_required
def bypass_toggle(mac):
    """Toggle BYPASS mode: this device becomes unrestricted — exempt from
    ALL blocking (even network-wide), never cut or throttled. The device
    can access everything, including domains blocked by the router via the
    DNS-bypass list."""
    from netshield.services.traffic_control import controller
    device = _get_device(mac)
    device.bypass = not device.bypass
    db.session.commit()
    try:
        controller.apply(device)
        db.session.commit()
    except Exception:
        db.session.rollback()
    state = "ON (unrestricted — full access)" if device.bypass else "OFF"
    flash(f"Bypass mode {state} for {device.display_name}.", "success")
    log_activity(current_user.username,
                 f"bypass mode {'ON' if device.bypass else 'OFF'} for {mac}")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/safe-mode", methods=["POST"])
@admin_required
def safe_mode_toggle(mac):
    """One-click Safe Mode: allowlist-only internet for this device
    (block everything except its allowed domains)."""
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    device = _get_device(mac)
    device.safe_mode = not device.safe_mode
    db.session.commit()
    try:
        controller.apply(device)
        db.session.commit()
        state = "ON" if device.safe_mode else "OFF"
        flash(f"Safe mode {state} for {device.display_name} — internet "
              f"blocked except allowed domains.", "success")
    except TrafficControlUnavailable as exc:
        flash(f"Safe mode saved, but not enforced: {exc}", "warning")
    log_activity(current_user.username,
                 f"safe mode {'ON' if device.safe_mode else 'OFF'} for {mac}")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/allowlist", methods=["POST"])
@admin_required
def save_allowlist(mac):
    """Save the safe-mode allowlist (one domain per line)."""
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    device = _get_device(mac)
    device.allowlist_domains = [
        d.strip().lower() for d in
        (request.form.get("allowlist") or "").splitlines() if d.strip()]
    db.session.commit()
    try:
        controller.apply(device)
        db.session.commit()
        flash(f"Allowlist saved ({len(device.allowlist_domains)} domain(s)).",
              "success")
    except TrafficControlUnavailable as exc:
        flash(f"Allowlist saved, but not enforced: {exc}", "warning")
    log_activity(current_user.username, f"updated allowlist for {mac}")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/data-cap", methods=["POST"])
@admin_required
def save_data_cap(mac):
    """Per-device daily data cap (MB, 0 = off). Auto-throttles the device to
    256 kbps for the rest of the day when exceeded."""
    device = _get_device(mac)
    mb = max(request.form.get("data_cap_mb", 0, type=int), 0)
    device.data_cap_mb = mb or None
    db.session.commit()
    log_activity(current_user.username,
                 f"set data cap for {mac} to {mb} MB/day")
    flash(f"Data cap {'removed' if not mb else f'set to {mb} MB/day'} for "
          f"{device.display_name} — exceeded cap auto-throttles the device.",
          "success")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/internet-window", methods=["POST"])
@admin_required
def save_internet_window(mac):
    """Internet allowed window (e.g. 16:00-21:00); outside it the device is
    cut automatically."""
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    device = _get_device(mac)
    start = request.form.get("internet_start") or None
    end = request.form.get("internet_end") or None
    if bool(start) != bool(end):
        flash("Set both start AND end (or neither) for the internet window.",
              "warning")
        return redirect(url_for("devices.detail", mac=mac))
    device.internet_start = start
    device.internet_end = end
    db.session.commit()
    try:
        controller.apply(device)
        db.session.commit()
        if start:
            flash(f"Internet window {start}-{end} for {device.display_name} "
                  f"— outside it, internet is cut.", "success")
        else:
            flash(f"Internet window removed for {device.display_name}.",
                  "success")
    except TrafficControlUnavailable as exc:
        flash(f"Window saved, but not enforced: {exc}", "warning")
    log_activity(current_user.username,
                 f"internet window {start}-{end} for {mac}")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/wake", methods=["POST"])
@admin_required
def wake(mac):
    """Wake-on-LAN: send the magic packet to this device."""
    from netshield.services.wol import wake_on_lan
    device = _get_device(mac)
    ok = wake_on_lan(device.mac)
    log_activity(current_user.username, f"sent Wake-on-LAN to {mac}")
    if ok:
        flash(f"Wake-on-LAN packet sent to {device.display_name} "
              f"({device.mac}). It will wake if it supports WoL.", "success")
    else:
        flash("Wake-on-LAN send failed.", "danger")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/block-domain", methods=["POST"])
@admin_required
def block_domain(mac):
    """Quick 'Block this domain' — adds the domain to the network-wide block
    list (applies to every device)."""
    from netshield.models.models import Setting
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    device = _get_device(mac)
    domain = (request.form.get("domain") or "").strip().lower()
    if not domain:
        flash("No domain given.", "warning")
        return redirect(url_for("devices.detail", mac=mac))
    doms = list(Setting.get("global_block_domains", []) or [])
    if domain not in doms:
        doms.append(domain)
    Setting.set("global_block_domains", doms)
    # remove from the allowlist if it was there
    allow = list(Setting.get("global_allow_domains", []) or [])
    if domain in allow:
        allow.remove(domain)
        Setting.set("global_allow_domains", allow)
    failures = 0
    for dev in Device.query.all():
        try:
            controller.apply(dev)
        except TrafficControlUnavailable:
            failures += 1
    db.session.commit()
    log_activity(current_user.username,
                 f"network-wide block of domain {domain}")
    flash(f"'{domain}' is now blocked network-wide (all devices).", "success")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/unblock-domain", methods=["POST"])
@admin_required
def unblock_domain(mac):
    """Quick 'Allow this domain' — exempts the domain from ALL blocking,
    network-wide."""
    from netshield.models.models import Setting
    from netshield.services.traffic_control import controller
    domain = (request.form.get("domain") or "").strip().lower()
    if not domain:
        flash("No domain given.", "warning")
        return redirect(url_for("devices.detail", mac=mac))
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
                 f"network-wide allow of domain {domain}")
    flash(f"'{domain}' is now allowed everywhere (exempt from blocks).",
          "success")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/nickname", methods=["POST"])
@login_required
def set_nickname(mac):
    device = _get_device(mac)
    nickname = (request.form.get("nickname") or "").strip()[:64]
    device.nickname = nickname or None
    db.session.commit()
    log_activity(current_user.username,
                 f"set nickname of {mac} to {nickname!r}")
    flash("Nickname updated.", "success")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/group", methods=["POST"])
@login_required
def set_group(mac):
    device = _get_device(mac)
    group_id = request.form.get("group_id", type=int)
    group = db.session.get(Group, group_id) if group_id else None
    device.group_id = group.id if group else None
    db.session.commit()
    log_activity(current_user.username,
                 f"assigned {mac} to group "
                 f"{group.name if group else '(none)'}")
    flash("Group updated.", "success")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/controls", methods=["POST"])
@admin_required
def controls(mac):
    """Unified control plane: cut / throttle / restore. Every branch goes
    through the shared safety gate inside the traffic controller.

    Semantics: the desired state is persisted FIRST (so the scheduler can
    enforce it as soon as packet capture is available), then the live
    session is applied. When capture is unavailable the user gets a clear
    warning instead of a silent no-op.
    """
    device = _get_device(mac)
    action = request.form.get("action")
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
            flash("Unknown control action.", "danger")
            return redirect(url_for("devices.detail", mac=mac))
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
        _emit_control_state(device)
    except SafetyViolation as exc:
        # revert the persisted state — the target failed validation
        device.control_state = previous_state
        db.session.commit()
        flash(str(exc), "danger")
    except ValueError as exc:
        device.control_state = previous_state
        db.session.commit()
        flash(str(exc), "danger")
    return redirect(request.referrer or url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/block-categories", methods=["POST"])
@admin_required
def block_categories(mac):
    device = _get_device(mac)
    selected = request.form.getlist("categories")
    previous = list(device.blocked_categories or [])
    # persist the desired configuration first (scheduler can enforce later)
    device.blocked_categories = selected
    db.session.commit()
    try:
        controller.apply(device)
        db.session.commit()
        flash("Category blocking updated and enforced.", "success")
    except SafetyViolation as exc:
        device.blocked_categories = []
        db.session.commit()
        flash(str(exc), "danger")
    except TrafficControlUnavailable as exc:
        flash(f"Category blocking saved, but not enforced right now: {exc}",
              "warning")
    for cat in selected:
        log_activity(current_user.username,
                     f"blocked category '{cat}' for device {mac}")
    for cat in (set(previous) - set(selected)):
        log_activity(current_user.username,
                     f"unblocked category '{cat}' for device {mac}")
    # clarify the unified-session semantics: category block only drops the
    # selected domains' DNS — but if the device is still CUT, ALL traffic is
    # still being dropped, which can look like "block blocked everything"
    if device.control_state in ("cut", "throttled"):
        flash(f"Note: {device.display_name} is still "
              f"'{device.control_state}' — category blocking only filters "
              f"the selected domains' DNS; press Restore to allow all other "
              f"traffic.", "warning")
    _emit_control_state(device)
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/speed-limit", methods=["POST"])
@admin_required
def speed_limit(mac):
    device = _get_device(mac)
    kbps = max(request.form.get("kbps", 256, type=int), 16)
    try:
        controller.throttle(device, kbps)
        db.session.commit()
        _emit_control_state(device)
        log_activity(current_user.username,
                     f"throttled device {mac} to {kbps} kbps")
        flash(f"Speed limit set to {kbps} kbps.", "success")
    except (SafetyViolation, TrafficControlUnavailable) as exc:
        flash(str(exc), "danger")
    return redirect(url_for("devices.detail", mac=mac))


@bp.route("/devices/<mac>/scan", methods=["POST"])
@admin_required
def start_scan(mac):
    device = _get_device(mac)
    if not device.current_ip:
        flash("Device has no current IP — cannot scan.", "danger")
        return redirect(url_for("devices.detail", mac=mac))
    try:
        scan_id = port_scanner.scan_device(device)
        log_activity(current_user.username,
                     f"started port scan of {device.current_ip} ({mac})")
        flash("Port scan started — results appear when it completes.",
              "info")
    except SafetyViolation as exc:
        flash(str(exc), "danger")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("devices.detail", mac=mac))


# ---------------------------------------------------------------------------
# Groups CRUD (admin)
# ---------------------------------------------------------------------------
@bp.route("/groups", methods=["POST"])
@admin_required
def create_group():
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Group name required.", "danger")
        return redirect(url_for("devices.list_devices"))
    if Group.query.filter_by(name=name).first():
        flash("A group with that name already exists.", "warning")
        return redirect(url_for("devices.list_devices"))
    group = Group(name=name,
                  default_blocked_categories=request.form.getlist("categories"),
                  default_speed_limit_kbps=(
                      request.form.get("kbps", type=int) or None),
                  bedtime_start=request.form.get("bedtime_start") or None,
                  bedtime_end=request.form.get("bedtime_end") or None,
                  bedtime_days=[int(x) for x in request.form.getlist("days")])
    db.session.add(group)
    db.session.commit()
    log_activity(current_user.username, f"created group {name}")
    flash(f"Group '{name}' created.", "success")
    return redirect(url_for("devices.list_devices"))


@bp.route("/groups/<int:group_id>", methods=["POST"])
@admin_required
def update_group(group_id):
    group = db.session.get(Group, group_id)
    if group is None:
        abort(404)
    group.name = (request.form.get("name") or group.name).strip()
    group.default_blocked_categories = request.form.getlist("categories")
    group.default_speed_limit_kbps = (request.form.get("kbps", type=int)
                                      or None)
    group.bedtime_start = request.form.get("bedtime_start") or None
    group.bedtime_end = request.form.get("bedtime_end") or None
    group.bedtime_days = [int(x) for x in request.form.getlist("days")]
    db.session.commit()
    log_activity(current_user.username, f"updated group {group.name}")
    flash(f"Group '{group.name}' updated.", "success")
    return redirect(url_for("devices.list_devices"))


@bp.route("/groups/<int:group_id>/delete", methods=["POST"])
@admin_required
def delete_group(group_id):
    group = db.session.get(Group, group_id)
    if group is None:
        abort(404)
    name = group.name
    Device.query.filter_by(group_id=group.id).update({"group_id": None})
    db.session.delete(group)
    db.session.commit()
    log_activity(current_user.username, f"deleted group {name}")
    flash(f"Group '{name}' deleted; members ungrouped.", "success")
    return redirect(url_for("devices.list_devices"))
