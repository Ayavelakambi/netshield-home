"""Tools — network toolbelt: dig, whois (RDAP), Wireshark-style packet
capture + pcap export, traffic matrix, live heatmap, traceroute, interfaces,
routes. Linux-style tools that run on Windows. All admin-visible."""
from __future__ import annotations

from flask import (Blueprint, Response, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import login_required

from netshield.models.models import Device
from netshield.security import admin_required
from netshield.services import net_tools
from netshield.services.traffic_control import controller

bp = Blueprint("tools", __name__)


@bp.route("/tools")
@login_required
def index():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    matrix = net_tools.traffic_matrix(devices)
    heat = net_tools.heatmap_today()
    ifaces = net_tools.iface_info()
    routes = net_tools.route_table()
    # live packet stream across all sessions
    packets = []
    for s in controller.sessions():
        for p in s.get("packets", [])[-60:]:
            p = dict(p)
            p["device"] = next((d.display_name for d in devices
                                if d.mac == s["mac"]), s["mac"])
            packets.append(p)
    packets.sort(key=lambda p: p.get("ts", 0))
    return render_template("tools.html", devices=devices, matrix=matrix,
                           heat=heat, ifaces=ifaces, routes=routes,
                           packets=packets[-120:],
                           admin=current_user_is_admin())


def current_user_is_admin():
    from flask_login import current_user
    return current_user.is_admin


@bp.route("/tools/dig", methods=["POST"])
@admin_required
def dig():
    domain = (request.form.get("domain") or "").strip()
    resolver = (request.form.get("resolver") or "8.8.8.8").strip()
    qtype = int(request.form.get("qtype", 1))
    result = net_tools.dig(domain, resolver, qtype)
    return jsonify(result)


@bp.route("/tools/rdap", methods=["POST"])
@admin_required
def rdap():
    ip = (request.form.get("ip") or "").strip()
    data = net_tools.rdap_lookup(ip) if ip else None
    return jsonify(data or {"error": "lookup failed or offline"})


@bp.route("/tools/traceroute", methods=["POST"])
@admin_required
def traceroute():
    mac = request.form.get("mac") or ""
    device = Device.query.get(mac) if mac else None
    ip = device.current_ip if device else (request.form.get("ip") or "").strip()
    hops = net_tools.traceroute(ip) if ip else []
    return jsonify({"ip": ip, "hops": hops})


@bp.route("/tools/pcap")
@admin_required
def pcap():
    """Download the captured packet log as a .pcap file (open in
    Wireshark)."""
    packets = []
    for s in controller.sessions():
        packets.extend(s.get("packets", []))
    data = net_tools.pcap_bytes(packets)
    from netshield.audit import log_activity
    from flask_login import current_user
    log_activity(current_user.username, "exported packet capture (pcap)")
    return Response(data, mimetype="application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition":
                             "attachment; filename=netshield-capture.pcap"})


@bp.route("/tools/api/packets")
@login_required
def api_packets():
    devices = {d.mac: d.display_name for d in Device.query.all()}
    packets = []
    for s in controller.sessions():
        for p in s.get("packets", [])[-60:]:
            p = dict(p)
            p["device"] = devices.get(s["mac"], s["mac"])
            packets.append(p)
    packets.sort(key=lambda p: p.get("ts", 0))
    return jsonify(packets[-120:])
