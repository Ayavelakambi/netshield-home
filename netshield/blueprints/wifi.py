"""WiFi — scan results, wireless IDS findings, RF channel recommendations."""
from __future__ import annotations

from flask import (Blueprint, flash, redirect, render_template, request, url_for)
from flask_login import current_user, login_required

import config
from netshield.audit import log_activity
from netshield.extensions import db
from netshield.models.models import WifiNetwork
from netshield.security import admin_required
from netshield.services import wireless_ids
from netshield.services.alerts_dispatch import create_alert

bp = Blueprint("wifi", __name__)


@bp.route("/wifi")
@login_required
def index():
    from netshield.services import mac_intel, network_scanner
    networks = WifiNetwork.query.order_by(WifiNetwork.band,
                                          WifiNetwork.channel).all()
    findings = wireless_ids.analyze()
    recs = wireless_ids.rf_recommendations()
    audit = wireless_ids.security_audit()
    vendors = {n.bssid: mac_intel.lookup_vendor(n.bssid)
               for n in networks if n.bssid}
    return render_template("wifi.html", networks=networks, findings=findings,
                           recs=recs,
                           gateway_info=network_scanner.gateway_info(),
                           ap_vendors=vendors,
                           security_audit=audit)


@bp.route("/wifi/scan", methods=["POST"])
@admin_required
def scan():
    result = wireless_ids.wifi_scan()
    if result["status"] == "ok":
        flash(f"WiFi scan complete — {len(result['networks'])} BSSID(s) "
              f"observed.", "success")
        findings = wireless_ids.analyze()
        for f in findings:
            # de-duplicate by the stable alert key: skip when an identical
            # active alert already exists
            from netshield.models.models import Alert
            dup = (Alert.query.filter_by(type=f["type"], message=f["message"],
                                         active=True).first())
            if dup:
                continue
            create_alert(alert_type=f["type"], message=f["message"],
                         severity=f["severity"])
            log_activity(current_user.username,
                         f"wireless finding: {f['type']} ({f['message'][:80]})")
        log_activity(current_user.username, "ran WiFi scan")
    elif result["status"] == "unsupported":
        flash(result["message"], "warning")
    else:
        flash(f"WiFi scan failed: {result.get('message')}", "danger")
    return redirect(url_for("wifi.index"))
