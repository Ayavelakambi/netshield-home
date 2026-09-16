"""Alerts — list, acknowledge, clear; live count API for the UI badge."""
from __future__ import annotations

from flask import Blueprint, flash, jsonify, redirect, render_template, \
    request, url_for
from flask_login import login_required

from netshield.extensions import db
from netshield.models.models import Alert
from netshield.security import admin_required
from netshield.services.alerts_dispatch import (ack_alert, active_alert_counts,
                                                clear_all_alerts)

bp = Blueprint("alerts", __name__)


@bp.route("/alerts")
@login_required
def index():
    severity = request.args.get("severity") or None
    alert_type = request.args.get("type") or None
    active_only = request.args.get("active", "1") != "0"
    page = max(request.args.get("page", 1, type=int), 1)
    q = Alert.query
    if severity:
        q = q.filter_by(severity=severity)
    if alert_type:
        q = q.filter_by(type=alert_type)
    if active_only:
        q = q.filter_by(active=True)
    alerts = (q.order_by(Alert.created_at.desc())
              .paginate(page=page, per_page=25, error_out=False))
    counts = active_alert_counts()
    types = [r[0] for r in db.session.query(Alert.type).distinct().all()]
    return render_template("alerts.html", alerts=alerts, counts=counts,
                           types=types, severity=severity, alert_type=alert_type,
                           active_only=active_only)


@bp.route("/alerts/api/count")
@login_required
def api_count():
    return jsonify(active_alert_counts())


@bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@admin_required
def ack(alert_id):
    ack_alert(alert_id)
    flash("Alert acknowledged.", "success")
    return redirect(url_for("alerts.index"))


@bp.route("/alerts/clear", methods=["POST"])
@admin_required
def clear():
    clear_all_alerts()
    flash("All active alerts cleared.", "success")
    return redirect(url_for("alerts.index"))
