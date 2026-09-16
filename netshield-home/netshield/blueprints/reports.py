"""Reports — weekly CSV (zero deps) + PDF (reportlab, optional) +
per-device CSV export."""
from __future__ import annotations

from flask import (Blueprint, Response, abort, flash, redirect, render_template,
                   request, url_for)
from flask_login import login_required

from netshield.models.models import Device
from netshield.services import reports

bp = Blueprint("reports", __name__)


@bp.route("/reports")
@login_required
def index():
    preview = reports.weekly_data(days=7)
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template("reports.html", preview=preview, devices=devices)


@bp.route("/reports/weekly.csv")
@login_required
def weekly_csv():
    days = min(request.args.get("days", 7, type=int) or 7, 90)
    filename, text = reports.weekly_csv(days=days)
    return Response(text, mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename={filename}"})


@bp.route("/reports/weekly.pdf")
@login_required
def weekly_pdf():
    days = min(request.args.get("days", 7, type=int) or 7, 90)
    data = reports.weekly_pdf(days=days)
    if data is None:
        flash("PDF export requires the optional `reportlab` package "
              "(pip install reportlab). CSV export works without it.",
              "warning")
        return redirect(url_for("reports.index"))
    return Response(data, mimetype="application/pdf",
                    headers={"Content-Disposition":
                             "attachment; filename="
                             "netshield-weekly-report.pdf"})


@bp.route("/reports/device/<mac>.csv")
@login_required
def device_csv(mac):
    device = Device.query.get(mac)
    if device is None:
        abort(404)
    days = min(request.args.get("days", 30, type=int) or 30, 365)
    filename, text = reports.device_csv(mac, days=days)
    return Response(text, mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename={filename}"})
