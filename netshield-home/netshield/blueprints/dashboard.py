"""Dashboard — live overview widgets."""
from __future__ import annotations

from flask import Blueprint, render_template
from flask_login import login_required

from netshield.extensions import db
from netshield.models.models import ActivityLog, Alert, Device, Scan, utcnow

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    devices = Device.query.all()
    total = len(devices)
    online = sum(1 for d in devices if d.is_online)

    alert_counts = {
        "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
    }
    for a in Alert.query.filter_by(active=True).all():
        alert_counts[a.severity] = alert_counts.get(a.severity, 0) + 1
    alert_counts["total"] = sum(v for k, v in alert_counts.items()
                                if k != "total")

    recent_scans = (Scan.query.order_by(Scan.started_at.desc())
                    .limit(6).all())
    recent_activity = (ActivityLog.query
                       .order_by(ActivityLog.timestamp.desc()).limit(10).all())
    top_domains = _top_domains_today()
    network_traffic = _network_traffic()
    from netshield.services import network_scanner
    cut_count = sum(1 for d in devices if d.control_state == "cut")
    return render_template(
        "dashboard.html", total_devices=total, online_devices=online,
        alert_counts=alert_counts, recent_scans=recent_scans,
        recent_activity=recent_activity, top_domains=top_domains,
        network_traffic=network_traffic, now=utcnow(),
        internet=network_scanner.internet_status(),
        gateway_info=network_scanner.gateway_info(),
        cut_count=cut_count,
    )


def _top_domains_today():
    from netshield.services.history import top_domains
    return top_domains(days=1, limit=8)


def _network_traffic():
    from netshield.services.bandwidth import network_daily_totals
    return network_daily_totals(days=7)
