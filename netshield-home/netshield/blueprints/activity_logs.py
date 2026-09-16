"""Activity log — every admin action, visible only to admins,
filterable by user / date / action type."""
from __future__ import annotations

from flask import Blueprint, render_template, request
from flask_login import login_required

from netshield.extensions import db
from netshield.models.models import ActivityLog
from netshield.security import admin_required

bp = Blueprint("activity_logs", __name__)


@bp.route("/activity")
@admin_required
@login_required
def index():
    user = request.args.get("user") or None
    action = (request.args.get("action") or "").strip()
    date_from = request.args.get("from") or None
    date_to = request.args.get("to") or None
    page = max(request.args.get("page", 1, type=int), 1)

    q = ActivityLog.query
    if user:
        q = q.filter_by(username=user)
    if action:
        q = q.filter(ActivityLog.action.like(f"%{action}%"))
    if date_from:
        q = q.filter(ActivityLog.timestamp >= f"{date_from} 00:00:00")
    if date_to:
        q = q.filter(ActivityLog.timestamp <= f"{date_to} 23:59:59")

    rows = (q.order_by(ActivityLog.timestamp.desc())
            .paginate(page=page, per_page=30, error_out=False))
    usernames = [r[0] for r in db.session.query(
        ActivityLog.username).distinct().order_by(ActivityLog.username).all()]
    return render_template("activity_logs.html", rows=rows, usernames=usernames,
                           user=user, action=action, date_from=date_from,
                           date_to=date_to)
