"""Activity-log helper — every admin action is recorded through this module.

Example entries (exact free-text format used throughout):
  "login"
  "blocked category 'adult' for device AA:BB:CC:DD:EE:FF"
  "cut device 192.168.1.42 (AA:BB:CC:DD:EE:FF)"
  "refreshed StevenBlack blocklist"
"""
from __future__ import annotations

import logging

from netshield.extensions import db
from netshield.models.models import ActivityLog, utcnow

logger = logging.getLogger("netshield.audit")


def log_activity(username: str, action: str) -> None:
    """Append one row to the activity log (requires an app context)."""
    try:
        db.session.add(ActivityLog(
            username=username or "unknown",
            action=action,
            timestamp=utcnow(),
        ))
        db.session.commit()
    except Exception as exc:  # never let audit failures break the action itself
        db.session.rollback()
        logger.error("failed to write activity log entry: %s", exc)
