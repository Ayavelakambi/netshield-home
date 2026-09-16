"""Alerts + outbound notification dispatch.

* create_alert() writes an Alert row, emits the real-time Socket.IO 'alert'
  event and fires the (optional, off-by-default) outbound notifications.
* Notifications: generic webhook URL, Discord webhook, Telegram bot —
  configured in Settings; fired on new-device join, evil-twin / open-network
  detection, and per-device data-threshold breaches.
* Activity logging for admin actions also lives here (log_activity wrapper
  in netshield.audit).
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone

import requests

from netshield.extensions import db, socketio
from netshield.models.models import Alert, Setting, utcnow

logger = logging.getLogger("netshield.alerts")

# notification event types
EVENT_NEW_DEVICE = "new_device"
EVENT_EVIL_TWIN = "evil_twin"
EVENT_OPEN_NETWORK = "open_network"
EVENT_DATA_THRESHOLD = "data_threshold"

_EVENT_SETTING_KEY = {
    EVENT_NEW_DEVICE: "notify_new_device",
    EVENT_EVIL_TWIN: "notify_wireless",
    EVENT_OPEN_NETWORK: "notify_wireless",
    EVENT_DATA_THRESHOLD: "notify_data_threshold",
}


def create_alert(alert_type: str, message: str, severity: str = "info",
                 device_mac: str | None = None) -> Alert | None:
    """Create an alert (de-duplicated per active type+device+message),
    push it over Socket.IO and fire notifications."""
    existing = Alert.query.filter_by(type=alert_type, device_mac=device_mac,
                                     message=message, active=True).first()
    if existing:
        return None
    alert = Alert(type=alert_type, device_mac=device_mac, message=message,
                  severity=severity, created_at=utcnow(), active=True)
    db.session.add(alert)
    db.session.commit()
    try:
        socketio.emit("alert", _alert_payload(alert))
    except Exception:
        pass
    _dispatch_notification(alert_type, message, severity)
    return alert


def _alert_payload(alert: Alert) -> dict:
    return {
        "id": alert.id, "type": alert.type, "device_mac": alert.device_mac,
        "message": alert.message, "severity": alert.severity,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }


def clear_active_for_device(device_mac: str, alert_type: str | None = None):
    """Deactivate active alerts (used on re-scan so findings are replaced,
    not duplicated)."""
    q = Alert.query.filter_by(device_mac=device_mac, active=True)
    if alert_type:
        q = q.filter_by(type=alert_type)
    for a in q.all():
        a.active = False
    db.session.commit()


def ack_alert(alert_id: int) -> None:
    alert = db.session.get(Alert, alert_id)
    if alert:
        alert.active = False
        db.session.commit()


def clear_all_alerts() -> None:
    for a in Alert.query.filter_by(active=True).all():
        a.active = False
    db.session.commit()


def active_alert_counts() -> dict:
    rows = (db.session.query(Alert.severity, db.func.count(Alert.id))
            .filter_by(active=True).group_by(Alert.severity).all())
    counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for severity, n in rows:
        counts[severity] = n
    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


# ---------------------------------------------------------------------------
# Outbound notifications (optional, off by default)
# ---------------------------------------------------------------------------
def _dispatch_notification(event_type: str, message: str, severity: str) -> None:
    """Fire-and-forget: notifications must never block or break the app."""
    # capture the app in the CALLING thread (the worker has no context)
    from flask import current_app, has_app_context
    _app = current_app._get_current_object() if has_app_context() else None

    def _send():
        try:
            if _app is not None:
                with _app.app_context():
                    notify(event_type, message, severity)
            else:
                notify(event_type, message, severity)
        except Exception as exc:
            logger.debug("notification failed: %s", exc)
    threading.Thread(target=_send, daemon=True).start()


def notify(event_type: str, message: str, severity: str) -> None:
    """POST to the configured channels (only if that event type is enabled)."""
    enabled = Setting.get(_EVENT_SETTING_KEY.get(event_type, ""), False)
    if not enabled:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "event": event_type, "message": message, "severity": severity,
        "timestamp": timestamp, "source": "NetShield Home",
    }

    webhook = (Setting.get("webhook_url") or "").strip()
    if webhook:
        try:
            requests.post(webhook, json=payload, timeout=5)
        except requests.RequestException as exc:
            logger.warning("webhook notify failed: %s", exc)

    discord = (Setting.get("discord_webhook") or "").strip()
    if discord:
        try:
            requests.post(discord, json={
                "content": f"[{severity.upper()}] {message}",
                "username": "NetShield Home",
            }, timeout=5)
        except requests.RequestException as exc:
            logger.warning("discord notify failed: %s", exc)

    token = (Setting.get("telegram_token") or "").strip()
    chat = (Setting.get("telegram_chat_id") or "").strip()
    if token and chat:
        try:
            requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat, "text": f"[{severity.upper()}] {message}"},
                timeout=5,
            )
        except requests.RequestException as exc:
            logger.warning("telegram notify failed: %s", exc)


def send_test_notification() -> str:
    """Settings-page test button; returns a human-readable outcome."""
    notify("test", "NetShield Home test notification", "info")
    return "Test notification sent to enabled channels."
