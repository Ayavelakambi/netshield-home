"""Background scheduler ("bedtime mode").

A background thread evaluates schedule rules once a minute and applies /
withdraws the corresponding traffic-control sessions automatically via the
TrafficController (which is idempotent — it diffs the desired config against
the live session and only acts on change). Group bedtime windows are
evaluated in the same pass (bedtime = full cut).
"""
from __future__ import annotations

import logging
import threading
import time

import config
from netshield.extensions import db
from netshield.models.models import Device

logger = logging.getLogger("netshield.scheduler")


def run_scheduler_loop(app=None) -> None:
    while True:
        time.sleep(config.SCHEDULER_INTERVAL)
        try:
            if app is not None:
                with app.app_context():
                    evaluate()
            else:
                evaluate()
        except Exception as exc:
            logger.warning("scheduler evaluation failed: %s", exc)


def evaluate() -> None:
    """Reconcile every device's live session with its desired config."""
    from netshield.services.traffic_control import (TrafficControlUnavailable,
                                                    controller)
    devices = Device.query.all()
    for device in devices:
        if not device.current_ip:
            continue
        try:
            controller.apply(device)
        except TrafficControlUnavailable:
            # capture capability missing — leave state untouched; the UI
            # banner already explains why control is unavailable
            pass
        except Exception as exc:
            logger.debug("apply failed for %s: %s", device.mac, exc)
    db.session.commit()


def start_scheduler(app=None) -> None:
    threading.Thread(target=run_scheduler_loop, args=(app,), daemon=True,
                     name="scheduler").start()
