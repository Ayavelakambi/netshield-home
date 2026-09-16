"""Per-device bandwidth accounting.

Periodic snapshots (every HISTORY_INTERVAL seconds) of bytes_up/bytes_down
per device, read from the same promiscuous capture the DNS sniffer uses.
Samples feed daily/weekly rollups for the SVG charts. When packet capture is
unavailable the engine stays inactive (banner explains why).
"""
from __future__ import annotations

import logging
import random
import threading
import time
from datetime import date, datetime, timedelta

import config
from netshield.extensions import db
from netshield.models.models import BandwidthSample, Device, Setting, utcnow

logger = logging.getLogger("netshield.bandwidth")

_sniff_filter = "ip"


class BandwidthEngine:
    def __init__(self):
        self._counters: dict[str, dict] = {}  # mac -> {up, down}
        self._lock = threading.Lock()
        self._known_macs: set[str] = set()
        self._macs_ts = 0.0

    # ------------------------------------------------------------------
    def start(self, app=None) -> bool:
        """Start the capture/sample threads. False when unavailable.

        ``app`` (optional) provides an application context for the threads
        that touch the database (sampler).
        """
        from netshield.services.network_scanner import packet_capability_available
        if not packet_capability_available():
            return False
        threading.Thread(target=self._ctx_wrap(app, self._capture_loop),
                         daemon=True, name="bw-capture").start()
        threading.Thread(target=self._ctx_wrap(app, self._sample_loop),
                         daemon=True, name="bw-sampler").start()
        return True

    @staticmethod
    def _ctx_wrap(app, fn):
        def _run():
            if app is not None:
                with app.app_context():
                    fn()
            else:
                fn()
        return _run

    # ------------------------------------------------------------------
    def _refresh_macs(self) -> None:
        if time.time() - self._macs_ts < 30:
            return
        self._macs_ts = time.time()
        # normalize so lowercase packet MACs match the uppercase registry
        from netshield.services import mac_intel
        self._known_macs = {mac_intel.normalize_mac(d.mac)
                            for d in Device.query.all()}
        self._known_macs.discard("")

    def _handle(self, pkt) -> None:
        """Count bytes per known device MAC.

        PACKET-LEVEL NOTE: passive accounting only — the frame length is
        attributed to the device whose MAC appears as src (up) or dst (down).
        """
        try:
            if not pkt.haslayer("Ether"):
                return
            src = pkt[0].src
            dst = pkt[0].dst
            size = len(pkt)
            # packet MACs are lowercase; registry MACs are uppercase
            src_u = src.upper().replace("-", ":") if src else ""
            dst_u = dst.upper().replace("-", ":") if dst else ""
            with self._lock:
                if src_u in self._known_macs:
                    c = self._counters.setdefault(src_u, {"up": 0, "down": 0})
                    c["up"] += size
                elif dst_u in self._known_macs:
                    c = self._counters.setdefault(dst_u, {"up": 0, "down": 0})
                    c["down"] += size
        except Exception:
            pass

    def _capture_loop(self) -> None:
        from scapy.all import sniff
        while True:
            try:
                sniff(store=False, prn=self._handle, filter=_sniff_filter)
            except Exception as exc:
                logger.warning("bandwidth capture stopped (%s) — restarting "
                               "in 5s", exc)
                time.sleep(5)

    def _sample_loop(self) -> None:
        while True:
            time.sleep(config.HISTORY_INTERVAL)
            try:
                self._refresh_macs()
                # primary: bytes the relay sessions actually forwarded per
                # device (the passive counter below may see nothing when the
                # raw capture path isn't delivering, but sessions always see
                # traffic they relay)
                counters: dict[str, dict] = {}
                from netshield.services.traffic_control import controller
                for s in controller.sessions():
                    mac = s.get("mac")
                    stats = s.get("stats", {})
                    if not mac or mac not in self._known_macs:
                        continue
                    counters.setdefault(mac, {"up": 0, "down": 0})
                    counters[mac]["up"] += stats.get("relay_bytes_up", 0)
                    counters[mac]["down"] += stats.get("relay_bytes_down", 0)
                    if counters[mac]["up"] == 0 and counters[mac]["down"] == 0:
                        # no byte counters yet — use packet counts * avg size
                        fwd = stats.get("pkts_forwarded", 0)
                        counters[mac]["up"] += int(fwd * 1200)
                # fallback: passive counter (if it captured anything)
                with self._lock:
                    passive = dict(self._counters)
                    self._counters = {}
                for mac, c in passive.items():
                    if mac not in self._known_macs:
                        continue
                    counters.setdefault(mac, {"up": 0, "down": 0})
                    counters[mac]["up"] += c["up"]
                    counters[mac]["down"] += c["down"]
                self._write_samples(counters)
            except Exception as exc:
                logger.warning("bandwidth sampler error: %s", exc)

    # ------------------------------------------------------------------
    def _write_samples(self, counters: dict) -> None:
        now = utcnow()
        for mac, c in counters.items():
            if c["up"] == 0 and c["down"] == 0:
                continue
            db.session.add(BandwidthSample(device_mac=mac, timestamp=now,
                                           bytes_up=c["up"],
                                           bytes_down=c["down"]))
        db.session.commit()
        self._check_data_thresholds(now)

    def _check_data_thresholds(self, now) -> None:
        """Alert (once per device per day) when a device's daily traffic
        exceeds the configured threshold (MB)."""
        threshold_mb = int(Setting.get("data_threshold_mb",
                                       config.DEFAULT_DATA_THRESHOLD_MB) or 0)
        if threshold_mb <= 0:
            return
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        rows = (db.session.query(BandwidthSample.device_mac,
                                 db.func.sum(BandwidthSample.bytes_up +
                                             BandwidthSample.bytes_down))
                .filter(BandwidthSample.timestamp >= day_start)
                .group_by(BandwidthSample.device_mac).all())
        for mac, total_bytes in rows:
            device = db.session.get(Device, mac)
            name = device.display_name if device else mac
            used_mb = total_bytes / (1024 * 1024)

            # per-device DATA CAP: exceed it -> auto-throttle to 256 kbps
            # for the rest of the day (auto-cut if the device was already
            # being controlled? keep throttle; alert + log)
            cap_mb = getattr(device, "data_cap_mb", None) if device else None
            if cap_mb and used_mb >= cap_mb:
                flag_key = f"data_cap:{mac}:{day_start.date().isoformat()}"
                if not Setting.get(flag_key, False):
                    Setting.set(flag_key, True)
                    try:
                        from netshield.services.traffic_control import \
                            controller
                        if device.control_state != "cut":
                            controller.throttle(device, 256)
                            db.session.commit()
                            from netshield.audit import log_activity
                            log_activity(
                                "system",
                                f"data cap reached for {name} ({mac}) — "
                                f"auto-throttled to 256 kbps")
                    except Exception:
                        pass
                    from netshield.services.alerts_dispatch import create_alert
                    create_alert(
                        alert_type="data_threshold",
                        message=(f"Device {name} ({mac}) exceeded its "
                                 f"{cap_mb} MB/day cap — auto-throttled to "
                                 f"256 kbps."),
                        severity="medium", device_mac=mac,
                    )

            if total_bytes >= threshold_mb * 1024 * 1024:
                flag_key = f"data_alert:{mac}:{day_start.date().isoformat()}"
                if Setting.get(flag_key, False):
                    continue
                Setting.set(flag_key, True)
                from netshield.services.alerts_dispatch import create_alert
                create_alert(
                    alert_type="data_threshold",
                    message=(f"Device {name} ({mac}) has used more than "
                             f"{threshold_mb} MB today."),
                    severity="medium", device_mac=mac,
                )


engine = BandwidthEngine()


# ---------------------------------------------------------------------------
# Rollups for the SVG charts
# ---------------------------------------------------------------------------
def totals_by_day(device_mac: str, days: int = 7) -> list[dict]:
    """Daily totals (up/down) for the last N days, zero-filled."""
    from datetime import date, datetime
    cutoff = datetime.combine(date.today(), datetime.min.time()) - timedelta(days=days - 1)
    rows = (db.session.query(
        db.func.strftime("%Y-%m-%d", BandwidthSample.timestamp).label("day"),
        db.func.sum(BandwidthSample.bytes_up).label("up"),
        db.func.sum(BandwidthSample.bytes_down).label("down"))
        .filter(BandwidthSample.device_mac == device_mac,
                BandwidthSample.timestamp >= cutoff)
        .group_by("day").all())
    by_day = {r[0]: (int(r[1] or 0), int(r[2] or 0)) for r in rows}
    out = []
    for i in range(days):
        d = (date.today() - timedelta(days=days - 1 - i)).isoformat()
        up, down = by_day.get(d, (0, 0))
        out.append({"day": d, "up": up, "down": down})
    return out


def totals_by_week(device_mac: str, weeks: int = 8) -> list[dict]:
    """Weekly totals for the last N ISO weeks, zero-filled."""
    from datetime import date
    today = date.today()
    out = []
    for i in range(weeks - 1, -1, -1):
        week_date = today - timedelta(weeks=i)
        iso = week_date.isocalendar()
        label = f"{iso.year}-W{iso.week:02d}"
        start = (week_date - timedelta(days=week_date.weekday()))
        start_dt = datetime.combine(start, datetime.min.time())
        rows = (db.session.query(
            db.func.sum(BandwidthSample.bytes_up),
            db.func.sum(BandwidthSample.bytes_down))
            .filter(BandwidthSample.device_mac == device_mac,
                    BandwidthSample.timestamp >= start_dt,
                    BandwidthSample.timestamp < start_dt + timedelta(days=7))
            .first())
        out.append({"week": label,
                    "up": int(rows[0] or 0), "down": int(rows[1] or 0)})
    return out


def network_daily_totals(days: int = 7) -> list[dict]:
    """Network-wide daily totals for the dashboard chart."""
    from datetime import date, datetime
    cutoff = datetime.combine(date.today(), datetime.min.time()) - timedelta(days=days - 1)
    rows = (db.session.query(
        db.func.strftime("%Y-%m-%d", BandwidthSample.timestamp).label("day"),
        db.func.sum(BandwidthSample.bytes_up).label("up"),
        db.func.sum(BandwidthSample.bytes_down).label("down"))
        .filter(BandwidthSample.timestamp >= cutoff)
        .group_by("day").all())
    by_day = {r[0]: (int(r[1] or 0), int(r[2] or 0)) for r in rows}
    out = []
    for i in range(days):
        d = (date.today() - timedelta(days=days - 1 - i)).isoformat()
        up, down = by_day.get(d, (0, 0))
        out.append({"day": d, "up": up, "down": down})
    return out
