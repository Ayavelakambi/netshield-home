"""Weekly report export.

CSV always works with ZERO extra dependencies (stdlib csv). PDF (reportlab,
if installed) formats a title page + top devices / top domains / alerts
tables. If reportlab is missing the PDF endpoint returns None and the UI
explains how to enable it.
"""
from __future__ import annotations

import csv
import io
from datetime import timedelta

import config
from netshield.models.models import (ActivityLog, Alert, BandwidthSample,
                                     DnsQueryLog, utcnow)
from netshield.services import dns_categories


def weekly_data(days: int = 7) -> dict:
    """Aggregates for the report: devices, domains, alerts in period."""
    now = utcnow()
    cutoff = now - timedelta(days=days)

    # top devices by bandwidth
    dev_rows = (BandwidthSample.query
                .filter(BandwidthSample.timestamp >= cutoff).all())
    by_dev: dict[str, dict] = {}
    for r in dev_rows:
        d = by_dev.setdefault(r.device_mac, {"up": 0, "down": 0})
        d["up"] += r.bytes_up
        d["down"] += r.bytes_down

    from netshield.models.models import Device
    devices = []
    for mac, totals in sorted(by_dev.items(),
                              key=lambda kv: -(kv[1]["up"] + kv[1]["down"])):
        dev = Device.query.get(mac)
        devices.append({
            "mac": mac,
            "nickname": dev.nickname if dev else None,
            "hostname": dev.hostname if dev else None,
            "vendor": dev.vendor if dev else None,
            "os_guess": dev.os_guess if dev else None,
            "bytes_up": totals["up"],
            "bytes_down": totals["down"],
            "last_seen": dev.last_seen if dev else None,
        })

    # top domains by query count
    domains = _domain_rows(cutoff)

    alerts = (Alert.query.filter(Alert.created_at >= cutoff)
              .order_by(Alert.created_at.desc()).all())

    return {
        "period_start": cutoff,
        "period_end": now,
        "devices": devices,
        "domains": domains,
        "alerts": alerts,
        "alert_count": len(alerts),
        "device_count": len(devices),
        "total_bytes": sum(d["bytes_up"] + d["bytes_down"] for d in devices),
    }


def _domain_rows(cutoff):
    from netshield.extensions import db
    rows = (db.session.query(DnsQueryLog.domain,
                             db.func.sum(DnsQueryLog.count).label("total"),
                             db.func.min(DnsQueryLog.timestamp),
                             db.func.max(DnsQueryLog.timestamp))
            .filter(DnsQueryLog.timestamp >= cutoff)
            .group_by(DnsQueryLog.domain)
            .order_by(db.desc("total")).limit(50).all())
    return [{"domain": d, "count": int(c), "first_seen": f, "last_seen": l}
            for d, c, f, l in rows]


# ---------------------------------------------------------------------------
# CSV export (zero optional dependencies)
# ---------------------------------------------------------------------------
def weekly_csv(days: int = 7) -> tuple[str, str]:
    """Returns (filename, csv_text)."""
    data = weekly_data(days)
    buf = io.StringIO()
    w = csv.writer(buf)

    w.writerow(["NetShield Home — weekly report"])
    w.writerow(["period", data["period_start"].date(),
                "to", data["period_end"].date()])
    w.writerow([])

    w.writerow(["TOP DEVICES (by bandwidth)"])
    w.writerow(["MAC", "Device name", "Vendor", "OS guess", "Bytes up",
                "Bytes down", "Last seen"])
    for d in data["devices"]:
        w.writerow([d["mac"], d["nickname"] or d["hostname"] or "",
                    d["vendor"] or "", d["os_guess"] or "", d["bytes_up"],
                    d["bytes_down"], d["last_seen"]])

    w.writerow([])
    w.writerow(["TOP DOMAINS (by DNS query count)"])
    w.writerow(["Domain", "Count", "First seen", "Last seen", "Categories"])
    for d in data["domains"]:
        cats = ",".join(dns_categories.classify(d["domain"]))
        w.writerow([d["domain"], d["count"], d["first_seen"], d["last_seen"],
                    cats])

    w.writerow([])
    w.writerow(["ALERTS IN PERIOD"])
    w.writerow(["Type", "Severity", "Device", "Message", "Created at"])
    for a in data["alerts"]:
        w.writerow([a.type, a.severity, a.device_mac or "", a.message,
                    a.created_at])

    filename = f"netshield-weekly-{data['period_end'].date().isoformat()}.csv"
    return filename, buf.getvalue()


def device_csv(device_mac: str, days: int = 30) -> tuple[str, str]:
    """Per-device domain history export."""
    from datetime import timedelta as _td
    from netshield.extensions import db
    cutoff = utcnow() - _td(days=days)
    rows = (db.session.query(DnsQueryLog.domain,
                             db.func.min(DnsQueryLog.timestamp),
                             db.func.max(DnsQueryLog.timestamp),
                             db.func.sum(DnsQueryLog.count))
            .filter(DnsQueryLog.device_mac == device_mac,
                    DnsQueryLog.timestamp >= cutoff)
            .group_by(DnsQueryLog.domain)
            .order_by(db.desc(db.func.sum(DnsQueryLog.count))).all())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["NetShield Home — device report", device_mac])
    w.writerow(["period (days)", days])
    w.writerow([])
    w.writerow(["Domain", "First seen", "Last seen", "Count", "Categories"])
    for domain, first, last, count in rows:
        w.writerow([domain, first, last, count,
                    ",".join(dns_categories.classify(domain))])
    filename = f"netshield-device-{device_mac.replace(':', '')}.csv"
    return filename, buf.getvalue()


# ---------------------------------------------------------------------------
# PDF export (reportlab — optional dependency)
# ---------------------------------------------------------------------------
def weekly_pdf(days: int = 7):
    """Render the weekly report as PDF bytes (None when reportlab is absent)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate,
                                        Spacer, Table, TableStyle)
    except ImportError:
        return None

    import config as _cfg
    data = weekly_data(days)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=1.6 * cm, rightMargin=1.6 * cm,
                            topMargin=1.6 * cm, bottomMargin=1.6 * cm,
                            title="NetShield Home — Weekly Report")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("BigTitle", parent=styles["Title"], fontSize=26)
    sub_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=11,
                               textColor=colors.HexColor("#555555"))
    h2 = styles["Heading2"]

    story = []
    # --- title page ---
    story.append(Spacer(1, 5 * cm))
    story.append(Paragraph("NetShield Home", title_style))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Weekly Security &amp; Network Report", h2))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        f"Reporting period: {data['period_start'].date()} — "
        f"{data['period_end'].date()}", sub_style))
    story.append(Paragraph(
        f"Generated: {data['period_end'].strftime('%Y-%m-%d %H:%M UTC')}",
        sub_style))
    story.append(Paragraph(
        f"Network: {_cfg.current_network()} (gateway {_cfg.gateway_ip()})",
        sub_style))
    story.append(Paragraph(f"Devices active: {data['device_count']}",
                           sub_style))
    story.append(Paragraph(f"Alerts in period: {data['alert_count']}",
                           sub_style))
    story.append(PageBreak())

    def _table(header, rows, widths=None):
        t = Table([header] + rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f1f5f9")]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        return t

    story.append(Paragraph("Top devices (by bandwidth)", h2))
    if data["devices"]:
        rows = [[d["mac"], d["nickname"] or d["hostname"] or "—",
                 d["vendor"] or "—",
                 _human_bytes(d["bytes_up"] + d["bytes_down"]),
                 f"{_human_bytes(d['bytes_up'])} / "
                 f"{_human_bytes(d['bytes_down'])}"]
                for d in data["devices"][:20]]
        story.append(_table(["MAC", "Device", "Vendor", "Total",
                             "Up / Down"], rows,
                            widths=[4.2 * cm, 3 * cm, 3 * cm, 2.6 * cm,
                                    4.6 * cm]))
    else:
        story.append(Paragraph("No bandwidth data in period.", sub_style))
    story.append(Spacer(1, 0.8 * cm))

    story.append(Paragraph("Top domains (DNS query count)", h2))
    if data["domains"]:
        rows = [[d["domain"], d["count"],
                 ",".join(dns_categories.classify(d["domain"])) or "—"]
                for d in data["domains"][:25]]
        story.append(_table(["Domain", "Queries", "Categories"], rows,
                            widths=[9 * cm, 2.5 * cm, 5.5 * cm]))
    else:
        story.append(Paragraph("No DNS data in period.", sub_style))
    story.append(Spacer(1, 0.8 * cm))

    story.append(Paragraph("Alerts in period", h2))
    if data["alerts"]:
        rows = [[a.type, a.severity, a.device_mac or "—",
                 Paragraph(a.message, sub_style)]
                for a in data["alerts"][:30]]
        story.append(_table(["Type", "Severity", "Device", "Message"], rows,
                            widths=[2.6 * cm, 1.8 * cm, 2.8 * cm, 10.2 * cm]))
    else:
        story.append(Paragraph("No alerts in period.", sub_style))

    doc.build(story)
    return buf.getvalue()


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{n} B"
