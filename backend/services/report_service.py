"""
AI-NIDS Reporting Service
Chinhoyi University of Technology - Group 5
Generates formal cybersecurity incident and telemetry reports in CSV and PDF formats,
complete with CUT institutional branding, statistical summaries, decision support disclaimers,
and filter parameters.
"""

import os
import io
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional

from backend.config import TEST_TRAFFIC_SOURCE, LIVE_TRAFFIC_SOURCE

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class ReportService:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory

    def generate_csv_report(self, events: List[Dict[str, Any]]) -> str:
        """Serializes events into RFC-4180 compliant CSV string without registration_number."""
        output = io.StringIO()
        fieldnames = [
            "event_id", "detection_time", "attack_type", "ml_class",
            "source_ip", "destination_ip", "source_mac", "destination_mac",
            "bssid", "channel", "protocol", "severity", "confidence_score",
            "detection_method", "response_status", "admin_action",
            "evidence", "capture_source", "integrity_hash"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for ev in events:
            writer.writerow(ev)

        return output.getvalue()

    def generate_pdf_report(
        self,
        events: List[Dict[str, Any]],
        title: str = "AI-NIDS Incident & Threat Report",
        filters_used: Optional[str] = None
    ) -> bytes:
        """Generates a professional CUT-branded PDF report with institutional styling."""
        buffer = io.BytesIO()

        if not HAS_REPORTLAB:
            fallback = (
                f"CHINHOYI UNIVERSITY OF TECHNOLOGY\n"
                f"Department of ICT and Electronics | AI-NIDS System\n"
                f"Report Title: {title}\n"
                f"Filters: {filters_used or 'All events'}\n"
                f"Total Events: {len(events)}\n"
                f"Notice: Alerts are decision support, not confirmed breaches.\n"
            )
            buffer.write(fallback.encode("utf-8"))
            buffer.seek(0)
            return buffer.getvalue()

        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        elements = []
        styles = getSampleStyleSheet()

        # CUT Branded Styles
        title_style = ParagraphStyle(
            "CUTTitle",
            parent=styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#0288D1"),  # Light Blue Primary
            spaceAfter=3,
            alignment=1
        )
        subtitle_style = ParagraphStyle(
            "CUTSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#B78103"),  # Gold Accent
            spaceAfter=10,
            alignment=1
        )
        header_meta_style = ParagraphStyle(
            "CUTMeta",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#334155"),
            spaceAfter=10
        )
        disclaimer_style = ParagraphStyle(
            "CUTDisclaimer",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#9A3412"),
            backColor=colors.HexColor("#FFF7ED"),
            borderColor=colors.HexColor("#FDBA74"),
            borderWidth=1,
            borderPadding=6,
            spaceAfter=12
        )

        elements.append(Paragraph("CHINHOYI UNIVERSITY OF TECHNOLOGY", title_style))
        elements.append(Paragraph("School of Engineering Sciences and Technology | Department of ICT and Electronics", subtitle_style))

        meta_line = (
            f"<b>Report Title:</b> {title} | <b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
            f"<b>Filters:</b> {filters_used or 'Default range'}"
        )
        elements.append(Paragraph(meta_line, header_meta_style))

        # Decision Support Disclaimer Note required by Chapter 3 & Specification
        disclaimer_text = (
            "<b>Institutional Notice:</b> Alerts and statistical deviations recorded in this report represent automated "
            "AI-NIDS decision support telemetry for cybersecurity analyst review and do not constitute confirmed network security breaches."
        )
        elements.append(Paragraph(disclaimer_text, disclaimer_style))
        elements.append(Spacer(1, 8))

        # Summary KPIs Table
        total = len(events)
        crit_count = sum(1 for e in events if e.get("severity") == "Critical")
        high_count = sum(1 for e in events if e.get("severity") == "High")
        med_count = sum(1 for e in events if e.get("severity") == "Medium")
        dataset_count = sum(1 for e in events if e.get("capture_source") == TEST_TRAFFIC_SOURCE)
        live_count = sum(1 for e in events if e.get("capture_source") == LIVE_TRAFFIC_SOURCE)

        kpi_data = [
            ["Total Events", str(total), "Critical Alerts", str(crit_count)],
            ["High Severity Threats", str(high_count), "Medium Priority", str(med_count)],
            ["Live Capture Detections", str(live_count), "Campus Test Data Baseline", str(dataset_count)]
        ]
        kpi_table = Table(kpi_data, colWidths=[150, 100, 150, 100])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F0F9FF")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#0D47A1")),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#BAE6FD")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#0288D1")),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 12))

        # Recent Incidents Table
        table_data = [
            ["Event ID", "Time (UTC)", "Threat Type", "Source IP / MAC", "Severity", "Method", "Status"]
        ]

        for ev in events[:50]:
            ev_id = ev.get("event_id", "")
            t_str = str(ev.get("detection_time", ""))[:19].replace("T", " ")
            att = ev.get("attack_type", "")
            src = ev.get("source_mac") or ev.get("source_ip", "")
            sev = ev.get("severity", "")
            meth = ev.get("detection_method", "")
            stat = ev.get("response_status", "")
            table_data.append([ev_id, t_str, att, src[:24], sev, meth, stat])

        event_table = Table(table_data, colWidths=[70, 95, 95, 95, 60, 60, 65])
        event_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0288D1")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 4),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ]))
        elements.append(event_table)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
