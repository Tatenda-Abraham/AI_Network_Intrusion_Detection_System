"""
AI-NIDS Dashboard Summary & Analytics Routes
Chinhoyi University of Technology - Group 5

One events table, one view: the campus test-data baseline and the live
Wireshark/TShark capture are separated only by the capture_source column.
"""

from flask import Blueprint, jsonify, current_app
from flask_jwt_extended import jwt_required
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta

from backend.config import CAMPUS_ACTIVE_DEVICES, TEST_TRAFFIC_SOURCE, LIVE_TRAFFIC_SOURCE
from backend.models import AnalysisTotal, CaptureSession, Event, Alert
from backend.services.analysis_totals import refresh_analysis_totals

dashboard_bp = Blueprint("dashboard", __name__)

MONITORED_SOURCES = (TEST_TRAFFIC_SOURCE, LIVE_TRAFFIC_SOURCE)

# The document's response tiers, most urgent first; the charts and the register order by it.
TIER_ORDER = ("Critical", "High", "Medium", "Low")


def _stored_totals(session):
    """The analysis_totals rows the dashboard reports from.

    A row is recounted when it is missing or no longer matches the events actually stored,
    so PostgreSQL always holds the same headline figures the console shows.
    """
    rows = {
        row.capture_source: row
        for row in session.query(AnalysisTotal).filter(
            AnalysisTotal.capture_source.in_(MONITORED_SOURCES)).all()
    }
    for source in MONITORED_SOURCES:
        row = rows[source] if source in rows else None
        stored = session.query(func.count(Event.id)).filter(
            Event.capture_source == source).scalar() or 0
        if row is None or row.records_analysed != stored:
            bootstrap_devices = (CAMPUS_ACTIVE_DEVICES
                                 if source == TEST_TRAFFIC_SOURCE and row is None else None)
            row = refresh_analysis_totals(
                session, source,
                devices_monitored=(row.devices_monitored if row else bootstrap_devices))
            rows[source] = row
    return rows


@dashboard_bp.route("/summary", methods=["GET"])
@jwt_required()
def get_dashboard_summary():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    ml_service = current_app.config["ML_SERVICE"]
    capture_service = current_app.config["CAPTURE_SERVICE"]
    session = SessionLocal()

    try:
        # The headline counts live in analysis_totals; everything below is what the charts
        # and the live alert feed need beyond those stored figures.
        base_query = session.query(Event).filter(Event.capture_source.in_(MONITORED_SOURCES))

        alert_query = (
            session.query(Alert)
            .join(Event, Alert.event_id == Event.id)
            .filter(Event.capture_source.in_(MONITORED_SOURCES))
        )
        active_alerts = alert_query.filter(Alert.status == "Active").count()

        attack_type_counts = dict(
            base_query.with_entities(Event.attack_type, func.count(Event.id))
            .group_by(Event.attack_type)
            .order_by(func.count(Event.id).desc()).all()
        )
        severity_counts = dict(
            sorted(
                base_query.with_entities(Event.severity, func.count(Event.id))
                .group_by(Event.severity).all(),
                key=lambda row: TIER_ORDER.index(row[0]) if row[0] in TIER_ORDER else len(TIER_ORDER)
            )
        )
        # The distribution charts answer "what did the system catch", so they rank the
        # flagged flows; the benign share stays on the Normal Baseline and Flagged Share cards.
        flagged = base_query.filter(Event.ml_class != "Normal")
        threat_type_counts = dict(
            flagged.with_entities(Event.attack_type, func.count(Event.id))
            .group_by(Event.attack_type)
            .order_by(func.count(Event.id).desc()).all()
        )
        flagged_severity_counts = dict(
            flagged.with_entities(Event.severity, func.count(Event.id))
            .group_by(Event.severity).all()
        )
        threat_severity_counts = {
            tier: flagged_severity_counts[tier]
            for tier in list(TIER_ORDER) + [t for t in flagged_severity_counts if t not in TIER_ORDER]
            if flagged_severity_counts.get(tier)
        }
        source_counts = dict(
            base_query.with_entities(Event.capture_source, func.count(Event.id))
            .group_by(Event.capture_source).all()
        )
        top_sources_raw = (
            base_query.with_entities(Event.source_ip, func.count(Event.id))
            .group_by(Event.source_ip)
            .order_by(func.count(Event.id).desc())
            .limit(5).all()
        )

        recent_alerts = (
            alert_query.options(joinedload(Alert.event))
            .order_by(Alert.id.desc()).limit(10).all()
        )

        # Timeline: the last 24 hours when traffic is current, otherwise the stored scan window.
        now = datetime.utcnow()
        recent_start = now - timedelta(hours=24)
        earliest, latest = base_query.with_entities(
            func.min(Event.detection_time), func.max(Event.detection_time)
        ).first()

        if latest and latest >= recent_start:
            start_window = recent_start
            bucket_count = 6
            bucket_span = timedelta(hours=4)
        elif earliest and latest:
            start_window = earliest
            bucket_count = 8
            bucket_span = max((latest - earliest) / bucket_count, timedelta(minutes=1))
        else:
            start_window = recent_start
            bucket_count = 6
            bucket_span = timedelta(hours=4)

        label_format = "%d %b" if bucket_span >= timedelta(days=2) else "%d %b %H:%M"

        events_window = base_query.with_entities(Event.detection_time, Event.ml_class).filter(
            Event.detection_time >= start_window
        ).all()

        time_labels = []
        attacks_series = []
        normal_series = []

        for i in range(bucket_count):
            slot_time = start_window + bucket_span * i
            slot_end = slot_time + bucket_span
            time_labels.append(slot_time.strftime(label_format))
            attacks_series.append(sum(1 for t, c in events_window if slot_time <= t < slot_end and c != "Normal"))
            normal_series.append(sum(1 for t, c in events_window if slot_time <= t < slot_end and c == "Normal"))

        metadata = ml_service.get_metrics()
        model_metrics = metadata.get("metrics", {})
        capture_status = capture_service.get_status()

        # Headline figures come from the analysis_totals rows, and the idle monitor strip
        # comes from the last capture_sessions row, so every number on this page is a
        # number that is stored in PostgreSQL.
        totals = _stored_totals(session)
        baseline_row = totals[TEST_TRAFFIC_SOURCE]
        live_row = totals[LIVE_TRAFFIC_SOURCE]
        records_analysed = baseline_row.records_analysed + live_row.records_analysed

        window_starts = [w for w in (baseline_row.traffic_window_start,
                                     live_row.traffic_window_start) if w]
        window_ends = [w for w in (baseline_row.traffic_window_end,
                                   live_row.traffic_window_end) if w]

        capture_block = {
            "state": capture_status.get("state", "STOPPED"),
            "adapter": capture_status.get("friendly_name") or capture_status.get("adapter"),
            "total_packets": capture_status.get("total_packets", 0),
            "total_flows": capture_status.get("total_flows", 0),
            "packets_per_second": capture_status.get("packets_per_second", 0.0),
            "last_window_latency_ms": capture_status.get("last_window_latency_ms"),
            "last_preprocessing_ms_per_flow": capture_status.get("last_preprocessing_ms_per_flow"),
            "last_inference_ms_per_flow": capture_status.get("last_inference_ms_per_flow"),
            "total_events": capture_status.get("total_events", 0),
            "total_alerts": capture_status.get("total_alerts", 0),
            "session_identifier": None,
            "started_at": None,
            "ended_at": None,
            "source": "live monitor"
        }
        if capture_block["state"] == "STOPPED":
            last_session = (session.query(CaptureSession)
                            .order_by(CaptureSession.id.desc()).first())
            if last_session:
                capture_block.update({
                    "adapter": last_session.adapter_friendly_name or last_session.interface_name,
                    "total_packets": last_session.packets_captured or 0,
                    "total_flows": last_session.flows_analyzed or 0,
                    "total_events": last_session.events_stored or 0,
                    "total_alerts": last_session.alerts_raised or 0,
                    "session_identifier": last_session.session_identifier,
                    "started_at": (last_session.started_at.isoformat()
                                   if last_session.started_at else None),
                    "ended_at": (last_session.ended_at.isoformat()
                                 if last_session.ended_at else None),
                    "source": "capture_sessions"
                })

        return jsonify({
            "status": "success",
            "kpis": {
                "total_events": records_analysed,
                "normal_count": baseline_row.normal_count + live_row.normal_count,
                "suspicious_count": baseline_row.suspicious_count + live_row.suspicious_count,
                "potential_attacks": (baseline_row.potential_attack_count
                                      + live_row.potential_attack_count),
                "critical_count": baseline_row.critical_count + live_row.critical_count,
                "high_count": baseline_row.high_count + live_row.high_count,
                "critical_high_count": (baseline_row.critical_count + live_row.critical_count
                                        + baseline_row.high_count + live_row.high_count),
                "medium_count": baseline_row.medium_count + live_row.medium_count,
                "active_alerts": active_alerts,
                "campus_devices_monitored": baseline_row.devices_monitored,
                "baseline_flows_stored": baseline_row.records_analysed,
                "baseline_normal_count": baseline_row.normal_count,
                "baseline_flagged_count": (baseline_row.suspicious_count
                                           + baseline_row.potential_attack_count),
                "live_classified_flows": live_row.records_analysed,
                "flagged_share_percent": (
                    round((baseline_row.suspicious_count + baseline_row.potential_attack_count
                           + live_row.suspicious_count + live_row.potential_attack_count)
                          / records_analysed * 100, 2) if records_analysed else 0.0),
                "totals_source": "analysis_totals",
                "analysis_window_start": (min(window_starts).isoformat() if window_starts else None),
                "analysis_window_end": (max(window_ends).isoformat() if window_ends else None),
            },
            "charts": {
                "attack_type_distribution": attack_type_counts,
                "severity_distribution": severity_counts,
                "threat_type_distribution": threat_type_counts,
                "threat_severity_distribution": threat_severity_counts,
                "source_split": source_counts,
                "top_source_ips": [{"ip": ip or "0.0.0.0", "count": count} for ip, count in top_sources_raw],
                "timeline": {
                    "labels": time_labels,
                    "attacks": attacks_series,
                    "normal": normal_series
                }
            },
            "model": {
                "algorithm": ml_service.active_algorithm,
                "version": metadata.get("model_version"),
                "accuracy": model_metrics.get("accuracy"),
                "false_positive_rate": model_metrics.get("false_positive_rate"),
                "f1_score": model_metrics.get("f1_score"),
                "validation_split": metadata.get("validation_split")
            },
            "capture": {
                "state": capture_block["state"],
                "adapter": capture_block["adapter"],
                "total_packets": capture_block["total_packets"],
                "total_flows": capture_block["total_flows"],
                "packets_per_second": capture_block["packets_per_second"],
                "last_window_latency_ms": capture_block["last_window_latency_ms"],
                "last_preprocessing_ms_per_flow": capture_block["last_preprocessing_ms_per_flow"],
                "last_inference_ms_per_flow": capture_block["last_inference_ms_per_flow"],
                "events_stored": capture_block["total_events"],
                "alerts_raised": capture_block["total_alerts"],
                "session_identifier": capture_block["session_identifier"],
                "session_started_at": capture_block["started_at"],
                "session_ended_at": capture_block["ended_at"],
                "counters_from": capture_block["source"]
            },
            "recent_alerts": [a.to_dict() for a in recent_alerts]
        }), 200
    finally:
        session.close()
