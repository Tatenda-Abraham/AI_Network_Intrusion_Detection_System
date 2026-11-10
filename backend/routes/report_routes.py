"""
AI-NIDS Incident & Telemetry Report Routes
Chinhoyi University of Technology - Group 5
"""

import os
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, Response, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt

from backend.models import Event, Report
from backend.services.permission_service import require_permission, PermissionService, mask_mac
from backend.config import TEST_TRAFFIC_SOURCE, LIVE_TRAFFIC_SOURCE

report_bp = Blueprint("reports", __name__)


def _apply_scope(query, report_type, severity):
    if severity:
        query = query.filter(Event.severity == severity)

    if report_type == "Critical Threats Only":
        query = query.filter(Event.severity.in_(["Critical", "High"]))
    elif report_type == "Live Capture Audit":
        query = query.filter(Event.capture_source == LIVE_TRAFFIC_SOURCE)
    elif report_type == "Test Data Audit":
        query = query.filter(Event.capture_source == TEST_TRAFFIC_SOURCE)

    return query


@report_bp.route("", methods=["GET"])
@jwt_required()
def get_reports():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    session = SessionLocal()
    try:
        reports = session.query(Report).order_by(Report.id.desc()).limit(50).all()
        return jsonify({
            "status": "success",
            "reports": [r.to_dict() for r in reports]
        }), 200
    finally:
        session.close()


@report_bp.route("/generate", methods=["POST"])
@jwt_required()
def generate_report():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    audit_service = current_app.config["AUDIT_SERVICE"]

    data = request.get_json(silent=True) or {}
    title = data.get("title", "CUT AI-NIDS Comprehensive Incident Report").strip()
    report_type = data.get("report_type", "General Incident")
    severity_filter = data.get("severity", "").strip()
    days_back = int(data.get("days", 30))
    username = get_jwt_identity()

    session = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        query = session.query(Event).filter(Event.detection_time >= cutoff)

        matching_events = _apply_scope(query, report_type, severity_filter) \
            .order_by(Event.id.desc()).all()

        rep = Report(
            title=title,
            report_type=report_type,
            generated_by=username,
            start_date=cutoff,
            end_date=datetime.utcnow(),
            total_events=len(matching_events),
            created_at=datetime.utcnow()
        )
        session.add(rep)
        session.commit()

        audit_service.log_event(
            action="REPORT_GENERATE",
            username=username,
            details=f"Generated report '{title}' ({report_type}) containing {len(matching_events)} events",
            outcome="success"
        )

        return jsonify({
            "status": "success",
            "message": f"Report '{title}' recorded successfully",
            "report": rep.to_dict(),
            "event_count": len(matching_events)
        }), 200
    finally:
        session.close()


@report_bp.route("/export", methods=["GET"])
@jwt_required()
def export_report():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    report_service = current_app.config["REPORT_SERVICE"]
    audit_service = current_app.config["AUDIT_SERVICE"]
    claims = get_jwt()
    role = claims.get("role")
    should_mask = PermissionService.should_mask_mac(role)
    username = get_jwt_identity()

    format_type = request.args.get("format", "csv").lower()
    severity = request.args.get("severity", "").strip()
    report_type = request.args.get("report_type", "General Incident").strip()
    days = int(request.args.get("days", 30))
    title = request.args.get("title", "CUT AI-NIDS Comprehensive Incident Report").strip()

    session = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=days)
        events_raw = _apply_scope(
            session.query(Event).filter(Event.detection_time >= cutoff), report_type, severity
        ).order_by(Event.id.desc()).all()
        events = []
        for e in events_raw:
            d = e.to_dict()
            if should_mask:
                d["source_mac"] = mask_mac(d.get("source_mac"))
                d["destination_mac"] = mask_mac(d.get("destination_mac"))
                d["bssid"] = mask_mac(d.get("bssid"))
            events.append(d)

        filter_desc = f"Scope: {report_type} | Severity: {severity or 'All'} | Days: {days}"
        date_str = datetime.utcnow().strftime("%Y%m%d")

        audit_service.log_event(
            action="REPORT_EXPORT",
            username=username,
            details=f"Exported {format_type.upper()} report with {len(events)} events ({filter_desc})",
            outcome="success"
        )

        if format_type == "pdf":
            pdf_bytes = report_service.generate_pdf_report(
                events=events,
                title=title,
                filters_used=filter_desc
            )
            return Response(
                pdf_bytes,
                mimetype="application/pdf",
                headers={"Content-Disposition": f"attachment;filename=CUT_AINIDS_Report_{date_str}.pdf"}
            )
        else:
            csv_text = report_service.generate_csv_report(events)
            return Response(
                csv_text,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment;filename=CUT_AINIDS_Report_{date_str}.csv"}
            )
    finally:
        session.close()


@report_bp.route("/<int:report_id>/download", methods=["GET"])
@jwt_required()
def redownload_report(report_id):
    """Re-downloads a previously recorded report from the reports table."""
    SessionLocal = current_app.config["SESSION_FACTORY"]
    report_service = current_app.config["REPORT_SERVICE"]
    format_type = request.args.get("format", "pdf").lower()
    session = SessionLocal()
    try:
        rep = session.query(Report).filter(Report.id == report_id).first()
        if not rep:
            return jsonify({"status": "error", "message": "Report record not found"}), 404

        query = session.query(Event)
        if rep.start_date:
            query = query.filter(Event.detection_time >= rep.start_date)
        if rep.end_date:
            query = query.filter(Event.detection_time <= rep.end_date)

        events = [e.to_dict() for e in query.order_by(Event.id.desc()).all()]
        date_str = rep.created_at.strftime("%Y%m%d") if rep.created_at else datetime.utcnow().strftime("%Y%m%d")

        if format_type == "pdf":
            pdf_bytes = report_service.generate_pdf_report(
                events=events,
                title=rep.title,
                filters_used=f"Scope: {rep.report_type} | Recorded: {rep.created_at}"
            )
            return Response(
                pdf_bytes,
                mimetype="application/pdf",
                headers={"Content-Disposition": f"attachment;filename=CUT_AINIDS_Report_{date_str}.pdf"}
            )
        else:
            csv_text = report_service.generate_csv_report(events)
            return Response(
                csv_text,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment;filename=CUT_AINIDS_Report_{date_str}.csv"}
            )
    finally:
        session.close()
