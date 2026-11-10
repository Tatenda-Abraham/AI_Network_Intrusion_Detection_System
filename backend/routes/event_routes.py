"""
AI-NIDS Event & Threat Management Routes
Chinhoyi University of Technology - Group 5
- Role-based MAC masking (Analysts: 00:11:22:xx:xx:xx, Admins: full MAC)
- Status, note and delete lifecycle with audit trail
- Search, sort and traffic-source filtering (campus test data / live capture)
"""

from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy import case, or_, desc, asc

from backend.models import Event, Alert
from backend.services.priority_queue import compute_event_integrity_hash
from backend.services.permission_service import PermissionService, mask_mac, require_permission
from backend.config import TEST_TRAFFIC_SOURCE, LIVE_TRAFFIC_SOURCE

event_bp = Blueprint("events", __name__)

SOURCE_BY_MODE = {"test": TEST_TRAFFIC_SOURCE, "live": LIVE_TRAFFIC_SOURCE}


def _mask_event_macs(ev_dict: dict, should_mask: bool) -> dict:
    if should_mask:
        if ev_dict.get("source_mac"):
            ev_dict["source_mac"] = mask_mac(ev_dict["source_mac"])
        if ev_dict.get("destination_mac"):
            ev_dict["destination_mac"] = mask_mac(ev_dict["destination_mac"])
        if ev_dict.get("bssid"):
            ev_dict["bssid"] = mask_mac(ev_dict["bssid"])
        # If source_ip contains a MAC address, mask it
        if ev_dict.get("source_ip") and ":" in ev_dict["source_ip"]:
            ev_dict["source_ip"] = mask_mac(ev_dict["source_ip"])
    return ev_dict


@event_bp.route("", methods=["GET"])
@jwt_required()
def get_events():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    session = SessionLocal()
    claims = get_jwt()
    role = claims.get("role")
    should_mask = PermissionService.should_mask_mac(role)

    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(int(request.args.get("page_size", 25)), 100)
        search_query = request.args.get("search", "").strip()
        severity = request.args.get("severity", "").strip()
        attack_type = request.args.get("attack_type", "").strip()
        detection_method = request.args.get("detection_method", "").strip()
        response_status = request.args.get("response_status", "").strip()
        sort_by = request.args.get("sort_by", "detection_time")
        ascending = request.args.get("ascending", "false").lower() == "true"
        mode = request.args.get("mode", "all").lower()

        query = session.query(Event)

        source = SOURCE_BY_MODE.get(mode)
        if source:
            query = query.filter(Event.capture_source == source)

        if search_query:
            term = f"%{search_query}%"
            query = query.filter(
                or_(
                    Event.event_id.ilike(term),
                    Event.source_ip.ilike(term),
                    Event.destination_ip.ilike(term),
                    Event.source_mac.ilike(term),
                    Event.destination_mac.ilike(term),
                    Event.bssid.ilike(term),
                    Event.attack_type.ilike(term),
                    Event.evidence.ilike(term)
                )
            )

        if severity:
            query = query.filter(Event.severity == severity)
        if attack_type:
            query = query.filter(Event.attack_type == attack_type)
        if detection_method:
            query = query.filter(Event.detection_method == detection_method)
        if response_status:
            query = query.filter(Event.response_status == response_status)

        total_matching = query.count()

        # Sorting
        sort_column = Event.id
        if sort_by == "detection_time":
            sort_column = Event.detection_time
        elif sort_by == "severity":
            sort_column = Event.severity
        elif sort_by == "confidence_score":
            sort_column = Event.confidence_score
        elif sort_by == "source_ip":
            sort_column = Event.source_ip
        elif sort_by == "attack_type":
            sort_column = Event.attack_type

        order_expr = asc(sort_column) if ascending else desc(sort_column)
        if sort_by == "detection_time":
            # The register is a triage list: flagged flows lead, benign traffic follows,
            # and each group stays newest-first. Sorting a different column keeps that
            # column's own order.
            query = query.order_by(
                case((Event.ml_class == "Normal", 1), else_=0),
                order_expr,
            )
        else:
            query = query.order_by(order_expr)

        offset = (page - 1) * page_size
        events = query.offset(offset).limit(page_size).all()

        events_data = [_mask_event_macs(e.to_dict(), should_mask) for e in events]

        return jsonify({
            "status": "success",
            "events": events_data,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_matching,
                "total_pages": (total_matching + page_size - 1) // page_size if total_matching > 0 else 1
            }
        }), 200
    finally:
        session.close()


@event_bp.route("/<int:event_id>", methods=["GET"])
@jwt_required()
def get_event_detail(event_id):
    SessionLocal = current_app.config["SESSION_FACTORY"]
    session = SessionLocal()
    claims = get_jwt()
    role = claims.get("role")
    should_mask = PermissionService.should_mask_mac(role)

    try:
        event = session.query(Event).filter(Event.id == event_id).first()
        if not event:
            return jsonify({"status": "error", "message": f"Event #{event_id} not found"}), 404

        ev_dict = event.to_dict()
        calc_hash = compute_event_integrity_hash(ev_dict)
        ev_dict["integrity_valid"] = (calc_hash == event.integrity_hash) if event.integrity_hash else True
        ev_dict = _mask_event_macs(ev_dict, should_mask)

        return jsonify({
            "status": "success",
            "event": ev_dict
        }), 200
    finally:
        session.close()


@event_bp.route("/<int:event_id>/status", methods=["PATCH", "POST"])
@jwt_required()
def update_event_status(event_id):
    SessionLocal = current_app.config["SESSION_FACTORY"]
    audit_service = current_app.config["AUDIT_SERVICE"]

    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "").strip()
    notes_append = data.get("notes", "").strip()
    allowed = ["Pending review", "Acknowledged", "Investigating", "Resolved", "False positive"]

    if new_status not in allowed:
        return jsonify({"status": "error", "message": f"Status must be one of: {allowed}"}), 400

    username = get_jwt_identity()
    session = SessionLocal()
    try:
        event = session.query(Event).filter(Event.id == event_id).first()
        if not event:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        old_status = event.response_status
        event.response_status = new_status
        event.reviewed_by = username
        event.reviewed_at = datetime.utcnow()

        if notes_append:
            timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            formatted_entry = f"[{timestamp_str} by {username}]: {notes_append}"
            event.notes = f"{event.notes}\n{formatted_entry}" if event.notes else formatted_entry

        if new_status == "False positive":
            alerts = session.query(Alert).filter(Alert.event_id == event_id).all()
            for a in alerts:
                a.status = "Suppressed"

        session.commit()

        audit_service.log_event(
            action="EVENT_STATUS_CHANGE",
            username=username,
            details=f"Event {event.format_event_id()} status changed from '{old_status}' to '{new_status}'",
            outcome="success"
        )

        return jsonify({
            "status": "success",
            "message": f"Event status updated to '{new_status}'",
            "event": event.to_dict()
        }), 200
    finally:
        session.close()


@event_bp.route("/<int:event_id>/note", methods=["POST"])
@jwt_required()
def add_event_note(event_id):
    SessionLocal = current_app.config["SESSION_FACTORY"]
    data = request.get_json(silent=True) or {}
    new_note = data.get("note", "").strip()
    username = get_jwt_identity()

    if not new_note:
        return jsonify({"status": "error", "message": "Note text is required"}), 400

    session = SessionLocal()
    try:
        event = session.query(Event).filter(Event.id == event_id).first()
        if not event:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        formatted_entry = f"[{timestamp_str} by {username}]: {new_note}"

        event.notes = f"{event.notes}\n{formatted_entry}" if event.notes else formatted_entry
        session.commit()

        return jsonify({
            "status": "success",
            "message": "Note recorded successfully",
            "notes": event.notes
        }), 200
    finally:
        session.close()


@event_bp.route("/<int:event_id>", methods=["DELETE"])
@require_permission("events:delete")
def delete_event(event_id):
    SessionLocal = current_app.config["SESSION_FACTORY"]
    audit_service = current_app.config["AUDIT_SERVICE"]
    username = get_jwt_identity()

    session = SessionLocal()
    try:
        event = session.query(Event).filter(Event.id == event_id).first()
        if not event:
            return jsonify({"status": "error", "message": "Event not found"}), 404

        ev_label = event.format_event_id()
        session.delete(event)
        session.commit()

        audit_service.log_event(
            action="EVENT_DELETED",
            username=username,
            details=f"Administrator {username} deleted event {ev_label}",
            outcome="success"
        )

        return jsonify({"status": "success", "message": f"Event {ev_label} deleted successfully"}), 200
    except Exception as e:
        session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        session.close()


@event_bp.route("/alerts", methods=["GET"])
@jwt_required()
def get_alerts():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    session = SessionLocal()
    try:
        status_filter = request.args.get("status", "Active")
        mode = request.args.get("mode", "all").lower()

        query = session.query(Alert).join(Event, Alert.event_id == Event.id)

        if status_filter != "all":
            query = query.filter(Alert.status == status_filter)

        source = SOURCE_BY_MODE.get(mode)
        if source:
            query = query.filter(Event.capture_source == source)

        alerts = query.order_by(Alert.id.desc()).limit(100).all()
        return jsonify({
            "status": "success",
            "alerts": [a.to_dict() for a in alerts]
        }), 200
    finally:
        session.close()
