"""
AI-NIDS Packet Capture Routes
Chinhoyi University of Technology - Group 5
Starts, stops and reports the live monitoring source (Wireshark/TShark).
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.services.permission_service import require_permission

capture_bp = Blueprint("capture", __name__)


@capture_bp.route("/interfaces", methods=["GET"])
@jwt_required()
def get_interfaces():
    capture_service = current_app.config["CAPTURE_SERVICE"]
    parser = capture_service.tshark_parser
    interfaces = parser.mark_active_interfaces(parser.list_interfaces())

    return jsonify({
        "status": "success",
        "tshark_available": parser.is_available,
        "tshark_info": parser.status_message,
        "interfaces": interfaces
    }), 200


@capture_bp.route("/start", methods=["POST"])
@require_permission("capture:start")
def start_capture():
    capture_service = current_app.config["CAPTURE_SERVICE"]
    audit_service = current_app.config["AUDIT_SERVICE"]

    data = request.get_json(silent=True) or {}
    interface_id = data.get("interface_id") or data.get("device")
    username = get_jwt_identity()

    res = capture_service.start_live_capture(
        interface_id=interface_id,
        adapter_friendly_name=data.get("adapter_friendly_name") or data.get("friendly_name"),
        device_name=data.get("device_name"),
        started_by=username
    )

    if res["status"] == "success" and not res.get("already_running"):
        audit_service.log_event(
            action="CAPTURE_START",
            username=username,
            details=res.get("message", "Live capture started"),
            outcome="success"
        )

    return jsonify(res), (200 if res["status"] == "success" else 400)


@capture_bp.route("/stop", methods=["POST"])
@require_permission("capture:stop")
def stop_capture():
    capture_service = current_app.config["CAPTURE_SERVICE"]
    audit_service = current_app.config["AUDIT_SERVICE"]
    username = get_jwt_identity()

    res = capture_service.stop_live_capture()

    if not res.get("already_stopped"):
        audit_service.log_event(
            action="CAPTURE_STOP",
            username=username,
            details=res.get("message", "Live capture stopped"),
            outcome="success"
        )

    return jsonify(res), 200


@capture_bp.route("/status", methods=["GET"])
@jwt_required()
def get_status():
    capture_service = current_app.config["CAPTURE_SERVICE"]
    return jsonify({
        "status": "success",
        "capture_status": capture_service.get_status()
    }), 200
