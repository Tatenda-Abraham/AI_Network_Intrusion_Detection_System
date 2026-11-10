"""
AI-NIDS Live Monitoring Routes
Chinhoyi University of Technology - Group 5
Reads the monitoring pipeline's stored output:
1. Capture status telemetry
2. Live classified traffic (events written by the monitor)
3. Packet stream and device conversations from the captured frames
4. Wireless analysis findings
5. Alert timeline and capture window log
"""

import json
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, current_app, request
from flask_jwt_extended import jwt_required, get_jwt
from sqlalchemy import desc

from backend.config import LIVE_TRAFFIC_SOURCE
from backend.models import (
    LiveCaptureWindow, LiveFinding, WifiFrame,
    DeviceConversation, Event, Alert, Setting
)
from backend.services.permission_service import PermissionService, mask_mac

live_bp = Blueprint("live", __name__)


def _session():
    return current_app.config["SESSION_FACTORY"]()


def _current_role():
    return (get_jwt() or {}).get("role")


@live_bp.route("/status", methods=["GET"])
@jwt_required()
def get_live_status():
    """Telemetry for the monitoring bar, refreshed by the page on its own interval."""
    capture_service = current_app.config["CAPTURE_SERVICE"]
    status = capture_service.get_status()
    state = status.get("state", "STOPPED")

    adapter_label = status.get("friendly_name") or status.get("adapter")
    db = _session()
    refresh_sec = 5
    try:
        s = db.query(Setting).filter_by(key="dashboard_refresh_seconds").first()
        if s and s.value:
            refresh_sec = max(2, int(s.value))
    except Exception:
        pass
    finally:
        db.close()

    return jsonify({
        "status": "success",
        "capture_state": state,
        "is_capturing": bool(status.get("is_capturing")),
        "adapter": adapter_label or "No adapter yet",
        "device": status.get("device"),
        "selection_method": status.get("selection_method"),
        "channel": status.get("channel", "Auto"),
        "packets_sec": status.get("packets_per_second", 0.0),
        "total_packets": status.get("total_packets", 0),
        "total_flows": status.get("total_flows", 0),
        "total_events": status.get("total_events", 0),
        "total_alerts": status.get("total_alerts", 0),
        "dropped_frames": status.get("dropped_frames", 0),
        "restart_count": status.get("restart_count", 0),
        "last_error": status.get("last_error"),
        "last_window_time": status.get("last_window_time"),
        "last_window_latency_ms": status.get("last_window_latency_ms"),
        "last_flows_in_window": status.get("last_flows_in_window", 0),
        "last_preprocessing_ms_per_flow": status.get("last_preprocessing_ms_per_flow"),
        "last_inference_ms_per_flow": status.get("last_inference_ms_per_flow"),
        "window_seconds": status.get("window_seconds", 10),
        "refresh_interval_seconds": refresh_sec,
        "data_source": (
            f"Live capture - {adapter_label}" if state == "CAPTURING"
            else "Live capture" if state == "RESTARTING"
            else "Stopped"
        ),
    }), 200


@live_bp.route("/detections", methods=["GET"])
@jwt_required()
def get_live_detections():
    """Recent traffic classifications produced by the live monitor."""
    db = _session()
    try:
        limit = min(int(request.args.get("limit", 25)), 100)
        flagged_only = request.args.get("flagged_only", "false").lower() == "true"

        query = db.query(Event).filter(Event.capture_source == LIVE_TRAFFIC_SOURCE)
        if flagged_only:
            query = query.filter(Event.ml_class != "Normal")

        rows = query.order_by(desc(Event.id)).limit(limit).all()
        detections = []
        for ev in rows:
            stats = {}
            try:
                stats = json.loads(ev.traffic_stats or "{}")
            except (TypeError, ValueError):
                stats = {}
            detections.append({
                "event_id": ev.event_id,
                "detection_time": ev.detection_time.isoformat() if ev.detection_time else None,
                "source_ip": ev.source_ip,
                "destination_ip": ev.destination_ip,
                "protocol": ev.protocol,
                "source_port": ev.source_port,
                "destination_port": ev.destination_port,
                "ml_class": ev.ml_class,
                "attack_type": ev.attack_type,
                "severity": ev.severity,
                "confidence_score": ev.confidence_score,
                "evidence": ev.evidence,
                "packets": stats.get("total_packets"),
                "bytes_per_sec": stats.get("bytes_per_sec"),
            })

        return jsonify({
            "status": "success",
            "count": len(detections),
            "detections": detections
        }), 200
    finally:
        db.close()


@live_bp.route("/packets", methods=["GET"])
@jwt_required()
def get_live_packets():
    """Latest dissected frames from the live capture."""
    db = _session()
    should_mask = PermissionService.should_mask_mac(_current_role())

    try:
        limit = min(int(request.args.get("limit", 200)), 500)
        frames = db.query(WifiFrame).order_by(desc(WifiFrame.id)).limit(limit).all()

        result = []
        for f in frames:
            d = f.to_dict()
            if should_mask:
                d["transmitter_mac"] = mask_mac(d.get("transmitter_mac"))
                d["receiver_mac"] = mask_mac(d.get("receiver_mac"))
                d["bssid"] = mask_mac(d.get("bssid"))
            result.append(d)

        return jsonify({"status": "success", "count": len(result), "packets": result}), 200
    finally:
        db.close()


@live_bp.route("/conversations", methods=["GET"])
@jwt_required()
def get_live_conversations():
    db = _session()
    should_mask = PermissionService.should_mask_mac(_current_role())

    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        convs = db.query(DeviceConversation).order_by(desc(DeviceConversation.id)).limit(limit).all()

        result = []
        for c in convs:
            d = c.to_dict()
            if should_mask:
                d["mac_a"] = mask_mac(d.get("mac_a"))
                d["mac_b"] = mask_mac(d.get("mac_b"))
                d["bssid"] = mask_mac(d.get("bssid"))
            result.append(d)

        return jsonify({"status": "success", "count": len(result), "conversations": result}), 200
    finally:
        db.close()


@live_bp.route("/findings", methods=["GET"])
@jwt_required()
def get_live_findings():
    """802.11 heuristic findings raised by the wireless analyser."""
    db = _session()
    should_mask = PermissionService.should_mask_mac(_current_role())

    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(int(request.args.get("limit", 25)), 100)

        query = db.query(LiveFinding)
        total = query.count()
        findings = query.order_by(desc(LiveFinding.id)).offset((page - 1) * limit).limit(limit).all()

        result = []
        for f in findings:
            d = f.to_dict()
            if should_mask:
                d["source_mac"] = mask_mac(d.get("source_mac"))
                d["target_mac"] = mask_mac(d.get("target_mac"))
                d["bssid"] = mask_mac(d.get("bssid"))
            result.append(d)

        return jsonify({
            "status": "success",
            "total": total,
            "page": page,
            "limit": limit,
            "findings": result
        }), 200
    finally:
        db.close()


@live_bp.route("/timeline", methods=["GET"])
@jwt_required()
def get_live_alert_timeline():
    """Alert volume across the last 60 minutes in five-minute buckets."""
    db = _session()
    try:
        now = datetime.utcnow()
        start = now - timedelta(minutes=60)

        labels = []
        counts = []
        for i in range(12):
            b_start = start + timedelta(minutes=i * 5)
            b_end = b_start + timedelta(minutes=5)
            labels.append(b_end.strftime("%H:%M"))
            counts.append(db.query(Alert).filter(
                Alert.created_at >= b_start,
                Alert.created_at < b_end
            ).count())

        return jsonify({"status": "success", "labels": labels, "counts": counts}), 200
    finally:
        db.close()


@live_bp.route("/windows", methods=["GET"])
@jwt_required()
def get_live_windows():
    """Per-window capture log: frames, rate, latency and stored events."""
    db = _session()
    try:
        windows = db.query(LiveCaptureWindow).order_by(desc(LiveCaptureWindow.id)).limit(20).all()
        return jsonify({
            "status": "success",
            "windows": [
                {
                    "id": w.id,
                    "start": w.window_start.isoformat() if w.window_start else None,
                    "frames": w.frames_count,
                    "pps": w.packets_per_second,
                    "findings": w.findings_count,
                    "processing_ms": w.processing_ms
                } for w in windows
            ]
        }), 200
    finally:
        db.close()
