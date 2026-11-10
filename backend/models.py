"""
AI-NIDS SQLAlchemy Database Models
Chinhoyi University of Technology - Group 5
Defines normalized schemas for events, alerts, users, identity sessions,
telemetry capture sessions, model evaluation runs, and audit logs.
"""

import json
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Index, SmallInteger
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="Cybersecurity Analyst")  # Administrator / Cybersecurity Analyst
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Security columns
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "active": self.active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(50), unique=True, nullable=False)
    detection_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    attack_type = Column(String(100), nullable=True)
    ml_class = Column(String(50), nullable=True)
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True)
    source_ips_list = Column(Text, nullable=True)
    protocol = Column(String(20), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    traffic_stats = Column(Text, nullable=True)
    detection_method = Column(String(50), nullable=True)
    severity = Column(String(30), nullable=True)
    confidence_score = Column(Float, nullable=True)
    evidence = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)
    response_status = Column(String(50), default="Pending review", nullable=True)
    system_response = Column(Text, nullable=True)
    admin_action = Column(String(100), default="None", nullable=True)
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    capture_source = Column(String(255), nullable=True)
    integrity_hash = Column(String(64), nullable=True)
    
    # Wireless columns
    source_mac = Column(String(17), nullable=True)
    destination_mac = Column(String(17), nullable=True)
    bssid = Column(String(17), nullable=True)
    channel = Column(Integer, nullable=True)
    rssi_dbm = Column(Integer, nullable=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=True)
    window_id = Column(Integer, ForeignKey("live_capture_windows.id", ondelete="CASCADE"), nullable=True)

    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")

    def format_event_id(self):
        if not self.event_id:
            self.event_id = f"THR-{self.id:06d}"
        return self.event_id

    def to_dict(self):
        stats = {}
        if self.traffic_stats:
            try:
                stats = json.loads(self.traffic_stats) if isinstance(self.traffic_stats, str) else self.traffic_stats
            except Exception:
                stats = {}

        ev_json = {}
        if self.evidence_json:
            try:
                ev_json = json.loads(self.evidence_json) if isinstance(self.evidence_json, str) else self.evidence_json
            except Exception:
                ev_json = {}

        return {
            "id": self.id,
            "event_id": self.event_id or (f"THR-{self.id:06d}" if self.id else "THR-000000"),
            "detection_time": self.detection_time.isoformat() if self.detection_time else None,
            "attack_type": self.attack_type,
            "ml_class": self.ml_class,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "traffic_stats": stats,
            "detection_method": self.detection_method,
            "severity": self.severity,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "evidence_json": ev_json,
            "response_status": self.response_status,
            "system_response": self.system_response,
            "admin_action": self.admin_action or "None",
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "notes": self.notes,
            "capture_source": self.capture_source,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "bssid": self.bssid,
            "channel": self.channel,
            "rssi_dbm": self.rssi_dbm
        }


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    severity = Column(String(30), nullable=False)
    status = Column(String(50), default="Active", nullable=False)  # Active / Acknowledged / Suppressed
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("Event", back_populates="alerts")

    def to_dict(self):
        data = {
            "id": self.id,
            "event_id": self.event_id,
            "severity": self.severity,
            "status": self.status,
            "message": self.message,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
        if self.event is not None:
            data["event"] = {
                "id": self.event.id,
                "event_id": self.event.event_id,
                "attack_type": self.event.attack_type,
                "source_ip": self.event.source_ip,
                "confidence_score": self.event.confidence_score,
                "response_status": self.event.response_status,
                "severity": self.event.severity
            }
        return data


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # New columns
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    role = Column(String(50), nullable=True)
    outcome = Column(String(20), default="success")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "action": self.action,
            "details": self.details,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "outcome": self.outcome,
            "role": self.role
        }


class LoginHistory(Base):
    __tablename__ = "login_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = Column(String(100), nullable=False)
    role = Column(String(50), nullable=True)
    event_type = Column(String(40), nullable=False)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String(255), nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    session_id = Column(String(64), nullable=True)
    event_time = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "event_type": self.event_type,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "ip_address": self.ip_address,
            "event_time": self.event_time.isoformat() if self.event_time else None
        }


class UserSession(Base):
    __tablename__ = "user_sessions"

    session_id = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token_hash = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
    revoked_reason = Column(String(100), nullable=True)


class LiveCaptureWindow(Base):
    __tablename__ = "live_capture_windows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=False)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    frames_count = Column(Integer, default=0)
    management_frames = Column(Integer, default=0)
    control_frames = Column(Integer, default=0)
    data_frames = Column(Integer, default=0)
    deauth_frames = Column(Integer, default=0)
    beacon_frames = Column(Integer, default=0)
    probe_frames = Column(Integer, default=0)
    unique_transmitters = Column(Integer, default=0)
    packets_per_second = Column(Float, nullable=True)
    avg_rssi_dbm = Column(Float, nullable=True)
    baseline_pps = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    findings_count = Column(Integer, default=0)
    processing_ms = Column(Float, nullable=True)


class LiveFinding(Base):
    __tablename__ = "live_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(30), unique=True, nullable=False)
    event_id = Column(Integer, ForeignKey("events.id", ondelete="SET NULL"), nullable=True)
    window_id = Column(Integer, ForeignKey("live_capture_windows.id", ondelete="SET NULL"), nullable=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id", ondelete="SET NULL"), nullable=True)
    found_at = Column(DateTime, default=datetime.utcnow)
    finding_type = Column(String(100), nullable=False)
    severity = Column(String(30), nullable=False)
    source_mac = Column(String(17), nullable=True)
    target_mac = Column(String(17), nullable=True)
    bssid = Column(String(17), nullable=True)
    source_ip = Column(String(100), nullable=True)
    target_ip = Column(String(100), nullable=True)
    channel = Column(Integer, nullable=True)
    rssi_dbm = Column(Integer, nullable=True)
    packets_in_window = Column(Integer, nullable=True)
    packets_per_second = Column(Float, nullable=True)
    confidence_score = Column(Float, nullable=True)
    detection_method = Column(String(50), nullable=False)
    evidence = Column(Text, nullable=False)
    evidence_json = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)
    status = Column(String(50), default="Pending review", nullable=False)
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "event_id": self.event_id,
            "window_id": self.window_id,
            "capture_session_id": self.capture_session_id,
            "found_at": self.found_at.isoformat() if self.found_at else None,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "source_mac": self.source_mac,
            "target_mac": self.target_mac,
            "bssid": self.bssid,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "channel": self.channel,
            "rssi_dbm": self.rssi_dbm,
            "packets_in_window": self.packets_in_window,
            "packets_per_second": self.packets_per_second,
            "confidence_score": self.confidence_score,
            "detection_method": self.detection_method,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "status": self.status,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None
        }


class WifiFrame(Base):
    __tablename__ = "wifi_frames"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=True)
    window_id = Column(Integer, ForeignKey("live_capture_windows.id", ondelete="CASCADE"), nullable=True)
    frame_time = Column(DateTime, nullable=False)
    delta_time = Column(Float, nullable=True)
    transmitter_mac = Column(String(17), nullable=True)
    receiver_mac = Column(String(17), nullable=True)
    bssid = Column(String(17), nullable=True)
    frame_type = Column(String(20), nullable=True)
    frame_subtype = Column(String(50), nullable=True)
    rssi_dbm = Column(Integer, nullable=True)
    channel = Column(Integer, nullable=True)
    frame_length = Column(Integer, nullable=True)
    ssid = Column(String(64), nullable=True)
    reason_code = Column(Integer, nullable=True)
    flagged = Column(Boolean, nullable=False, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "frame_time": self.frame_time.isoformat() if self.frame_time else None,
            "delta_time": self.delta_time,
            "transmitter_mac": self.transmitter_mac,
            "receiver_mac": self.receiver_mac,
            "bssid": self.bssid,
            "frame_type": self.frame_type,
            "frame_subtype": self.frame_subtype,
            "rssi_dbm": self.rssi_dbm,
            "channel": self.channel,
            "frame_length": self.frame_length,
            "ssid": self.ssid,
            "reason_code": self.reason_code,
            "flagged": self.flagged
        }


class DeviceConversation(Base):
    __tablename__ = "device_conversations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id", ondelete="CASCADE"), nullable=True)
    window_id = Column(Integer, ForeignKey("live_capture_windows.id", ondelete="CASCADE"), nullable=True)
    mac_a = Column(String(17), nullable=False)
    mac_b = Column(String(17), nullable=False)
    bssid = Column(String(17), nullable=True)
    channel = Column(Integer, nullable=True)
    packets = Column(Integer, nullable=False, default=0)
    bytes = Column(Integer, nullable=False, default=0)
    packets_per_second = Column(Float, nullable=True)
    avg_rssi_dbm = Column(Float, nullable=True)
    delta_rssi = Column(Float, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    vendor_a = Column(String(100), nullable=True)
    vendor_b = Column(String(100), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "mac_a": self.mac_a,
            "mac_b": self.mac_b,
            "bssid": self.bssid,
            "channel": self.channel,
            "packets": self.packets,
            "bytes": self.bytes,
            "packets_per_second": self.packets_per_second,
            "avg_rssi_dbm": self.avg_rssi_dbm,
            "delta_rssi": self.delta_rssi,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "vendor_a": self.vendor_a or "Unknown",
            "vendor_b": self.vendor_b or "Unknown"
        }


class WifiAccessPoint(Base):
    __tablename__ = "wifi_access_points"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ssid = Column(String(64), nullable=True)
    bssid = Column(String(17), unique=True, nullable=False)
    channel = Column(Integer, nullable=True)
    encryption = Column(String(50), nullable=True)
    approved = Column(Boolean, nullable=False, default=False)
    approved_by = Column(String(100), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "encryption": self.encryption,
            "approved": self.approved,
            "approved_by": self.approved_by,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None
        }


class BaselineStat(Base):
    __tablename__ = "baseline_stats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    day_of_week = Column(SmallInteger, nullable=False)
    hour_of_day = Column(SmallInteger, nullable=False)
    avg_pps = Column(Float, nullable=True)
    std_pps = Column(Float, nullable=True)
    avg_deauth_rate = Column(Float, nullable=True)
    samples = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow)


class AnalysisTotal(Base):
    """One row per traffic source holding the headline figures the dashboard shows.

    Written by the campus ingester for the test-data baseline and by the live monitor
    for captured traffic, so every number on the dashboard can be read straight from
    PostgreSQL instead of being recomputed from a constant.
    """
    __tablename__ = "analysis_totals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_source = Column(String(120), unique=True, nullable=False)
    devices_monitored = Column(Integer, nullable=False, default=0)
    records_analysed = Column(Integer, nullable=False, default=0)
    normal_count = Column(Integer, nullable=False, default=0)
    suspicious_count = Column(Integer, nullable=False, default=0)
    potential_attack_count = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    flagged_share_percent = Column(Float, nullable=False, default=0.0)
    traffic_window_start = Column(DateTime, nullable=True)
    traffic_window_end = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "capture_source": self.capture_source,
            "devices_monitored": self.devices_monitored,
            "records_analysed": self.records_analysed,
            "normal_count": self.normal_count,
            "suspicious_count": self.suspicious_count,
            "potential_attack_count": self.potential_attack_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "flagged_share_percent": self.flagged_share_percent,
            "traffic_window_start": self.traffic_window_start.isoformat() if self.traffic_window_start else None,
            "traffic_window_end": self.traffic_window_end.isoformat() if self.traffic_window_end else None,
            "notes": self.notes,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None
        }


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50), default="General Incident", nullable=False)
    generated_by = Column(String(100), nullable=False)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    total_events = Column(Integer, default=0, nullable=False)
    file_path = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "report_type": self.report_type,
            "generated_by": self.generated_by,
            "total_events": self.total_events,
            "file_path": self.file_path,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class CaptureSession(Base):
    __tablename__ = "capture_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_identifier = Column(String(100), unique=True, nullable=False)
    interface_name = Column(String(255), nullable=False)
    capture_type = Column(String(50), nullable=False)
    packets_captured = Column(Integer, default=0, nullable=False)
    flows_analyzed = Column(Integer, default=0, nullable=False)
    status = Column(String(50), default="Completed", nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime, nullable=True)
    
    # New columns
    adapter_friendly_name = Column(String(255), nullable=True)
    monitor_mode = Column(Boolean, default=False)
    channel = Column(Integer, nullable=True)
    window_seconds = Column(Integer, default=10)
    restart_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    started_by = Column(String(100), nullable=True)
    total_frames = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    events_stored = Column(Integer, default=0, nullable=False)
    alerts_raised = Column(Integer, default=0, nullable=False)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
