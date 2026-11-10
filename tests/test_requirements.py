"""
AI-NIDS Test Requirements Suite (TD01 - TD12)
Chinhoyi University of Technology - Group 5
Validates specific test data design specifications required for Chapter 5 evidence.
"""

import os
import sys
import pytest
import json
from datetime import datetime
from uuid import uuid4

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app import create_app
from backend.config import TEST_TRAFFIC_SOURCE, LIVE_TRAFFIC_SOURCE
from backend.models import Event
from backend.services.feature_pipeline import FeaturePipeline, FeatureValidationError
from backend.services.severity_engine import SeverityEngine
from backend.services.ml_service import MLService
from database.seed import seed_database


@pytest.fixture(scope="module")
def app_client():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"
    })
    seed_database(target_session_factory=app.config["SESSION_FACTORY"])
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="module")
def admin_token(app_client):
    res = app_client.post("/api/auth/login", json={
        "username": "admin",
        "password": "CUT_Nids_Admin2026!"
    })
    assert res.status_code == 200
    return res.get_json()["token"]


@pytest.fixture(scope="module")
def analyst_token(app_client):
    res = app_client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "CUT_Analyst2026!"
    })
    assert res.status_code == 200
    return res.get_json()["token"]


# TD01: Normal traffic classified Normal with no alert
def test_td01_normal_traffic():
    sev_engine = SeverityEngine()
    severity, latency, rationale = sev_engine.evaluate_severity(
        attack_type="Normal",
        ml_class="Normal",
        confidence_score=0.99,
        packet_count=50,
        destination_ip="192.168.1.1"
    )
    assert severity == "Low"
    assert "Normal benign traffic" in rationale
    assert latency < 2.0


# TD02: Suspicious traffic gives a medium alert
def test_td02_suspicious_traffic():
    sev_engine = SeverityEngine()
    severity, latency, rationale = sev_engine.evaluate_severity(
        attack_type="Other/Suspicious",
        ml_class="Suspicious",
        confidence_score=0.75,
        packet_count=100,
        destination_ip="192.168.1.50"
    )
    assert severity == "Medium"
    assert latency < 2.0


# TD03: Potential attack gives a high alert
def test_td03_potential_attack():
    sev_engine = SeverityEngine()
    severity, latency, rationale = sev_engine.evaluate_severity(
        attack_type="Port Scanning",
        ml_class="Potential Attack",
        confidence_score=0.96,
        packet_count=500,
        destination_ip="192.168.1.10"
    )
    assert severity in ["High", "Critical"]
    assert latency < 2.0


# TD04: Missing feature rejected
def test_td04_missing_feature_rejected():
    pipeline = FeaturePipeline()
    incomplete_features = {
        "Dst Port": 80,
        "Protocol": 6
        # Missing remaining 32 required features
    }
    is_valid, msg = pipeline.validate_features(incomplete_features)
    assert not is_valid
    assert "Missing required feature" in msg


# TD05: Invalid data type rejected
def test_td05_invalid_data_type_rejected():
    pipeline = FeaturePipeline()
    invalid_type_features = {feat: 1.0 for feat in pipeline.feature_list}
    invalid_type_features["Dst Port"] = "INVALID_STRING_PORT"

    is_valid, msg = pipeline.validate_features(invalid_type_features)
    assert not is_valid
    assert "Invalid data type" in msg


# TD06: Out-of-range value rejected/flagged
def test_td06_out_of_range_rejected():
    pipeline = FeaturePipeline()
    out_of_range_features = {feat: 1.0 for feat in pipeline.feature_list}
    out_of_range_features["Dst Port"] = 999999  # Port exceeds 65535 limit

    is_valid, msg = pipeline.validate_features(out_of_range_features)
    assert not is_valid
    assert "out of permitted range" in msg


# TD07: Valid admin login
def test_td07_valid_admin_login(app_client):
    res = app_client.post("/api/auth/login", json={
        "username": "admin",
        "password": "CUT_Nids_Admin2026!"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "token" in data
    assert data["user"]["role"] == "Administrator"


# TD08: Invalid login denied and audited
def test_td08_invalid_login_denied(app_client):
    res = app_client.post("/api/auth/login", json={
        "username": "admin",
        "password": "WRONG_PASSWORD_XYZ"
    })
    assert res.status_code == 401
    data = res.get_json()
    assert data["status"] == "error"


# TD09: Unauthorised management request rejected
def test_td09_unauthorized_management_rejected(app_client, analyst_token):
    # Cybersecurity Analyst attempting administrator-only management actions
    headers = {"Authorization": f"Bearer {analyst_token}"}
    res = app_client.get("/api/users", headers=headers)
    assert res.status_code == 403

    res_delete = app_client.delete("/api/events/1", headers=headers)
    assert res_delete.status_code == 403


# TD10: Alert search/filter returns only matches
def test_td10_alert_search_filter(app_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}

    session = app_client.application.config["SESSION_FACTORY"]()
    try:
        for attack_type, ml_class, severity in [
            ("Brute Force", "Potential Attack", "High"),
            ("Brute Force", "Potential Attack", "High"),
            ("Normal", "Normal", "Low"),
        ]:
            session.add(Event(
                event_id=f"TD10-{attack_type}-{ml_class}-{uuid4().hex[:8]}",
                detection_time=datetime.utcnow(),
                attack_type=attack_type,
                ml_class=ml_class,
                severity=severity,
                source_ip="192.168.1.50",
                destination_ip="192.168.1.1",
                protocol="TCP",
                source_port=41000,
                destination_port=22,
                detection_method="AI Model",
                confidence_score=0.97,
                evidence="Seeded by TD10 filter test",
                capture_source=TEST_TRAFFIC_SOURCE,
                traffic_stats=json.dumps({"total_packets": 120})
            ))
        session.commit()
    finally:
        session.close()

    res = app_client.get("/api/events?attack_type=Brute%20Force", headers=headers)
    assert res.status_code == 200
    events = res.get_json()["events"]
    assert len(events) >= 1
    assert all(e["attack_type"] == "Brute Force" for e in events)
    assert all(e["capture_source"] == TEST_TRAFFIC_SOURCE for e in events)


# TD11: Every report scope compiles a non-empty report over the shared traffic store
def test_td11_report_generated(app_client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}

    session = app_client.application.config["SESSION_FACTORY"]()
    try:
        for idx, source in enumerate((TEST_TRAFFIC_SOURCE, LIVE_TRAFFIC_SOURCE)):
            session.add(Event(
                event_id=f"TD11-{source[-8:]}-{uuid4().hex[:8]}",
                detection_time=datetime.utcnow(),
                attack_type="Brute Force",
                ml_class="Potential Attack",
                severity="High",
                source_ip=f"192.168.1.5{idx}",
                destination_ip="10.10.0.5",
                protocol="TCP",
                source_port=42000 + idx,
                destination_port=22,
                detection_method="AI Model",
                confidence_score=0.96,
                evidence="Seeded by TD11 report scope test",
                capture_source=source,
                traffic_stats=json.dumps({"total_packets": 400})
            ))
        session.commit()
    finally:
        session.close()

    counts = {}
    for scope in ("General Incident", "Critical Threats Only", "Live Capture Audit", "Test Data Audit"):
        res = app_client.post("/api/reports/generate", headers=headers, json={
            "title": f"Automated Test Report TD11 - {scope}",
            "report_type": scope,
            "days": 7
        })
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "success"
        assert "report" in data
        counts[scope] = data["event_count"]

    # No scope may silently produce an empty dossier
    assert all(count > 0 for count in counts.values()), counts
    assert counts["General Incident"] >= counts["Critical Threats Only"]
    assert (counts["Live Capture Audit"] + counts["Test Data Audit"]
            <= counts["General Incident"])

    for fmt, mimetype in (("csv", "text/csv"), ("pdf", "application/pdf")):
        export = app_client.get(
            f"/api/reports/export?format={fmt}&report_type=General%20Incident&days=7",
            headers=headers
        )
        assert export.status_code == 200
        assert mimetype in export.content_type
        assert len(export.data) > 0


# TD12: Controlled error message handling
def test_td12_controlled_error_messages(app_client):
    # Non-existent endpoint should give clean JSON without traceback
    res = app_client.get("/api/non_existent_route")
    assert res.status_code == 404
    data = res.get_json()
    assert data["status"] == "error"
    assert "resource was not found" in data["message"]
