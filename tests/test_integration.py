"""
AI-NIDS Integration Testing Suite (IT01 - IT04)
Chinhoyi University of Technology - Group 5
Validates cross-tier workflows:
IT01: ML Model -> Backend inference integration
IT02: Backend -> Database event persistence
IT03: Database -> Dashboard analytics aggregation
IT04: Backend -> Priority Queue & Alert Dispatch
"""

import os
import sys
import pytest
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app import create_app
from backend.config import TEST_TRAFFIC_SOURCE, AI_MODEL_METHOD
from backend.models import Alert, Event
from backend.services.ml_service import MLService
from backend.services.feature_pipeline import LIVE_FEATURE_NAMES
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
def auth_headers(app_client):
    res = app_client.post("/api/auth/login", json={
        "username": "admin",
        "password": "CUT_Nids_Admin2026!"
    })
    token = res.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def seeded_events(app_client):
    """Writes classified flows plus their alerts, exactly as the capture pipeline does."""
    session = app_client.application.config["SESSION_FACTORY"]()
    created_ids = []
    try:
        for index in range(3):
            flagged = Event(
                event_id=f"IT-ATTACK-{index}",
                detection_time=datetime.utcnow(),
                attack_type="Brute Force",
                ml_class="Potential Attack",
                severity="High",
                source_ip=f"192.168.1.{20 + index}",
                destination_ip="192.168.1.1",
                protocol="TCP",
                source_port=40000 + index,
                destination_port=22,
                detection_method=AI_MODEL_METHOD,
                confidence_score=0.96,
                evidence="Repeated short-lived sessions to port 22",
                capture_source=TEST_TRAFFIC_SOURCE,
                traffic_stats='{"total_packets": 240}'
            )
            session.add(flagged)
            session.flush()
            session.add(Alert(
                event_id=flagged.id,
                severity="High",
                status="Active",
                message=f"Brute Force against {flagged.destination_ip}"
            ))
            created_ids.append(flagged.event_id)

        for index in range(2):
            session.add(Event(
                event_id=f"IT-NORMAL-{index}",
                detection_time=datetime.utcnow(),
                attack_type="Normal",
                ml_class="Normal",
                severity="Low",
                source_ip=f"192.168.1.{100 + index}",
                destination_ip="192.168.1.5",
                protocol="TCP",
                source_port=50000 + index,
                destination_port=443,
                detection_method=AI_MODEL_METHOD,
                confidence_score=0.99,
                evidence="Within operational baseline",
                capture_source=TEST_TRAFFIC_SOURCE,
                traffic_stats='{"total_packets": 40}'
            ))
            created_ids.append(f"IT-NORMAL-{index}")
        session.commit()
    finally:
        session.close()
    return created_ids


# IT01: ML -> Backend Inference Pipeline
def test_it01_ml_to_backend_pipeline():
    ml_service = MLService()
    sample_flow = {f: 0.0 for f in LIVE_FEATURE_NAMES}
    sample_flow["Dst Port"] = 22.0
    sample_flow["Tot Fwd Pkts"] = 15.0
    sample_flow["Flow Duration"] = 500000.0

    pred = ml_service.predict_flow(sample_flow)
    assert "attack_type" in pred
    assert "confidence_score" in pred
    assert "ml_class" in pred
    assert pred["inference_latency_ms"] < 2000.0


# IT02: Backend -> Database Event Persistence
def test_it02_backend_to_database_persistence(app_client, auth_headers, seeded_events):
    res = app_client.get("/api/events", headers=auth_headers)
    assert res.status_code == 200
    events = res.get_json()["events"]
    assert len(events) >= len(seeded_events)
    assert all(e["capture_source"] in (TEST_TRAFFIC_SOURCE,) for e in events)


# IT03: Database -> Dashboard Aggregation
def test_it03_database_to_dashboard_aggregation(app_client, auth_headers, seeded_events):
    res = app_client.get("/api/dashboard/summary", headers=auth_headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "kpis" in data
    assert "charts" in data
    assert data["kpis"]["total_events"] >= len(seeded_events)
    assert data["kpis"]["potential_attacks"] >= 3
    assert data["charts"]["attack_type_distribution"]["Brute Force"] >= 3


# IT04: Backend -> Priority Queue & Alert Generation
def test_it04_backend_to_alert_dispatch(app_client, auth_headers, seeded_events):
    res = app_client.get("/api/events/alerts", headers=auth_headers)
    assert res.status_code == 200
    alerts = res.get_json()["alerts"]
    assert len(alerts) >= 1
    # Check alert structure
    assert "severity" in alerts[0]
    assert "event" in alerts[0]
    assert alerts[0]["event"]["attack_type"] == "Brute Force"
