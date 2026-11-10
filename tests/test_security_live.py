"""
AI-NIDS Security & Live Capture Testing Suite
Chinhoyi University of Technology - Group 5
Covers RBAC, Sessions, Lockout, and Live Pipeline.
"""

import os
import sys
import time
import pytest
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app import create_app
from backend.config import ANALYST_ROLE
from backend.models import User, UserSession, LoginHistory, LiveCaptureWindow, LiveFinding
from database.seed import seed_database

@pytest.fixture(scope="module")
def app():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:"
    })
    # Seed the database
    with app.app_context():
        seed_database(target_session_factory=app.config["SESSION_FACTORY"])
    return app

@pytest.fixture(scope="module")
def client(app):
    return app.test_client()

@pytest.fixture(scope="module")
def admin_headers(app):
    with app.app_context():
        SessionLocal = app.config["SESSION_FACTORY"]
        db = SessionLocal()
        user = db.query(User).filter_by(username="admin").first()
        
        session_id = "test_admin_session"
        new_session = UserSession(
            session_id=session_id,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            revoked=False,
            last_activity=datetime.utcnow()
        )
        db.add(new_session)
        db.commit()
        
        token = create_access_token(
            identity="admin", 
            additional_claims={"role": "Administrator", "session_id": session_id, "user_id": user.id}
        )
        db.close()
        return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="module")
def analyst_headers(app):
    with app.app_context():
        SessionLocal = app.config["SESSION_FACTORY"]
        db = SessionLocal()
        user = db.query(User).filter_by(username="analyst").first()
        
        session_id = "test_analyst_session"
        new_session = UserSession(
            session_id=session_id,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            revoked=False,
            last_activity=datetime.utcnow()
        )
        db.add(new_session)
        db.commit()
        
        token = create_access_token(
            identity="analyst", 
            additional_claims={"role": ANALYST_ROLE, "session_id": session_id, "user_id": user.id}
        )
        db.close()
        return {"Authorization": f"Bearer {token}"}

# 1. Permissions Matrix Tests
def test_rbac_admin_vs_analyst(client, admin_headers, analyst_headers):
    # Both roles drive the live monitor
    assert client.get("/api/capture/status", headers=admin_headers).status_code == 200
    assert client.get("/api/capture/status", headers=analyst_headers).status_code == 200

    # User management is administrator only
    assert client.get("/api/users", headers=admin_headers).status_code == 200
    res = client.get("/api/users", headers=analyst_headers)
    assert res.status_code == 403

    # Audit trail is administrator only
    assert client.get("/api/audit-logs", headers=admin_headers).status_code == 200
    res = client.get("/api/audit-logs", headers=analyst_headers)
    assert res.status_code == 403

    # Deleting a recorded event is administrator only
    res = client.delete("/api/events/1", headers=analyst_headers)
    assert res.status_code == 403

# 2. Login Lockout Tests
def test_login_lockout(client, app):
    # Try multiple failed logins
    for _ in range(6):
        client.post("/api/auth/login", json={
            "username": "admin",
            "password": "wrong_password"
        })
    
    # Verify user is locked
    SessionLocal = app.config["SESSION_FACTORY"]
    db = SessionLocal()
    user = db.query(User).filter_by(username="admin").first()
    assert user.failed_login_count >= 5
    assert user.locked_until is not None
    db.close()
    
    # Try login while locked
    res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "CUT_Nids_Admin2026!"
    })
    assert res.status_code == 403
    assert "locked" in res.get_json()["message"].lower()

# 3. Session Management & Revocation
def test_session_revocation(client, app, admin_headers):
    # Create a session in DB
    SessionLocal = app.config["SESSION_FACTORY"]
    db = SessionLocal()
    session_id = "test_revoke_session"
    new_session = UserSession(
        session_id=session_id,
        user_id=1,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        revoked=False
    )
    db.add(new_session)
    db.commit()
    
    # Revoke it
    res = client.post(f"/api/auth/sessions/{session_id}/revoke", headers=admin_headers)
    assert res.status_code == 200
    
    # Verify revoked in DB
    db.refresh(new_session)
    assert new_session.revoked == True
    db.close()

# 4. Login History Recording
def test_login_history_logging(client, app):
    # Reset lockout first to ensure login works
    SessionLocal = app.config["SESSION_FACTORY"]
    db = SessionLocal()
    user = db.query(User).filter_by(username="admin").first()
    user.failed_login_count = 0
    user.locked_until = None
    db.commit()
    db.close()
    
    # Perform a login
    res = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "CUT_Nids_Admin2026!"
    })
    assert res.status_code == 200
    
    # Check login_history table
    SessionLocal = app.config["SESSION_FACTORY"]
    db = SessionLocal()
    history = db.query(LoginHistory).filter(
        LoginHistory.username == "admin",
        LoginHistory.event_type.in_(["LOGIN_SUCCESS", "LOGIN_FAILED"])
    ).order_by(LoginHistory.id.desc()).first()
    assert history is not None
    db.close()

# 5. Live Window Processing
def test_live_window_processing(app):
    SessionLocal = app.config["SESSION_FACTORY"]
    db = SessionLocal()
    
    from backend.services.wireless_analyzer import WirelessAnalyzer
    analyzer = WirelessAnalyzer(db, {"wireless": {"deauth_flood": {"enabled": True, "frame_threshold": 5}}})
    
    # Mock packets
    packets = [
        {"fc_type": 0, "fc_subtype": 12, "transmitter_mac": "AA:BB:CC:DD:EE:FF", "rssi": -50, "length": 64},
        {"fc_type": 0, "fc_subtype": 12, "transmitter_mac": "AA:BB:CC:DD:EE:FF", "rssi": -50, "length": 64},
        {"fc_type": 0, "fc_subtype": 12, "transmitter_mac": "AA:BB:CC:DD:EE:FF", "rssi": -50, "length": 64},
        {"fc_type": 0, "fc_subtype": 12, "transmitter_mac": "AA:BB:CC:DD:EE:FF", "rssi": -50, "length": 64},
        {"fc_type": 0, "fc_subtype": 12, "transmitter_mac": "AA:BB:CC:DD:EE:FF", "rssi": -50, "length": 64},
        {"fc_type": 0, "fc_subtype": 12, "transmitter_mac": "AA:BB:CC:DD:EE:FF", "rssi": -50, "length": 64},
    ]
    
    start = datetime.utcnow()
    end = start + timedelta(seconds=10)
    
    window = analyzer.analyze_window(1, packets, start, end)
    db.commit()
    
    # Verify window data
    assert window.deauth_frames == 6
    assert window.findings_count > 0
    
    # Verify finding created
    finding = db.query(LiveFinding).filter_by(window_id=window.id).first()
    assert finding is not None
    assert finding.finding_type == "Deauthentication Flood"
    
    db.close()

# 6. Campus access point register
def test_bssid_register_approval(app):
    from backend.services.wireless_analyzer import WirelessAnalyzer

    SessionLocal = app.config["SESSION_FACTORY"]
    db = SessionLocal()
    try:
        rules = {"wireless": {"approved_access_points": [
            {"bssid": "00:11:22:33:44:55", "ssid": "CUT-Staff"},
        ]}}
        analyzer = WirelessAnalyzer(db, rules)

        assert analyzer._is_authorised_ap("00:11:22:33:44:55", None) is True
        assert analyzer._is_authorised_ap("00:11:22:33:44:55".upper(), "anything") is True
        assert analyzer._is_authorised_ap("99:88:77:66:55:44", "CUT-Staff") is True
        assert analyzer._is_authorised_ap("99:88:77:66:55:44", "Guest-WiFi") is False

        # Without a configured register the analyser cannot brand every AP as rogue
        empty = WirelessAnalyzer(db, {"wireless": {}})
        assert empty._is_authorised_ap("00:11:22:33:44:55", "CUT-Staff") is False
    finally:
        db.close()
