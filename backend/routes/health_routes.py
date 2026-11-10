"""
AI-NIDS System Health Route
Chinhoyi University of Technology - Group 5

Answers one question for the header indicator and the login page: are the
database, the AI classifier and the live capture all up?
"""

from flask import Blueprint, jsonify, current_app
from datetime import datetime
from sqlalchemy import text

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def check_health():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    capture_service = current_app.config["CAPTURE_SERVICE"]
    ml_service = current_app.config["ML_SERVICE"]

    db_connected = False
    db_engine = "postgresql"

    session = SessionLocal()
    try:
        session.execute(text("SELECT 1"))
        db_connected = True
        db_engine = session.bind.dialect.name
    except Exception:
        db_connected = False
    finally:
        session.close()

    capture_stat = capture_service.get_status()
    engine_ready = capture_service.tshark_parser.is_available
    model_ready = ml_service.current_model is not None

    healthy = db_connected and engine_ready and model_ready

    return jsonify({
        "status": "healthy" if healthy else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "database": {"connected": db_connected, "engine": db_engine},
        "ai_model": {"loaded": model_ready, "algorithm": ml_service.active_algorithm},
        "capture": {
            "state": capture_stat.get("state", "STOPPED"),
            "is_capturing": capture_stat.get("is_capturing", False),
            "adapter": capture_stat.get("friendly_name") or capture_stat.get("adapter")
        }
    }), (200 if db_connected else 500)
