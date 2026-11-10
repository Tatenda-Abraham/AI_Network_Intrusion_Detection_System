"""
AI-NIDS Flask Application Factory & Server
Chinhoyi University of Technology (CUT)
School of Engineering Sciences and Technology
Department of ICT and Electronics (Group 5)
"""

import os
import sys
from datetime import datetime

# Ensure root directory is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt, verify_jwt_in_request
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from backend.config import Config
from backend.models import Base
from backend.services.priority_queue import AlertPriorityQueue
from backend.services.capture_service import CaptureService
from backend.services.audit_service import AuditService
from backend.services.ml_service import MLService
from backend.services.report_service import ReportService
from backend.services.severity_engine import SeverityEngine
from backend.services.feature_pipeline import FeaturePipeline
from backend.services.auth_service import AuthService
from backend.services.retention_service import RetentionService
from database.seed import seed_database

# Route blueprints
from backend.routes.auth_routes import auth_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.event_routes import event_bp
from backend.routes.capture_routes import capture_bp
from backend.routes.report_routes import report_bp
from backend.routes.user_routes import user_bp
from backend.routes.health_routes import health_bp
from backend.routes.live_routes import live_bp


def print_startup_self_check(engine, tshark_parser, ml_service, capture_service):
    """Prints comprehensive system diagnostic checks in the backend terminal at startup."""
    print("\n" + "=" * 70)
    print("CHINHOYI UNIVERSITY OF TECHNOLOGY - AI-NIDS STARTUP SYSTEM CHECK")
    print("=" * 70)

    # 1. Database & Table Check
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            db_dialect = engine.dialect.name
            print(f"[+] PostgreSQL Database: CONNECTED ({db_dialect}) | Tables found: {len(tables)} [PASS]")
            critical_tables = ["users", "events", "alerts", "live_findings", "wifi_frames", "login_history"]
            missing = [t for t in critical_tables if t not in tables]
            if missing:
                print(f"[!] Warning: missing tables: {missing}")
    except Exception as e:
        print(f"[-] Database Connection: FAILED ({e}) [FAIL]")

    # 2. TShark & Wireshark Check
    if tshark_parser.is_available:
        print(f"[+] TShark / Wireshark: FOUND at '{tshark_parser.tshark_path}' [PASS]")
        print(f"    Driver info: {tshark_parser.status_message}")
        ifaces = tshark_parser.list_interfaces()
        real_ifaces = [i for i in ifaces if not i.get("is_virtual")]
        print(f"    Available Adapters: {len(ifaces)} total ({len(real_ifaces)} physical/non-virtual)")
    else:
        print(f"[-] TShark / Wireshark: NOT FOUND at '{tshark_parser.tshark_path}' [FAIL]")

    # 3. Monitoring source selection
    if tshark_parser.is_available:
        primary = tshark_parser.select_primary_interface()
        if primary:
            print(f"[+] Monitoring source selected: {primary['friendly_name']} ({primary['device']})")
        else:
            print("[!] Monitoring source: no capture interface could be listed")

    # 4. AI Machine Learning Core Check
    if ml_service.current_model is not None:
        metrics = ml_service.get_metrics().get("metrics", {})
        acc = metrics.get("accuracy")
        fpr = metrics.get("false_positive_rate")
        infer_sec = metrics.get("evaluation_latency_seconds")

        model_meta = ml_service.metadata
        feature_count = model_meta.get("feature_count") or len(model_meta.get("features", []))
        print(f"[+] AI Classifier Loaded: {ml_service.active_algorithm} "
              f"({model_meta.get('model_version', 'v1')}, {feature_count} features) [PASS]")
        if acc is not None:
            print(f"    - Accuracy: {float(acc)*100:.2f}% (Target: >= 95.0%) "
                  f"[{'PASS' if float(acc) >= 0.95 else 'FAIL'}]")
        if fpr is not None:
            print(f"    - False-Positive Rate: {float(fpr)*100:.2f}% (Target: < 3.0%) "
                  f"[{'PASS' if float(fpr) < 0.03 else 'FAIL'}]")
        if infer_sec is not None:
            print(f"    - Classification Latency: {float(infer_sec)*1000:.1f} ms (Target: < 2.0 s) "
                  f"[{'PASS' if float(infer_sec) < 2.0 else 'FAIL'}]")
    else:
        print("[-] AI Classifier: NOT LOADED [FAIL]")

    print("=" * 70 + "\n")


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    # Chart payloads are built ranked (threats by count, tiers by urgency); sorting the
    # JSON keys alphabetically would throw that order away before it reaches the browser.
    app.json.sort_keys = False

    if test_config:
        app.config.update(test_config)

    # Initialize CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

    # Initialize JWT Authentication
    jwt = JWTManager(app)

    @jwt.unauthorized_loader
    def unauthorized_callback(callback):
        return jsonify({
            "status": "error",
            "message": "Authorization header missing or invalid token provided"
        }), 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            "status": "error",
            "message": "Access session has expired. Please log in again."
        }), 401

    # Database Initialization
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI")
    engine = create_engine(db_uri)
    SessionLocal = sessionmaker(bind=engine, autoflush=False)
    Base.metadata.create_all(bind=engine)

    # Dependency Injection into app.config
    alert_queue = AlertPriorityQueue()
    audit_service = AuditService(SessionLocal)
    capture_service = CaptureService(SessionLocal, alert_queue=alert_queue)
    ml_service = MLService()
    report_service = ReportService(SessionLocal)
    severity_engine = SeverityEngine()
    feature_pipeline = FeaturePipeline()
    retention_service = RetentionService(SessionLocal)

    app.config["SESSION_FACTORY"] = SessionLocal
    app.config["AUDIT_SERVICE"] = audit_service
    app.config["CAPTURE_SERVICE"] = capture_service
    app.config["ML_SERVICE"] = ml_service
    app.config["REPORT_SERVICE"] = report_service
    app.config["PRIORITY_QUEUE"] = alert_queue
    app.config["SEVERITY_ENGINE"] = severity_engine
    app.config["FEATURE_PIPELINE"] = feature_pipeline
    app.config["RETENTION_SERVICE"] = retention_service

    # Start retention service
    retention_service.start()

    # Security Headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        return response

    # Active session validation on each request
    @app.before_request
    def validate_session_activity():
        if request.path.startswith('/api/auth') or not request.path.startswith('/api/'):
            return

        try:
            verify_jwt_in_request(optional=True)
            claims = get_jwt()
            if claims:
                session_id = claims.get("session_id")
                if session_id:
                    db = SessionLocal()
                    auth_service = AuthService(db)
                    is_valid, _ = auth_service.validate_session(session_id)
                    db.close()
                    if not is_valid:
                        return jsonify({"status": "error", "message": "Session expired or revoked"}), 401
        except Exception:
            pass

    # Register Blueprints cleanly
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(event_bp, url_prefix="/api/events")
    app.register_blueprint(capture_bp, url_prefix="/api/capture")
    app.register_blueprint(report_bp, url_prefix="/api/reports")
    app.register_blueprint(user_bp, url_prefix="/api")
    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(live_bp, url_prefix="/api/live")

    # Controlled Error Handlers - no stack traces
    @app.errorhandler(404)
    def not_found_handler(e):
        return jsonify({"status": "error", "message": "The requested API resource was not found"}), 404

    @app.errorhandler(403)
    def forbidden_handler(e):
        return jsonify({"status": "error", "message": "Access forbidden: insufficient role permissions"}), 403

    @app.errorhandler(500)
    def internal_error_handler(e):
        return jsonify({"status": "error", "message": "An internal system error occurred. Action has been logged."}), 500

    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "system": "AI-Based Network Intrusion Detection and Monitoring System (AI-NIDS)",
            "institution": "Chinhoyi University of Technology",
            "school": "School of Engineering Sciences and Technology",
            "department": "Department of ICT and Electronics",
            "group": "Group 5 (BSc Hons Information Technology)",
            "status": "Operational",
            "api_version": "v1.0.0"
        }), 200

    return app


if __name__ == "__main__":
    try:
        seed_database()
    except Exception as e:
        print(f"[!] Startup seed notice: {e}")

    application = create_app()

    # A capture session still marked Running belongs to a process that no longer exists.
    closed = application.config["CAPTURE_SERVICE"].close_abandoned_sessions()
    if closed:
        print(f"[+] Closed {closed} capture session(s) left Running by an earlier run.")

    # Terminal self check printout
    print_startup_self_check(
        engine=create_engine(Config.SQLALCHEMY_DATABASE_URI),
        tshark_parser=application.config["CAPTURE_SERVICE"].tshark_parser,
        ml_service=application.config["ML_SERVICE"],
        capture_service=application.config["CAPTURE_SERVICE"]
    )

    port = int(os.getenv("PORT", 5000))
    print(f"\n[+] AI-NIDS Backend running on http://127.0.0.1:{port}")
    application.run(host="0.0.0.0", port=port, debug=False, threaded=True)
