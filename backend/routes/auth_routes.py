"""
AI-NIDS Authentication & Session Security Routes
Chinhoyi University of Technology - Group 5
"""

import io
import csv
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app, Response
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt, set_refresh_cookies, unset_jwt_cookies
)
import bcrypt
from sqlalchemy import func, desc

from backend.models import User, LoginHistory, UserSession, Setting
from backend.services.auth_service import AuthService
from backend.services.permission_service import require_permission

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["POST"])
def login():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    auth_service = AuthService(db)

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    sign_in_as = (data.get("sign_in_as") or "").strip()
    ip_addr = request.remote_addr or "127.0.0.1"
    user_agent = request.user_agent.string if request.user_agent else "Unknown Client"

    generic_error = {"status": "error", "message": "Invalid username or password"}

    if not username or not password:
        return jsonify(generic_error), 401

    try:
        user = db.query(User).filter(User.username == username).first()

        # Check account lockout before verifying password
        if user:
            is_locked, lock_msg = auth_service.check_lockout(user)
            if is_locked:
                auth_service.handle_failed_login(user, username, ip_addr, "Account locked")
                return jsonify({"status": "error", "message": lock_msg}), 403

        if not user or not user.active:
            auth_service.handle_failed_login(user, username, ip_addr, "Invalid credentials or inactive account")
            return jsonify(generic_error), 401

        # Verify password hash
        if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
            auth_service.handle_failed_login(user, username, ip_addr, "Incorrect password")
            # Re-check lockout immediately
            is_locked, lock_msg = auth_service.check_lockout(user)
            if is_locked:
                return jsonify({"status": "error", "message": lock_msg}), 403
            return jsonify(generic_error), 401

        # Authentication successful - Reset failed login count
        user.failed_login_count = 0
        user.locked_until = None

        # The console asks which role the operator is signing in as. Only after the
        # password is proven is that role checked, so a wrong guess reveals nothing.
        if sign_in_as and sign_in_as != user.role:
            log_entry = LoginHistory(
                user_id=user.id,
                username=user.username,
                role=sign_in_as,
                event_type="LOGIN_ROLE_MISMATCH",
                success=False,
                failure_reason=f"Account holds role {user.role}, signed in as {sign_in_as}",
                ip_address=ip_addr,
                user_agent=user_agent,
                event_time=datetime.utcnow()
            )
            db.add(log_entry)
            db.commit()
            return jsonify({
                "status": "error",
                "message": f"'{username}' is not signed up as a {sign_in_as}. "
                           f"Pick the role this account was created with."
            }), 403

        user.last_login = datetime.utcnow()
        db.commit()

        # Create managed server-side session
        session_obj = auth_service.create_session(user, ip_addr, user_agent)

        token_claims = {
            "role": user.role,
            "username": user.username,
            "user_id": user.id,
            "session_id": session_obj.session_id
        }

        access_token = create_access_token(identity=user.username, additional_claims=token_claims)
        refresh_token = create_refresh_token(identity=user.username, additional_claims={"session_id": session_obj.session_id})

        # Record LOGIN_SUCCESS in login_history
        log_entry = LoginHistory(
            user_id=user.id,
            username=user.username,
            role=user.role,
            event_type="LOGIN_SUCCESS",
            success=True,
            ip_address=ip_addr,
            user_agent=user_agent,
            session_id=session_obj.session_id,
            event_time=datetime.utcnow()
        )
        db.add(log_entry)
        db.commit()

        response = jsonify({
            "status": "success",
            "message": "Authentication successful",
            "token": access_token,
            "access_token": access_token,
            "user": user.to_dict()
        })

        set_refresh_cookies(response, refresh_token)
        return response, 200

    except Exception as e:
        db.rollback()
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": "Internal authentication service error"}), 500
    finally:
        db.close()


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    auth_service = AuthService(db)

    claims = get_jwt()
    session_id = claims.get("session_id")
    user_id = claims.get("user_id")
    username = get_jwt_identity()
    ip_addr = request.remote_addr or "127.0.0.1"

    if session_id:
        auth_service.revoke_session(session_id, "User logout")

    log_entry = LoginHistory(
        user_id=user_id,
        username=username,
        role=claims.get("role"),
        event_type="LOGOUT",
        success=True,
        ip_address=ip_addr,
        session_id=session_id,
        event_time=datetime.utcnow()
    )
    db.add(log_entry)
    db.commit()

    response = jsonify({"status": "success", "message": "Logged out successfully"})
    unset_jwt_cookies(response)
    db.close()
    return response, 200


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    auth_service = AuthService(db)

    identity = get_jwt_identity()
    claims = get_jwt()
    session_id = claims.get("session_id")
    ip_addr = request.remote_addr or "127.0.0.1"

    is_valid, session_obj = auth_service.validate_session(session_id)
    if not is_valid:
        log_entry = LoginHistory(
            username=identity,
            event_type="TOKEN_REFRESH_FAILED",
            success=False,
            failure_reason="Session revoked or expired",
            ip_address=ip_addr,
            event_time=datetime.utcnow()
        )
        db.add(log_entry)
        db.commit()
        response = jsonify({"status": "error", "message": "Session expired or revoked"})
        unset_jwt_cookies(response)
        db.close()
        return response, 401

    user = db.query(User).filter(User.id == session_obj.user_id).first()
    token_claims = {
        "role": user.role,
        "username": user.username,
        "user_id": user.id,
        "session_id": session_id
    }

    access_token = create_access_token(identity=identity, additional_claims=token_claims)
    db.close()

    return jsonify({
        "status": "success",
        "access_token": access_token
    }), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    username = get_jwt_identity()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        return jsonify({
            "status": "success",
            "user": user.to_dict()
        }), 200
    finally:
        db.close()


@auth_bp.route("/login-history/summary", methods=["GET"])
@require_permission("login_history:view_all")
def get_login_history_summary():
    """Summary KPI cards for Login History tab: logins today, failed today, active sessions, locked accounts."""
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        start_of_today = datetime(now.year, now.month, now.day)

        logins_today = db.query(LoginHistory).filter(
            LoginHistory.event_time >= start_of_today,
            LoginHistory.event_type == "LOGIN_SUCCESS"
        ).count()

        failed_today = db.query(LoginHistory).filter(
            LoginHistory.event_time >= start_of_today,
            LoginHistory.event_type == "LOGIN_FAILED"
        ).count()

        active_sessions = db.query(UserSession).filter(
            UserSession.revoked == False,
            UserSession.expires_at > now
        ).count()

        locked_accounts = db.query(User).filter(
            User.locked_until > now
        ).count()

        return jsonify({
            "status": "success",
            "logins_today": logins_today,
            "failed_today": failed_today,
            "active_sessions": active_sessions,
            "locked_accounts": locked_accounts
        }), 200
    finally:
        db.close()


@auth_bp.route("/login-history/admin", methods=["GET"])
@require_permission("login_history:view_all")
def get_all_login_history():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()

    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = (page - 1) * limit

        query = db.query(LoginHistory)

        username = request.args.get("username", "").strip()
        if username:
            query = query.filter(LoginHistory.username.ilike(f"%{username}%"))

        event_type = request.args.get("event_type", "").strip()
        if event_type:
            query = query.filter(LoginHistory.event_type == event_type)

        role = request.args.get("role", "").strip()
        if role:
            query = query.filter(LoginHistory.role == role)

        success_filter = request.args.get("success")
        if success_filter is not None and success_filter != "":
            query = query.filter(LoginHistory.success == (success_filter.lower() == "true"))

        total = query.count()
        records = query.order_by(desc(LoginHistory.event_time)).offset(offset).limit(limit).all()

        return jsonify({
            "status": "success",
            "data": [r.to_dict() for r in records],
            "total": total,
            "page": page,
            "limit": limit
        }), 200
    finally:
        db.close()


@auth_bp.route("/login-history/export", methods=["GET"])
@require_permission("login_history:view_all")
def export_login_history_csv():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    try:
        records = db.query(LoginHistory).order_by(desc(LoginHistory.event_time)).limit(1000).all()
        output = io.StringIO()
        fieldnames = ["id", "event_time", "username", "role", "event_type", "success", "failure_reason", "ip_address", "session_id"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for r in records:
            writer.writerow(r.to_dict())

        date_str = datetime.utcnow().strftime("%Y%m%d_%H%M")
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment;filename=CUT_Login_History_{date_str}.csv"}
        )
    finally:
        db.close()


@auth_bp.route("/login-history/me", methods=["GET"])
@require_permission("login_history:view_own")
def get_my_login_history():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    try:
        user_id = get_jwt().get("user_id")
        limit = min(int(request.args.get("limit", 50)), 50)

        records = db.query(LoginHistory).filter(LoginHistory.user_id == user_id)\
                    .order_by(desc(LoginHistory.event_time)).limit(limit).all()

        return jsonify({
            "status": "success",
            "data": [r.to_dict() for r in records]
        }), 200
    finally:
        db.close()


@auth_bp.route("/sessions", methods=["GET"])
@require_permission("sessions:revoke")
def get_active_sessions():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        sessions = db.query(UserSession).filter(
            UserSession.revoked == False,
            UserSession.expires_at > now
        ).all()

        result = []
        for s in sessions:
            user = db.query(User.username).filter(User.id == s.user_id).scalar()
            result.append({
                "session_id": s.session_id,
                "username": user or "Unknown",
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "created_at": s.created_at.isoformat(),
                "last_activity": s.last_activity.isoformat(),
                "expires_at": s.expires_at.isoformat()
            })

        return jsonify({"status": "success", "data": result}), 200
    finally:
        db.close()


@auth_bp.route("/sessions/<session_id>/revoke", methods=["POST"])
@require_permission("sessions:revoke")
def revoke_user_session(session_id):
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    auth_service = AuthService(db)
    audit_service = current_app.config["AUDIT_SERVICE"]
    admin_user = get_jwt_identity()

    success = auth_service.revoke_session(session_id, f"Revoked by Administrator {admin_user}")
    if success:
        audit_service.log_event(
            action="SESSION_REVOKED",
            username=admin_user,
            details=f"Admin {admin_user} revoked user session {session_id[:12]}...",
            outcome="success"
        )
    db.close()
    return jsonify({"status": "success", "message": "Session revoked successfully"}), 200


@auth_bp.route("/sessions/revoke-all", methods=["POST"])
@require_permission("sessions:revoke")
def revoke_all_sessions():
    """Revokes all active sessions (Logout all devices)."""
    SessionLocal = current_app.config["SESSION_FACTORY"]
    db = SessionLocal()
    audit_service = current_app.config["AUDIT_SERVICE"]
    admin_user = get_jwt_identity()
    try:
        now = datetime.utcnow()
        updated = db.query(UserSession).filter(
            UserSession.revoked == False,
            UserSession.expires_at > now
        ).update({"revoked": True, "revoked_reason": f"Bulk revocation by {admin_user}"})
        db.commit()

        audit_service.log_event(
            action="SESSION_REVOKE_ALL",
            username=admin_user,
            details=f"Admin {admin_user} revoked all {updated} active sessions",
            outcome="success"
        )
        return jsonify({"status": "success", "message": f"Revoked {updated} active sessions"}), 200
    finally:
        db.close()
