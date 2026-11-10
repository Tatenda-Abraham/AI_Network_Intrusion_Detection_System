"""
AI-NIDS User Management and Audit Log Routes
Chinhoyi University of Technology - Group 5
Strictly enforced RBAC: Administrator access only.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
import bcrypt
from datetime import datetime

from backend.config import ADMIN_ROLE, ANALYST_ROLE, USER_ROLES
from backend.models import User, AuditLog
from backend.services.permission_service import require_permission

user_bp = Blueprint("users", __name__)


def is_admin():
    claims = get_jwt()
    return claims.get("role") == ADMIN_ROLE


@user_bp.route("/users", methods=["GET"])
@require_permission("user_management:all")
def list_users():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    session = SessionLocal()
    try:
        users = session.query(User).order_by(User.id.asc()).all()
        return jsonify({
            "status": "success",
            "users": [u.to_dict() for u in users]
        }), 200
    finally:
        session.close()


@user_bp.route("/users", methods=["POST"])
@require_permission("user_management:all")
def create_user():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    audit_service = current_app.config["AUDIT_SERVICE"]

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", ANALYST_ROLE).strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    if role not in USER_ROLES:
        return jsonify({"status": "error", "message": f"Invalid role. Allowed: {', '.join(USER_ROLES)}"}), 400

    session = SessionLocal()
    try:
        if session.query(User).filter(User.username == username).first():
            return jsonify({"status": "error", "message": f"User '{username}' already exists"}), 400

        salt = bcrypt.gensalt(12)
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

        new_user = User(
            username=username,
            password_hash=pw_hash,
            role=role,
            active=True,
            created_at=datetime.utcnow(),
            password_changed_at=datetime.utcnow()
        )
        session.add(new_user)
        session.commit()

        admin_user = get_jwt_identity()
        audit_service.log_event(
            action="USER_CREATED",
            username=admin_user,
            details=f"Created user '{username}' with role '{role}'",
            outcome="success"
        )

        return jsonify({
            "status": "success",
            "message": f"User '{username}' created successfully",
            "user": new_user.to_dict()
        }), 201
    finally:
        session.close()


@user_bp.route("/users/<int:user_id>", methods=["PATCH", "PUT"])
@require_permission("user_management:all")
def update_user(user_id):
    SessionLocal = current_app.config["SESSION_FACTORY"]
    audit_service = current_app.config["AUDIT_SERVICE"]

    data = request.get_json(silent=True) or {}
    session = SessionLocal()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        changes = []
        if "active" in data:
            user.active = bool(data["active"])
            changes.append(f"active={user.active}")
        if "role" in data:
            if data["role"] not in USER_ROLES:
                return jsonify({"status": "error", "message": f"Invalid role. Allowed: {', '.join(USER_ROLES)}"}), 400
            user.role = data["role"]
            changes.append(f"role={user.role}")
        if "unlock" in data and data["unlock"]:
            user.locked_until = None
            user.failed_login_count = 0
            changes.append("account unlocked")
        if "password" in data and len(data["password"]) >= 6:
            salt = bcrypt.gensalt(12)
            user.password_hash = bcrypt.hashpw(data["password"].encode("utf-8"), salt).decode("utf-8")
            user.password_changed_at = datetime.utcnow()
            changes.append("password reset")

        session.commit()
        admin_user = get_jwt_identity()
        audit_service.log_event(
            action="USER_UPDATED",
            username=admin_user,
            details=f"Updated user #{user_id} ('{user.username}'): {', '.join(changes)}",
            outcome="success"
        )

        return jsonify({
            "status": "success",
            "message": f"User '{user.username}' updated successfully",
            "user": user.to_dict()
        }), 200
    finally:
        session.close()


@user_bp.route("/users/<int:user_id>", methods=["DELETE"])
@require_permission("user_management:all")
def delete_user(user_id):
    SessionLocal = current_app.config["SESSION_FACTORY"]
    audit_service = current_app.config["AUDIT_SERVICE"]
    admin_user = get_jwt_identity()

    session = SessionLocal()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        if user.username == admin_user:
            return jsonify({"status": "error", "message": "Cannot delete your own active administrator account"}), 400

        u_name = user.username
        session.delete(user)
        session.commit()

        audit_service.log_event(
            action="USER_DELETED",
            username=admin_user,
            details=f"Deleted user account '{u_name}'",
            outcome="success"
        )

        return jsonify({"status": "success", "message": f"User '{u_name}' deleted successfully"}), 200
    finally:
        session.close()


@user_bp.route("/audit-logs", methods=["GET"])
@require_permission("audit_logs:view")
def get_audit_logs():
    SessionLocal = current_app.config["SESSION_FACTORY"]
    session = SessionLocal()
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        action_filter = request.args.get("action", "").strip()
        username_filter = request.args.get("username", "").strip()

        query = session.query(AuditLog)
        if action_filter:
            query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))
        if username_filter:
            query = query.filter(AuditLog.username.ilike(f"%{username_filter}%"))

        logs = query.order_by(AuditLog.id.desc()).limit(limit).all()
        return jsonify({
            "status": "success",
            "audit_logs": [l.to_dict() for l in logs]
        }), 200
    finally:
        session.close()
