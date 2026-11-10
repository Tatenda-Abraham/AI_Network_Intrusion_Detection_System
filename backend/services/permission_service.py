"""
AI-NIDS Permission Service
Chinhoyi University of Technology - Group 5
Handles loading permissions from config/permissions.yaml and checking user access.
"""

import os
import yaml
from flask import current_app, request, jsonify
from flask_jwt_extended import get_jwt, verify_jwt_in_request
from functools import wraps

from backend.config import ADMIN_ROLE, ANALYST_ROLE

class PermissionService:
    _permissions = None

    @classmethod
    def load_permissions(cls):
        if cls._permissions is None:
            config_path = os.path.join(current_app.root_path, "..", "config", "permissions.yaml")
            if not os.path.exists(config_path):
                # Fallback if file doesn't exist
                cls._permissions = {
                    ADMIN_ROLE: {"permissions": ["*"]},
                    ANALYST_ROLE: {"permissions": ["dashboard:view", "findings:view"]}
                }
            else:
                with open(config_path, 'r') as f:
                    cls._permissions = yaml.safe_load(f)
        return cls._permissions

    @classmethod
    def has_permission(cls, role, permission):
        perms_config = cls.load_permissions()
        if role not in perms_config:
            return False
        
        role_perms = perms_config[role].get("permissions", [])
        if "*" in role_perms:
            return True
        
        return permission in role_perms

    @classmethod
    def should_mask_mac(cls, role):
        perms_config = cls.load_permissions()
        if role not in perms_config:
            return True
        
        role_perms = perms_config[role].get("permissions", [])
        return "mac_address:full" not in role_perms

def mask_mac(mac):
    if not mac:
        return mac
    mac_clean = str(mac).strip().replace("-", ":")
    parts = mac_clean.split(':')
    if len(parts) == 6:
        return f"{parts[0]}:{parts[1]}:{parts[2]}:xx:xx:xx"
    return mac

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            role = claims.get("role")
            
            if not PermissionService.has_permission(role, permission):
                # Log 403 attempt
                audit_service = current_app.config.get("AUDIT_SERVICE")
                if audit_service:
                    audit_service.log_event(
                        action="403_FORBIDDEN",
                        username=claims.get("username"),
                        details=f"Attempted to access {request.path} requiring {permission}",
                        ip_address=request.remote_addr,
                        outcome="failure"
                    )
                
                return jsonify({
                    "status": "error",
                    "message": "Access Denied: You do not have permission to perform this action."
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
