"""
AI-NIDS Authentication & Session Service
Chinhoyi University of Technology - Group 5
Handles login protection, session lifecycle, and login history tracking.
"""

import bcrypt
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from flask import current_app, request
from sqlalchemy.orm import Session
from backend.models import User, UserSession, LoginHistory, Setting

class AuthService:
    def __init__(self, db_session: Session):
        self.db = db_session

    def get_setting(self, key: str, default: str) -> str:
        setting = self.db.query(Setting).filter(Setting.key == key).first()
        return setting.value if setting else default

    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        return True, ""

    def check_lockout(self, user: User) -> Tuple[bool, Optional[str]]:
        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = (user.locked_until - datetime.utcnow()).total_seconds() / 60
            return True, f"Account is locked. Try again in {int(remaining)} minutes."
        
        if user.locked_until and user.locked_until <= datetime.utcnow():
            # Lock expired, reset failed count
            user.failed_login_count = 0
            user.locked_until = None
            self.db.commit()
            
        return False, None

    def handle_failed_login(self, user: Optional[User], username: str, ip_address: str, reason: str):
        if user:
            user.failed_login_count += 1
            max_failed = int(self.get_setting('max_failed_logins', '5'))
            if user.failed_login_count >= max_failed:
                lockout_mins = int(self.get_setting('lockout_minutes', '15'))
                user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_mins)
                reason = f"{reason} (Account locked due to multiple failures)"
            self.db.commit()

        # Log history
        history = LoginHistory(
            user_id=user.id if user else None,
            username=username,
            role=user.role if user else None,
            event_type='LOGIN_FAILED',
            success=False,
            failure_reason=reason,
            ip_address=ip_address,
            user_agent=request.user_agent.string
        )
        self.db.add(history)
        
        # Audit log
        audit_service = current_app.config.get("AUDIT_SERVICE")
        if audit_service:
            audit_service.log_event(
                action="LOGIN_FAILED",
                username=username,
                details=reason,
                ip_address=ip_address,
                user_id=user.id if user else None,
                role=user.role if user else None,
                outcome="failure"
            )
        
        self.db.commit()

    def create_session(self, user: User, ip_address: str, user_agent: str) -> UserSession:
        # Revoke old sessions if any (or keep them if multi-device allowed)
        # For this project, we'll allow multiple but keep track
        
        session_id = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(64)
        refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        abs_timeout_hours = int(self.get_setting('absolute_timeout_hours', '8'))
        expires_at = datetime.utcnow() + timedelta(hours=abs_timeout_hours)
        
        new_session = UserSession(
            session_id=session_id,
            user_id=user.id,
            refresh_token_hash=refresh_token_hash,
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            revoked=False
        )
        
        self.db.add(new_session)
        
        # Log success
        history = LoginHistory(
            user_id=user.id,
            username=user.username,
            role=user.role,
            event_type='LOGIN_SUCCESS',
            success=True,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id
        )
        self.db.add(history)
        
        user.last_login = datetime.utcnow()
        user.failed_login_count = 0
        user.locked_until = None
        
        self.db.commit()
        
        # Return the raw refresh token to be set in cookie
        new_session.raw_refresh_token = refresh_token
        return new_session

    def revoke_session(self, session_id: str, reason: str = "User logout"):
        session = self.db.query(UserSession).filter(UserSession.session_id == session_id).first()
        if session:
            session.revoked = True
            session.revoked_reason = reason
            
            # Log history
            history = LoginHistory(
                user_id=session.user_id,
                username=self.db.query(User.username).filter(User.id == session.user_id).scalar(),
                event_type='LOGOUT' if reason == "User logout" else 'SESSION_REVOKED',
                success=True,
                ip_address=session.ip_address,
                session_id=session_id
            )
            self.db.add(history)
            self.db.commit()
            return True
        return False

    def validate_session(self, session_id: str) -> Tuple[bool, Optional[UserSession]]:
        session = self.db.query(UserSession).filter(
            UserSession.session_id == session_id,
            UserSession.revoked == False
        ).first()
        
        if not session:
            return False, None
            
        if session.expires_at < datetime.utcnow():
            self.revoke_session(session_id, "Absolute timeout")
            return False, None
            
        # Idle timeout check
        idle_mins = int(self.get_setting('idle_timeout_minutes', '15'))
        if session.last_activity + timedelta(minutes=idle_mins) < datetime.utcnow():
            self.revoke_session(session_id, "Idle timeout")
            return False, None
            
        # Update last activity
        session.last_activity = datetime.utcnow()
        self.db.commit()
        
        return True, session
