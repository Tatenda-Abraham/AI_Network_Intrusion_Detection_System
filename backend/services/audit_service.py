"""
AI-NIDS Audit Logging Service
Chinhoyi University of Technology - Group 5
Maintains immutable audit records for logins, failed access attempts,
threat status mutations, identity correlations, uploads, and capture sessions.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional


class AuditService:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory

    def log_event(self, action: str, username: str = "SYSTEM", details: str = "", 
                  ip_address: Optional[str] = None, user_id: Optional[int] = None, 
                  role: Optional[str] = None, outcome: str = "success"):
        """Persists a new entry into the audit_logs table."""
        session = self.db_session_factory()
        try:
            from backend.models import AuditLog
            audit = AuditLog(
                username=username,
                action=action,
                details=details,
                ip_address=ip_address,
                timestamp=datetime.utcnow(),
                user_id=user_id,
                role=role,
                outcome=outcome
            )
            session.add(audit)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"[!] Failed to write audit log: {e}")
        finally:
            session.close()

    def get_logs(self, limit: int = 100, action_filter: Optional[str] = None, 
                 username_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves audit entries ordered chronologically descending."""
        session = self.db_session_factory()
        try:
            from backend.models import AuditLog
            query = session.query(AuditLog)
            if action_filter:
                query = query.filter(AuditLog.action == action_filter)
            if username_filter:
                query = query.filter(AuditLog.username == username_filter)

            records = query.order_by(AuditLog.id.desc()).limit(limit).all()
            return [r.to_dict() for r in records]
        finally:
            session.close()
