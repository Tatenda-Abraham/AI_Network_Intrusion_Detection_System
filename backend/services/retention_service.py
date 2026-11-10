"""
AI-NIDS Data Retention Background Service
Chinhoyi University of Technology - Group 5
Enforces retention policies from database settings:
- frame_retention_days (default: 7)
- login_history_retention_days (default: 365)
- findings_retention_days (default: 365)
- Purges expired user sessions
"""

import time
import threading
from datetime import datetime, timedelta
from sqlalchemy import text
from backend.models import Setting, WifiFrame, LoginHistory, LiveFinding, UserSession


class RetentionService:
    def __init__(self, db_session_factory, check_interval_seconds: int = 3600):
        self.db_session_factory = db_session_factory
        self.check_interval_seconds = check_interval_seconds
        self._stop_event = threading.Event()
        self._worker_thread = None

    def start(self):
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._run_loop, daemon=True, name="RetentionWorker")
        self._worker_thread.start()
        print("[+] Data Retention service initialized.")

    def stop(self):
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=3)

    def _get_setting_days(self, session, key: str, default: int) -> int:
        setting = session.query(Setting).filter(Setting.key == key).first()
        if setting and setting.value:
            try:
                return int(setting.value)
            except ValueError:
                pass
        return default

    def enforce_retention(self) -> dict:
        """Runs one retention purge cycle across frames, login history, findings, and sessions."""
        session = self.db_session_factory()
        purged = {
            "wifi_frames": 0,
            "login_history": 0,
            "live_findings": 0,
            "expired_sessions": 0
        }
        try:
            now = datetime.utcnow()

            frame_days = self._get_setting_days(session, "frame_retention_days", 7)
            login_days = self._get_setting_days(session, "login_history_retention_days", 365)
            findings_days = self._get_setting_days(session, "findings_retention_days", 365)

            # 1. Purge old wifi_frames
            frame_cutoff = now - timedelta(days=frame_days)
            q1 = session.query(WifiFrame).filter(WifiFrame.frame_time < frame_cutoff)
            purged["wifi_frames"] = q1.delete(synchronize_session=False)

            # 2. Purge old login_history
            login_cutoff = now - timedelta(days=login_days)
            q2 = session.query(LoginHistory).filter(LoginHistory.event_time < login_cutoff)
            purged["login_history"] = q2.delete(synchronize_session=False)

            # 3. Purge old live_findings
            findings_cutoff = now - timedelta(days=findings_days)
            q3 = session.query(LiveFinding).filter(LiveFinding.found_at < findings_cutoff)
            purged["live_findings"] = q3.delete(synchronize_session=False)

            # 4. Purge expired sessions
            q4 = session.query(UserSession).filter(UserSession.expires_at < now)
            purged["expired_sessions"] = q4.delete(synchronize_session=False)

            session.commit()
            if any(purged.values()):
                print(f"[RETENTION] Purged: {purged}")
        except Exception as e:
            session.rollback()
            print(f"[!] Retention job error: {e}")
        finally:
            session.close()

        return purged

    def _run_loop(self):
        # Initial run on startup
        self.enforce_retention()
        while not self._stop_event.is_set():
            # Wait for check_interval_seconds or stop event
            if self._stop_event.wait(timeout=self.check_interval_seconds):
                break
            self.enforce_retention()
