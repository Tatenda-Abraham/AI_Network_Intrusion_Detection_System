"""
AI-NIDS Database Seeder
Chinhoyi University of Technology - Group 5
Seeds:
1. Initial Administrator and Cybersecurity Analyst user accounts with bcrypt hashing
2. Default system settings and retention metadata
"""

import os
import sys
import bcrypt
from datetime import datetime

# Ensure project root is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.config import ADMIN_ROLE, ANALYST_ROLE, Config
from backend.models import Base, User, Setting

engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
SessionLocal = sessionmaker(bind=engine)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt with salt rounds."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def seed_database(target_engine=None, target_session_factory=None):
    eng = target_engine or engine
    Base.metadata.create_all(bind=eng)
    session = target_session_factory() if target_session_factory else SessionLocal()

    try:
        # 1. Seed Administrator and Cybersecurity Analyst accounts
        admin_username = Config.INITIAL_ADMIN_USERNAME
        admin_password = Config.INITIAL_ADMIN_PASSWORD

        existing_admin = session.query(User).filter(User.username == admin_username).first()
        if not existing_admin:
            print(f"[*] Creating Administrator account: '{admin_username}'...")
            admin_user = User(
                username=admin_username,
                password_hash=hash_password(admin_password),
                role=ADMIN_ROLE,
                active=True,
                created_at=datetime.utcnow()
            )
            session.add(admin_user)

        analyst_user = session.query(User).filter(User.username == "analyst").first()
        if not analyst_user:
            print(f"[*] Creating {ANALYST_ROLE} account: 'analyst'...")
            analyst_user = User(
                username="analyst",
                password_hash=hash_password("CUT_Analyst2026!"),
                role=ANALYST_ROLE,
                active=True,
                created_at=datetime.utcnow()
            )
            session.add(analyst_user)
        elif analyst_user.role != ANALYST_ROLE:
            print(f"[*] Updating account 'analyst' role: '{analyst_user.role}' -> '{ANALYST_ROLE}'")
            analyst_user.role = ANALYST_ROLE

        # 2. Seed Default Settings
        settings_defaults = [
            ("system_name", "AI-Based Network Intrusion Detection and Monitoring System (AI-NIDS)", "University System Title"),
            ("institution", "Chinhoyi University of Technology", "Institutional Identity"),
            ("department", "School of Engineering Sciences and Technology, Dept of ICT", "Academic Department"),
            ("group", "BSc Hons Information Technology, Group 5", "Project Group"),
            ("live_window_seconds", "10", "Live capture analysis window and dashboard refresh (seconds)"),
            ("idle_timeout_minutes", "15", "Idle session timeout in minutes"),
            ("absolute_timeout_hours", "8", "Absolute session lifetime in hours"),
            ("max_failed_logins", "5", "Failed logins before lockout"),
            ("lockout_minutes", "15", "Account lockout duration"),
            ("frame_retention_days", "7", "Days to keep wifi_frames rows"),
            ("login_history_retention_days", "365", "Days to keep login_history rows"),
            ("findings_retention_days", "365", "Days to keep live_findings rows"),
            ("enable_active_blocking", "false", "Automated firewall mitigation hook"),
            ("tshark_path", Config.TSHARK_PATH, "Executable location for Wireshark TShark CLI")
        ]

        for k, v, desc in settings_defaults:
            setting_row = session.query(Setting).filter(Setting.key == k).first()
            if not setting_row:
                session.add(Setting(key=k, value=v, description=desc))

        session.commit()
        print("[+] Core database initialization completed successfully.")
    except Exception as e:
        session.rollback()
        print(f"[!] Error seeding database: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    seed_database()
