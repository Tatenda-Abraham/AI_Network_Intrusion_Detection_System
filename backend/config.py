"""
AI-NIDS Backend Configuration
Chinhoyi University of Technology - Group 5
Loads environmental settings from .env with secure production defaults.
Supports PostgreSQL (default), MySQL, and SQLite.
"""

import os
from datetime import timedelta

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Traffic source labels stored on every event so test traffic and live capture
# share one events table without being confused for each other.
TEST_TRAFFIC_SOURCE = "Campus network (test data)"
LIVE_TRAFFIC_SOURCE = "Campus network (live capture)"
AI_MODEL_METHOD = "AI Model"
BEHAVIOUR_METHOD = "Behavioural Analysis"

# Console roles. The analyst role is named for the campus security team that staffs it.
ADMIN_ROLE = "Administrator"
ANALYST_ROLE = "Cybersecurity Analyst"
USER_ROLES = (ADMIN_ROLE, ANALYST_ROLE)

# Devices connected to the CUT campus network, as reported by the ICT network office.
# The campus traffic baseline is built one flow per device.
CAMPUS_ACTIVE_DEVICES = 15876

# Repository .env values back every os.getenv() lookup below; real environment wins.
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "cut-group5-ai-nids-production-secret-key-2026")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cut-jwt-cybersecurity-secret-key-2026")
    
    # Session & Security Settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=int(os.getenv("JWT_REFRESH_EXPIRES_HOURS", 8)))
    JWT_TOKEN_LOCATION = ['headers', 'cookies']
    JWT_REFRESH_COOKIE_PATH = '/api/auth/refresh'
    JWT_COOKIE_SECURE = os.getenv("HTTPS_ENABLED", "false").lower() == "true"
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_COOKIE_SAMESITE = 'Strict'
    JWT_SESSION_COOKIE = False

    # Database Configuration: PostgreSQL default, configurable via .env, with SQLite fallback
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        # Default PostgreSQL connection
        DATABASE_URL = "postgresql+psycopg2://postgres:postgres@localhost:5432/ai_nids"
    elif DATABASE_URL.startswith("postgresql://"):
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # TShark / Wireshark Configuration
    TSHARK_PATH = os.getenv("TSHARK_PATH", r"C:\Program Files\Wireshark\tshark.exe")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_SIZE_MB", 100)) * 1024 * 1024

    # Initial Admin Seed Credentials
    INITIAL_ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    INITIAL_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CUT_Nids_Admin2026!")

    # Remote Sensor Ingestion Key
    SENSOR_API_KEY = os.getenv("SENSOR_API_KEY", "cut-sensor-agent-key-secret-2026")

    # Automated Mitigation Setting
    ENABLE_ACTIVE_BLOCKING = os.getenv("ENABLE_ACTIVE_BLOCKING", "false").lower() == "true"
