-- Migration 003: Unified PostgreSQL Safe Re-runnable Migration
-- Target: PostgreSQL 16 database 'ai_nids'

BEGIN;

-- 1. Users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Security Analyst',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITHOUT TIME ZONE
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITHOUT TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITHOUT TIME ZONE;

-- Enforce role check constraint
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'check_user_role'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT check_user_role CHECK (role IN ('Administrator', 'Security Analyst'));
    END IF;
END $$;

-- 2. Capture Sessions
CREATE TABLE IF NOT EXISTS capture_sessions (
    id SERIAL PRIMARY KEY,
    session_identifier VARCHAR(100) UNIQUE NOT NULL,
    interface_name VARCHAR(255) NOT NULL,
    capture_type VARCHAR(50) NOT NULL DEFAULT 'Live Wireless',
    packets_captured INTEGER NOT NULL DEFAULT 0,
    flows_analyzed INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'Completed',
    started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITHOUT TIME ZONE
);

ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS adapter_friendly_name VARCHAR(255);
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS monitor_mode BOOLEAN DEFAULT FALSE;
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS channel INTEGER;
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS window_seconds INTEGER DEFAULT 10;
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS restart_count INTEGER DEFAULT 0;
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS last_error TEXT;
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS started_by VARCHAR(100);
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS total_frames INTEGER DEFAULT 0;
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS total_findings INTEGER DEFAULT 0;

-- 3. Live Capture Windows
CREATE TABLE IF NOT EXISTS live_capture_windows (
    id SERIAL PRIMARY KEY,
    capture_session_id INTEGER NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
    window_start TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    window_end TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    frames_count INTEGER DEFAULT 0,
    management_frames INTEGER DEFAULT 0,
    control_frames INTEGER DEFAULT 0,
    data_frames INTEGER DEFAULT 0,
    deauth_frames INTEGER DEFAULT 0,
    beacon_frames INTEGER DEFAULT 0,
    probe_frames INTEGER DEFAULT 0,
    unique_transmitters INTEGER DEFAULT 0,
    packets_per_second REAL,
    avg_rssi_dbm REAL,
    baseline_pps REAL,
    anomaly_score REAL,
    findings_count INTEGER DEFAULT 0,
    processing_ms REAL
);

-- 4. Events
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(50) UNIQUE NOT NULL,
    detection_time TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attack_type VARCHAR(100) NOT NULL,
    ml_class VARCHAR(50) NOT NULL,
    source_ip VARCHAR(100),
    destination_ip VARCHAR(100),
    source_ips_list TEXT,
    protocol VARCHAR(20) NOT NULL DEFAULT 'TCP',
    source_port INTEGER NOT NULL DEFAULT 0,
    destination_port INTEGER NOT NULL DEFAULT 0,
    traffic_stats TEXT,
    detection_method VARCHAR(50) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    confidence_score DOUBLE PRECISION,
    evidence TEXT NOT NULL,
    evidence_json TEXT,
    response_status VARCHAR(50) NOT NULL DEFAULT 'Pending review',
    system_response TEXT DEFAULT 'Event recorded and administrator alerted',
    admin_action VARCHAR(100) DEFAULT 'None',
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP WITHOUT TIME ZONE,
    notes TEXT,
    capture_source VARCHAR(255) NOT NULL,
    integrity_hash VARCHAR(64)
);

-- Drop registration_number if present
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'registration_number') THEN
        ALTER TABLE events DROP COLUMN registration_number;
    END IF;
END $$;

ALTER TABLE events ADD COLUMN IF NOT EXISTS source_mac VARCHAR(17);
ALTER TABLE events ADD COLUMN IF NOT EXISTS destination_mac VARCHAR(17);
ALTER TABLE events ADD COLUMN IF NOT EXISTS bssid VARCHAR(17);
ALTER TABLE events ADD COLUMN IF NOT EXISTS channel INTEGER;
ALTER TABLE events ADD COLUMN IF NOT EXISTS rssi_dbm INTEGER;
ALTER TABLE events ADD COLUMN IF NOT EXISTS capture_session_id INTEGER REFERENCES capture_sessions(id) ON DELETE CASCADE;
ALTER TABLE events ADD COLUMN IF NOT EXISTS window_id INTEGER REFERENCES live_capture_windows(id) ON DELETE CASCADE;

-- 5. Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    severity VARCHAR(30) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Active',
    message TEXT NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(50),
    timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS role VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS outcome VARCHAR(20) DEFAULT 'success';

-- 7. Login History
CREATE TABLE IF NOT EXISTS login_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100) NOT NULL,
    role VARCHAR(50),
    event_type VARCHAR(40) NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    ip_address VARCHAR(50),
    user_agent TEXT,
    session_id VARCHAR(64),
    event_time TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 8. User Sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(128),
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    ip_address VARCHAR(50),
    user_agent TEXT,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(100)
);

-- 9. Live Findings
CREATE TABLE IF NOT EXISTS live_findings (
    id SERIAL PRIMARY KEY,
    finding_id VARCHAR(30) UNIQUE NOT NULL,
    event_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
    window_id INTEGER REFERENCES live_capture_windows(id) ON DELETE SET NULL,
    capture_session_id INTEGER REFERENCES capture_sessions(id) ON DELETE SET NULL,
    found_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    source_mac VARCHAR(17),
    target_mac VARCHAR(17),
    bssid VARCHAR(17),
    source_ip VARCHAR(100),
    target_ip VARCHAR(100),
    channel INTEGER,
    rssi_dbm INTEGER,
    packets_in_window INTEGER,
    packets_per_second REAL,
    confidence_score REAL,
    detection_method VARCHAR(50) NOT NULL,
    evidence TEXT NOT NULL,
    evidence_json TEXT,
    recommended_action TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'Pending review',
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP WITHOUT TIME ZONE
);

-- 10. WiFi Frames
CREATE TABLE IF NOT EXISTS wifi_frames (
    id SERIAL PRIMARY KEY,
    capture_session_id INTEGER REFERENCES capture_sessions(id) ON DELETE CASCADE,
    window_id INTEGER REFERENCES live_capture_windows(id) ON DELETE CASCADE,
    frame_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    delta_time REAL,
    transmitter_mac VARCHAR(17),
    receiver_mac VARCHAR(17),
    bssid VARCHAR(17),
    frame_type VARCHAR(20),
    frame_subtype VARCHAR(50),
    rssi_dbm INTEGER,
    channel INTEGER,
    frame_length INTEGER,
    ssid VARCHAR(64),
    reason_code INTEGER,
    flagged BOOLEAN NOT NULL DEFAULT FALSE
);

-- 11. Device Conversations
CREATE TABLE IF NOT EXISTS device_conversations (
    id SERIAL PRIMARY KEY,
    capture_session_id INTEGER REFERENCES capture_sessions(id) ON DELETE CASCADE,
    window_id INTEGER REFERENCES live_capture_windows(id) ON DELETE CASCADE,
    mac_a VARCHAR(17) NOT NULL,
    mac_b VARCHAR(17) NOT NULL,
    bssid VARCHAR(17),
    channel INTEGER,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    packets_per_second REAL,
    avg_rssi_dbm REAL,
    delta_rssi REAL,
    first_seen TIMESTAMP WITHOUT TIME ZONE,
    last_seen TIMESTAMP WITHOUT TIME ZONE,
    vendor_a VARCHAR(100),
    vendor_b VARCHAR(100)
);

-- 12. WiFi Access Points
CREATE TABLE IF NOT EXISTS wifi_access_points (
    id SERIAL PRIMARY KEY,
    ssid VARCHAR(64),
    bssid VARCHAR(17) UNIQUE NOT NULL,
    channel INTEGER,
    encryption VARCHAR(50),
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by VARCHAR(100),
    first_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 13. Sensor Locations
CREATE TABLE IF NOT EXISTS sensor_locations (
    id SERIAL PRIMARY KEY,
    sensor_name VARCHAR(100) UNIQUE NOT NULL,
    adapter_name VARCHAR(255),
    location_label VARCHAR(255) NOT NULL,
    updated_by VARCHAR(100),
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 14. Baseline Stats
CREATE TABLE IF NOT EXISTS baseline_stats (
    id SERIAL PRIMARY KEY,
    day_of_week SMALLINT NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
    hour_of_day SMALLINT NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
    avg_pps REAL,
    std_pps REAL,
    avg_deauth_rate REAL,
    samples INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (day_of_week, hour_of_day)
);

-- 15. Model Runs
CREATE TABLE IF NOT EXISTS model_runs (
    id SERIAL PRIMARY KEY,
    model_version VARCHAR(50) NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    accuracy DOUBLE PRECISION NOT NULL,
    precision_score DOUBLE PRECISION NOT NULL,
    recall_score DOUBLE PRECISION NOT NULL,
    f1_score DOUBLE PRECISION NOT NULL,
    false_positive_rate DOUBLE PRECISION NOT NULL,
    training_samples INTEGER NOT NULL,
    evaluation_latency_ms DOUBLE PRECISION,
    metrics_json TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 16. Reports
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL DEFAULT 'General Incident',
    generated_by VARCHAR(100) NOT NULL,
    start_date TIMESTAMP WITHOUT TIME ZONE,
    end_date TIMESTAMP WITHOUT TIME ZONE,
    total_events INTEGER NOT NULL DEFAULT 0,
    file_path VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 17. Settings
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 18. Identity Sessions removal (back up first if present)
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'identity_sessions') THEN
        CREATE TABLE IF NOT EXISTS identity_sessions_backup AS SELECT * FROM identity_sessions;
        DROP TABLE identity_sessions;
    END IF;
END $$;

-- 19. Seed required Settings
INSERT INTO settings (key, value, description) VALUES
    ('live_window_seconds', '10', 'Live capture analysis window and dashboard refresh (seconds)'),
    ('idle_timeout_minutes', '15', 'Idle session timeout in minutes'),
    ('absolute_timeout_hours', '8', 'Absolute session lifetime in hours'),
    ('max_failed_logins', '5', 'Max failed logins before account lockout'),
    ('lockout_minutes', '15', 'Account lockout duration in minutes'),
    ('frame_retention_days', '7', 'Days to keep wifi_frames rows'),
    ('login_history_retention_days', '365', 'Days to keep login_history rows'),
    ('findings_retention_days', '365', 'Days to keep live_findings rows')
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description;

COMMIT;
