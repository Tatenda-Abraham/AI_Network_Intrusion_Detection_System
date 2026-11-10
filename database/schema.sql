-- AI-NIDS PostgreSQL Relational Database Schema & Unified Migration
-- Chinhoyi University of Technology (CUT)
-- Department of ICT and Electronics | Group 5 Capstone Project

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Cybersecurity Analyst' CHECK (role IN ('Administrator', 'Cybersecurity Analyst')),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITHOUT TIME ZONE,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITHOUT TIME ZONE,
    password_changed_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- 2. Capture Sessions Table
CREATE TABLE IF NOT EXISTS capture_sessions (
    id SERIAL PRIMARY KEY,
    session_identifier VARCHAR(100) UNIQUE NOT NULL,
    interface_name VARCHAR(255) NOT NULL,
    adapter_friendly_name VARCHAR(255),
    capture_type VARCHAR(50) NOT NULL, -- Live Wireless, Pcap Upload, Remote Sensor
    monitor_mode BOOLEAN DEFAULT FALSE,
    channel INTEGER,
    window_seconds INTEGER DEFAULT 10,
    restart_count INTEGER DEFAULT 0,
    last_error TEXT,
    started_by VARCHAR(100),
    packets_captured INTEGER NOT NULL DEFAULT 0,
    flows_analyzed INTEGER NOT NULL DEFAULT 0,
    total_frames INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    events_stored INTEGER NOT NULL DEFAULT 0,
    alerts_raised INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(50) NOT NULL DEFAULT 'Completed',
    started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITHOUT TIME ZONE
);

-- 3. Live Capture Windows Table (10-second analysis windows)
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

CREATE INDEX IF NOT EXISTS idx_windows_session_time ON live_capture_windows (capture_session_id, window_start DESC);

-- 4. Events Table (Unified Record Structure - NO registration_number)
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
    integrity_hash VARCHAR(64),
    -- Wireless telemetry extensions
    source_mac VARCHAR(17),
    destination_mac VARCHAR(17),
    bssid VARCHAR(17),
    channel INTEGER,
    rssi_dbm INTEGER,
    capture_session_id INTEGER REFERENCES capture_sessions(id) ON DELETE CASCADE,
    window_id INTEGER REFERENCES live_capture_windows(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_detection_time ON events (detection_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_attack_type ON events (attack_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_method ON events (detection_method);
CREATE INDEX IF NOT EXISTS idx_events_ml_class ON events (ml_class, detection_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_mac ON events (source_mac);
CREATE INDEX IF NOT EXISTS idx_events_bssid ON events (bssid);
-- Every headline figure is recounted per traffic source, so the source column needs an index.
CREATE INDEX IF NOT EXISTS idx_events_capture_source ON events (capture_source);

-- 5. Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    severity VARCHAR(30) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Active',
    message TEXT NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_event ON alerts (event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);

-- 6. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100) NOT NULL,
    role VARCHAR(50),
    action VARCHAR(100) NOT NULL,
    outcome VARCHAR(20) DEFAULT 'success',
    details TEXT,
    ip_address VARCHAR(50),
    timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs (username);

-- 7. Login History Table
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

CREATE INDEX IF NOT EXISTS idx_login_user_time ON login_history (user_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_login_event ON login_history (event_type);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_history (ip_address);
CREATE INDEX IF NOT EXISTS idx_login_time ON login_history (event_time DESC);

-- 8. User Sessions Table (Server-side Session State)
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

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions (user_id, revoked);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions (expires_at);

-- 9. Live Findings Table
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

CREATE INDEX IF NOT EXISTS idx_findings_time ON live_findings (found_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON live_findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON live_findings (finding_type);

-- 10. WiFi Frames Table (Sampled 802.11 Header Telemetry)
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

CREATE INDEX IF NOT EXISTS idx_frames_time ON wifi_frames (frame_time DESC);
CREATE INDEX IF NOT EXISTS idx_frames_session ON wifi_frames (capture_session_id, frame_time DESC);
CREATE INDEX IF NOT EXISTS idx_frames_tx ON wifi_frames (transmitter_mac);

-- 11. Device Conversations Table
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

CREATE INDEX IF NOT EXISTS idx_conv_window ON device_conversations (window_id);
CREATE INDEX IF NOT EXISTS idx_conv_pair ON device_conversations (mac_a, mac_b);

-- 12. WiFi Access Points Table
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

-- 13. Baseline Stats Table
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

-- 14. Reports Table
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

-- 15. Settings Table
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 16. Analysis Totals Table
-- One row per traffic source holding the headline figures the dashboard renders, so the
-- monitored-device count and the classification totals are readable straight from PostgreSQL.
CREATE TABLE IF NOT EXISTS analysis_totals (
    id SERIAL PRIMARY KEY,
    capture_source VARCHAR(120) UNIQUE NOT NULL,
    devices_monitored INTEGER NOT NULL DEFAULT 0,
    records_analysed INTEGER NOT NULL DEFAULT 0,
    normal_count INTEGER NOT NULL DEFAULT 0,
    suspicious_count INTEGER NOT NULL DEFAULT 0,
    potential_attack_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    flagged_share_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
    traffic_window_start TIMESTAMP WITHOUT TIME ZONE,
    traffic_window_end TIMESTAMP WITHOUT TIME ZONE,
    notes TEXT,
    generated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Ensure identity_sessions is backed up if it exists, then dropped
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'identity_sessions') THEN
        CREATE TABLE IF NOT EXISTS identity_sessions_backup AS SELECT * FROM identity_sessions;
        DROP TABLE identity_sessions;
    END IF;
END $$;

-- Drop registration_number if it exists on events
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'registration_number') THEN
        ALTER TABLE events DROP COLUMN registration_number;
    END IF;
END $$;

-- Seed Default Settings if missing
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
