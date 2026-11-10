-- AI-NIDS Migration 002: Live Capture and Security Features (SQLite version)
-- Chinhoyi University of Technology - Group 5

BEGIN TRANSACTION;

-- 0. Back up data that will be removed
CREATE TABLE IF NOT EXISTS events_backup_regnum AS
SELECT id, event_id, registration_number FROM events;

-- Drop registration_number column (SQLite requires recreating table)
CREATE TABLE IF NOT EXISTS events_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(50) UNIQUE NOT NULL,
    detection_time TIMESTAMP NOT NULL,
    attack_type VARCHAR(100),
    ml_class VARCHAR(50),
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    source_ips_list TEXT,
    protocol VARCHAR(20),
    source_port INTEGER,
    destination_port INTEGER,
    traffic_stats TEXT,
    detection_method VARCHAR(50),
    severity VARCHAR(30),
    confidence_score DOUBLE PRECISION,
    evidence TEXT,
    evidence_json TEXT,
    response_status VARCHAR(50),
    system_response TEXT,
    capture_source VARCHAR(255),
    integrity_hash VARCHAR(64),
    -- New wireless columns
    source_mac VARCHAR(17),
    destination_mac VARCHAR(17),
    bssid VARCHAR(17),
    channel INTEGER,
    rssi_dbm INTEGER,
    capture_session_id INTEGER,
    window_id INTEGER
);

INSERT INTO events_new (
    id, event_id, detection_time, attack_type, ml_class, source_ip, destination_ip,
    source_ips_list, protocol, source_port, destination_port, traffic_stats,
    detection_method, severity, confidence_score, evidence, evidence_json,
    response_status, system_response, capture_source, integrity_hash
)
SELECT 
    id, event_id, detection_time, attack_type, ml_class, source_ip, destination_ip,
    source_ips_list, protocol, source_port, destination_port, traffic_stats,
    detection_method, severity, confidence_score, evidence, evidence_json,
    response_status, system_response, capture_source, integrity_hash
FROM events;

DROP TABLE events;
ALTER TABLE events_new RENAME TO events;

-- 1. users: security columns
ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMP;
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP;

-- 2. capture_sessions: extended
ALTER TABLE capture_sessions ADD COLUMN adapter_friendly_name VARCHAR(255);
ALTER TABLE capture_sessions ADD COLUMN monitor_mode BOOLEAN DEFAULT 0;
ALTER TABLE capture_sessions ADD COLUMN channel INTEGER;
ALTER TABLE capture_sessions ADD COLUMN window_seconds INTEGER DEFAULT 10;
ALTER TABLE capture_sessions ADD COLUMN restart_count INTEGER DEFAULT 0;
ALTER TABLE capture_sessions ADD COLUMN last_error TEXT;
ALTER TABLE capture_sessions ADD COLUMN started_by VARCHAR(100);
ALTER TABLE capture_sessions ADD COLUMN total_frames INTEGER DEFAULT 0;
ALTER TABLE capture_sessions ADD COLUMN total_findings INTEGER DEFAULT 0;

-- 3. audit_logs: extended
ALTER TABLE audit_logs ADD COLUMN user_id INTEGER;
ALTER TABLE audit_logs ADD COLUMN role VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN outcome VARCHAR(20) DEFAULT 'success';

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);

-- 4. login_history: every authentication event
CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username VARCHAR(100) NOT NULL,
    role VARCHAR(50),
    event_type VARCHAR(40) NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    ip_address VARCHAR(50),
    user_agent TEXT,
    session_id VARCHAR(64),
    event_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_login_user_time ON login_history (user_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_login_event ON login_history (event_type);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_history (ip_address);

-- 5. user_sessions: server-side session control
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    user_id INTEGER NOT NULL,
    refresh_token_hash VARCHAR(128),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(50),
    user_agent TEXT,
    revoked BOOLEAN NOT NULL DEFAULT 0,
    revoked_reason VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions (user_id, revoked);

-- 6. live_capture_windows: one row per 10-second analysis window
CREATE TABLE IF NOT EXISTS live_capture_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_session_id INTEGER NOT NULL,
    window_start TIMESTAMP NOT NULL,
    window_end TIMESTAMP NOT NULL,
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
    processing_ms REAL,
    FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_windows_session_time ON live_capture_windows (capture_session_id, window_start DESC);

-- 7. events: add foreign keys for wireless columns
CREATE INDEX IF NOT EXISTS idx_events_session ON events (capture_session_id);
CREATE INDEX IF NOT EXISTS idx_events_source_mac ON events (source_mac);
CREATE INDEX IF NOT EXISTS idx_events_bssid ON events (bssid);
CREATE INDEX IF NOT EXISTS idx_events_method_time ON events (detection_method, detection_time DESC);

-- 8. live_findings: the findings log
CREATE TABLE IF NOT EXISTS live_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id VARCHAR(30) UNIQUE NOT NULL,
    event_id INTEGER,
    window_id INTEGER,
    capture_session_id INTEGER,
    found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
    reviewed_at TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL,
    FOREIGN KEY (window_id) REFERENCES live_capture_windows(id) ON DELETE SET NULL,
    FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_time ON live_findings (found_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON live_findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_type ON live_findings (finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_src ON live_findings (source_mac);

-- 9. wifi_frames: 802.11 header records
CREATE TABLE IF NOT EXISTS wifi_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_session_id INTEGER,
    window_id INTEGER,
    frame_time TIMESTAMP NOT NULL,
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
    flagged BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (window_id) REFERENCES live_capture_windows(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_frames_time ON wifi_frames (frame_time DESC);
CREATE INDEX IF NOT EXISTS idx_frames_session ON wifi_frames (capture_session_id, frame_time DESC);
CREATE INDEX IF NOT EXISTS idx_frames_tx ON wifi_frames (transmitter_mac);

-- 10. device_conversations: over-the-air device pairs
CREATE TABLE IF NOT EXISTS device_conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_session_id INTEGER,
    window_id INTEGER,
    mac_a VARCHAR(17) NOT NULL,
    mac_b VARCHAR(17) NOT NULL,
    bssid VARCHAR(17),
    channel INTEGER,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    packets_per_second REAL,
    avg_rssi_dbm REAL,
    delta_rssi REAL,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    vendor_a VARCHAR(100),
    vendor_b VARCHAR(100),
    FOREIGN KEY (capture_session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (window_id) REFERENCES live_capture_windows(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_conv_window ON device_conversations (window_id);
CREATE INDEX IF NOT EXISTS idx_conv_pair ON device_conversations (mac_a, mac_b);

-- 11. wifi_access_points: approved vs unknown APs
CREATE TABLE IF NOT EXISTS wifi_access_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid VARCHAR(64),
    bssid VARCHAR(17) UNIQUE NOT NULL,
    channel INTEGER,
    encryption VARCHAR(50),
    approved BOOLEAN NOT NULL DEFAULT 0,
    approved_by VARCHAR(100),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 12. sensor_locations: campus location labels
CREATE TABLE IF NOT EXISTS sensor_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_name VARCHAR(100) UNIQUE NOT NULL,
    adapter_name VARCHAR(255),
    location_label VARCHAR(255) NOT NULL,
    updated_by VARCHAR(100),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 13. baseline_stats: historical campus baseline
CREATE TABLE IF NOT EXISTS baseline_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    day_of_week SMALLINT NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
    hour_of_day SMALLINT NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
    avg_pps REAL,
    std_pps REAL,
    avg_deauth_rate REAL,
    samples INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (day_of_week, hour_of_day)
);

-- 14. settings defaults (only insert if missing)
INSERT OR IGNORE INTO settings (key, value, description) VALUES
  ('live_window_seconds', '10', 'Live capture analysis window and dashboard refresh (seconds)'),
  ('idle_timeout_minutes', '15', 'Idle session timeout'),
  ('absolute_timeout_hours', '8', 'Absolute session lifetime'),
  ('max_failed_logins', '5', 'Failed logins before lockout'),
  ('lockout_minutes', '15', 'Account lockout duration'),
  ('frame_retention_days', '7', 'Days to keep wifi_frames rows'),
  ('login_history_retention_days', '365', 'Days to keep login_history rows'),
  ('findings_retention_days', '365', 'Days to keep live_findings rows');

COMMIT;
