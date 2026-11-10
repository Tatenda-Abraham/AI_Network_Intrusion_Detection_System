-- Migration 006: Analysis totals table and persisted live-capture counters
-- Target: PostgreSQL 16 database 'ai_nids'
-- Safe to re-run: every statement is conditional.

BEGIN;

-- Headline figures per traffic source, read directly by the dashboard.
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

-- Keep the monitor's own totals on its session row, so the numbers survive a restart.
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS events_stored INTEGER NOT NULL DEFAULT 0;
ALTER TABLE capture_sessions ADD COLUMN IF NOT EXISTS alerts_raised INTEGER NOT NULL DEFAULT 0;

COMMIT;
