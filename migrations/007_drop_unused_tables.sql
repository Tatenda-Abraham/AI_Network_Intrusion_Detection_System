-- Migration 007: Drop the two tables no code path reads or writes
-- Target: PostgreSQL 16 database 'ai_nids'
--
-- model_runs held the training metrics, but train_model.py writes models/rf_v1.joblib and
-- the dashboard reads that file, so the table stayed empty since it was created.
-- sensor_locations was never wired to a route or a page; wireless_analyzer only imported it.
-- Safe to re-run.

BEGIN;

DROP TABLE IF EXISTS model_runs;
DROP TABLE IF EXISTS sensor_locations;

COMMIT;
