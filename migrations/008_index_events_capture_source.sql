-- 008: index the traffic source on events
-- The dashboard recounts each source's events to keep the stored analysis_totals rows
-- truthful, and the live monitor does the same after every window, so the column both
-- filters on needs an index instead of a full table scan.
CREATE INDEX IF NOT EXISTS idx_events_capture_source ON events (capture_source);
