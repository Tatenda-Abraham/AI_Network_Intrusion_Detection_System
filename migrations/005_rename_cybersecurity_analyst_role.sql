-- Migration 005: Rename the analyst console role Network Analyst -> Cybersecurity Analyst
-- Target: PostgreSQL 16 database 'ai_nids'
-- Safe to re-run: the constraint is replaced unconditionally and the UPDATE matches nothing twice.

BEGIN;

-- The old CHECK forbids the new value, so drop it before rewriting the rows.
ALTER TABLE users DROP CONSTRAINT IF EXISTS check_user_role;

UPDATE users SET role = 'Cybersecurity Analyst' WHERE role = 'Network Analyst';

ALTER TABLE users ALTER COLUMN role SET DEFAULT 'Cybersecurity Analyst';

ALTER TABLE users ADD CONSTRAINT check_user_role CHECK (role IN ('Administrator', 'Cybersecurity Analyst'));

COMMIT;
