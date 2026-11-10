-- 009: drop the unused forced-password-change flag
-- users.must_change_password was set when an Administrator created an account, but nothing
-- in the console ever read it and there is no change-password screen, so every account was
-- simply used with the password its creator set. The column is removed so the schema only
-- describes behaviour the system actually performs.
ALTER TABLE users DROP COLUMN IF EXISTS must_change_password;
