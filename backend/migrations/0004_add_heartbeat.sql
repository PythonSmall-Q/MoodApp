-- Add heartbeat tracking for anonymous chat
PRAGMA foreign_keys=ON;

ALTER TABLE user_table ADD COLUMN last_heartbeat TEXT; -- ISO datetime string

CREATE INDEX IF NOT EXISTS idx_user_last_heartbeat ON user_table(last_heartbeat);
