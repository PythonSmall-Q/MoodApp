-- Add disabled flag to user_table
PRAGMA foreign_keys=ON;

ALTER TABLE user_table ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0; -- 0=enabled,1=disabled

CREATE INDEX IF NOT EXISTS idx_user_disabled ON user_table(disabled);
