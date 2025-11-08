-- Add per-feature disable flags to user_table
PRAGMA foreign_keys=ON;

ALTER TABLE user_table ADD COLUMN disable_anon_chat INTEGER NOT NULL DEFAULT 0; -- 0=enabled,1=disabled
ALTER TABLE user_table ADD COLUMN disable_mood INTEGER NOT NULL DEFAULT 0;      -- 0=enabled,1=disabled
ALTER TABLE user_table ADD COLUMN disable_ai INTEGER NOT NULL DEFAULT 0;        -- 0=enabled,1=disabled

CREATE INDEX IF NOT EXISTS idx_user_disable_anon_chat ON user_table(disable_anon_chat);
CREATE INDEX IF NOT EXISTS idx_user_disable_mood ON user_table(disable_mood);
CREATE INDEX IF NOT EXISTS idx_user_disable_ai ON user_table(disable_ai);
