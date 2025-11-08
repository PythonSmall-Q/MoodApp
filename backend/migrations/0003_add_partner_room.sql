-- Add partner/session fields for anonymous chat recovery
-- SQLite (Cloudflare D1)
PRAGMA foreign_keys=ON;

-- Add columns if they don't exist (SQLite ADD COLUMN is idempotent for repeated applies in D1 migrations)
ALTER TABLE user_table ADD COLUMN partner_username TEXT;
ALTER TABLE user_table ADD COLUMN current_room_id TEXT;

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_user_partner ON user_table(partner_username);
CREATE INDEX IF NOT EXISTS idx_user_room ON user_table(current_room_id);
