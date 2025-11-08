-- 0012_create_user_groups.sql
-- Create a simple mapping of username -> group_name
-- Intended for use with the D1 (SQLite) database named `scoring`.

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS user_groups (
  username TEXT PRIMARY KEY,
  group_name TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_user_groups_group_name ON user_groups(group_name);

COMMIT;
