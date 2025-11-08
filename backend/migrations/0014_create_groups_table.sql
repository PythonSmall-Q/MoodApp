-- 0014_create_groups_table.sql
-- Create a dedicated groups table for admin-managed group names

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS groups (
  group_name TEXT PRIMARY KEY,
  created_at TEXT DEFAULT (datetime('now'))
);

COMMIT;
