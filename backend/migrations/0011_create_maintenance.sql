-- 0011_create_maintenance.sql
-- Create maintenance table for planned maintenance notices / temporary issues
CREATE TABLE IF NOT EXISTS maintenance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  details TEXT,
  start_time TEXT,
  end_time TEXT,
  created_by TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);
