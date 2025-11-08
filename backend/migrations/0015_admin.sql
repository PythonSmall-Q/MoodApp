CREATE TABLE IF NOT EXISTS admin_users (
  username TEXT PRIMARY KEY,
  password_sha TEXT,
  is_super INTEGER DEFAULT 0,
  groups TEXT,
  permissions TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  session_id TEXT PRIMARY KEY,
  username TEXT,
  expires TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
