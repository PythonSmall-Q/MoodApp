-- Create sessions table for server-side session management
-- Create sessions table for server-side session management
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  expires TEXT NOT NULL,
  csrf_token TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);