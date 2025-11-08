-- Schema: mood app initial (SQLite / D1)
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS user_table (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_sha TEXT NOT NULL,
  hobby TEXT,
  sex INTEGER CHECK (sex IN (1,2,3)),
  mood TEXT,
  last_mood_date TEXT, -- ISO date string YYYY-MM-DD
  chatting INTEGER NOT NULL DEFAULT 0
);

-- Chat history for AI chat (and optionally anon chat)
CREATE TABLE IF NOT EXISTS chat_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  message TEXT NOT NULL,
  reply TEXT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (username) REFERENCES user_table(username) ON DELETE CASCADE
);

-- Anonymous chat messages (polling model)
CREATE TABLE IF NOT EXISTS anon_chat (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  message TEXT NOT NULL,
  timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_user_username ON user_table(username);
CREATE INDEX IF NOT EXISTS idx_anon_room_time ON anon_chat(room_id, timestamp);
