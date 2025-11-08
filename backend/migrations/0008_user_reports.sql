-- Create user_reports table for storing reports from users
CREATE TABLE IF NOT EXISTS user_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter TEXT NOT NULL,
  target_username TEXT,
  target_room_id TEXT,
  reason TEXT,
  details TEXT,
  time DATETIME DEFAULT (CURRENT_TIMESTAMP)
);
