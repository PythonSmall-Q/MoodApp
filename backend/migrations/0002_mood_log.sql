-- Create table for per-day mood logs
CREATE TABLE IF NOT EXISTS mood_log (
  username TEXT NOT NULL,
  date TEXT NOT NULL,
  mood TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (username, date)
);

CREATE INDEX IF NOT EXISTS idx_mood_log_user_date ON mood_log(username, date);
