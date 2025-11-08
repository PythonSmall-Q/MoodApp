-- Track page visits by users (optional username)
CREATE TABLE IF NOT EXISTS page_visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  page TEXT NOT NULL,
  title TEXT,
  referrer TEXT,
  ua TEXT,
  time TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
);
