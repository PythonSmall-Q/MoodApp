-- rate_limits: simple counters per key with window start
CREATE TABLE rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  window_start TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0
);

-- admin_audit: log admin actions
CREATE TABLE admin_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_token TEXT,
  action TEXT,
  target TEXT,
  reason TEXT,
  meta TEXT,
  time TEXT DEFAULT CURRENT_TIMESTAMP
);
