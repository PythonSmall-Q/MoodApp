-- room_states: lightweight table to track per-room version/last_update
CREATE TABLE room_states (
  room_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL DEFAULT 1,
  last_update TEXT DEFAULT CURRENT_TIMESTAMP
);
