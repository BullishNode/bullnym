-- Activity timestamp for chain-watcher prioritization (P4).
--
-- The watcher polls every active user every tick × lookahead Electrum
-- queries per nym. Linear in `users` row count, this saturates the
-- Electrum bucket once the table is large (R4 finding: 1000 nyms made
-- next_addr_idx advances stall for >8 minutes).
--
-- We split users into "active" (recent callback) and "idle" (no recent
-- callback). The watcher polls active users on every tick and idle users
-- only every N minutes — bounding per-tick work to the active subset.
--
-- NULL means "never seen a callback"; treated as idle for prioritization.
-- Backfilled to NULL on existing rows; populated by the callback handler
-- on every successful Liquid LUD-22 hit.

ALTER TABLE users ADD COLUMN last_callback_at TIMESTAMPTZ;

-- Partial index covering only active rows (the common watcher query path).
CREATE INDEX idx_users_active_recent_callback
    ON users(last_callback_at DESC)
    WHERE is_active = TRUE;
