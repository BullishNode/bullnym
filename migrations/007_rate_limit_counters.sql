-- Sliding-window rate limit event log.
-- Bucket format:
--   "ip:<addr>"      — per-source-IP
--   "pubkey:<hex>"   — per-UTXO-owner pubkey
--   "nym:<nym>"      — per-nym lightning-path callback
-- Periodic GC prunes rows older than the longest configured window.

CREATE TABLE rate_limit_events (
    id         BIGSERIAL PRIMARY KEY,
    bucket     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rate_limit_bucket_time ON rate_limit_events(bucket, created_at DESC);
