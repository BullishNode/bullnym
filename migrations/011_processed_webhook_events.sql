-- D2 fix: idempotency table for `/webhook/boltz`.
--
-- Boltz can deliver the same webhook event multiple times (network
-- retries, re-deliveries during their incidents). Without an
-- idempotency check the handler would re-run claims, double-update
-- swap state, and waste Electrum tokens.
--
-- The handler computes a deterministic event_id from the payload
-- (`{swap_id}:{status}`) and tries to INSERT here. If the row already
-- exists, the event has been processed and the handler short-circuits
-- with 200 OK without doing the work twice.

CREATE TABLE processed_webhook_events (
    event_id     TEXT PRIMARY KEY,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_processed_webhook_events_processed_at
    ON processed_webhook_events(processed_at);
