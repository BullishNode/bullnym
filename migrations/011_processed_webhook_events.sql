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

CREATE TABLE IF NOT EXISTS processed_webhook_events (
    event_id     TEXT PRIMARY KEY,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_processed_webhook_events_processed_at
    ON processed_webhook_events(processed_at);

-- When this migration is applied as `postgres`, the table is owned by
-- `postgres` and the runtime role gets nothing. Without these GRANTs the
-- webhook handler 500s on every Boltz delivery and swaps stall in
-- `pending` until manually rescued. (Hit prod 2026-05-01.)
--
-- Guarded by a `pg_roles` check so fresh dev DBs without the `payservice`
-- role can still apply this migration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON processed_webhook_events
            TO payservice;
    END IF;
END
$$;
