-- D1 fix: partial index for the outpoint-addresses recycler in
-- `pay-service/src/gc.rs::prune_outpoint_addresses`.
--
-- The recycler runs every 10 min and deletes unfulfilled rows older
-- than `outpoint_pending_ttl_secs` (1h default). Without this partial
-- index the DELETE scans the full table; with it the planner can walk
-- only the unfulfilled subset, which is bounded by the TTL.

CREATE INDEX idx_outpoint_addresses_unfulfilled_created
    ON outpoint_addresses(created_at)
    WHERE fulfilled = FALSE;
