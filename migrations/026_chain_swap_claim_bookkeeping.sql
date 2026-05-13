-- ============================================================================
-- 026: Chain swap claim bookkeeping
-- ============================================================================
--
-- BTC-to-LBTC chain-swap claims spend a Liquid server-lockup output. Like
-- reverse-swap claims, Liquid transaction construction is not stable across
-- retries because blinding data and signing details can change. Persist the
-- first constructed claim transaction so every retry rebroadcasts the same tx.
-- ============================================================================

BEGIN;

ALTER TABLE chain_swap_records
    ADD COLUMN claim_tx_hex TEXT CHECK (claim_tx_hex IS NULL OR claim_tx_hex ~ '^[0-9a-fA-F]+$'),
    ADD COLUMN claim_attempts INTEGER NOT NULL DEFAULT 0 CHECK (claim_attempts >= 0),
    ADD COLUMN last_claim_error TEXT,
    ADD COLUMN last_claim_error_at TIMESTAMPTZ,
    ADD COLUMN next_claim_attempt_at TIMESTAMPTZ;

CREATE INDEX chain_swap_records_ready_to_claim_idx
    ON chain_swap_records(next_claim_attempt_at)
    WHERE status IN ('server_lock_mempool', 'server_lock_confirmed', 'claiming', 'claim_failed');

COMMIT;
