-- Add claim state fields to swap_records for cooperative MuSig2 claiming.
-- The Pay Service now claims swaps itself (no covclaim daemon).

ALTER TABLE swap_records
    ADD COLUMN preimage_hex       TEXT,
    ADD COLUMN claim_key_hex      TEXT,
    ADD COLUMN boltz_response_json TEXT,
    ADD COLUMN status             TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN claim_txid         TEXT,
    ADD COLUMN updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Status lifecycle: pending → lockup_mempool → lockup_confirmed → claiming → claimed
-- On failure: claiming → claim_failed (retryable)
-- On timeout: pending → expired (if invoice never paid)

CREATE INDEX idx_swap_records_status ON swap_records(status);
