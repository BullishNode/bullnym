-- ============================================================================
-- 025: Donation Page BTC-to-LBTC chain swap records
-- ============================================================================
--
-- Chain swaps have different lifecycle and key material than Lightning
-- reverse swaps:
--   - two local keys (claim + refund), not one claim key
--   - a payer-facing Bitcoin lockup address/BIP21, not a BOLT11 invoice
--   - server-lockup states before merchant-side LBTC claim
--
-- Keep them out of `swap_records` until the semantics are stable. Public
-- exposure comes in a later phase after claim/reconcile handling is wired.
-- ============================================================================

BEGIN;

CREATE TABLE chain_swap_records (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id              UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    nym                     TEXT REFERENCES users(nym),
    boltz_swap_id           TEXT NOT NULL UNIQUE,
    from_chain              TEXT NOT NULL CHECK (from_chain = 'BTC'),
    to_chain                TEXT NOT NULL CHECK (to_chain = 'L-BTC'),
    lockup_address          TEXT NOT NULL,
    lockup_bip21            TEXT,
    user_lock_amount_sat    BIGINT NOT NULL CHECK (user_lock_amount_sat > 0),
    server_lock_amount_sat  BIGINT NOT NULL CHECK (server_lock_amount_sat > 0),
    preimage_hex            TEXT NOT NULL CHECK (preimage_hex ~ '^[0-9a-fA-F]{64}$'),
    claim_key_hex           TEXT NOT NULL CHECK (claim_key_hex ~ '^[0-9a-fA-F]{64}$'),
    refund_key_hex          TEXT NOT NULL CHECK (refund_key_hex ~ '^[0-9a-fA-F]{64}$'),
    boltz_response_json     TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN (
        'pending',
        'user_lock_mempool',
        'user_lock_confirmed',
        'server_lock_mempool',
        'server_lock_confirmed',
        'claiming',
        'claimed',
        'claim_failed',
        'claim_stuck',
        'expired',
        'lockup_failed',
        'refunded'
      )),
    claim_txid              TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX chain_swap_records_invoice_idx
    ON chain_swap_records(invoice_id, created_at DESC);

CREATE INDEX chain_swap_records_nym_idx
    ON chain_swap_records(nym)
    WHERE nym IS NOT NULL;

CREATE INDEX chain_swap_records_status_idx
    ON chain_swap_records(status);

CREATE INDEX chain_swap_records_non_terminal_age_idx
    ON chain_swap_records(updated_at)
    WHERE status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON chain_swap_records
            TO payservice;
    END IF;
END
$$;

COMMIT;
