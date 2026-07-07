-- ============================================================================
-- 038: chain swap customer self-claim refund (BTC refund waterfall Phase 4)
-- ============================================================================
-- Adds the machinery for the customer to reclaim their BTC from a `refund_due`
-- chain swap:
--   * `refunding` — a non-terminal in-flight state, set atomically under the
--     per-swap advisory lock BEFORE the refund tx is broadcast. It is EXCLUDED
--     from every claim path so the L-BTC claim and the BTC refund (which spend
--     different UTXOs on different chains and could otherwise both confirm) can
--     never both fire — the double-payout guard (G12). A refund only ever
--     starts from `refund_due`; a claim never starts from `refunding`.
--   * `refund_address` — the customer-supplied BTC address, FIRST-WRITE-WINS and
--     immutable once set (G13/G14): persisted before any broadcast so a
--     bystander who knows the public invoice URL cannot redirect an
--     in-flight or completed refund.
--   * `refund_txid` — the broadcast refund transaction id, for operator
--     forensics and idempotent re-broadcast.
-- On success the swap flips `refunding` -> `refunded` (terminal) with the txid;
-- on broadcast failure it reverts `refunding` -> `refund_due` so it stays
-- recoverable (never terminalized while funds are unclaimed).
-- ============================================================================

BEGIN;

ALTER TABLE chain_swap_records
    ADD COLUMN IF NOT EXISTS refund_address TEXT,
    ADD COLUMN IF NOT EXISTS refund_txid TEXT;

ALTER TABLE chain_swap_records
    DROP CONSTRAINT IF EXISTS chain_swap_records_status_check;

ALTER TABLE chain_swap_records
    ADD CONSTRAINT chain_swap_records_status_check
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
        'refunded',
        'refund_due',
        'refunding'
      ));

COMMIT;
