-- ============================================================================
-- 036: chain swap `refund_due` status
-- ============================================================================
-- Adds a non-terminal `refund_due` status for chain (BTC) swaps whose lockup is
-- funded but the swap failed/expired, so the payer's BTC is recoverable rather
-- than silently terminalized (see the BTC refund waterfall). `refund_due` is
-- the join point: it is set on funded failure and later drained by
-- renegotiation (settle) or customer self-claim (refund); it must never be a
-- dead terminal state.
-- ============================================================================

BEGIN;

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
        'refund_due'
      ));

COMMIT;
