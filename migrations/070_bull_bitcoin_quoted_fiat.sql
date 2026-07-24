-- ============================================================================
-- 070: locked fiat quote for Get Paid history contract v2
-- ============================================================================
--
-- Get Paid history v1 could only expose a fiat amount once a settlement was
-- final (credited_fiat_minor). Merchants need the fiat value that was locked
-- (quoted) when the order was created, at zero-conf, so a pending fiat leg can
-- show its amount immediately.
--
-- payoutAmount from the Bull Bitcoin create/read responses is that quote. It is
-- captured when the order is bound and re-observed on every poll, so a late
-- payment repriced by API-Orders flows through as an updated quote. The quote
-- is authoritative within the quote window and can differ from the eventually
-- credited amount for a late payment; the two remain distinct columns.
--
-- The configured split already lives on this row as the NOT NULL
-- fiat_percentage column (migration 067: fiat_only = 100, mixed = 1..99), so
-- Get Paid history v2 reuses it and this migration adds no percentage column.
--
-- bull_bitcoin_settlements already carries table-level SELECT/INSERT/UPDATE for
-- the runtime role (migration 067). A table-level privilege covers columns
-- added later, so this new column needs no additional grant -- exactly as
-- migration 069 added reverse_swap_id/chain_swap_id to this table with none.

BEGIN;

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN quoted_fiat_minor BIGINT,
    ADD CONSTRAINT bull_bitcoin_settlements_quoted_amount_chk CHECK (
        quoted_fiat_minor IS NULL OR quoted_fiat_minor > 0
    );

-- The quote is captured at binding, so like every other provider observation
-- field it must stay NULL until the order is bound. Fold it into the existing
-- observation-shape invariant rather than leaving a gap a corrupt pre-bound
-- row could exploit.
ALTER TABLE bull_bitcoin_settlements
    DROP CONSTRAINT bull_bitcoin_settlements_observation_shape_chk,
    ADD CONSTRAINT bull_bitcoin_settlements_observation_shape_chk CHECK (
        (provider_state <> 'bound'
            AND order_status IS NULL AND payin_status IS NULL
            AND payout_status IS NULL AND actual_received_sat IS NULL
            AND credited_fiat_minor IS NULL AND quoted_fiat_minor IS NULL
            AND NOT provider_final)
        OR provider_state = 'bound'
    );

COMMENT ON COLUMN bull_bitcoin_settlements.quoted_fiat_minor IS
    'Fiat quote (payoutAmount) locked at order creation; re-observed each poll. Distinct from the settled credited_fiat_minor for late repriced payments.';

COMMIT;
