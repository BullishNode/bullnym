-- ============================================================================
-- 074: authoritative Bull Bitcoin execution rate (R2)
-- ============================================================================
--
-- API-Orders exposes the order's persisted exchangeRate as
-- exchangeRateAmount/exchangeRateCurrency. Store that explicit provider fact
-- so merchant accounting can explain the exact fiat credit without deriving a
-- rate from rounded payout and received-amount totals. Existing rows stay NULL;
-- this migration never invents historical provider evidence.

BEGIN;

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN execution_rate_minor_per_btc BIGINT,
    ADD CONSTRAINT bull_bitcoin_settlements_execution_rate_chk CHECK (
        execution_rate_minor_per_btc IS NULL
        OR execution_rate_minor_per_btc > 0
    );

ALTER TABLE bull_bitcoin_settlements
    DROP CONSTRAINT bull_bitcoin_settlements_observation_shape_chk,
    ADD CONSTRAINT bull_bitcoin_settlements_observation_shape_chk CHECK (
        (provider_state <> 'bound'
            AND order_status IS NULL AND payin_status IS NULL
            AND payout_status IS NULL AND actual_received_sat IS NULL
            AND credited_fiat_minor IS NULL AND quoted_fiat_minor IS NULL
            AND execution_rate_minor_per_btc IS NULL
            AND NOT provider_final)
        OR provider_state = 'bound'
    );

COMMENT ON COLUMN bull_bitcoin_settlements.execution_rate_minor_per_btc IS
    'Explicit API-Orders exchangeRateAmount in payout-currency minor units per BTC; nullable for pending/legacy observations and never derived from payout totals.';

COMMIT;
