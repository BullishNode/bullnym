-- Value a mixed Bull Bitcoin Liquid output with the exact Bullnym payer quote.
-- The provider's payout amount remains separate settlement evidence and is
-- never used to value what the payer sent.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

-- Migration 069 intentionally made mixed outputs valuation-free. Remove that
-- narrow exception and let the existing quote-attribution trigger own their
-- valuation just like the merchant output from the same payer instruction.
DROP TRIGGER invoice_payment_events_guard_quote_attribution
    ON invoice_payment_events;
DROP TRIGGER invoice_payment_events_guard_bull_bitcoin
    ON invoice_payment_events;

ALTER TABLE invoice_payment_events
    DROP CONSTRAINT invoice_payment_events_bull_bitcoin_shape_chk;

-- Repair only historical rows for which the immutable parent swap proves an
-- on-time quote and no later committed event would have had different
-- cumulative rounding. Anything less certain remains unchanged and is exposed
-- by invoice_mixed_valuation_exceptions below; migrations never invent a rate.
DO $$
DECLARE
    candidate RECORD;
    prior_eligible_sat BIGINT;
    prior_credit BIGINT;
    next_credit BIGINT;
BEGIN
    FOR candidate IN
        SELECT event.id AS event_id,
               event.invoice_id,
               event.accounting_sequence,
               event.amount_sat,
               COALESCE(reverse_swap.invoice_quote_version_id,
                        chain_swap.invoice_quote_version_id) AS quote_version_id,
               COALESCE(reverse_swap.invoice_quote_offer_id,
                        chain_swap.invoice_quote_offer_id) AS quote_offer_id,
               COALESCE(reverse_swap.quote_payment_first_observed_at,
                        chain_swap.quote_payment_first_observed_at) AS first_observed_at,
               quote.fiat_target_amount_minor,
               quote.merchant_amount_sat,
               quote.rate_minor_per_btc,
               quote.rate_source,
               quote.rate_observed_at,
               quote.rate_fetched_at,
               quote.rate_fresh_until
          FROM invoice_payment_events event
          JOIN bull_bitcoin_settlements settlement
            ON settlement.id = event.bull_bitcoin_settlement_id
           AND settlement.purpose = 'mixed'
          LEFT JOIN swap_records reverse_swap
            ON reverse_swap.id = settlement.reverse_swap_id
          LEFT JOIN chain_swap_records chain_swap
            ON chain_swap.id = settlement.chain_swap_id
          JOIN invoice_quote_versions quote
            ON quote.id = COALESCE(reverse_swap.invoice_quote_version_id,
                                   chain_swap.invoice_quote_version_id)
           AND quote.invoice_id = event.invoice_id
         WHERE event.source = 'bull_bitcoin_mixed_output'
           AND event.invoice_quote_version_id IS NULL
           AND event.invoice_quote_offer_id IS NULL
           AND event.quote_first_observed_at IS NULL
           AND event.fiat_credited_minor IS NULL
           AND COALESCE(reverse_swap.invoice_quote_offer_id,
                        chain_swap.invoice_quote_offer_id) IS NOT NULL
           AND COALESCE(reverse_swap.quote_payment_first_observed_at,
                        chain_swap.quote_payment_first_observed_at) IS NOT NULL
           AND COALESCE(reverse_swap.quote_payment_first_observed_at,
                        chain_swap.quote_payment_first_observed_at) < quote.expires_at
           AND NOT EXISTS (
               SELECT 1
                 FROM invoice_payment_events later
                WHERE later.invoice_id = event.invoice_id
                  AND later.accounting_sequence > event.accounting_sequence
                  AND later.fiat_valuation_quote_version_id = quote.id
           )
         ORDER BY event.invoice_id, quote.id, event.accounting_sequence
    LOOP
        SELECT COALESCE(SUM(prior.amount_sat), 0)::BIGINT
          INTO prior_eligible_sat
          FROM invoice_payment_events prior
         WHERE prior.invoice_id = candidate.invoice_id
           AND prior.fiat_valuation_quote_version_id = candidate.quote_version_id
           AND prior.accounting_sequence < candidate.accounting_sequence;

        prior_credit := invoice_quote_credit_for_sats(
            candidate.fiat_target_amount_minor,
            candidate.merchant_amount_sat,
            candidate.rate_minor_per_btc,
            prior_eligible_sat
        );
        next_credit := invoice_quote_credit_for_sats(
            candidate.fiat_target_amount_minor,
            candidate.merchant_amount_sat,
            candidate.rate_minor_per_btc,
            prior_eligible_sat + candidate.amount_sat
        );

        UPDATE invoice_payment_events
           SET invoice_quote_version_id = candidate.quote_version_id,
               invoice_quote_offer_id = candidate.quote_offer_id,
               quote_first_observed_at = candidate.first_observed_at,
               fiat_credited_minor = next_credit - prior_credit,
               fiat_credit_policy = 'quote_cumulative_saturation_v1',
               fiat_valued_at = clock_timestamp(),
               fiat_valuation_quote_version_id = candidate.quote_version_id,
               fiat_rate_minor_per_btc = candidate.rate_minor_per_btc,
               fiat_rate_source = candidate.rate_source,
               fiat_rate_observed_at = candidate.rate_observed_at,
               fiat_rate_fetched_at = candidate.rate_fetched_at,
               fiat_rate_fresh_until = candidate.rate_fresh_until
         WHERE id = candidate.event_id;
    END LOOP;
END
$$;

ALTER TABLE invoice_payment_events
    ADD CONSTRAINT invoice_payment_events_bull_bitcoin_shape_chk CHECK (
        (
            source = 'bull_bitcoin_fiat'
            AND bull_bitcoin_settlement_id IS NOT NULL
            AND event_key = 'bull_bitcoin_fiat:' || bull_bitcoin_settlement_id::TEXT
            AND txid IS NULL AND vout IS NULL
            AND boltz_swap_id IS NULL AND address IS NULL
            AND accounting_state = 'active'
            AND verification_state = 'not_applicable'
        ) OR (
            source = 'bull_bitcoin_mixed_output'
            AND bull_bitcoin_settlement_id IS NOT NULL
            AND event_key = 'bull_bitcoin_mixed_output:' || bull_bitcoin_settlement_id::TEXT
            AND txid ~ '^[0-9a-f]{64}$' AND vout = 1
            AND boltz_swap_id IS NULL AND address IS NULL
            AND accounting_state IN ('active', 'inactive')
            AND verification_state = 'not_applicable'
        ) OR (
            source IS DISTINCT FROM 'bull_bitcoin_fiat'
            AND source IS DISTINCT FROM 'bull_bitcoin_mixed_output'
            AND bull_bitcoin_settlement_id IS NULL
        )
    );

CREATE TRIGGER invoice_payment_events_guard_quote_attribution
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source IS DISTINCT FROM 'bull_bitcoin_fiat')
    EXECUTE FUNCTION guard_invoice_payment_quote_attribution();

CREATE TRIGGER invoice_payment_events_guard_bull_bitcoin
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source IN ('bull_bitcoin_fiat', 'bull_bitcoin_mixed_output'))
    EXECUTE FUNCTION guard_bull_bitcoin_invoice_payment_event();

CREATE VIEW invoice_mixed_valuation_exceptions
WITH (security_invoker = TRUE)
AS
SELECT event.id AS payment_event_id,
       event.invoice_id,
       event.bull_bitcoin_settlement_id,
       event.amount_sat,
       event.accounting_sequence,
       event.created_at,
       CASE
           WHEN COALESCE(reverse_swap.invoice_quote_version_id,
                         chain_swap.invoice_quote_version_id) IS NULL
             OR COALESCE(reverse_swap.invoice_quote_offer_id,
                         chain_swap.invoice_quote_offer_id) IS NULL
               THEN 'missing_parent_quote_attribution'
           WHEN COALESCE(reverse_swap.quote_payment_first_observed_at,
                         chain_swap.quote_payment_first_observed_at) IS NULL
               THEN 'missing_parent_first_observed_at'
           ELSE 'valuation_unavailable_for_observation_time'
       END AS reason
  FROM invoice_payment_events event
  JOIN bull_bitcoin_settlements settlement
    ON settlement.id = event.bull_bitcoin_settlement_id
   AND settlement.purpose = 'mixed'
  LEFT JOIN swap_records reverse_swap
    ON reverse_swap.id = settlement.reverse_swap_id
  LEFT JOIN chain_swap_records chain_swap
    ON chain_swap.id = settlement.chain_swap_id
 WHERE event.source = 'bull_bitcoin_mixed_output'
   AND event.accounting_state = 'active'
   AND event.fiat_credited_minor IS NULL;

COMMENT ON VIEW invoice_mixed_valuation_exceptions IS
    'Mixed invoice pay-in evidence that cannot be valued without inventing quote/rate authority.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE invoice_mixed_valuation_exceptions FROM PUBLIC;
    EXECUTE format(
        'GRANT SELECT ON TABLE invoice_mixed_valuation_exceptions TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
