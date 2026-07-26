DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'bull_bitcoin_settlements'
           AND column_name = 'invoice_quote_version_id'
           AND data_type = 'uuid'
           AND is_nullable = 'YES'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'bull_bitcoin_settlements'
           AND column_name = 'quote_payment_first_observed_at'
           AND data_type = 'timestamp with time zone'
           AND is_nullable = 'YES'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'bull_bitcoin_settlements'::regclass
           AND conname = 'bull_bitcoin_settlements_funded_instruction_closed_chk'
           AND convalidated
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger
         WHERE tgrelid = 'invoice_payment_events'::regclass
           AND tgname = 'invoice_payment_events_guard_bull_bitcoin_fiat'
           AND tgenabled = 'O' AND NOT tgisinternal
    ) THEN
        RAISE EXCEPTION 'migration 075 accounting boundary is incomplete';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM bull_bitcoin_settlements
         WHERE id = '75000000-0000-4000-8000-000000000003'
           AND invoice_quote_version_id =
               '75000000-0000-4000-8000-000000000002'
           AND quote_payment_first_observed_at IS NULL
           AND instruction_kind = 'bitcoin'
           AND payer_instruction = 'bc1q075payerinstruction'
    ) THEN
        RAISE EXCEPTION 'migration 075 did not deterministically recover the unfunded quote';
    END IF;

    -- Migration 073 left a funded legacy fixture with a payer instruction.
    -- Migration 075 must close that instruction without inventing a quote or
    -- first-observation timestamp which the old schema never recorded.
    IF NOT EXISTS (
        SELECT 1 FROM bull_bitcoin_settlements
         WHERE id = '73000000-0000-4000-8000-000000000002'
           AND actual_received_sat = 10000
           AND payer_instruction IS NULL
           AND instruction_kind IS NULL
           AND invoice_quote_version_id IS NULL
           AND quote_payment_first_observed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 075 mishandled funded legacy admission state';
    END IF;
END
$$;

-- Exercise the post-cutover path as the actual runtime role. The provider's
-- CAD payout remains on the settlement; the invoice event receives USD face
-- credit exclusively from the immutable Bullnym payer quote.
BEGIN;
SET LOCAL ROLE bullnym_app;
UPDATE bull_bitcoin_settlements
   SET order_status = 'Completed', payin_status = 'Completed',
       payout_status = 'Completed', actual_received_sat = 10000,
       quote_payment_first_observed_at = clock_timestamp(),
       credited_fiat_minor = 31406, provider_final = TRUE,
       settlement_status = 'settled', terminal_at = clock_timestamp(),
       payer_instruction = NULL, instruction_kind = NULL,
       instruction_expires_at = NULL, next_attempt_at = NULL,
       updated_at = clock_timestamp()
 WHERE id = '75000000-0000-4000-8000-000000000003';

INSERT INTO invoice_payment_events (
    invoice_id, rail, source, event_key, amount_sat,
    accounting_state, verification_state, bull_bitcoin_settlement_id
) VALUES (
    '75000000-0000-4000-8000-000000000001', 'bitcoin',
    'bull_bitcoin_fiat',
    'bull_bitcoin_fiat:75000000-0000-4000-8000-000000000003',
    10000, 'active', 'not_applicable',
    '75000000-0000-4000-8000-000000000003'
);
COMMIT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM invoice_payment_events event
          JOIN invoice_quote_versions quote
            ON quote.id = event.fiat_valuation_quote_version_id
          JOIN bull_bitcoin_settlements settlement
            ON settlement.id = event.bull_bitcoin_settlement_id
         WHERE event.bull_bitcoin_settlement_id =
               '75000000-0000-4000-8000-000000000003'
           AND event.fiat_credited_minor = 1000
           AND event.invoice_quote_version_id = quote.id
           AND event.invoice_quote_offer_id IS NULL
           AND event.fiat_rate_minor_per_btc = 10000000
           AND quote.fiat_currency = 'USD'
           AND settlement.fiat_currency = 'CAD'
           AND settlement.credited_fiat_minor = 31406
    ) THEN
        RAISE EXCEPTION 'migration 075 conflated invoice face and payout currency';
    END IF;

    BEGIN
        INSERT INTO bull_bitcoin_settlements (
            id, owner_npub, invoice_id, invoice_quote_version_id,
            credential_id, product, purpose, payer_rail, request_key,
            fiat_percentage, fiat_currency, requested_bitcoin_sat
        ) VALUES (
            '75000000-0000-4000-8000-000000000006', repeat('6', 64),
            '75000000-0000-4000-8000-000000000001',
            '75000000-0000-4000-8000-000000000002',
            '66000000-0000-4000-8000-000000000001',
            'invoice', 'fiat_only', 'liquid', repeat('7', 64),
            100, 'CAD', 10000
        );
        RAISE EXCEPTION 'migration 075 accepted a second payer intent after funds';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        INSERT INTO invoice_quote_versions (
            invoice_id, quote_purpose, fiat_target_amount_minor,
            rate_minor_per_btc, rate_source,
            rate_observed_at, rate_fetched_at, rate_fresh_until,
            merchant_amount_sat
        ) VALUES (
            '75000000-0000-4000-8000-000000000001',
            'payer_instruction', 1000, 20000000,
            'test:migration-075-must-reject',
            clock_timestamp() - INTERVAL '1 second', clock_timestamp(),
            clock_timestamp() + INTERVAL '5 minutes', 5000
        );
        RAISE EXCEPTION 'migration 075 accepted a payer quote after funds';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
END
$$;
