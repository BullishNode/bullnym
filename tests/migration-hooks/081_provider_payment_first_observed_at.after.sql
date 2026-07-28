DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'bull_bitcoin_settlements'
           AND column_name = 'provider_payment_first_observed_at'
           AND data_type = 'timestamp with time zone'
           AND is_nullable = 'YES'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'bull_bitcoin_settlements'::REGCLASS
           AND conname = 'bull_bitcoin_settlements_provider_payment_time_chk'
           AND convalidated
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_proc
         WHERE proname = 'guard_fiat_only_quote_authority'
           AND POSITION(
               'provider_payment_first_observed_at'
               IN pg_get_functiondef(oid)
           ) > 0
    ) THEN
        RAISE EXCEPTION 'migration 081 provider payment-time boundary is incomplete';
    END IF;
END
$$;

BEGIN;
SET LOCAL ROLE bullnym_app;
UPDATE bull_bitcoin_settlements settlement
   SET actual_received_sat = 10000,
       provider_payment_first_observed_at = quote.created_at,
       payer_instruction = NULL, instruction_kind = NULL,
       updated_at = clock_timestamp()
  FROM invoice_quote_versions quote
 WHERE settlement.id = '81000000-0000-4000-8000-000000000003'
   AND quote.id = settlement.invoice_quote_version_id;
COMMIT;

DO $$
DECLARE
    rejected_constraint TEXT;
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM bull_bitcoin_settlements settlement
          JOIN invoice_quote_versions quote
            ON quote.id = settlement.invoice_quote_version_id
         WHERE settlement.id = '81000000-0000-4000-8000-000000000003'
           AND settlement.provider_payment_first_observed_at = quote.created_at
           AND settlement.quote_payment_first_observed_at = quote.created_at
    ) THEN
        RAISE EXCEPTION 'migration 081 used delivery time instead of provider payment time';
    END IF;

    BEGIN
        UPDATE bull_bitcoin_settlements
           SET provider_payment_first_observed_at =
               provider_payment_first_observed_at + INTERVAL '1 second'
         WHERE id = '81000000-0000-4000-8000-000000000003';
        RAISE EXCEPTION 'migration 081 allowed provider payment-time mutation';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
        IF rejected_constraint <>
           'bull_bitcoin_settlements_provider_observation_immutable' THEN
            RAISE EXCEPTION 'provider timestamp mutation failed at wrong boundary: %',
                rejected_constraint;
        END IF;
    END;

    BEGIN
        UPDATE bull_bitcoin_settlements settlement
           SET actual_received_sat = 10000,
               provider_payment_first_observed_at = quote.created_at - INTERVAL '1 second',
               payer_instruction = NULL, instruction_kind = NULL,
               updated_at = clock_timestamp()
          FROM invoice_quote_versions quote
         WHERE settlement.id = '81000000-0000-4000-8000-000000000013'
           AND quote.id = settlement.invoice_quote_version_id;
        RAISE EXCEPTION 'migration 081 accepted provider time before payer instruction';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
        IF rejected_constraint <>
           'bull_bitcoin_settlements_provider_observation_time_chk' THEN
            RAISE EXCEPTION 'invalid provider timestamp failed at wrong boundary: %',
                rejected_constraint;
        END IF;
    END;
END
$$;

-- An older provider may omit the new field during a rolling deployment. If
-- the callback arrives after quote expiry, keep the money evidence but do not
-- invent a late-payment timestamp from delivery time.
ALTER TABLE invoice_quote_versions DISABLE TRIGGER
    invoice_quote_versions_reject_update;
UPDATE invoice_quote_versions
   SET rate_observed_at = clock_timestamp() - INTERVAL '602 seconds',
       rate_fetched_at = clock_timestamp() - INTERVAL '601 seconds',
       rate_fresh_until = clock_timestamp() - INTERVAL '1 second',
       created_at = clock_timestamp() - INTERVAL '601 seconds',
       expires_at = clock_timestamp() - INTERVAL '301 seconds'
 WHERE id = '81000000-0000-4000-8000-000000000012';
ALTER TABLE invoice_quote_versions ENABLE TRIGGER
    invoice_quote_versions_reject_update;

BEGIN;
SET LOCAL ROLE bullnym_app;
UPDATE bull_bitcoin_settlements
   SET actual_received_sat = 10000,
       payer_instruction = NULL, instruction_kind = NULL,
       updated_at = clock_timestamp()
 WHERE id = '81000000-0000-4000-8000-000000000013';
COMMIT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM bull_bitcoin_settlements
         WHERE id = '81000000-0000-4000-8000-000000000013'
           AND actual_received_sat = 10000
           AND provider_payment_first_observed_at IS NULL
           AND quote_payment_first_observed_at IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 081 invented payment time from delayed delivery';
    END IF;
END
$$;
