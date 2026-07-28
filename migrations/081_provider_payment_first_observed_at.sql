-- ============================================================================
-- 081: authoritative provider payment time for fiat-only invoice accounting
-- ============================================================================
--
-- Provider status delivery can lag the chain observation that locked the
-- customer's pay-in. Preserve the chain authority's first-seen timestamp and
-- use it, rather than reconciliation time, to select the invoice-face rate.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE), ''
    );
    runtime_role_oid OID;
    table_owner_oid OID;
BEGIN
    SELECT oid INTO runtime_role_oid
      FROM pg_roles WHERE rolname = runtime_role_name;
    IF runtime_role_name IS NULL OR runtime_role_oid IS NULL THEN
        RAISE EXCEPTION 'migration 081 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 081 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;

    SELECT relowner INTO table_owner_oid
      FROM pg_class
     WHERE oid = to_regclass('public.bull_bitcoin_settlements');
    IF table_owner_oid IS NULL
       OR pg_get_userbyid(table_owner_oid) <> current_user THEN
        RAISE EXCEPTION 'migration 081 must run as the Bull Bitcoin settlement table owner'
            USING ERRCODE = '42501';
    END IF;
    IF runtime_role_oid = table_owner_oid
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 081 runtime role can assume the settlement table owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN provider_payment_first_observed_at TIMESTAMPTZ,
    ADD CONSTRAINT bull_bitcoin_settlements_provider_payment_time_chk CHECK (
        provider_payment_first_observed_at IS NULL
        OR actual_received_sat IS NOT NULL
    );

COMMENT ON COLUMN bull_bitcoin_settlements.provider_payment_first_observed_at IS
    'Immutable earliest pay-in time from the provider chain authority; never API delivery or reconciliation time.';

DROP TRIGGER bull_bitcoin_settlements_guard_fiat_only_quote
    ON bull_bitcoin_settlements;

CREATE OR REPLACE FUNCTION guard_fiat_only_quote_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    quote_row RECORD;
    invoice_pricing_mode TEXT;
    expected_request_key TEXT;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.invoice_quote_version_id IS DISTINCT FROM OLD.invoice_quote_version_id THEN
        RAISE EXCEPTION 'Bull Bitcoin invoice quote authority is immutable'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'bull_bitcoin_settlements_invoice_quote_immutable';
    END IF;

    IF TG_OP = 'INSERT'
       AND NEW.provider_payment_first_observed_at IS NOT NULL THEN
        RAISE EXCEPTION 'provider first-observation evidence requires the first-funds transition'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_provider_observation_immutable';
    ELSIF TG_OP = 'UPDATE'
       AND NEW.provider_payment_first_observed_at IS DISTINCT FROM
           OLD.provider_payment_first_observed_at
       AND NOT (
           OLD.provider_payment_first_observed_at IS NULL
           AND OLD.actual_received_sat IS NULL
           AND NEW.actual_received_sat IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'provider first-observation evidence is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_provider_observation_immutable';
    END IF;

    IF TG_OP = 'UPDATE'
       AND OLD.actual_received_sat IS NULL
       AND NEW.actual_received_sat IS NOT NULL
       AND NEW.provider_payment_first_observed_at IS NOT NULL
       AND (
           NEW.provider_payment_first_observed_at <=
               TIMESTAMPTZ '1970-01-01 00:00:00+00'
           OR NEW.provider_payment_first_observed_at >
               clock_timestamp() + INTERVAL '30 seconds'
       ) THEN
        RAISE EXCEPTION 'provider first-observation evidence is outside the admissible clock boundary'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_provider_observation_time_chk';
    END IF;

    IF NEW.invoice_id IS NOT NULL AND NEW.purpose = 'fiat_only' THEN
        PERFORM pg_advisory_xact_lock(
            hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
        );

        SELECT invoice.pricing_mode
          INTO invoice_pricing_mode
          FROM invoices invoice
         WHERE invoice.id = NEW.invoice_id;
        IF TG_OP = 'INSERT'
           AND invoice_pricing_mode = 'fiat_fixed'
           AND NEW.invoice_quote_version_id IS NULL THEN
            RAISE EXCEPTION 'fiat-fixed Bull Bitcoin settlement requires a payer quote'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_invoice_quote_authority';
        END IF;
    END IF;

    IF TG_OP = 'INSERT'
       AND NEW.invoice_id IS NOT NULL
       AND NEW.purpose = 'fiat_only'
       AND EXISTS (
           SELECT 1 FROM bull_bitcoin_settlements funded
            WHERE funded.invoice_id = NEW.invoice_id
              AND funded.purpose = 'fiat_only'
              AND funded.actual_received_sat IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'Bull Bitcoin payment evidence closes payer admission'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'bull_bitcoin_settlements_funded_admission_closed';
    END IF;

    IF NEW.invoice_quote_version_id IS NOT NULL THEN
        SELECT quote.id, quote.invoice_id, quote.quote_purpose,
               quote.merchant_amount_sat, quote.created_at, quote.expires_at,
               invoice.pricing_mode
          INTO quote_row
          FROM invoice_quote_versions quote
          JOIN invoices invoice ON invoice.id = quote.invoice_id
         WHERE quote.id = NEW.invoice_quote_version_id
           AND quote.invoice_id = NEW.invoice_id;
        IF NOT FOUND
           OR NEW.purpose <> 'fiat_only'
           OR quote_row.pricing_mode <> 'fiat_fixed'
           OR quote_row.quote_purpose <> 'payer_instruction'
           OR quote_row.merchant_amount_sat <> NEW.requested_bitcoin_sat THEN
            RAISE EXCEPTION 'fiat-only settlement does not match its payer quote'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_invoice_quote_authority';
        END IF;

        expected_request_key := encode(
            digest(
                convert_to('bullnym-invoice-quote-offer-v1', 'UTF8')
                || decode('00', 'hex')
                || decode(replace(quote_row.id::TEXT, '-', ''), 'hex')
                || decode('00', 'hex')
                || convert_to(NEW.payer_rail, 'UTF8')
                || decode('00', 'hex')
                || convert_to('bull_bitcoin_fiat_only', 'UTF8'),
                'sha256'
            ),
            'hex'
        );
        IF NEW.request_key IS DISTINCT FROM expected_request_key THEN
            RAISE EXCEPTION 'fiat-only settlement request key does not commit to its payer quote'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_invoice_quote_authority';
        END IF;
    END IF;

    IF TG_OP = 'INSERT'
       AND NEW.purpose = 'fiat_only'
       AND NEW.actual_received_sat IS NOT NULL THEN
        RAISE EXCEPTION 'funded Bull Bitcoin settlements must cross the observed transition'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_funded_insert_forbidden';
    ELSIF TG_OP = 'INSERT'
       AND NEW.quote_payment_first_observed_at IS NOT NULL THEN
        RAISE EXCEPTION 'Bull Bitcoin first-funds observation is database-owned'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_first_observation_immutable';
    ELSIF TG_OP = 'UPDATE'
       AND OLD.actual_received_sat IS NULL
       AND NEW.actual_received_sat IS NOT NULL
       AND NEW.purpose = 'fiat_only'
       AND NEW.invoice_quote_version_id IS NOT NULL THEN
        IF NEW.provider_payment_first_observed_at IS NOT NULL THEN
            IF NEW.provider_payment_first_observed_at < quote_row.created_at THEN
                RAISE EXCEPTION 'provider first-observation predates its payer instruction quote'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'bull_bitcoin_settlements_provider_observation_time_chk';
            END IF;
            NEW.quote_payment_first_observed_at :=
                NEW.provider_payment_first_observed_at;
        ELSIF clock_timestamp() >= quote_row.created_at
              AND clock_timestamp() < quote_row.expires_at THEN
            -- A payment first learned before quote expiry necessarily occurred
            -- during the live quote window even with an older provider that
            -- does not yet return the authoritative timestamp.
            NEW.quote_payment_first_observed_at := clock_timestamp();
        ELSE
            -- Delayed delivery without payment-time evidence must remain
            -- durably unvalued instead of being mislabeled as a late payment.
            NEW.quote_payment_first_observed_at := NULL;
        END IF;
    ELSIF TG_OP = 'UPDATE'
       AND NEW.quote_payment_first_observed_at IS DISTINCT FROM
           OLD.quote_payment_first_observed_at THEN
        RAISE EXCEPTION 'Bull Bitcoin first-funds observation is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_first_observation_immutable';
    END IF;

    IF NEW.actual_received_sat IS NOT NULL
       AND (NEW.payer_instruction IS NOT NULL OR NEW.instruction_kind IS NOT NULL) THEN
        RAISE EXCEPTION 'funded Bull Bitcoin settlement retained a payer instruction'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_funded_instruction_closed_chk';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER bull_bitcoin_settlements_guard_fiat_only_quote
    BEFORE INSERT OR UPDATE OF invoice_quote_version_id, invoice_id, purpose,
        requested_bitcoin_sat, actual_received_sat,
        provider_payment_first_observed_at,
        quote_payment_first_observed_at, request_key, payer_rail,
        payer_instruction, instruction_kind
    ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION guard_fiat_only_quote_authority();

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE), ''
    );
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON TABLE bull_bitcoin_settlements TO %I',
        runtime_role_name
    );
    IF NOT has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'SELECT')
       OR NOT has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'INSERT')
       OR NOT has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'UPDATE')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'DELETE')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'TRUNCATE')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'REFERENCES')
       OR has_table_privilege(runtime_role_name, 'bull_bitcoin_settlements', 'TRIGGER') THEN
        RAISE EXCEPTION 'migration 081 could not establish exact runtime settlement privileges'
            USING ERRCODE = '42501';
    END IF;
END
$$;

REVOKE ALL ON FUNCTION guard_fiat_only_quote_authority() FROM PUBLIC;

COMMIT;
