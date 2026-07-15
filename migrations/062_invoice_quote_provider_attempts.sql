-- Durable pre-network intent for quote-scoped provider mutations.
BEGIN;

SELECT set_config('bullnym.migration_runtime_role', :'runtime_role', TRUE);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(current_setting('bullnym.migration_runtime_role', TRUE), '');
    runtime_role_oid OID;
    runtime_role_is_superuser BOOLEAN;
    executor_role_oid OID;
BEGIN
    IF runtime_role_name IS NULL THEN
        RAISE EXCEPTION 'migration 062 requires a non-empty runtime_role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid, rolsuper INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 062 runtime role does not exist'
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 062 refuses a superuser runtime role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid INTO STRICT executor_role_oid FROM pg_roles WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 062 runtime role owns or can assume its schema owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

-- The invoice row owns exactly one denomination. Sat-fixed invoices retain
-- their immutable sat target. Fiat-fixed invoices retain only their immutable
-- face value; conversion authority belongs exclusively to versioned quotes.
-- This is deliberately strict and unvalidated legacy fiat rows are not
-- grandfathered or rewritten: deployment must reset/refuse an incompatible
-- database rather than fabricate monetary evidence.
ALTER TABLE invoices
    DROP CONSTRAINT invoices_amount_sat_check,
    ADD COLUMN checkout_surface_kind TEXT,
    ADD CONSTRAINT invoices_pricing_amount_authority_check CHECK (
        (
            pricing_mode = 'sat_fixed'
            AND fiat_amount_minor IS NULL
            AND fiat_currency IS NULL
            AND amount_sat > 0
            AND rate_minor_per_btc IS NULL
        )
        OR
        (
            pricing_mode = 'fiat_fixed'
            AND fiat_amount_minor IS NOT NULL
            AND fiat_currency IS NOT NULL
            AND amount_sat = 0
            AND rate_minor_per_btc IS NULL
        )
    ),
    ADD CONSTRAINT invoices_checkout_surface_kind_check CHECK (
        (origin = 'checkout' AND checkout_surface_kind IN ('payment_page', 'pos'))
        OR (origin = 'wallet' AND checkout_surface_kind IS NULL)
    );

-- Each version prices one immutable slice of the still-outstanding fiat face.
-- The original face remains separately snapshotted for audit and UI context.
-- This column is intentionally added without a default: a database containing
-- pre-cutover quote rows must be reset/refused rather than assigned invented
-- remaining-fiat evidence.
ALTER TABLE invoice_quote_versions
    ADD COLUMN fiat_target_amount_minor INTEGER NOT NULL,
    ADD CONSTRAINT invoice_quote_versions_fiat_target_check CHECK (
        fiat_target_amount_minor > 0
        AND fiat_target_amount_minor <= fiat_face_amount_minor
    );

-- Direct fiat instructions use a unique destination per quote. Reusing the
-- invoice settlement address would make an expired-A/active-B partial output
-- impossible to attribute to its own rate window. Provider offers keep these
-- fields NULL because their canonical swap rows own their destinations.
ALTER TABLE invoice_quote_offers
    ADD COLUMN direct_address TEXT,
    ADD COLUMN direct_liquid_blinding_key_hex TEXT,
    ADD COLUMN direct_address_index INTEGER,
    ADD CONSTRAINT invoice_quote_offers_direct_destination_shape_check CHECK (
        (
            offer_kind = 'direct'
            AND direct_address IS NOT NULL
            AND octet_length(direct_address) BETWEEN 8 AND 256
            AND direct_address = btrim(direct_address)
            AND direct_address_index IS NOT NULL
            AND direct_address_index >= 0
            AND (
                (
                    rail = 'liquid'
                    AND direct_liquid_blinding_key_hex ~ '^[0-9a-f]{64}$'
                )
                OR (
                    rail = 'bitcoin'
                    AND direct_liquid_blinding_key_hex IS NULL
                )
            )
        )
        OR
        (
            offer_kind IN ('boltz_reverse', 'boltz_chain')
            AND direct_address IS NULL
            AND direct_liquid_blinding_key_hex IS NULL
            AND direct_address_index IS NULL
        )
    );
CREATE UNIQUE INDEX invoice_quote_offers_direct_destination_key
    ON invoice_quote_offers (rail, direct_address)
    WHERE direct_address IS NOT NULL;

CREATE FUNCTION invoice_quote_credit_for_sats(
    fiat_target_minor INTEGER,
    merchant_target_sat BIGINT,
    rate_minor_per_btc BIGINT,
    eligible_sat BIGINT
) RETURNS BIGINT
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN eligible_sat <= 0 THEN 0
        WHEN eligible_sat >= merchant_target_sat THEN fiat_target_minor::BIGINT
        ELSE LEAST(
            fiat_target_minor::BIGINT,
            floor(
                eligible_sat::NUMERIC * rate_minor_per_btc::NUMERIC
                / 100000000::NUMERIC
            )::BIGINT
        )
    END
$$;

-- A committed event valuation is immutable audit evidence. Reorgs,
-- deactivation, reactivation, and Boltz supersession instead alter this
-- explicit active projection. `accounting_adjustment_minor` makes any
-- cumulative-rounding/supersession adjustment observable rather than silently
-- rewriting an event's committed credit.
CREATE VIEW invoice_quote_active_fiat_projection
WITH (security_invoker = TRUE)
AS
SELECT
    q.id AS quote_version_id,
    q.invoice_id,
    q.fiat_target_amount_minor,
    q.merchant_amount_sat,
    COALESCE(SUM(e.amount_sat) FILTER (
        WHERE e.accounting_state = 'active'
          AND e.fiat_credited_minor IS NOT NULL
          AND e.quote_first_observed_at < q.expires_at
    ), 0)::BIGINT AS active_eligible_sat,
    invoice_quote_credit_for_sats(
        q.fiat_target_amount_minor,
        q.merchant_amount_sat,
        q.rate_minor_per_btc,
        COALESCE(SUM(e.amount_sat) FILTER (
            WHERE e.accounting_state = 'active'
              AND e.fiat_credited_minor IS NOT NULL
              AND e.quote_first_observed_at < q.expires_at
        ), 0)::BIGINT
    ) AS active_fiat_credited_minor,
    COALESCE(SUM(e.fiat_credited_minor) FILTER (
        WHERE e.accounting_state = 'active'
          AND e.fiat_credited_minor IS NOT NULL
          AND e.quote_first_observed_at < q.expires_at
    ), 0)::BIGINT AS committed_active_event_credit_minor,
    invoice_quote_credit_for_sats(
        q.fiat_target_amount_minor,
        q.merchant_amount_sat,
        q.rate_minor_per_btc,
        COALESCE(SUM(e.amount_sat) FILTER (
            WHERE e.accounting_state = 'active'
              AND e.fiat_credited_minor IS NOT NULL
              AND e.quote_first_observed_at < q.expires_at
        ), 0)::BIGINT
    ) - COALESCE(SUM(e.fiat_credited_minor) FILTER (
        WHERE e.accounting_state = 'active'
          AND e.fiat_credited_minor IS NOT NULL
          AND e.quote_first_observed_at < q.expires_at
    ), 0)::BIGINT AS accounting_adjustment_minor
FROM invoice_quote_versions q
LEFT JOIN invoice_payment_events e
  ON e.invoice_quote_version_id = q.id
 AND e.invoice_id = q.invoice_id
GROUP BY q.id;

-- Quote creation derives the remaining fiat target under the shared invoice
-- lock. It permits a new version after on-time valued partial evidence, but
-- fails closed if any prior event lacks attribution or a committed valuation
-- (the deliberately unresolved late-first-observed policy).
CREATE OR REPLACE FUNCTION enforce_invoice_quote_version_insert() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    write_now TIMESTAMPTZ := clock_timestamp();
    invoice_row RECORD;
    active_fiat_credit BIGINT;
    remaining_fiat BIGINT;
    expected_merchant_amount BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
    );

    SELECT pricing_mode, fiat_amount_minor, fiat_currency, status,
           presentation_status, expires_at
      INTO invoice_row
      FROM invoices
     WHERE id = NEW.invoice_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invoice quote source invoice does not exist'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'invoice_quote_versions_invoice_fkey';
    END IF;
    IF invoice_row.pricing_mode IS DISTINCT FROM 'fiat_fixed'
       OR invoice_row.fiat_amount_minor IS NULL
       OR invoice_row.fiat_currency IS NULL THEN
        RAISE EXCEPTION 'invoice quote versions require a fiat-fixed invoice'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_versions_fiat_source_check';
    END IF;
    IF invoice_row.status NOT IN ('unpaid', 'partially_paid', 'in_progress')
       OR invoice_row.presentation_status NOT IN ('unpaid', 'partial')
       OR invoice_row.expires_at <= write_now THEN
        RAISE EXCEPTION 'invoice is not eligible for a new fiat quote version'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM invoice_payment_events e
         WHERE e.invoice_id = NEW.invoice_id
           AND (
               e.invoice_quote_version_id IS NULL
               OR e.invoice_quote_offer_id IS NULL
               OR e.quote_first_observed_at IS NULL
               OR e.fiat_credited_minor IS NULL
               OR e.fiat_credit_policy IS NULL
               OR e.fiat_valued_at IS NULL
           )
    ) THEN
        RAISE EXCEPTION 'invoice has payment evidence awaiting fiat valuation policy'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM invoice_quote_versions q
         WHERE q.invoice_id = NEW.invoice_id
           AND q.expires_at > write_now
    ) THEN
        RAISE EXCEPTION 'an unexpired quote version already exists for this invoice'
            USING ERRCODE = '23505',
                  CONSTRAINT = 'invoice_quote_versions_one_current_at_insert';
    END IF;

    SELECT COALESCE(SUM(p.active_fiat_credited_minor), 0)::BIGINT
      INTO active_fiat_credit
      FROM invoice_quote_active_fiat_projection p
     WHERE p.invoice_id = NEW.invoice_id;
    remaining_fiat := invoice_row.fiat_amount_minor::BIGINT - active_fiat_credit;
    IF remaining_fiat <= 0 OR remaining_fiat > invoice_row.fiat_amount_minor THEN
        RAISE EXCEPTION 'invoice has no valid remaining fiat target'
            USING ERRCODE = '55000';
    END IF;

    NEW.fiat_face_amount_minor := invoice_row.fiat_amount_minor;
    NEW.fiat_target_amount_minor := remaining_fiat::INTEGER;
    NEW.fiat_currency := invoice_row.fiat_currency;
    NEW.version_number := COALESCE((
        SELECT MAX(version_number)
          FROM invoice_quote_versions
         WHERE invoice_id = NEW.invoice_id
    ), 0) + 1;
    NEW.created_at := write_now;
    NEW.expires_at := write_now + INTERVAL '5 minutes';

    expected_merchant_amount := floor(
        remaining_fiat::NUMERIC * 100000000::NUMERIC
        / NEW.rate_minor_per_btc::NUMERIC
    )::BIGINT;
    IF expected_merchant_amount <= 0
       OR NEW.merchant_amount_sat <> expected_merchant_amount THEN
        RAISE EXCEPTION 'merchant sat target does not match the remaining fiat/rate snapshot'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_versions_merchant_target_check';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION enforce_invoice_quote_offer_insert() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    write_now TIMESTAMPTZ := clock_timestamp();
    quote_row RECORD;
    invoice_row RECORD;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
    );
    SELECT merchant_amount_sat, expires_at
      INTO quote_row
      FROM invoice_quote_versions
     WHERE id = NEW.quote_version_id AND invoice_id = NEW.invoice_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invoice quote offer source version does not exist'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'invoice_quote_offers_quote_invoice_fkey';
    END IF;
    SELECT status, presentation_status, expires_at
      INTO invoice_row
      FROM invoices
     WHERE id = NEW.invoice_id
     FOR UPDATE;
    IF invoice_row.status NOT IN ('unpaid', 'partially_paid', 'in_progress')
       OR invoice_row.presentation_status NOT IN ('unpaid', 'partial')
       OR invoice_row.expires_at <= write_now
       OR quote_row.expires_at <= write_now THEN
        RAISE EXCEPTION 'invoice quote is not eligible for a new payer offer'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM invoice_payment_events e
         WHERE e.invoice_id = NEW.invoice_id
           AND (
               e.fiat_credited_minor IS NULL
               OR e.invoice_quote_version_id = NEW.quote_version_id
           )
    ) THEN
        RAISE EXCEPTION 'payer offer cannot be created after unresolved or same-quote payment evidence'
            USING ERRCODE = '55000';
    END IF;
    NEW.created_at := write_now;
    IF NEW.expires_at > quote_row.expires_at THEN
        RAISE EXCEPTION 'payer offer cannot outlive its quote version'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_offers_quote_window_check';
    END IF;
    IF NEW.offer_kind = 'direct'
       AND NEW.payer_amount_sat <> quote_row.merchant_amount_sat THEN
        RAISE EXCEPTION 'direct payer amount must equal the merchant sat target'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_offers_direct_amount_check';
    END IF;
    IF NEW.offer_kind = 'direct'
       AND EXISTS (
           SELECT 1 FROM invoice_payment_addresses a
            WHERE a.rail = NEW.rail AND a.address = NEW.direct_address
       ) THEN
        RAISE EXCEPTION 'direct quote destination is already bound to an invoice address'
            USING ERRCODE = '23505',
                  CONSTRAINT = 'invoice_quote_offers_direct_destination_key';
    END IF;
    IF NEW.offer_kind IN ('boltz_reverse', 'boltz_chain')
       AND NEW.payer_amount_sat <= quote_row.merchant_amount_sat THEN
        RAISE EXCEPTION 'provider payer amount must gross up the merchant sat target'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_offers_provider_amount_check';
    END IF;
    RETURN NEW;
END
$$;

-- Persist the first authoritative funding observation on the provider
-- obligation itself. Later accounting must use this durable boundary, never
-- the time a webhook/repair handler happens to insert its payment event.
ALTER TABLE swap_records
    ADD COLUMN quote_payment_first_observed_at TIMESTAMPTZ;
ALTER TABLE chain_swap_records
    ADD COLUMN quote_payment_first_observed_at TIMESTAMPTZ;

CREATE FUNCTION stamp_quote_payment_first_observed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    qualifying BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'swap_records' THEN
        qualifying := NEW.status IN (
            'lockup_mempool', 'lockup_confirmed', 'claiming', 'claimed',
            'claim_failed', 'claim_stuck', 'lockup_refunded'
        );
    ELSE
        qualifying := NEW.status IN (
            'user_lock_mempool', 'user_lock_confirmed',
            'server_lock_mempool', 'server_lock_confirmed',
            'claiming', 'claimed', 'claim_failed', 'claim_stuck',
            'refund_due', 'refunding', 'refunded'
        );
    END IF;
    IF TG_OP = 'UPDATE'
       AND OLD.quote_payment_first_observed_at IS NOT NULL
       AND NEW.quote_payment_first_observed_at IS DISTINCT FROM
           OLD.quote_payment_first_observed_at THEN
        RAISE EXCEPTION 'provider payment first-observed time is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.invoice_quote_version_id IS NOT NULL
       AND NEW.quote_payment_first_observed_at IS NULL
       AND qualifying THEN
        NEW.quote_payment_first_observed_at := clock_timestamp();
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER swap_records_stamp_quote_payment_first_observed
BEFORE INSERT OR UPDATE OF status, quote_payment_first_observed_at
ON swap_records FOR EACH ROW
EXECUTE FUNCTION stamp_quote_payment_first_observed();
CREATE TRIGGER chain_swap_records_stamp_quote_payment_first_observed
BEFORE INSERT OR UPDATE OF status, quote_payment_first_observed_at
ON chain_swap_records FOR EACH ROW
EXECUTE FUNCTION stamp_quote_payment_first_observed();

ALTER TABLE invoice_payment_events
    DROP CONSTRAINT invoice_payment_events_fiat_valuation_deferred_check,
    ADD CONSTRAINT invoice_payment_events_fiat_valuation_policy_check CHECK (
        fiat_credit_policy IS NULL
        OR fiat_credit_policy = 'quote_cumulative_saturation_v1'
    );

CREATE OR REPLACE FUNCTION guard_invoice_payment_quote_attribution() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    quote_row RECORD;
    prior_eligible_sat BIGINT;
    prior_credit BIGINT;
    next_credit BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.invoice_quote_version_id IS NULL THEN
            IF num_nonnulls(
                NEW.invoice_quote_offer_id,
                NEW.quote_first_observed_at,
                NEW.fiat_credited_minor,
                NEW.fiat_credit_policy,
                NEW.fiat_valued_at
            ) <> 0 THEN
                RAISE EXCEPTION 'unattributed payment cannot carry fiat valuation'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END IF;
        PERFORM pg_advisory_xact_lock(
            hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
        );
        SELECT created_at, expires_at, fiat_target_amount_minor,
               merchant_amount_sat, rate_minor_per_btc
          INTO quote_row
          FROM invoice_quote_versions
         WHERE id = NEW.invoice_quote_version_id
           AND invoice_id = NEW.invoice_id;
        IF NOT FOUND
           OR NEW.quote_first_observed_at < quote_row.created_at
           OR NEW.quote_first_observed_at > clock_timestamp() + INTERVAL '30 seconds' THEN
            RAISE EXCEPTION 'payment quote observation predates, postdates, or mismatches its quote'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'invoice_payment_events_quote_observation_check';
        END IF;
        NEW.fiat_credited_minor := NULL;
        NEW.fiat_credit_policy := NULL;
        NEW.fiat_valued_at := NULL;
        IF NEW.quote_first_observed_at < quote_row.expires_at THEN
            SELECT COALESCE(SUM(e.amount_sat), 0)::BIGINT
              INTO prior_eligible_sat
              FROM invoice_payment_events e
             WHERE e.invoice_quote_version_id = NEW.invoice_quote_version_id
               AND e.invoice_id = NEW.invoice_id
               AND e.quote_first_observed_at < quote_row.expires_at
               AND e.accounting_sequence < NEW.accounting_sequence;
            prior_credit := invoice_quote_credit_for_sats(
                quote_row.fiat_target_amount_minor,
                quote_row.merchant_amount_sat,
                quote_row.rate_minor_per_btc,
                prior_eligible_sat
            );
            next_credit := invoice_quote_credit_for_sats(
                quote_row.fiat_target_amount_minor,
                quote_row.merchant_amount_sat,
                quote_row.rate_minor_per_btc,
                prior_eligible_sat + NEW.amount_sat
            );
            NEW.fiat_credited_minor := next_credit - prior_credit;
            NEW.fiat_credit_policy := 'quote_cumulative_saturation_v1';
            NEW.fiat_valued_at := clock_timestamp();
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(
        OLD.invoice_quote_version_id,
        OLD.invoice_quote_offer_id,
        OLD.quote_first_observed_at
    ) IS DISTINCT FROM ROW(
        NEW.invoice_quote_version_id,
        NEW.invoice_quote_offer_id,
        NEW.quote_first_observed_at
    ) THEN
        RAISE EXCEPTION 'payment quote/offer attribution is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF ROW(
        OLD.fiat_credited_minor,
        OLD.fiat_credit_policy,
        OLD.fiat_valued_at
    ) IS DISTINCT FROM ROW(
        NEW.fiat_credited_minor,
        NEW.fiat_credit_policy,
        NEW.fiat_valued_at
    ) THEN
        RAISE EXCEPTION 'committed fiat valuation is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE invoice_quote_provider_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL,
    quote_version_id UUID NOT NULL,
    rail TEXT NOT NULL,
    request_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    operation TEXT NOT NULL,
    merchant_amount_sat BIGINT NOT NULL,
    claim_key_allocation_id UUID NOT NULL REFERENCES swap_key_allocations(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    refund_key_allocation_id UUID REFERENCES swap_key_allocations(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT invoice_quote_provider_attempts_quote_invoice_fkey FOREIGN KEY
        (quote_version_id, invoice_id) REFERENCES invoice_quote_versions(id, invoice_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT invoice_quote_provider_attempts_request_key_check CHECK
        (request_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT invoice_quote_provider_attempts_identity_key UNIQUE
        (quote_version_id, rail, request_key),
    CONSTRAINT invoice_quote_provider_attempts_offer_binding_key UNIQUE
        (id, quote_version_id, invoice_id, rail, request_key),
    CONSTRAINT invoice_quote_provider_attempts_claim_key UNIQUE
        (claim_key_allocation_id),
    CONSTRAINT invoice_quote_provider_attempts_refund_key UNIQUE
        (refund_key_allocation_id),
    CONSTRAINT invoice_quote_provider_attempts_shape_check CHECK (
        provider = 'boltz' AND merchant_amount_sat > 0 AND (
            (rail = 'lightning' AND operation = 'fixed_checkout_reverse'
             AND refund_key_allocation_id IS NULL)
            OR
            (rail = 'bitcoin' AND operation = 'chain_create'
             AND refund_key_allocation_id IS NOT NULL)
        )
    )
);

ALTER TABLE invoice_quote_offers
    ADD COLUMN provider_attempt_id UUID,
    ADD CONSTRAINT invoice_quote_offers_provider_attempt_shape_check CHECK (
        (offer_kind = 'direct' AND provider_attempt_id IS NULL)
        OR
        (offer_kind IN ('boltz_reverse', 'boltz_chain') AND provider_attempt_id IS NOT NULL)
    ),
    ADD CONSTRAINT invoice_quote_offers_provider_attempt_fkey FOREIGN KEY (
        provider_attempt_id, quote_version_id, invoice_id, rail, request_key
    ) REFERENCES invoice_quote_provider_attempts (
        id, quote_version_id, invoice_id, rail, request_key
    ) ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE FUNCTION enforce_invoice_quote_offer_attempt_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.offer_kind = 'direct' AND NEW.provider_attempt_id IS NOT NULL THEN
        RAISE EXCEPTION 'direct quote offer cannot reference a provider attempt'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.offer_kind IN ('boltz_reverse', 'boltz_chain')
       AND NEW.provider_attempt_id IS NULL THEN
        RAISE EXCEPTION 'provider quote offer requires its durable pre-network attempt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoice_quote_offers_enforce_attempt_binding
BEFORE INSERT ON invoice_quote_offers FOR EACH ROW
EXECUTE FUNCTION enforce_invoice_quote_offer_attempt_binding();

CREATE FUNCTION enforce_invoice_quote_provider_attempt_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    quote_amount BIGINT;
    claim_purpose TEXT;
    refund_purpose TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('invoice-lightning:' || NEW.invoice_id::TEXT));
    SELECT merchant_amount_sat INTO quote_amount
      FROM invoice_quote_versions
     WHERE id = NEW.quote_version_id AND invoice_id = NEW.invoice_id
     FOR SHARE;
    IF NOT FOUND OR quote_amount <> NEW.merchant_amount_sat THEN
        RAISE EXCEPTION 'provider attempt does not match its quote'
            USING ERRCODE = '23514';
    END IF;
    SELECT purpose INTO claim_purpose FROM swap_key_allocations
     WHERE id = NEW.claim_key_allocation_id;
    IF NEW.rail = 'lightning' AND claim_purpose IS DISTINCT FROM 'reverse_claim' THEN
        RAISE EXCEPTION 'reverse attempt has invalid claim allocation'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.rail = 'bitcoin' THEN
        SELECT purpose INTO refund_purpose FROM swap_key_allocations
         WHERE id = NEW.refund_key_allocation_id;
        IF claim_purpose IS DISTINCT FROM 'chain_claim'
           OR refund_purpose IS DISTINCT FROM 'chain_refund' THEN
            RAISE EXCEPTION 'chain attempt has invalid key allocations'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_invoice_quote_provider_attempt_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'invoice quote provider attempts are immutable'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER invoice_quote_provider_attempts_enforce_insert
BEFORE INSERT ON invoice_quote_provider_attempts FOR EACH ROW
EXECUTE FUNCTION enforce_invoice_quote_provider_attempt_insert();
CREATE TRIGGER invoice_quote_provider_attempts_reject_update
BEFORE UPDATE ON invoice_quote_provider_attempts FOR EACH ROW
EXECUTE FUNCTION reject_invoice_quote_provider_attempt_mutation();
CREATE TRIGGER invoice_quote_provider_attempts_reject_delete
BEFORE DELETE ON invoice_quote_provider_attempts FOR EACH ROW
EXECUTE FUNCTION reject_invoice_quote_provider_attempt_mutation();

DO $$
DECLARE runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE invoice_quote_active_fiat_projection FROM PUBLIC;
    EXECUTE format(
        'GRANT SELECT ON TABLE invoice_quote_active_fiat_projection TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (checkout_surface_kind) ON TABLE invoices TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (fiat_target_amount_minor) ON TABLE invoice_quote_versions TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (direct_address, direct_liquid_blinding_key_hex, direct_address_index) ON TABLE invoice_quote_offers TO %I',
        runtime_role_name
    );
    REVOKE ALL ON TABLE invoice_quote_provider_attempts FROM PUBLIC;
    EXECUTE format('REVOKE ALL ON TABLE invoice_quote_provider_attempts FROM %I', runtime_role_name);
    EXECUTE format('GRANT SELECT ON TABLE invoice_quote_provider_attempts TO %I', runtime_role_name);
    EXECUTE format(
        'GRANT INSERT (invoice_id, quote_version_id, rail, request_key, provider, operation, merchant_amount_sat, claim_key_allocation_id, refund_key_allocation_id) ON TABLE invoice_quote_provider_attempts TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (provider_attempt_id) ON TABLE invoice_quote_offers TO %I',
        runtime_role_name
    );
    REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_attempt_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION reject_invoice_quote_provider_attempt_mutation() FROM PUBLIC;
    REVOKE ALL ON FUNCTION enforce_invoice_quote_offer_attempt_binding() FROM PUBLIC;
    REVOKE ALL ON FUNCTION invoice_quote_credit_for_sats(INTEGER, BIGINT, BIGINT, BIGINT) FROM PUBLIC;
    REVOKE ALL ON FUNCTION stamp_quote_payment_first_observed() FROM PUBLIC;
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION invoice_quote_credit_for_sats(INTEGER, BIGINT, BIGINT, BIGINT) TO %I',
        runtime_role_name
    );
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_attempt_insert() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION reject_invoice_quote_provider_attempt_mutation() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_offer_attempt_binding() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION stamp_quote_payment_first_observed() FROM %I', runtime_role_name);
END
$$;

COMMIT;
