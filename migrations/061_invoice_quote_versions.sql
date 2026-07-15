-- ============================================================================
-- 061: immutable, versioned fiat invoice quote/offer foundation
-- ============================================================================
--
-- This migration is intentionally a storage and attribution boundary only.
-- It does not refresh quotes from a GET, create provider obligations, or choose
-- how a payment first observed after quote expiry is credited in fiat.  New
-- quote creation is therefore limited to invoices with no payment evidence;
-- later runtime wiring must make the focused expired-quote valuation decision
-- before it can quote a partially paid fiat invoice.
--
-- Existing invoices, swaps, and payment events are left un-attributed.  Their
-- old instructions remain durable and observable, but migration 061 does not
-- invent rate/source/version facts that were never persisted.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE),
        ''
    );
    runtime_role_oid OID;
    runtime_role_is_superuser BOOLEAN;
    executor_role_oid OID;
BEGIN
    IF runtime_role_name IS NULL THEN
        RAISE EXCEPTION 'migration 061 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 061 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 061 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 061 runtime role % owns or can assume its schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE invoice_quote_versions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id            UUID NOT NULL,
    version_number        INTEGER NOT NULL DEFAULT 0,
    fiat_face_amount_minor INTEGER NOT NULL,
    fiat_currency         TEXT NOT NULL,
    rate_minor_per_btc    BIGINT NOT NULL,
    rate_source           TEXT NOT NULL,
    rate_observed_at      TIMESTAMPTZ NOT NULL,
    rate_fetched_at       TIMESTAMPTZ NOT NULL,
    rate_fresh_until      TIMESTAMPTZ NOT NULL,
    merchant_amount_sat   BIGINT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,

    CONSTRAINT invoice_quote_versions_id_non_nil_check CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT invoice_quote_versions_invoice_fkey FOREIGN KEY (invoice_id)
        REFERENCES invoices(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT invoice_quote_versions_number_check CHECK (version_number > 0),
    CONSTRAINT invoice_quote_versions_invoice_number_key UNIQUE (
        invoice_id,
        version_number
    ),
    CONSTRAINT invoice_quote_versions_id_invoice_key UNIQUE (id, invoice_id),
    CONSTRAINT invoice_quote_versions_fiat_face_check CHECK (
        fiat_face_amount_minor > 0
        AND fiat_currency ~ '^[A-Z]{3}$'
    ),
    CONSTRAINT invoice_quote_versions_rate_check CHECK (
        rate_minor_per_btc > 0
        AND rate_source = btrim(rate_source)
        AND rate_source ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$'
    ),
    CONSTRAINT invoice_quote_versions_rate_time_check CHECK (
        rate_observed_at < rate_fresh_until
        AND rate_fetched_at < rate_fresh_until
        AND rate_observed_at <= rate_fetched_at + INTERVAL '30 seconds'
        AND rate_observed_at <= created_at + INTERVAL '30 seconds'
        AND rate_fetched_at <= created_at + INTERVAL '30 seconds'
        AND rate_fresh_until > created_at
    ),
    CONSTRAINT invoice_quote_versions_amount_check CHECK (
        merchant_amount_sat > 0
    ),
    CONSTRAINT invoice_quote_versions_window_check CHECK (
        expires_at = created_at + INTERVAL '5 minutes'
    )
);

CREATE INDEX invoice_quote_versions_invoice_current_idx
    ON invoice_quote_versions (invoice_id, expires_at DESC, version_number DESC);

CREATE TABLE invoice_quote_offers (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id            UUID NOT NULL,
    quote_version_id      UUID NOT NULL,
    rail                  TEXT NOT NULL,
    offer_kind            TEXT NOT NULL,
    request_key           TEXT NOT NULL,
    provider              TEXT,
    provider_offer_id     TEXT,
    payer_amount_sat      BIGINT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,

    CONSTRAINT invoice_quote_offers_id_non_nil_check CHECK (
        id <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    CONSTRAINT invoice_quote_offers_quote_invoice_fkey FOREIGN KEY (
        quote_version_id,
        invoice_id
    ) REFERENCES invoice_quote_versions(id, invoice_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT invoice_quote_offers_id_quote_invoice_key UNIQUE (
        id,
        quote_version_id,
        invoice_id
    ),
    CONSTRAINT invoice_quote_offers_request_key_check CHECK (
        request_key ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT invoice_quote_offers_request_key UNIQUE (
        quote_version_id,
        rail,
        request_key
    ),
    CONSTRAINT invoice_quote_offers_rail_kind_check CHECK (
        (rail = 'liquid' AND offer_kind = 'direct')
        OR (rail = 'bitcoin' AND offer_kind IN ('direct', 'boltz_chain'))
        OR (rail = 'lightning' AND offer_kind = 'boltz_reverse')
    ),
    CONSTRAINT invoice_quote_offers_provider_shape_check CHECK (
        (
            offer_kind = 'direct'
            AND provider IS NULL
            AND provider_offer_id IS NULL
        ) OR (
            offer_kind IN ('boltz_reverse', 'boltz_chain')
            AND provider = 'boltz'
            AND provider_offer_id IS NOT NULL
            AND provider_offer_id = btrim(provider_offer_id)
            AND octet_length(provider_offer_id) BETWEEN 1 AND 255
        )
    ),
    CONSTRAINT invoice_quote_offers_amount_check CHECK (payer_amount_sat > 0),
    CONSTRAINT invoice_quote_offers_window_check CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX invoice_quote_offers_provider_identity_idx
    ON invoice_quote_offers (provider, provider_offer_id)
    WHERE provider_offer_id IS NOT NULL;

CREATE INDEX invoice_quote_offers_quote_rail_idx
    ON invoice_quote_offers (
        quote_version_id,
        rail,
        created_at DESC,
        id DESC
    );

CREATE FUNCTION enforce_invoice_quote_version_insert() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    write_now TIMESTAMPTZ := clock_timestamp();
    invoice_row RECORD;
    expected_merchant_amount BIGINT;
BEGIN
    -- Share the exact invoice presentation/offer boundary used by reducers
    -- and provider-offer creation.  Direct SQL callers cannot bypass the
    -- serialization contract enforced by the Rust API.
    PERFORM pg_advisory_xact_lock(
        hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
    );

    SELECT pricing_mode, fiat_amount_minor, fiat_currency, status,
           presentation_status, settlement_status, expires_at
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
    IF invoice_row.status IS DISTINCT FROM 'unpaid'
       OR invoice_row.presentation_status IS DISTINCT FROM 'unpaid'
       OR invoice_row.settlement_status IS DISTINCT FROM 'none'
       OR invoice_row.expires_at <= write_now THEN
        RAISE EXCEPTION 'invoice is not eligible for a new fiat quote version'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM invoice_payment_events
         WHERE invoice_id = NEW.invoice_id
    ) OR EXISTS (
        SELECT 1 FROM invoice_payment_observations
         WHERE invoice_id = NEW.invoice_id
    ) THEN
        RAISE EXCEPTION 'new fiat quote after payment evidence requires the unresolved valuation policy'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM invoice_quote_versions
         WHERE invoice_id = NEW.invoice_id
           AND expires_at > write_now
    ) THEN
        RAISE EXCEPTION 'an unexpired quote version already exists for this invoice'
            USING ERRCODE = '23505',
                  CONSTRAINT = 'invoice_quote_versions_one_current_at_insert';
    END IF;

    NEW.fiat_face_amount_minor := invoice_row.fiat_amount_minor;
    NEW.fiat_currency := invoice_row.fiat_currency;
    NEW.version_number := COALESCE((
        SELECT MAX(version_number)
          FROM invoice_quote_versions
         WHERE invoice_id = NEW.invoice_id
    ), 0) + 1;
    NEW.created_at := write_now;
    NEW.expires_at := write_now + INTERVAL '5 minutes';

    expected_merchant_amount := ceil(
        invoice_row.fiat_amount_minor::NUMERIC * 100000000::NUMERIC
        / NEW.rate_minor_per_btc::NUMERIC
    )::BIGINT;
    IF expected_merchant_amount <= 0
       OR NEW.merchant_amount_sat <> expected_merchant_amount THEN
        RAISE EXCEPTION 'merchant sat target does not match the fiat face/rate snapshot'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_versions_merchant_target_check';
    END IF;

    RETURN NEW;
END
$$;

CREATE FUNCTION reject_invoice_quote_version_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'invoice quote versions are immutable'
        USING ERRCODE = '55000';
END
$$;

CREATE FUNCTION enforce_invoice_quote_offer_insert() RETURNS trigger
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
     WHERE id = NEW.quote_version_id
       AND invoice_id = NEW.invoice_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invoice quote offer source version does not exist'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'invoice_quote_offers_quote_invoice_fkey';
    END IF;

    SELECT status, presentation_status, settlement_status, expires_at
      INTO invoice_row
      FROM invoices
     WHERE id = NEW.invoice_id
     FOR UPDATE;
    IF invoice_row.status IS DISTINCT FROM 'unpaid'
       OR invoice_row.presentation_status IS DISTINCT FROM 'unpaid'
       OR invoice_row.settlement_status IS DISTINCT FROM 'none'
       OR invoice_row.expires_at <= write_now
       OR quote_row.expires_at <= write_now THEN
        RAISE EXCEPTION 'invoice quote is not eligible for a new payer offer'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM invoice_payment_events
         WHERE invoice_id = NEW.invoice_id
    ) OR EXISTS (
        SELECT 1 FROM invoice_payment_observations
         WHERE invoice_id = NEW.invoice_id
    ) THEN
        RAISE EXCEPTION 'new payer offer after payment evidence requires the unresolved valuation policy'
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
    IF NEW.offer_kind IN ('boltz_reverse', 'boltz_chain')
       AND NEW.payer_amount_sat <= quote_row.merchant_amount_sat THEN
        RAISE EXCEPTION 'provider payer amount must gross up the merchant sat target'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_offers_provider_amount_check';
    END IF;

    RETURN NEW;
END
$$;

CREATE FUNCTION reject_invoice_quote_offer_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'invoice quote offers are immutable'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER invoice_quote_versions_enforce_insert
BEFORE INSERT ON invoice_quote_versions
FOR EACH ROW EXECUTE FUNCTION enforce_invoice_quote_version_insert();

CREATE TRIGGER invoice_quote_versions_reject_update
BEFORE UPDATE ON invoice_quote_versions
FOR EACH ROW EXECUTE FUNCTION reject_invoice_quote_version_mutation();

CREATE TRIGGER invoice_quote_versions_reject_delete
BEFORE DELETE ON invoice_quote_versions
FOR EACH ROW EXECUTE FUNCTION reject_invoice_quote_version_mutation();

CREATE TRIGGER invoice_quote_offers_enforce_insert
BEFORE INSERT ON invoice_quote_offers
FOR EACH ROW EXECUTE FUNCTION enforce_invoice_quote_offer_insert();

CREATE TRIGGER invoice_quote_offers_reject_update
BEFORE UPDATE ON invoice_quote_offers
FOR EACH ROW EXECUTE FUNCTION reject_invoice_quote_offer_mutation();

CREATE TRIGGER invoice_quote_offers_reject_delete
BEFORE DELETE ON invoice_quote_offers
FOR EACH ROW EXECUTE FUNCTION reject_invoice_quote_offer_mutation();

-- Nullable legacy-safe attribution.  New wired rows carry the complete quote
-- and offer pair; existing rows retain NULL rather than fabricated lineage.
ALTER TABLE swap_records
    ADD COLUMN invoice_quote_version_id UUID,
    ADD COLUMN invoice_quote_offer_id UUID,
    ADD CONSTRAINT swap_records_invoice_quote_shape_check CHECK (
        (
            invoice_quote_version_id IS NULL
            AND invoice_quote_offer_id IS NULL
        ) OR (
            invoice_quote_version_id IS NOT NULL
            AND invoice_quote_offer_id IS NOT NULL
            AND invoice_id IS NOT NULL
        )
    ),
    ADD CONSTRAINT swap_records_invoice_quote_offer_fkey FOREIGN KEY (
        invoice_quote_offer_id,
        invoice_quote_version_id,
        invoice_id
    ) REFERENCES invoice_quote_offers(id, quote_version_id, invoice_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT;

ALTER TABLE chain_swap_records
    ADD COLUMN invoice_quote_version_id UUID,
    ADD COLUMN invoice_quote_offer_id UUID,
    ADD CONSTRAINT chain_swap_records_invoice_quote_shape_check CHECK (
        num_nonnulls(invoice_quote_version_id, invoice_quote_offer_id) IN (0, 2)
    ),
    ADD CONSTRAINT chain_swap_records_invoice_quote_offer_fkey FOREIGN KEY (
        invoice_quote_offer_id,
        invoice_quote_version_id,
        invoice_id
    ) REFERENCES invoice_quote_offers(id, quote_version_id, invoice_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT;

ALTER TABLE invoice_payment_events
    ADD COLUMN invoice_quote_version_id UUID,
    ADD COLUMN invoice_quote_offer_id UUID,
    ADD COLUMN quote_first_observed_at TIMESTAMPTZ,
    ADD COLUMN fiat_credited_minor BIGINT,
    ADD COLUMN fiat_credit_policy TEXT,
    ADD COLUMN fiat_valued_at TIMESTAMPTZ,
    ADD CONSTRAINT invoice_payment_events_quote_attribution_shape_check CHECK (
        (
            invoice_quote_version_id IS NULL
            AND invoice_quote_offer_id IS NULL
            AND quote_first_observed_at IS NULL
            AND fiat_credited_minor IS NULL
            AND fiat_credit_policy IS NULL
            AND fiat_valued_at IS NULL
        ) OR (
            invoice_quote_version_id IS NOT NULL
            AND invoice_quote_offer_id IS NOT NULL
            AND quote_first_observed_at IS NOT NULL
            AND (
                (
                    fiat_credited_minor IS NULL
                    AND fiat_credit_policy IS NULL
                    AND fiat_valued_at IS NULL
                ) OR (
                    fiat_credited_minor IS NOT NULL
                    AND fiat_credited_minor >= 0
                    AND fiat_credit_policy IS NOT NULL
                    AND fiat_credit_policy ~ '^[a-z][a-z0-9_]{0,62}_v[1-9][0-9]*$'
                    AND fiat_valued_at IS NOT NULL
                )
            )
        )
    ),
    -- The product rule for a payment first observed after quote expiry is not
    -- selected yet. Preserve its attribution/timestamp, but make every fiat
    -- credit impossible until the focused decision migration replaces this
    -- fail-closed constraint.
    ADD CONSTRAINT invoice_payment_events_fiat_valuation_deferred_check CHECK (
        fiat_credited_minor IS NULL
        AND fiat_credit_policy IS NULL
        AND fiat_valued_at IS NULL
    ),
    ADD CONSTRAINT invoice_payment_events_quote_offer_fkey FOREIGN KEY (
        invoice_quote_offer_id,
        invoice_quote_version_id,
        invoice_id
    ) REFERENCES invoice_quote_offers(id, quote_version_id, invoice_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE INDEX invoice_payment_events_quote_version_idx
    ON invoice_payment_events (invoice_quote_version_id, accounting_sequence)
    WHERE invoice_quote_version_id IS NOT NULL;

CREATE FUNCTION guard_swap_quote_attribution() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(
        OLD.invoice_quote_version_id,
        OLD.invoice_quote_offer_id
    ) IS DISTINCT FROM ROW(
        NEW.invoice_quote_version_id,
        NEW.invoice_quote_offer_id
    ) THEN
        RAISE EXCEPTION 'swap quote attribution is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION guard_invoice_payment_quote_attribution() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    quote_created_at TIMESTAMPTZ;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.invoice_quote_version_id IS NOT NULL THEN
            SELECT created_at
              INTO quote_created_at
              FROM invoice_quote_versions
             WHERE id = NEW.invoice_quote_version_id
               AND invoice_id = NEW.invoice_id;
            IF NOT FOUND
               OR NEW.quote_first_observed_at < quote_created_at THEN
                RAISE EXCEPTION 'payment quote observation predates or mismatches its quote'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'invoice_payment_events_quote_observation_check';
            END IF;
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

    IF OLD.fiat_credit_policy IS NULL THEN
        IF num_nonnulls(
            NEW.fiat_credited_minor,
            NEW.fiat_credit_policy,
            NEW.fiat_valued_at
        ) NOT IN (0, 3) THEN
            RAISE EXCEPTION 'fiat valuation must be committed as one complete decision'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'invoice_payment_events_fiat_valuation_transition_check';
        END IF;
    ELSIF ROW(
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

CREATE TRIGGER swap_records_guard_quote_attribution
BEFORE UPDATE ON swap_records
FOR EACH ROW EXECUTE FUNCTION guard_swap_quote_attribution();

CREATE TRIGGER chain_swap_records_guard_quote_attribution
BEFORE UPDATE ON chain_swap_records
FOR EACH ROW EXECUTE FUNCTION guard_swap_quote_attribution();

CREATE TRIGGER invoice_payment_events_guard_quote_attribution
BEFORE INSERT OR UPDATE ON invoice_payment_events
FOR EACH ROW EXECUTE FUNCTION guard_invoice_payment_quote_attribution();

DO $$
DECLARE
    runtime_role_name TEXT := current_setting(
        'bullnym.migration_runtime_role'
    );
    runtime_role_oid OID;
    quote_owner_oid OID;
    function_name TEXT;
BEGIN
    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    SELECT relowner INTO STRICT quote_owner_oid
      FROM pg_class
     WHERE oid = 'invoice_quote_versions'::REGCLASS;
    IF quote_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, quote_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, quote_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 061 runtime role % owns or can assume the quote-ledger owner',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    REVOKE ALL ON TABLE invoice_quote_versions FROM PUBLIC;
    REVOKE ALL ON TABLE invoice_quote_offers FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON TABLE invoice_quote_versions FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'REVOKE ALL ON TABLE invoice_quote_offers FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT ON TABLE invoice_quote_versions TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (invoice_id, rate_minor_per_btc, rate_source, rate_observed_at, rate_fetched_at, rate_fresh_until, merchant_amount_sat) ON TABLE invoice_quote_versions TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT ON TABLE invoice_quote_offers TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (invoice_id, quote_version_id, rail, offer_kind, request_key, provider, provider_offer_id, payer_amount_sat, expires_at) ON TABLE invoice_quote_offers TO %I',
        runtime_role_name
    );

    FOREACH function_name IN ARRAY ARRAY[
        'enforce_invoice_quote_version_insert',
        'reject_invoice_quote_version_mutation',
        'enforce_invoice_quote_offer_insert',
        'reject_invoice_quote_offer_mutation',
        'guard_swap_quote_attribution',
        'guard_invoice_payment_quote_attribution'
    ] LOOP
        EXECUTE format(
            'REVOKE ALL ON FUNCTION %I() FROM PUBLIC',
            function_name
        );
        EXECUTE format(
            'REVOKE ALL ON FUNCTION %I() FROM %I',
            function_name,
            runtime_role_name
        );
    END LOOP;
END
$$;

COMMIT;
