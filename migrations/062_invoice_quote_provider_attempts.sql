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
    );

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
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_attempt_insert() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION reject_invoice_quote_provider_attempt_mutation() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_offer_attempt_binding() FROM %I', runtime_role_name);
END
$$;

COMMIT;
