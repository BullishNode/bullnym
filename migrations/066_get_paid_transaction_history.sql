-- ==========================================================================
-- 066: durable Get Paid transaction-history evidence
-- ==========================================================================
--
-- Lightning Address swaps predate invoice payment events. Preserve the first
-- authoritative lockup observation so authenticated history can order those
-- payments without using mutable status-update or comment timestamps.

BEGIN;

SELECT set_config('bullnym.migration_runtime_role', :'runtime_role', TRUE);

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
        RAISE EXCEPTION 'migration 066 requires a non-empty runtime_role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 066 runtime role does not exist'
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 066 refuses a superuser runtime role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid INTO STRICT executor_role_oid FROM pg_roles WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 066 runtime role owns or can assume its schema owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE swap_records
    ADD COLUMN payment_first_observed_at TIMESTAMPTZ;

-- Existing rows cannot recover their historical first-observation instant.
-- Prefer the quote observation where one exists, then the closest durable
-- lifecycle timestamp. The value becomes immutable after this cutover.
UPDATE swap_records
   SET payment_first_observed_at = COALESCE(
       quote_payment_first_observed_at,
       updated_at,
       created_at
   )
 WHERE status IN (
       'lockup_mempool', 'lockup_confirmed', 'claiming', 'claimed',
       'claim_failed', 'claim_stuck', 'lockup_refunded'
   );

CREATE FUNCTION stamp_payment_first_observed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    qualifying BOOLEAN := NEW.status IN (
        'lockup_mempool', 'lockup_confirmed', 'claiming', 'claimed',
        'claim_failed', 'claim_stuck', 'lockup_refunded'
    );
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.payment_first_observed_at IS NOT NULL
       AND NEW.payment_first_observed_at IS DISTINCT FROM
           OLD.payment_first_observed_at THEN
        RAISE EXCEPTION 'payment first-observed time is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF qualifying AND NEW.payment_first_observed_at IS NULL THEN
        NEW.payment_first_observed_at := COALESCE(
            NEW.quote_payment_first_observed_at,
            pg_catalog.clock_timestamp()
        );
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION stamp_payment_first_observed() FROM PUBLIC;

CREATE TRIGGER swap_records_stamp_payment_first_observed
BEFORE INSERT OR UPDATE OF status, payment_first_observed_at
ON swap_records FOR EACH ROW
EXECUTE FUNCTION stamp_payment_first_observed();

CREATE INDEX swap_records_get_paid_history_idx
    ON swap_records(nym, payment_first_observed_at DESC, id DESC)
    WHERE invoice_id IS NULL AND payment_first_observed_at IS NOT NULL;

CREATE INDEX invoices_get_paid_history_owner_idx
    ON invoices(npub_owner, id);

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    EXECUTE format(
        'GRANT SELECT (payment_first_observed_at) ON TABLE swap_records TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
