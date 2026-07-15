-- ============================================================================
-- 059: current-only permanent public-name registry
-- ============================================================================
--
-- 058 proved the stopped production reset was empty. Recheck that fact under
-- the same exclusive locks, install the one current permanent-name model, and
-- remove pre-launch per-surface alias/mode storage. Nothing is inferred or
-- migrated from historical users, surfaces, invoices, or payout wallets.

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
        RAISE EXCEPTION 'migration 059 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 059 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 059 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 059 runtime role % can assume its schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;
END
$$;

LOCK TABLE users, donation_pages, invoices, swap_records,
    chain_swap_records, outpoint_addresses, swap_key_allocations,
    swap_key_legacy_high_water, recovery_address_commitments,
    rate_limit_events, nym_access_events, processed_webhook_events,
    watcher_lane_progress, fee_last_known_good_observations
    IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    nonempty JSONB;
BEGIN
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'users', NULLIF((SELECT COUNT(*) FROM users), 0),
        'donation_pages', NULLIF((SELECT COUNT(*) FROM donation_pages), 0),
        'invoices', NULLIF((SELECT COUNT(*) FROM invoices), 0),
        'swap_records', NULLIF((SELECT COUNT(*) FROM swap_records), 0),
        'chain_swap_records', NULLIF((SELECT COUNT(*) FROM chain_swap_records), 0),
        'outpoint_addresses', NULLIF((SELECT COUNT(*) FROM outpoint_addresses), 0),
        'swap_key_allocations', NULLIF((SELECT COUNT(*) FROM swap_key_allocations), 0),
        'swap_key_legacy_high_water', NULLIF((SELECT COUNT(*) FROM swap_key_legacy_high_water), 0),
        'recovery_address_commitments', NULLIF((SELECT COUNT(*) FROM recovery_address_commitments), 0),
        'rate_limit_events', NULLIF((SELECT COUNT(*) FROM rate_limit_events), 0),
        'nym_access_events', NULLIF((SELECT COUNT(*) FROM nym_access_events), 0),
        'processed_webhook_events', NULLIF((SELECT COUNT(*) FROM processed_webhook_events), 0),
        'watcher_lane_progress', NULLIF((SELECT COUNT(*) FROM watcher_lane_progress), 0),
        'fee_last_known_good_observations', NULLIF((SELECT COUNT(*) FROM fee_last_known_good_observations), 0)
    )) INTO nonempty;

    IF nonempty <> '{}'::JSONB THEN
        RAISE EXCEPTION
            'migration 059 requires the documented empty production reset: %',
            nonempty
            USING ERRCODE = '23514';
    END IF;

    IF to_regclass('public.public_names') IS NOT NULL
       OR to_regclass('public.public_name_migration_choices') IS NOT NULL
       OR to_regclass('public.public_name_migration_merchant_communications') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 059 found obsolete public-name migration state'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_attribute
         WHERE attrelid = 'public.donation_pages'::REGCLASS
           AND attname = 'alias'
           AND attnum > 0
           AND NOT attisdropped
    ) OR to_regclass('public.donation_pages_alias_uidx') IS NULL THEN
        RAISE EXCEPTION 'migration 059 expected the pre-cutover alias schema'
            USING ERRCODE = '23514';
    END IF;
END
$$;

ALTER TABLE donation_pages
    ALTER COLUMN ct_descriptor SET NOT NULL;
ALTER TABLE donation_pages
    DROP COLUMN IF EXISTS pos_mode;

CREATE TABLE public_names (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    owner_npub  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    claimed_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT public_names_kind_check
        CHECK (kind IN ('nym', 'alias')),
    CONSTRAINT public_names_claimed_at_check
        CHECK (claimed_at > '1970-01-01 00:00:00+00'::TIMESTAMPTZ),
    CONSTRAINT public_names_name_shape_check
        CHECK (name ~ '^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,30}[a-z0-9])$'),
    CONSTRAINT public_names_owner_shape_check
        CHECK (owner_npub ~ '^[0-9a-f]{64}$'),
    CONSTRAINT public_names_shared_namespace_key
        UNIQUE (name),
    CONSTRAINT public_names_owner_kind_lifetime_key
        UNIQUE (owner_npub, kind)
);

CREATE FUNCTION enforce_public_name_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('public-name-owner:' || NEW.owner_npub, 5801)
    );
    PERFORM pg_advisory_xact_lock(
        hashtextextended('public-name:' || NEW.name, 5801)
    );

    IF NEW.kind = 'alias' AND NOT EXISTS (
        SELECT 1
          FROM public_names
         WHERE owner_npub = NEW.owner_npub
           AND kind = 'nym'
    ) THEN
        RAISE EXCEPTION 'a permanent alias requires an owner-matched nym'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'public_names_alias_requires_nym';
    END IF;

    NEW.claimed_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE TRIGGER public_names_validate_insert
BEFORE INSERT ON public_names
FOR EACH ROW
EXECUTE FUNCTION enforce_public_name_insert();

CREATE FUNCTION reject_public_name_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'public-name ownership is immutable'
        USING ERRCODE = '23000',
              CONSTRAINT = CASE
                  WHEN TG_OP = 'DELETE'
                      THEN 'public_names_reject_delete'
                  ELSE 'public_names_reject_update'
              END;
END
$$;

CREATE TRIGGER public_names_reject_mutation
BEFORE UPDATE OR DELETE ON public_names
FOR EACH ROW
EXECUTE FUNCTION reject_public_name_mutation();

CREATE FUNCTION require_user_permanent_nym()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM public_names
         WHERE name = NEW.nym
           AND owner_npub = NEW.npub
           AND kind = 'nym'
    ) THEN
        RAISE EXCEPTION 'users row requires its owner-matched permanent nym'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'users_require_permanent_nym';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER users_require_permanent_nym
BEFORE INSERT OR UPDATE OF nym, npub ON users
FOR EACH ROW
EXECUTE FUNCTION require_user_permanent_nym();

DROP INDEX donation_pages_alias_uidx;
ALTER TABLE donation_pages DROP COLUMN alias;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE public_names FROM PUBLIC;
    EXECUTE format('REVOKE ALL ON TABLE public_names FROM %I', runtime_role_name);
    EXECUTE format('GRANT SELECT ON TABLE public_names TO %I', runtime_role_name);
    EXECUTE format(
        'GRANT INSERT (name, owner_npub, kind) ON TABLE public_names TO %I',
        runtime_role_name
    );

    REVOKE ALL ON FUNCTION enforce_public_name_insert() FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON FUNCTION enforce_public_name_insert() FROM %I',
        runtime_role_name
    );
    REVOKE ALL ON FUNCTION reject_public_name_mutation() FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON FUNCTION reject_public_name_mutation() FROM %I',
        runtime_role_name
    );
    REVOKE ALL ON FUNCTION require_user_permanent_nym() FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON FUNCTION require_user_permanent_nym() FROM %I',
        runtime_role_name
    );
END
$$;

COMMIT;
