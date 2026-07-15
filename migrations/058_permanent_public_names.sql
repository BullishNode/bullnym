-- ============================================================================
-- 058: stopped-writer empty-state public-name preflight
-- ============================================================================
--
-- Production is reset before the permanent-name contract is installed. This
-- migration deliberately has no historical owner-selection or backfill path:
-- it proves the reset is empty under an exclusive writer lock, then 059 creates
-- the one current registry from scratch.

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
        RAISE EXCEPTION 'migration 058 requires a non-empty runtime_role psql variable'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 058 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 058 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 058 runtime role % can assume its schema owner %',
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
            'migration 058 requires the documented empty production reset: %',
            nonempty
            USING ERRCODE = '23514';
    END IF;

    IF to_regclass('public.public_names') IS NOT NULL
       OR to_regclass('public.public_name_migration_choices') IS NOT NULL
       OR to_regclass('public.public_name_migration_merchant_communications') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 058 found obsolete public-name migration state'
            USING ERRCODE = '23514';
    END IF;
END
$$;

COMMIT;
