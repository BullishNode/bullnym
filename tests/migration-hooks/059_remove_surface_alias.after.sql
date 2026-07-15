-- Lock the current-only schema, constraints, trigger behavior, and empty-state
-- cutover. There is no historical selection/backfill representation.
DO $$
DECLARE
    actual_columns TEXT[];
    mutation_error TEXT;
    claimed_timestamp TIMESTAMPTZ;
BEGIN
    SELECT array_agg(
               format('%s:%s:%s', column_name, data_type, is_nullable)
               ORDER BY ordinal_position
           )
      INTO actual_columns
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'public_names';
    IF actual_columns IS DISTINCT FROM ARRAY[
        'id:uuid:NO',
        'name:text:NO',
        'owner_npub:text:NO',
        'kind:text:NO',
        'claimed_at:timestamp with time zone:NO'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 059 column contract changed: %', actual_columns;
    END IF;

    IF EXISTS (SELECT 1 FROM users)
       OR EXISTS (SELECT 1 FROM donation_pages)
       OR EXISTS (SELECT 1 FROM invoices)
       OR to_regclass('public.public_name_migration_choices') IS NOT NULL
       OR to_regclass('public.public_name_migration_merchant_communications') IS NOT NULL
       OR EXISTS (
           SELECT 1
             FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'donation_pages'
              AND column_name IN ('alias', 'pos_mode')
       )
       OR to_regclass('public.donation_pages_alias_uidx') IS NOT NULL
       OR NOT EXISTS (
           SELECT 1
             FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'donation_pages'
              AND column_name = 'ct_descriptor'
              AND is_nullable = 'NO'
       ) THEN
        RAISE EXCEPTION 'migration 059 retained obsolete or nullable surface state';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.public_names'::REGCLASS
           AND conname = 'public_names_shared_namespace_key'
           AND contype = 'u'
           AND convalidated
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.public_names'::REGCLASS
           AND conname = 'public_names_owner_kind_lifetime_key'
           AND contype = 'u'
           AND convalidated
    ) THEN
        RAISE EXCEPTION 'migration 059 permanent-name uniqueness changed';
    END IF;

    INSERT INTO public_names (name, owner_npub, kind, claimed_at)
    VALUES (
        'current-owner', repeat('a', 64), 'nym',
        '2000-01-01 00:00:00+00'::TIMESTAMPTZ
    )
    RETURNING claimed_at INTO claimed_timestamp;
    IF claimed_timestamp = '2000-01-01 00:00:00+00'::TIMESTAMPTZ
       OR claimed_timestamp < statement_timestamp() - INTERVAL '1 minute'
       OR claimed_timestamp > statement_timestamp() + INTERVAL '1 minute' THEN
        RAISE EXCEPTION 'migration 059 did not own the claim timestamp';
    END IF;
    INSERT INTO public_names (name, owner_npub, kind)
    VALUES ('current-shop', repeat('a', 64), 'alias');

    BEGIN
        INSERT INTO public_names (name, owner_npub, kind)
        VALUES ('second-nym', repeat('a', 64), 'nym');
        RAISE EXCEPTION 'migration 059 allowed a second owner nym';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS mutation_error = CONSTRAINT_NAME;
        IF mutation_error <> 'public_names_owner_kind_lifetime_key' THEN
            RAISE;
        END IF;
    END;

    BEGIN
        INSERT INTO public_names (name, owner_npub, kind)
        VALUES ('current-shop', repeat('b', 64), 'nym');
        RAISE EXCEPTION 'migration 059 allowed a shared-namespace collision';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS mutation_error = CONSTRAINT_NAME;
        IF mutation_error <> 'public_names_shared_namespace_key' THEN
            RAISE;
        END IF;
    END;

    BEGIN
        INSERT INTO public_names (name, owner_npub, kind)
        VALUES ('orphan-shop', repeat('c', 64), 'alias');
        RAISE EXCEPTION 'migration 059 allowed an alias without a nym';
    EXCEPTION WHEN foreign_key_violation THEN
        GET STACKED DIAGNOSTICS mutation_error = CONSTRAINT_NAME;
        IF mutation_error <> 'public_names_alias_requires_nym' THEN
            RAISE;
        END IF;
    END;

    BEGIN
        UPDATE public_names SET name = 'renamed' WHERE name = 'current-owner';
        RAISE EXCEPTION 'migration 059 allowed a name mutation';
    EXCEPTION WHEN integrity_constraint_violation THEN
        GET STACKED DIAGNOSTICS mutation_error = CONSTRAINT_NAME;
        IF mutation_error <> 'public_names_reject_update' THEN
            RAISE;
        END IF;
    END;

    BEGIN
        DELETE FROM public_names WHERE name = 'current-shop';
        RAISE EXCEPTION 'migration 059 allowed a name deletion';
    EXCEPTION WHEN integrity_constraint_violation THEN
        GET STACKED DIAGNOSTICS mutation_error = CONSTRAINT_NAME;
        IF mutation_error <> 'public_names_reject_delete' THEN
            RAISE;
        END IF;
    END;

    TRUNCATE public_names;
END
$$;

-- Runtime can insert only the three claim inputs; identity and timestamp stay
-- database-owned. The transaction is rolled back so the post-hook state stays
-- empty for later migration fixtures.
BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO public_names (name, owner_npub, kind)
VALUES ('runtime-probe', repeat('d', 64), 'nym');
ROLLBACK;

DO $$
DECLARE
    runtime_role_oid OID;
    relation_owner_oid OID;
    function_name TEXT;
    function_owner_oid OID;
BEGIN
    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT relation_owner_oid
      FROM pg_class WHERE oid = 'public.public_names'::REGCLASS;

    IF relation_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'SET')
       OR NOT has_table_privilege('bullnym_app', 'public.public_names', 'SELECT')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'INSERT')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'DELETE')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'TRUNCATE')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'REFERENCES')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'TRIGGER')
       OR NOT has_column_privilege('bullnym_app', 'public.public_names', 'name', 'INSERT')
       OR NOT has_column_privilege('bullnym_app', 'public.public_names', 'owner_npub', 'INSERT')
       OR NOT has_column_privilege('bullnym_app', 'public.public_names', 'kind', 'INSERT')
       OR has_column_privilege('bullnym_app', 'public.public_names', 'id', 'INSERT')
       OR has_column_privilege('bullnym_app', 'public.public_names', 'claimed_at', 'INSERT') THEN
        RAISE EXCEPTION 'migration 059 retained unsafe runtime owner/ACL';
    END IF;

    FOREACH function_name IN ARRAY ARRAY[
        'enforce_public_name_insert',
        'reject_public_name_mutation',
        'require_user_permanent_nym'
    ] LOOP
        SELECT proowner INTO STRICT function_owner_oid
          FROM pg_proc function_info
          JOIN pg_namespace namespace ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND function_info.proname = function_name
           AND function_info.pronargs = 0;
        IF function_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'USAGE')
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'SET')
           OR has_function_privilege(
               'bullnym_app', format('public.%I()', function_name), 'EXECUTE'
           ) THEN
            RAISE EXCEPTION 'migration 059 retained unsafe function ACL for %',
                function_name;
        END IF;
    END LOOP;
END
$$;
