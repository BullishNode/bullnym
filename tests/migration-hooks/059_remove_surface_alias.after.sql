-- Lock the historical backfill, typed collision, canonical/tombstone,
-- independent descriptor, runtime-claim, and least-privilege contracts.
DO $$
DECLARE
    actual_columns TEXT[];
    refusal_constraint TEXT;
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
        'canonical:boolean:NO',
        'claimed_at:timestamp with time zone:NO',
        'grandfathered:boolean:NO'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 059 column contract changed: %', actual_columns;
    END IF;

    IF to_regclass('public.public_name_migration_choices') IS NOT NULL
       OR to_regclass('public.public_name_migration_merchant_communications') IS NOT NULL
       OR EXISTS (
           SELECT 1
           FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'donation_pages'
             AND column_name = 'alias'
       )
       OR to_regclass('public.donation_pages_alias_uidx') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 059 retained temporary/mutable alias authority';
    END IF;

    IF (SELECT COUNT(*) FROM public_names WHERE kind = 'nym')
       <> (SELECT COUNT(*) FROM users) THEN
        RAISE EXCEPTION 'migration 059 lost historical nym reservations';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public_names
        WHERE name = 'active-canonical'
          AND owner_npub = repeat('b', 64)
          AND kind = 'nym' AND canonical AND grandfathered
    ) OR NOT EXISTS (
        SELECT 1 FROM public_names
        WHERE name = 'inactive-tombstone'
          AND owner_npub = repeat('b', 64)
          AND kind = 'nym' AND NOT canonical AND grandfathered
    ) OR NOT EXISTS (
        SELECT 1 FROM public_names
        WHERE name = 'operator-choice-one'
          AND owner_npub = repeat('d', 64)
          AND kind = 'nym' AND canonical AND grandfathered
    ) OR NOT EXISTS (
        SELECT 1 FROM public_names
        WHERE name = 'operator-choice-two'
          AND owner_npub = repeat('d', 64)
          AND kind = 'nym' AND NOT canonical AND grandfathered
    ) THEN
        RAISE EXCEPTION 'migration 059 canonical/tombstone nym backfill changed';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public_names
        WHERE name = 'shop-page' AND owner_npub = repeat('e', 64)
          AND kind = 'alias' AND canonical AND grandfathered
    ) OR NOT EXISTS (
        SELECT 1 FROM public_names
        WHERE name = 'shop-pos' AND owner_npub = repeat('e', 64)
          AND kind = 'alias' AND NOT canonical AND grandfathered
    ) THEN
        RAISE EXCEPTION 'migration 059 canonical/tombstone alias backfill changed';
    END IF;

    -- Same string, two typed historical reservations, different owners.
    IF (SELECT COUNT(*) FROM public_names
        WHERE name = 'og-migration-fixture') <> 2
       OR NOT EXISTS (
           SELECT 1 FROM public_names
           WHERE name = 'og-migration-fixture' AND kind = 'nym'
             AND owner_npub = repeat('a', 64)
       )
       OR NOT EXISTS (
           SELECT 1 FROM public_names
           WHERE name = 'og-migration-fixture' AND kind = 'alias'
             AND owner_npub = repeat('f', 64)
       ) THEN
        RAISE EXCEPTION 'migration 059 did not preserve typed collision';
    END IF;

    -- The name cutover leaves each product's descriptor/cursor untouched and
    -- enforces the current non-null surface descriptor contract.
    IF NOT EXISTS (
        SELECT 1
        FROM donation_pages
        WHERE nym = 'independent-page-owner'
          AND kind = 'payment_page'
          AND ct_descriptor = 'surface-page-descriptor'
          AND next_addr_idx = 3
    ) OR NOT EXISTS (
        SELECT 1 FROM users
        WHERE nym = 'independent-page-owner'
          AND ct_descriptor = 'lightning-address-descriptor'
          AND next_addr_idx = 118
    ) OR EXISTS (
        SELECT 1 FROM donation_pages WHERE ct_descriptor IS NULL
    ) OR NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'donation_pages'
          AND column_name = 'ct_descriptor'
          AND is_nullable = 'NO'
    ) THEN
        RAISE EXCEPTION 'migration 059 surface descriptor/cursor contract changed';
    END IF;

    -- Existing product state and old invoice owner identity are untouched.
    IF NOT EXISTS (
        SELECT 1 FROM donation_pages
        WHERE nym = 'archived-alias-owner'
          AND kind = 'payment_page'
          AND archived_at IS NOT NULL
          AND NOT enabled
    ) OR NOT EXISTS (
        SELECT 1 FROM invoices
        WHERE id = '46000000-0000-0000-0000-000000000001'
          AND nym_owner = 'og-migration-fixture'
          AND npub_owner = repeat('a', 64)
          AND public_slug = 'invoice-only-alias'
    ) OR NOT EXISTS (
        SELECT 1 FROM public_names
        WHERE name = 'invoice-only-alias'
          AND owner_npub = repeat('a', 64)
          AND kind = 'alias'
          AND canonical
          AND grandfathered
    ) THEN
        RAISE EXCEPTION 'migration 059 changed product or invoice ownership state';
    END IF;

    -- Tombstones can never become active product identity.
    BEGIN
        UPDATE users SET is_active = TRUE WHERE nym = 'inactive-tombstone';
        RAISE EXCEPTION 'migration 059 allowed tombstone activation';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint <> 'users_active_nym_must_be_canonical' THEN
            RAISE;
        END IF;
    END;

    -- Historical typed collision blocks every new claim of the string.
    BEGIN
        INSERT INTO public_names (name, owner_npub, kind)
        VALUES ('og-migration-fixture', repeat('3', 64), 'nym');
        RAISE EXCEPTION 'migration 059 admitted a reserved historical name';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint <> 'public_names_shared_namespace_key' THEN
            RAISE;
        END IF;
    END;

    -- Any historical claim of a kind exhausts that owner's lifetime slot.
    BEGIN
        INSERT INTO public_names (name, owner_npub, kind)
        VALUES ('another-nym', repeat('b', 64), 'nym');
        RAISE EXCEPTION 'migration 059 admitted a second owner nym';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint <> 'public_names_owner_kind_lifetime_key' THEN
            RAISE;
        END IF;
    END;
END
$$;

-- Runtime can create only normal canonical claims through the three claim
-- columns.  Database-owned metadata is not forgeable.
BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO public_names (name, owner_npub, kind)
VALUES ('runtime-probe', repeat('3', 64), 'nym');
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
       OR has_table_privilege('bullnym_app', 'public.public_names', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'DELETE')
       OR has_table_privilege('bullnym_app', 'public.public_names', 'TRUNCATE')
       OR NOT has_column_privilege('bullnym_app', 'public.public_names', 'name', 'INSERT')
       OR NOT has_column_privilege('bullnym_app', 'public.public_names', 'owner_npub', 'INSERT')
       OR NOT has_column_privilege('bullnym_app', 'public.public_names', 'kind', 'INSERT')
       OR has_column_privilege('bullnym_app', 'public.public_names', 'id', 'INSERT')
       OR has_column_privilege('bullnym_app', 'public.public_names', 'canonical', 'INSERT')
       OR has_column_privilege('bullnym_app', 'public.public_names', 'claimed_at', 'INSERT')
       OR has_column_privilege('bullnym_app', 'public.public_names', 'grandfathered', 'INSERT') THEN
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
