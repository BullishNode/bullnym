-- Migration 058 is a read-only ownership snapshot, not the registry cutover.
DO $$
DECLARE
    refusal_constraint TEXT;
BEGIN
    IF to_regclass('public.public_names') IS NOT NULL
       OR NOT EXISTS (
           SELECT 1
           FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'donation_pages'
             AND column_name = 'alias'
       ) THEN
        RAISE EXCEPTION 'migration 058 changed live name authority';
    END IF;

    IF (SELECT COUNT(*) FROM public_name_migration_choices)
       <> (SELECT COUNT(DISTINCT npub) FROM users) THEN
        RAISE EXCEPTION 'migration 058 did not snapshot every owner';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public_name_migration_choices
        WHERE owner_npub = repeat('a', 64)
          AND candidate_aliases = ARRAY['invoice-only-alias']
          AND canonical_alias = 'invoice-only-alias'
          AND resolved
    ) THEN
        RAISE EXCEPTION 'migration 058 omitted verified invoice-only alias';
    END IF;

    -- A3 selected the exact active row and made it unchangeable by CHECK.
    IF NOT EXISTS (
        SELECT 1
        FROM public_name_migration_choices
        WHERE owner_npub = repeat('b', 64)
          AND candidate_nyms = ARRAY['active-canonical', 'inactive-tombstone']
          AND active_nym = 'active-canonical'
          AND canonical_nym = 'active-canonical'
          AND resolved
    ) THEN
        RAISE EXCEPTION 'migration 058 did not constrain active canonical nym';
    END IF;

    BEGIN
        UPDATE public_name_migration_choices
           SET canonical_nym = 'inactive-tombstone'
         WHERE owner_npub = repeat('b', 64);
        RAISE EXCEPTION 'migration 058 allowed a non-active canonical choice';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint <> 'public_name_choices_active_canonical_check' THEN
            RAISE;
        END IF;
    END;

    -- A4 rejects a completion bit without the fully-offline nym choice.
    BEGIN
        UPDATE public_name_migration_choices
           SET resolved = TRUE
         WHERE owner_npub = repeat('d', 64);
        RAISE EXCEPTION 'migration 058 accepted incomplete nym resolution';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint <> 'public_name_choices_resolution_complete_check' THEN
            RAISE;
        END IF;
    END;

    UPDATE public_name_migration_choices
       SET canonical_nym = 'operator-choice-one', resolved = TRUE
     WHERE owner_npub = repeat('d', 64);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 058 missing explicit multi-nym choice';
    END IF;

    -- A4 also requires an alias when alias history exists.
    BEGIN
        UPDATE public_name_migration_choices
           SET resolved = TRUE
         WHERE owner_npub = repeat('e', 64);
        RAISE EXCEPTION 'migration 058 accepted incomplete alias resolution';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint <> 'public_name_choices_resolution_complete_check' THEN
            RAISE;
        END IF;
    END;

    UPDATE public_name_migration_choices
       SET canonical_alias = 'shop-page', resolved = TRUE
     WHERE owner_npub = repeat('e', 64)
       AND candidate_aliases = ARRAY['shop-page', 'shop-pos'];
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 058 missing explicit multi-alias choice';
    END IF;

    -- Candidate snapshots cannot be edited to conceal drift.
    BEGIN
        UPDATE public_name_migration_choices
           SET candidate_nyms = ARRAY['operator-choice-one']
         WHERE owner_npub = repeat('d', 64);
        RAISE EXCEPTION 'migration 058 allowed candidate snapshot mutation';
    EXCEPTION WHEN integrity_constraint_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint <> 'public_name_migration_snapshot_immutable' THEN
            RAISE;
        END IF;
    END;

    IF EXISTS (
        SELECT 1 FROM public_name_migration_choices WHERE NOT resolved
    ) THEN
        RAISE EXCEPTION 'migration 058 fixture left unresolved choices';
    END IF;

    -- The archived alias becomes the canonical owner alias and changes the
    -- live POS URL, so A10 must surface that owner before deployment.
    IF NOT EXISTS (
        SELECT 1
        FROM public_name_migration_merchant_communications
        WHERE owner_npub = repeat('1', 64)
          AND canonical_alias = 'old-shop'
          AND surface_kind = 'pos'
          AND previous_public_name = 'archived-alias-owner'
          AND surface_enabled
          AND NOT surface_archived
    ) THEN
        RAISE EXCEPTION 'migration 058 omitted archived-alias merchant communication';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public_name_migration_merchant_communications
        WHERE owner_npub = repeat('a', 64)
          AND canonical_alias = 'invoice-only-alias'
          AND surface_nym = 'og-migration-fixture'
          AND previous_public_name = 'og-migration-fixture'
    ) THEN
        RAISE EXCEPTION 'migration 058 omitted invoice-alias merchant communication';
    END IF;

    -- A2 belongs to 059; the preflight itself is non-mutating.
    IF NOT EXISTS (
        SELECT 1
        FROM donation_pages
        WHERE nym = 'fallback-page-owner'
          AND kind = 'payment_page'
          AND ct_descriptor IS NULL
          AND next_addr_idx = 3
    ) THEN
        RAISE EXCEPTION 'migration 058 changed fallback descriptor state';
    END IF;
END
$$;
