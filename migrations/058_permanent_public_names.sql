-- ============================================================================
-- 058: stopped-writer public-name migration preflight
-- ============================================================================
--
-- Snapshot every historical nym and alias before the authoritative registry
-- is created by migration 059.  Normal owners are resolved deterministically;
-- genuinely ambiguous, fully-offline multi-nym or multi-alias owners require
-- an explicit operator choice.  This migration does not change public routing,
-- descriptors, cursors, product availability, invoices, or ownership rows.
--
-- Writers must remain stopped after this migration.  Resolve a row with:
--
--   UPDATE public_name_migration_choices
--      SET canonical_nym = '<candidate nym>',
--          canonical_alias = '<candidate alias>', -- omit when candidates={}
--          resolved = TRUE
--    WHERE owner_npub = '<npub>';
--
-- Migration 059 recomputes both candidate sets and the active nym under an
-- exclusive lock.  Any drift or incomplete choice aborts its transaction.

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

-- The deployment runbook stops writers before 058.  This lock closes the
-- final race while the exact candidate snapshot is constructed.
LOCK TABLE users, donation_pages, invoices IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE public_name_migration_choices (
    owner_npub         TEXT PRIMARY KEY,
    candidate_nyms     TEXT[] NOT NULL,
    active_nym         TEXT,
    canonical_nym      TEXT,
    candidate_aliases  TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    canonical_alias    TEXT,
    resolved           BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT public_name_choices_nyms_nonempty_check CHECK (
        cardinality(candidate_nyms) > 0
    ),
    CONSTRAINT public_name_choices_active_candidate_check CHECK (
        active_nym IS NULL OR active_nym = ANY(candidate_nyms)
    ),
    CONSTRAINT public_name_choices_nym_candidate_check CHECK (
        canonical_nym IS NULL OR canonical_nym = ANY(candidate_nyms)
    ),
    CONSTRAINT public_name_choices_alias_candidate_check CHECK (
        canonical_alias IS NULL OR canonical_alias = ANY(candidate_aliases)
    ),
    -- A3: an existing active Lightning Address is the canonical nym.  IS NOT
    -- DISTINCT FROM makes NULL canonical_nym fail when active_nym is present.
    CONSTRAINT public_name_choices_active_canonical_check CHECK (
        active_nym IS NULL
        OR canonical_nym IS NOT DISTINCT FROM active_nym
    ),
    -- A4: setting only resolved is structurally incapable of completing an
    -- ambiguous row.  An owner with alias history must retain one alias.
    CONSTRAINT public_name_choices_resolution_complete_check CHECK (
        NOT resolved
        OR (
            canonical_nym IS NOT NULL
            AND (
                candidate_aliases = ARRAY[]::TEXT[]
                OR canonical_alias IS NOT NULL
            )
        )
    )
);

-- An invoice slug is a surviving historical alias record.  Attribute it only
-- through an exact durable nym/npub owner tuple; a corrupt or unlinked slug is
-- not safe to guess.  Likewise, one alias string attributed to two owners by
-- surfaces/invoices requires evidence repair before canonical selection.
DO $$
DECLARE
    invalid_invoice_aliases JSONB;
    ambiguous_alias_owners JSONB;
BEGIN
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO invalid_invoice_aliases
      FROM (
          SELECT invoices.id, invoices.public_slug,
                 invoices.nym_owner, invoices.npub_owner
          FROM invoices
          WHERE invoices.public_slug IS NOT NULL
            AND (
                invoices.nym_owner IS NULL
                OR NOT EXISTS (
                    SELECT 1
                    FROM users
                    WHERE users.nym = invoices.nym_owner
                      AND users.npub = invoices.npub_owner
                )
            )
          ORDER BY invoices.id
      ) AS conflicts;
    IF invalid_invoice_aliases IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 058 cannot attribute historical invoice aliases: %',
            invalid_invoice_aliases
            USING ERRCODE = '23514';
    END IF;

    WITH historical_alias_claims AS (
        SELECT donation_pages.alias AS name, users.npub AS owner_npub
        FROM donation_pages
        JOIN users ON users.nym = donation_pages.nym
        WHERE donation_pages.alias IS NOT NULL
        UNION ALL
        SELECT invoices.public_slug, invoices.npub_owner
        FROM invoices
        WHERE invoices.public_slug IS NOT NULL
    )
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO ambiguous_alias_owners
      FROM (
          SELECT name, array_agg(DISTINCT owner_npub ORDER BY owner_npub) AS owners
          FROM historical_alias_claims
          GROUP BY name
          HAVING COUNT(DISTINCT owner_npub) > 1
          ORDER BY name
      ) AS conflicts;
    IF ambiguous_alias_owners IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 058 found aliases attributed to multiple owners: %',
            ambiguous_alias_owners
            USING ERRCODE = '23514';
    END IF;
END
$$;

WITH nym_candidates AS (
    SELECT
        npub AS owner_npub,
        array_agg(nym ORDER BY nym) AS candidate_nyms,
        COALESCE(
            array_agg(nym ORDER BY nym) FILTER (WHERE is_active),
            ARRAY[]::TEXT[]
        ) AS active_nyms
    FROM users
    GROUP BY npub
),
historical_alias_claims AS (
    SELECT donation_pages.alias AS name, users.npub AS owner_npub
    FROM donation_pages
    JOIN users ON users.nym = donation_pages.nym
    WHERE donation_pages.alias IS NOT NULL
    UNION ALL
    SELECT invoices.public_slug, invoices.npub_owner
    FROM invoices
    WHERE invoices.public_slug IS NOT NULL
),
alias_candidates AS (
    SELECT
        historical_alias_claims.owner_npub,
        array_agg(DISTINCT historical_alias_claims.name ORDER BY historical_alias_claims.name)
            AS candidate_aliases
    FROM historical_alias_claims
    GROUP BY historical_alias_claims.owner_npub
),
resolved_candidates AS (
    SELECT
        nyms.owner_npub,
        nyms.candidate_nyms,
        CASE
            WHEN cardinality(nyms.active_nyms) = 1 THEN nyms.active_nyms[1]
            ELSE NULL
        END AS active_nym,
        CASE
            WHEN cardinality(nyms.candidate_nyms) = 1
                THEN nyms.candidate_nyms[1]
            WHEN cardinality(nyms.active_nyms) = 1
                THEN nyms.active_nyms[1]
            ELSE NULL
        END AS canonical_nym,
        COALESCE(aliases.candidate_aliases, ARRAY[]::TEXT[])
            AS candidate_aliases,
        CASE
            WHEN cardinality(aliases.candidate_aliases) = 1
                THEN aliases.candidate_aliases[1]
            ELSE NULL
        END AS canonical_alias
    FROM nym_candidates AS nyms
    LEFT JOIN alias_candidates AS aliases USING (owner_npub)
)
INSERT INTO public_name_migration_choices (
    owner_npub,
    candidate_nyms,
    active_nym,
    canonical_nym,
    candidate_aliases,
    canonical_alias,
    resolved
)
SELECT
    owner_npub,
    candidate_nyms,
    active_nym,
    canonical_nym,
    candidate_aliases,
    canonical_alias,
    canonical_nym IS NOT NULL
        AND (
            candidate_aliases = ARRAY[]::TEXT[]
            OR canonical_alias IS NOT NULL
        )
FROM resolved_candidates;

-- A corrupt preflight must not silently choose among multiple active rows,
-- even on a schema variant where the historical partial index is absent.
DO $$
DECLARE
    multiple_active JSONB;
BEGIN
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO multiple_active
      FROM (
          SELECT npub AS owner_npub, array_agg(nym ORDER BY nym) AS active_nyms
          FROM users
          WHERE is_active
          GROUP BY npub
          HAVING COUNT(*) > 1
          ORDER BY npub
      ) AS conflicts;

    IF multiple_active IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 058 found owners with multiple active nyms: %',
            multiple_active
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- Only canonical fields and the completion bit are operator-editable.  The
-- candidate snapshot and A3 active nym cannot be rewritten to hide drift.
CREATE FUNCTION guard_public_name_migration_choice()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'public-name migration candidate snapshot is immutable'
            USING ERRCODE = '23000',
                  CONSTRAINT = 'public_name_migration_snapshot_immutable';
    END IF;
    IF NEW.owner_npub IS DISTINCT FROM OLD.owner_npub
       OR NEW.candidate_nyms IS DISTINCT FROM OLD.candidate_nyms
       OR NEW.active_nym IS DISTINCT FROM OLD.active_nym
       OR NEW.candidate_aliases IS DISTINCT FROM OLD.candidate_aliases THEN
        RAISE EXCEPTION 'public-name migration candidate snapshot is immutable'
            USING ERRCODE = '23000',
                  CONSTRAINT = 'public_name_migration_snapshot_immutable';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER public_name_migration_choices_guard
BEFORE UPDATE OR DELETE ON public_name_migration_choices
FOR EACH ROW
EXECUTE FUNCTION guard_public_name_migration_choice();

-- A10: rows whose effective public URL changes to the canonical alias.  The
-- candidate scan includes archived surfaces, so an alias found only on an
-- archived row is still selected and reported when it changes another route.
CREATE VIEW public_name_migration_merchant_communications AS
SELECT
    choices.owner_npub,
    choices.canonical_nym,
    choices.canonical_alias,
    donation_pages.nym AS surface_nym,
    donation_pages.kind AS surface_kind,
    donation_pages.alias AS previous_alias,
    COALESCE(donation_pages.alias, donation_pages.nym) AS previous_public_name,
    donation_pages.enabled AS surface_enabled,
    donation_pages.archived_at IS NOT NULL AS surface_archived
FROM public_name_migration_choices AS choices
JOIN users ON users.npub = choices.owner_npub
JOIN donation_pages ON donation_pages.nym = users.nym
WHERE choices.canonical_alias IS NOT NULL
  AND COALESCE(donation_pages.alias, donation_pages.nym)
      IS DISTINCT FROM choices.canonical_alias;

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
    unresolved JSONB;
    cross_type_collisions JSONB;
    fallback_pages JSONB;
    merchant_communications JSONB;
BEGIN
    REVOKE ALL ON TABLE public_name_migration_choices FROM PUBLIC;
    REVOKE ALL ON TABLE public_name_migration_merchant_communications FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON TABLE public_name_migration_choices FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'REVOKE ALL ON TABLE public_name_migration_merchant_communications FROM %I',
        runtime_role_name
    );
    REVOKE ALL ON FUNCTION guard_public_name_migration_choice() FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON FUNCTION guard_public_name_migration_choice() FROM %I',
        runtime_role_name
    );

    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO unresolved
      FROM (
          SELECT owner_npub, candidate_nyms, candidate_aliases
          FROM public_name_migration_choices
          WHERE NOT resolved
          ORDER BY owner_npub
      ) AS conflicts;
    IF unresolved IS NOT NULL THEN
        RAISE NOTICE
            'public-name migration needs explicit canonical choices: %',
            unresolved;
    END IF;

    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO cross_type_collisions
      FROM (
          SELECT
              aliases.alias AS name,
              aliases.owner_npub AS alias_owner_npub,
              users.npub AS nym_owner_npub
          FROM (
              SELECT donation_pages.alias, alias_users.npub AS owner_npub
              FROM donation_pages
              JOIN users AS alias_users ON alias_users.nym = donation_pages.nym
              WHERE donation_pages.alias IS NOT NULL
              UNION
              SELECT invoices.public_slug, invoices.npub_owner
              FROM invoices
              WHERE invoices.public_slug IS NOT NULL
          ) AS aliases
          JOIN users ON users.nym = aliases.alias
          ORDER BY aliases.alias, aliases.owner_npub, users.npub
      ) AS conflicts;
    IF cross_type_collisions IS NOT NULL THEN
        RAISE NOTICE
            'migration 059 will grandfather typed alias/nym collisions: %',
            cross_type_collisions;
    END IF;

    SELECT jsonb_agg(to_jsonb(fallbacks))
      INTO fallback_pages
      FROM (
          SELECT
              users.npub AS owner_npub,
              donation_pages.nym,
              donation_pages.next_addr_idx AS surface_cursor,
              users.next_addr_idx AS user_cursor,
              donation_pages.archived_at IS NOT NULL AS surface_archived
          FROM donation_pages
          JOIN users ON users.nym = donation_pages.nym
          WHERE donation_pages.kind = 'payment_page'
            AND donation_pages.ct_descriptor IS NULL
            AND NOT EXISTS (
                SELECT 1
                FROM donation_pages AS pos
                WHERE pos.nym = donation_pages.nym
                  AND pos.kind = 'pos'
            )
          ORDER BY users.npub, donation_pages.nym
      ) AS fallbacks;
    IF fallback_pages IS NOT NULL THEN
        RAISE NOTICE
            'migration 059 will snapshot legacy Page descriptors/cursors: %',
            fallback_pages;
    END IF;

    SELECT jsonb_agg(to_jsonb(communications))
      INTO merchant_communications
      FROM (
          SELECT *
          FROM public_name_migration_merchant_communications
          ORDER BY owner_npub, surface_nym, surface_kind
      ) AS communications;
    IF merchant_communications IS NOT NULL THEN
        RAISE NOTICE
            'merchant public URLs changing to canonical aliases: %',
            merchant_communications;
    END IF;
END
$$;

COMMIT;
