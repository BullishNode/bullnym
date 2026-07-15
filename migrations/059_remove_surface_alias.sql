-- ============================================================================
-- 059: authoritative permanent-name registry and historical backfill
-- ============================================================================
--
-- Apply only after migration 058 has been reviewed and every ambiguous owner
-- has an explicit canonical choice.  This stopped-writer transaction rechecks
-- nym, alias, and active-nym drift; rejects any descriptor-less surface;
-- reserves every historical name; and removes the mutable per-surface alias
-- authority.

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

LOCK TABLE users, donation_pages, invoices, public_name_migration_choices
    IN ACCESS EXCLUSIVE MODE;

-- A5: candidate drift is symmetric.  Owners, nyms, aliases, and the A3 active
-- nym must still match the exact 058 snapshot.
DO $$
DECLARE
    candidate_drift JSONB;
    unresolved JSONB;
    invalid_surface_descriptors JSONB;
    invoice_owner_drift JSONB;
BEGIN
    WITH current_nyms AS (
        SELECT
            npub AS owner_npub,
            array_agg(nym ORDER BY nym) AS candidate_nyms,
            CASE
                WHEN COUNT(*) FILTER (WHERE is_active) = 1
                    THEN (array_agg(nym ORDER BY nym)
                          FILTER (WHERE is_active))[1]
                ELSE NULL
            END AS active_nym,
            COUNT(*) FILTER (WHERE is_active) AS active_count
        FROM users
        GROUP BY npub
    ),
    current_alias_claims AS (
        SELECT donation_pages.alias AS name, users.npub AS owner_npub
        FROM donation_pages
        JOIN users ON users.nym = donation_pages.nym
        WHERE donation_pages.alias IS NOT NULL
        UNION ALL
        SELECT invoices.public_slug, invoices.npub_owner
        FROM invoices
        WHERE invoices.public_slug IS NOT NULL
    ),
    current_aliases AS (
        SELECT
            current_alias_claims.owner_npub,
            array_agg(DISTINCT current_alias_claims.name ORDER BY current_alias_claims.name)
                AS candidate_aliases
        FROM current_alias_claims
        GROUP BY current_alias_claims.owner_npub
    ),
    current_candidates AS (
        SELECT
            nyms.owner_npub,
            nyms.candidate_nyms,
            nyms.active_nym,
            nyms.active_count,
            COALESCE(aliases.candidate_aliases, ARRAY[]::TEXT[])
                AS candidate_aliases
        FROM current_nyms AS nyms
        LEFT JOIN current_aliases AS aliases USING (owner_npub)
    )
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO candidate_drift
      FROM (
          SELECT
              COALESCE(current.owner_npub, choices.owner_npub) AS owner_npub,
              current.candidate_nyms AS current_nyms,
              choices.candidate_nyms AS preflight_nyms,
              current.active_nym AS current_active_nym,
              choices.active_nym AS preflight_active_nym,
              current.candidate_aliases AS current_aliases,
              choices.candidate_aliases AS preflight_aliases,
              current.active_count
          FROM current_candidates AS current
          FULL OUTER JOIN public_name_migration_choices AS choices
            ON choices.owner_npub = current.owner_npub
          WHERE current.candidate_nyms IS DISTINCT FROM choices.candidate_nyms
             OR current.active_nym IS DISTINCT FROM choices.active_nym
             OR current.candidate_aliases IS DISTINCT FROM choices.candidate_aliases
             OR current.active_count > 1
          ORDER BY COALESCE(current.owner_npub, choices.owner_npub)
      ) AS conflicts;

    IF candidate_drift IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 059 aborted; public-name candidates changed after preflight: %',
            candidate_drift
            USING ERRCODE = '23514';
    END IF;

    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO unresolved
      FROM (
          SELECT
              owner_npub,
              candidate_nyms,
              canonical_nym,
              candidate_aliases,
              canonical_alias
          FROM public_name_migration_choices
          WHERE NOT resolved
             OR canonical_nym IS NULL
             OR (
                 candidate_aliases <> ARRAY[]::TEXT[]
                 AND canonical_alias IS NULL
             )
          ORDER BY owner_npub
      ) AS conflicts;
    IF unresolved IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 059 aborted; resolve every canonical choice first: %',
            unresolved
            USING ERRCODE = '23514';
    END IF;

    -- The current contract has no descriptor-less surface. Never infer or
    -- copy a payout wallet from another product during this name cutover.
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO invalid_surface_descriptors
      FROM (
          SELECT
              donation_pages.nym,
              donation_pages.kind,
              donation_pages.enabled,
              donation_pages.archived_at IS NOT NULL AS archived
          FROM donation_pages
          WHERE donation_pages.ct_descriptor IS NULL
          ORDER BY donation_pages.nym, donation_pages.kind
      ) AS conflicts;
    IF invalid_surface_descriptors IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 059 aborted; descriptor-less surfaces violate the current contract: %',
            invalid_surface_descriptors
            USING ERRCODE = '23514';
    END IF;

    -- Historical invoices are not rewritten.  Verify their durable owner
    -- tuple before changing the lookup authority that protects old renders.
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO invoice_owner_drift
      FROM (
          SELECT invoices.id, invoices.nym_owner, invoices.npub_owner
          FROM invoices
          WHERE invoices.nym_owner IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM users
                WHERE users.nym = invoices.nym_owner
                  AND users.npub = invoices.npub_owner
            )
          ORDER BY invoices.id
      ) AS conflicts;
    IF invoice_owner_drift IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 059 aborted; historical invoice owner tuples are inconsistent: %',
            invoice_owner_drift
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- Every current Page/POS surface owns its payout descriptor. Runtime checkout
-- never falls back to the Lightning Address descriptor or cursor.
ALTER TABLE donation_pages
    ALTER COLUMN ct_descriptor SET NOT NULL;

CREATE TABLE public_names (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL,
    owner_npub     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    canonical      BOOLEAN NOT NULL DEFAULT TRUE,
    claimed_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    grandfathered  BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT public_names_kind_check CHECK (kind IN ('nym', 'alias')),
    CONSTRAINT public_names_claimed_at_check CHECK (
        grandfathered
        OR claimed_at > '1970-01-01 00:00:00+00'::TIMESTAMPTZ
    ),
    -- Historical rows must be preserved even if they predate today's input
    -- grammar.  Every runtime-created row is non-grandfathered and therefore
    -- receives the strict checks.
    CONSTRAINT public_names_new_name_shape_check CHECK (
        grandfathered
        OR name ~ '^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,30}[a-z0-9])$'
    ),
    CONSTRAINT public_names_new_owner_shape_check CHECK (
        grandfathered OR owner_npub ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT public_names_name_kind_key UNIQUE (name, kind)
);

CREATE INDEX public_names_owner_kind_idx
    ON public_names (owner_npub, kind);
CREATE UNIQUE INDEX public_names_one_canonical_kind_per_owner_idx
    ON public_names (owner_npub, kind)
    WHERE canonical;

-- Preserve every nym, including the inactive duplicate rows selected by the
-- operator as non-payable tombstones.
INSERT INTO public_names (
    name,
    owner_npub,
    kind,
    canonical,
    claimed_at,
    grandfathered
)
SELECT
    users.nym,
    users.npub,
    'nym',
    users.nym = choices.canonical_nym,
    users.created_at,
    TRUE
FROM users
JOIN public_name_migration_choices AS choices
  ON choices.owner_npub = users.npub;

-- Preserve aliases from enabled and archived surfaces alike.  A typed unique
-- key deliberately permits a historical alias/nym string collision while the
-- new-claim trigger below blocks that string for all future claims.
INSERT INTO public_names (
    name,
    owner_npub,
    kind,
    canonical,
    claimed_at,
    grandfathered
)
SELECT
    alias_claims.name,
    alias_claims.owner_npub,
    'alias',
    alias_claims.name = choices.canonical_alias,
    alias_claims.claimed_at,
    TRUE
FROM (
    SELECT
        historical_alias_claims.name,
        historical_alias_claims.owner_npub,
        MIN(historical_alias_claims.claimed_at) AS claimed_at
    FROM (
        SELECT
            donation_pages.alias AS name,
            users.npub AS owner_npub,
            donation_pages.created_at AS claimed_at
        FROM donation_pages
        JOIN users ON users.nym = donation_pages.nym
        WHERE donation_pages.alias IS NOT NULL
        UNION ALL
        SELECT
            invoices.public_slug,
            invoices.npub_owner,
            invoices.created_at
        FROM invoices
        WHERE invoices.public_slug IS NOT NULL
    ) AS historical_alias_claims
    GROUP BY historical_alias_claims.name, historical_alias_claims.owner_npub
) AS alias_claims
JOIN public_name_migration_choices AS choices
  ON choices.owner_npub = alias_claims.owner_npub;

DO $$
DECLARE
    canonical_drift JSONB;
BEGIN
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO canonical_drift
      FROM (
          SELECT
              choices.owner_npub,
              choices.canonical_nym,
              choices.canonical_alias,
              COUNT(*) FILTER (
                  WHERE public_names.kind = 'nym' AND public_names.canonical
              ) AS canonical_nyms,
              COUNT(*) FILTER (
                  WHERE public_names.kind = 'alias' AND public_names.canonical
              ) AS canonical_aliases
          FROM public_name_migration_choices AS choices
          LEFT JOIN public_names
            ON public_names.owner_npub = choices.owner_npub
          GROUP BY
              choices.owner_npub,
              choices.canonical_nym,
              choices.canonical_alias,
              choices.candidate_aliases
          HAVING COUNT(*) FILTER (
                     WHERE public_names.kind = 'nym' AND public_names.canonical
                 ) <> 1
              OR COUNT(*) FILTER (
                     WHERE public_names.kind = 'alias' AND public_names.canonical
                 ) <> CASE
                         WHEN choices.candidate_aliases = ARRAY[]::TEXT[] THEN 0
                         ELSE 1
                      END
          ORDER BY choices.owner_npub
      ) AS conflicts;
    IF canonical_drift IS NOT NULL THEN
        RAISE EXCEPTION
            'migration 059 canonical backfill did not match operator choices: %',
            canonical_drift
            USING ERRCODE = '23514';
    END IF;
END
$$;

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

    IF NEW.grandfathered OR NOT NEW.canonical THEN
        RAISE EXCEPTION 'new public-name claims must be canonical runtime claims'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'public_names_new_claim_state_check';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public_names
        WHERE owner_npub = NEW.owner_npub
          AND kind = NEW.kind
    ) THEN
        RAISE EXCEPTION 'owner already has a lifetime % claim', NEW.kind
            USING ERRCODE = '23505',
                  CONSTRAINT = 'public_names_owner_kind_lifetime_key';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public_names WHERE name = NEW.name
    ) THEN
        RAISE EXCEPTION 'public name is permanently reserved'
            USING ERRCODE = '23505',
                  CONSTRAINT = 'public_names_shared_namespace_key';
    END IF;

    IF NEW.kind = 'alias' AND NOT EXISTS (
        SELECT 1
        FROM public_names
        WHERE owner_npub = NEW.owner_npub
          AND kind = 'nym'
          AND canonical
    ) THEN
        RAISE EXCEPTION 'a permanent alias requires an owner-matched canonical nym'
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
    IF TG_OP = 'DELETE'
       AND current_setting('bullnym.allow_public_name_delete', TRUE)
           IS NOT DISTINCT FROM 'on' THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'public-name ownership and canonical selection are immutable'
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
DECLARE
    claim_is_canonical BOOLEAN;
BEGIN
    SELECT canonical
      INTO claim_is_canonical
      FROM public_names
     WHERE name = NEW.nym
       AND owner_npub = NEW.npub
       AND kind = 'nym';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'users row requires its owner-matched permanent nym'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'users_require_permanent_nym';
    END IF;

    IF NEW.is_active AND NOT claim_is_canonical THEN
        RAISE EXCEPTION 'a historical nym tombstone cannot become a Lightning Address'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'users_active_nym_must_be_canonical';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER users_require_permanent_nym
BEFORE INSERT OR UPDATE OF nym, npub, is_active ON users
FOR EACH ROW
EXECUTE FUNCTION require_user_permanent_nym();

-- The A10 report is consumed between 058 and 059 and depends on the legacy
-- alias column.  Remove the view before removing that column; the immutable
-- candidate table remains until the final backfill assertions are complete.
DROP VIEW public_name_migration_merchant_communications;
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

DROP TABLE public_name_migration_choices;
DROP FUNCTION guard_public_name_migration_choice();

COMMIT;
