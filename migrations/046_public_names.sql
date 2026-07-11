-- Authoritative lifetime registry for public nyms and aliases.
--
-- New policy:
--   * one lifetime nym claim per npub;
--   * one optional lifetime alias claim per npub;
--   * new nym and alias claims share one namespace;
--   * claims are deactivated/reactivated, never released or reassigned;
--   * an alias belongs to the npub and selects Payment Page vs POS by route.
--
-- Historical states that predate the policy are preserved. Existing owners
-- may therefore have multiple grandfathered claims, and a pre-existing alias
-- may equal a pre-existing nym. Typed lookups keep those old routes working;
-- the insertion trigger rejects every such collision for new claims.

BEGIN;

LOCK TABLE users, donation_pages, public_name_migration_alias_choices
    IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
    unresolved JSONB;
    preflight_drift JSONB;
BEGIN
    WITH current_aliases AS (
        SELECT
            users.npub AS owner_npub,
            array_agg(DISTINCT donation_pages.alias ORDER BY donation_pages.alias)
                AS candidate_aliases
        FROM donation_pages
        JOIN users ON users.nym = donation_pages.nym
        WHERE donation_pages.alias IS NOT NULL
        GROUP BY users.npub
    )
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO preflight_drift
      FROM (
          SELECT
              COALESCE(current_aliases.owner_npub, choices.owner_npub)
                  AS owner_npub,
              current_aliases.candidate_aliases AS current_aliases,
              choices.candidate_aliases AS preflight_aliases
          FROM current_aliases
          FULL OUTER JOIN public_name_migration_alias_choices AS choices
            ON choices.owner_npub = current_aliases.owner_npub
          WHERE current_aliases.candidate_aliases
                IS DISTINCT FROM choices.candidate_aliases
          ORDER BY COALESCE(current_aliases.owner_npub, choices.owner_npub)
      ) AS conflicts;

    IF preflight_drift IS NOT NULL THEN
        RAISE EXCEPTION
            'public-name migration aborted; aliases changed after preflight: %',
            preflight_drift
            USING ERRCODE = 'check_violation';
    END IF;

    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO unresolved
      FROM (
          SELECT owner_npub, candidate_aliases
          FROM public_name_migration_alias_choices
          WHERE resolved = FALSE
          ORDER BY owner_npub
      ) AS conflicts;

    IF unresolved IS NOT NULL THEN
        RAISE EXCEPTION
            'public-name migration aborted; resolve alias choices first: %',
            unresolved
            USING ERRCODE = 'check_violation';
    END IF;
END
$$;

CREATE TYPE public_name_kind AS ENUM ('nym', 'alias');

CREATE TABLE public_name_owners (
    npub        TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO public_name_owners (npub, created_at)
SELECT npub, MIN(created_at)
FROM users
GROUP BY npub;

CREATE TABLE public_names (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    owner_npub          TEXT NOT NULL REFERENCES public_name_owners(npub)
                        ON DELETE RESTRICT,
    kind                public_name_kind NOT NULL,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    claimed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at      TIMESTAMPTZ,
    grandfathered       BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT public_names_active_state_check CHECK (
        (active AND deactivated_at IS NULL)
        OR (NOT active AND deactivated_at IS NOT NULL)
    ),
    CONSTRAINT public_names_name_kind_key UNIQUE (name, kind)
);

CREATE INDEX public_names_owner_kind_idx
    ON public_names (owner_npub, kind);

CREATE UNIQUE INDEX public_names_one_active_nym_per_owner_idx
    ON public_names (owner_npub)
    WHERE kind = 'nym' AND active = TRUE;

CREATE UNIQUE INDEX public_names_one_active_alias_per_owner_idx
    ON public_names (owner_npub)
    WHERE kind = 'alias' AND active = TRUE;

INSERT INTO public_names (
    name,
    owner_npub,
    kind,
    active,
    claimed_at,
    deactivated_at,
    grandfathered
)
SELECT
    users.nym,
    users.npub,
    'nym'::public_name_kind,
    users.is_active,
    users.created_at,
    CASE WHEN users.is_active THEN NULL ELSE now() END,
    owner_counts.claim_count > 1
        OR EXISTS (
            SELECT 1
            FROM donation_pages
            WHERE donation_pages.alias = users.nym
        )
FROM users
JOIN (
    SELECT npub, COUNT(*) AS claim_count
    FROM users
    GROUP BY npub
) AS owner_counts ON owner_counts.npub = users.npub;

INSERT INTO public_names (
    name,
    owner_npub,
    kind,
    active,
    claimed_at,
    deactivated_at,
    grandfathered
)
SELECT
    alias_claims.name,
    alias_claims.owner_npub,
    'alias'::public_name_kind,
    users.is_active
        AND choices.active_alias = alias_claims.name,
    alias_claims.claimed_at,
    CASE
        WHEN users.is_active AND choices.active_alias = alias_claims.name
            THEN NULL
        ELSE now()
    END,
    cardinality(choices.candidate_aliases) > 1
        OR EXISTS (
            SELECT 1
            FROM users AS nym_users
            WHERE nym_users.nym = alias_claims.name
        )
FROM (
    SELECT
        donation_pages.alias AS name,
        users.npub AS owner_npub,
        MIN(donation_pages.created_at) AS claimed_at
    FROM donation_pages
    JOIN users ON users.nym = donation_pages.nym
    WHERE donation_pages.alias IS NOT NULL
    GROUP BY donation_pages.alias, users.npub
) AS alias_claims
JOIN public_name_migration_alias_choices AS choices
  ON choices.owner_npub = alias_claims.owner_npub
JOIN LATERAL (
    SELECT is_active
    FROM users
    WHERE users.npub = alias_claims.owner_npub
    ORDER BY is_active DESC, created_at DESC
    LIMIT 1
) AS users ON TRUE;

ALTER TABLE users
    ADD CONSTRAINT users_public_name_owner_fkey
    FOREIGN KEY (npub) REFERENCES public_name_owners(npub)
    ON DELETE RESTRICT NOT VALID;

ALTER TABLE users
    VALIDATE CONSTRAINT users_public_name_owner_fkey;

DROP INDEX donation_pages_alias_uidx;

ALTER TABLE donation_pages
    DROP COLUMN alias;

CREATE FUNCTION public_names_enforce_new_claim()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Serialize different-name races by one owner and same-name races by
    -- different owners. These locks also protect direct SQL callers that do
    -- not use the application transaction helpers.
    PERFORM pg_advisory_xact_lock(
        hashtext('public-name-owner:' || NEW.owner_npub || ':' || NEW.kind::text)::bigint
    );
    PERFORM pg_advisory_xact_lock(
        hashtext('public-name:' || NEW.name)::bigint
    );

    IF EXISTS (
        SELECT 1
        FROM public_names
        WHERE owner_npub = NEW.owner_npub
          AND kind = NEW.kind
    ) THEN
        RAISE EXCEPTION
            'owner already has a lifetime % claim', NEW.kind
            USING
                ERRCODE = 'unique_violation',
                CONSTRAINT = 'public_names_owner_kind_lifetime_key';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public_names
        WHERE name = NEW.name
    ) THEN
        RAISE EXCEPTION
            'public name is permanently reserved'
            USING
                ERRCODE = 'unique_violation',
                CONSTRAINT = 'public_names_shared_namespace_key';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER public_names_enforce_new_claim_trigger
BEFORE INSERT ON public_names
FOR EACH ROW
EXECUTE FUNCTION public_names_enforce_new_claim();

CREATE FUNCTION public_names_guard_reservation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('bullnym.allow_public_name_delete', TRUE)
            IS DISTINCT FROM 'on'
        THEN
            RAISE EXCEPTION
                'public-name reservations cannot be deleted'
                USING
                    ERRCODE = 'integrity_constraint_violation',
                    CONSTRAINT = 'public_names_permanent_reservation';
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.name IS DISTINCT FROM OLD.name
        OR NEW.owner_npub IS DISTINCT FROM OLD.owner_npub
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.claimed_at IS DISTINCT FROM OLD.claimed_at
        OR NEW.grandfathered IS DISTINCT FROM OLD.grandfathered
    THEN
        RAISE EXCEPTION
            'public-name reservation identity is immutable'
            USING
                ERRCODE = 'integrity_constraint_violation',
                CONSTRAINT = 'public_names_immutable_reservation';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER public_names_guard_reservation_trigger
BEFORE UPDATE OR DELETE ON public_names
FOR EACH ROW
EXECUTE FUNCTION public_names_guard_reservation();

CREATE FUNCTION users_require_nym_claim()
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
        RAISE EXCEPTION
            'users row requires its owner-matched nym reservation'
            USING
                ERRCODE = 'foreign_key_violation',
                CONSTRAINT = 'users_public_name_claim_fkey';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER users_require_nym_claim_trigger
BEFORE INSERT OR UPDATE OF nym, npub ON users
FOR EACH ROW
EXECUTE FUNCTION users_require_nym_claim();

DROP TABLE public_name_migration_alias_choices;

COMMIT;
