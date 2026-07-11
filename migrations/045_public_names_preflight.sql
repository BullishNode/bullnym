-- Prepare the one-nym/one-alias public-name migration.
--
-- Existing deployments may contain more than one historical nym or alias for
-- an npub because those were previously valid states. They must remain
-- permanently reserved. This table makes the only ambiguous migration choice
-- explicit: which existing alias (if any) should remain active for an owner
-- that already has more than one.
--
-- Applying this migration is safe and does not change public routing. Before
-- applying 046, operators must review unresolved rows and set:
--
--   UPDATE public_name_migration_alias_choices
--      SET active_alias = '<chosen alias>', resolved = TRUE
--    WHERE owner_npub = '<npub>';
--
-- Set active_alias = NULL with resolved = TRUE to keep every historical alias
-- reserved but inactive. Migration 046 fails closed while any row is
-- unresolved or if aliases change after this snapshot. Quiesce name/surface
-- writes between migrations 045 and 046.

BEGIN;

LOCK TABLE users, donation_pages IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE public_name_migration_alias_choices (
    owner_npub       TEXT PRIMARY KEY,
    candidate_aliases TEXT[] NOT NULL,
    active_alias     TEXT,
    resolved         BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (
        active_alias IS NULL
        OR active_alias = ANY(candidate_aliases)
    )
);

INSERT INTO public_name_migration_alias_choices (
    owner_npub,
    candidate_aliases,
    active_alias,
    resolved
)
SELECT
    aliases.owner_npub,
    aliases.candidate_aliases,
    CASE
        WHEN cardinality(aliases.candidate_aliases) = 1
            THEN aliases.candidate_aliases[1]
        ELSE NULL
    END,
    cardinality(aliases.candidate_aliases) = 1
FROM (
    SELECT
        users.npub AS owner_npub,
        array_agg(DISTINCT donation_pages.alias ORDER BY donation_pages.alias)
            AS candidate_aliases
    FROM donation_pages
    JOIN users ON users.nym = donation_pages.nym
    WHERE donation_pages.alias IS NOT NULL
    GROUP BY users.npub
) AS aliases;

DO $$
DECLARE
    unresolved JSONB;
    cross_type_collisions JSONB;
    historical_nym_overages JSONB;
    inactive_or_archived_aliases JSONB;
BEGIN
    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO unresolved
      FROM (
          SELECT owner_npub, candidate_aliases
          FROM public_name_migration_alias_choices
          WHERE resolved = FALSE
          ORDER BY owner_npub
      ) AS conflicts;

    IF unresolved IS NOT NULL THEN
        RAISE NOTICE
            'public-name migration needs explicit alias choices: %',
            unresolved;
    END IF;

    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO cross_type_collisions
      FROM (
          SELECT
              donation_pages.alias AS name,
              alias_users.npub AS alias_owner_npub,
              nym_users.npub AS nym_owner_npub
          FROM donation_pages
          JOIN users AS alias_users ON alias_users.nym = donation_pages.nym
          JOIN users AS nym_users ON nym_users.nym = donation_pages.alias
          WHERE donation_pages.alias IS NOT NULL
          ORDER BY donation_pages.alias
      ) AS conflicts;

    IF cross_type_collisions IS NOT NULL THEN
        RAISE NOTICE
            'grandfathering existing alias/nym name collisions: %',
            cross_type_collisions;
    END IF;

    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO historical_nym_overages
      FROM (
          SELECT npub AS owner_npub, array_agg(nym ORDER BY created_at) AS nyms
          FROM users
          GROUP BY npub
          HAVING COUNT(*) > 1
          ORDER BY npub
      ) AS conflicts;

    IF historical_nym_overages IS NOT NULL THEN
        RAISE NOTICE
            'grandfathering existing multi-nym owners: %',
            historical_nym_overages;
    END IF;

    SELECT jsonb_agg(to_jsonb(conflicts))
      INTO inactive_or_archived_aliases
      FROM (
          SELECT
              donation_pages.alias AS name,
              users.npub AS owner_npub,
              donation_pages.nym,
              donation_pages.kind,
              users.is_active AS nym_active,
              donation_pages.archived_at IS NOT NULL AS surface_archived
          FROM donation_pages
          JOIN users ON users.nym = donation_pages.nym
          WHERE donation_pages.alias IS NOT NULL
            AND (
                users.is_active = FALSE
                OR donation_pages.archived_at IS NOT NULL
            )
          ORDER BY users.npub, donation_pages.alias
      ) AS conflicts;

    IF inactive_or_archived_aliases IS NOT NULL THEN
        RAISE NOTICE
            'preserving aliases found on inactive or archived surfaces: %',
            inactive_or_archived_aliases;
    END IF;
END
$$;

COMMIT;
