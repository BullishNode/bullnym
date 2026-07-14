-- Representative non-empty schema-056 history for the permanent-name
-- preflight.  Earlier hooks already left real users, surfaces, invoices, and
-- swap evidence in this database; do not erase any of it.
DO $$
BEGIN
    IF current_database() <> 'bullnym_upgrade' THEN
        RAISE EXCEPTION 'migration 058 fixture refused outside bullnym_upgrade';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users)
       OR NOT EXISTS (SELECT 1 FROM donation_pages)
       OR NOT EXISTS (SELECT 1 FROM invoices) THEN
        RAISE EXCEPTION 'migration 058 requires preserved historical fixtures';
    END IF;
    IF to_regclass('public.public_names') IS NOT NULL
       OR to_regclass('public.public_name_migration_choices') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 058 authority exists before preflight';
    END IF;
END
$$;

-- A historical invoice can be the last surviving record of an alias after a
-- surface changed/cleared it.  Its exact nym/npub tuple makes the attribution
-- authoritative and migration 059 must retain it for old invoice rendering.
UPDATE invoices
   SET public_slug = 'invoice-only-alias'
 WHERE id = '46000000-0000-0000-0000-000000000001'
   AND nym_owner = 'og-migration-fixture'
   AND npub_owner = repeat('a', 64);
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM invoices
        WHERE id = '46000000-0000-0000-0000-000000000001'
          AND public_slug = 'invoice-only-alias'
    ) THEN
        RAISE EXCEPTION 'migration 058 invoice-only alias fixture is unavailable';
    END IF;
END
$$;

-- A3: one active row constrains the canonical nym despite older inactive
-- history for the same owner.
INSERT INTO users (nym, npub, ct_descriptor, next_addr_idx, is_active)
VALUES
    ('active-canonical', repeat('b', 64), 'active-canonical-descriptor', 9, TRUE),
    ('inactive-tombstone', repeat('b', 64), 'inactive-tombstone-descriptor', 0, FALSE);

-- The only real operator choice: a fully-offline owner with two historical
-- nyms.  Migration 058 must not choose silently.
INSERT INTO users (nym, npub, ct_descriptor, is_active)
VALUES
    ('operator-choice-one', repeat('d', 64), 'operator-choice-one-descriptor', FALSE),
    ('operator-choice-two', repeat('d', 64), 'operator-choice-two-descriptor', FALSE);

-- One owner historically used a different alias per surface.  Both names
-- remain reservations; the operator explicitly selects one canonical alias.
INSERT INTO users (nym, npub, ct_descriptor, is_active)
VALUES ('multi-alias-owner', repeat('e', 64), 'multi-alias-owner-descriptor', TRUE);

INSERT INTO donation_pages (
    nym, kind, header, description, display_currency, enabled,
    ct_descriptor, next_addr_idx, alias
)
VALUES
    (
        'multi-alias-owner', 'payment_page', 'Multi alias Page',
        'Historical Page alias', 'USD', TRUE,
        'multi-alias-page-descriptor', 12, 'shop-page'
    ),
    (
        'multi-alias-owner', 'pos', 'Multi alias POS',
        'Historical POS alias', 'USD', TRUE,
        'multi-alias-pos-descriptor', 8, 'shop-pos'
    );

-- A historical typed collision is legal to preserve: this alias equals the
-- nym left by migration hook 045, but belongs to a different owner.
INSERT INTO users (nym, npub, ct_descriptor, is_active)
VALUES ('collision-alias-owner', repeat('f', 64), 'collision-owner-descriptor', TRUE);

INSERT INTO donation_pages (
    nym, kind, header, description, display_currency, enabled,
    ct_descriptor, alias
)
VALUES (
    'collision-alias-owner', 'payment_page', 'Collision fixture',
    'Typed collision alias', 'USD', TRUE,
    'collision-page-descriptor', 'og-migration-fixture'
);

-- A10: the canonical alias is discovered on an archived Page, while the
-- owner's live POS currently falls back to its nym URL and must appear in the
-- merchant communication report.
INSERT INTO users (nym, npub, ct_descriptor, is_active)
VALUES ('archived-alias-owner', repeat('1', 64), 'archived-owner-descriptor', TRUE);

INSERT INTO donation_pages (
    nym, kind, header, description, display_currency, enabled,
    archived_at, ct_descriptor, alias
)
VALUES
    (
        'archived-alias-owner', 'payment_page', 'Archived Page',
        'Archived alias source', 'USD', FALSE, clock_timestamp(),
        'archived-page-descriptor', 'old-shop'
    ),
    (
        'archived-alias-owner', 'pos', 'Live POS',
        'Live nym URL before cutover', 'USD', TRUE, NULL,
        'archived-owner-pos-descriptor', NULL
    );

-- A2: this Page really uses the LA fallback (no POS sibling).  Its own cursor
-- is stale; 059 must copy the descriptor and retain the higher user cursor.
INSERT INTO users (nym, npub, ct_descriptor, next_addr_idx, is_active)
VALUES ('fallback-page-owner', repeat('2', 64), 'fallback-user-descriptor', 118, TRUE);

INSERT INTO donation_pages (
    nym, kind, header, description, display_currency, enabled,
    ct_descriptor, next_addr_idx
)
VALUES (
    'fallback-page-owner', 'payment_page', 'Fallback Page',
    'Cursor migration fixture', 'USD', TRUE, NULL, 3
);
