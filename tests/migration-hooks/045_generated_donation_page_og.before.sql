-- Representative schema-044 data. The 200-emoji description is valid under
-- the old 280-character CHECK but occupies 800 UTF-8 bytes, exercising the
-- migration's change from scalar-count to byte-count storage protection.
INSERT INTO users (nym, npub, ct_descriptor)
VALUES ('og-migration-fixture', repeat('a', 64), 'fixture-descriptor');

INSERT INTO donation_pages (
    nym, kind, header, description, display_currency, enabled, ct_descriptor
)
VALUES (
    'og-migration-fixture',
    'payment_page',
    'Pre-045 Page',
    repeat('😀', 200),
    'USD',
    TRUE,
    'fixture-descriptor'
);
