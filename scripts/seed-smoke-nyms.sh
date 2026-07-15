#!/usr/bin/env bash
# Seed the two local smoke-test nyms (smokedonate: donation/USD, smokepos:
# POS/CRC) into the bullnym-test-pg Docker database. Idempotent. Re-run
# after any integration-test run — the test suite's cleanup_db() truncates
# users/donation_pages and wipes these rows.
set -euo pipefail

DESC='ct(slip77(9e553d57a2df492db3d99a2a9c0762fd76a6ce6a53a628902a01a5b2c9058c8b),elwpkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/*))#cqvwp6w4'

docker exec -i bullnym-test-pg psql -q -U postgres -d bullnym_test <<SQL
INSERT INTO users (npub, verification_npub, nym, ct_descriptor)
VALUES ('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        'smokedonate', '$DESC')
ON CONFLICT DO NOTHING;
INSERT INTO donation_pages
    (nym, kind, ct_descriptor, header, description, display_currency, enabled)
VALUES ('smokedonate', 'payment_page', '$DESC', 'Smoke Test', 'donation smoke', 'USD', true)
ON CONFLICT (nym, kind) DO UPDATE SET enabled = true, archived_at = NULL;

INSERT INTO users (npub, verification_npub, nym, ct_descriptor)
VALUES ('ffe2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6ffe2',
        'ffe2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6ffe2',
        'smokepos', '$DESC')
ON CONFLICT DO NOTHING;
INSERT INTO donation_pages
    (nym, kind, ct_descriptor, header, description, display_currency, enabled)
VALUES ('smokepos', 'pos', '$DESC', 'Smoke POS', 'pos smoke', 'CRC', true)
ON CONFLICT (nym, kind) DO UPDATE SET enabled = true, archived_at = NULL;

SELECT nym, kind, display_currency FROM donation_pages WHERE nym LIKE 'smoke%';
SQL
