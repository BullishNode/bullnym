-- ============================================================================
-- 020: Pre-get_paid user wipe (OPERATOR-GATED, NOT auto-applied)
-- ============================================================================
--
-- Wipes 108 internal/test users + their dependent rows so that migration 021
-- can apply schema changes (npub_owner NOT NULL, coherence CHECKs, etc.)
-- without having to backfill or repair lossy historical data.
--
-- TRUNCATE users CASCADE blast radius (verified 2026-05-09 against bullpay.ca):
--   users:              108 rows
--   invoices:           252 rows  (CASCADE)
--   swap_records:       359 rows  (TRUNCATE CASCADE wipes regardless of FK delete_rule)
--   donation_pages:       2 rows  (CASCADE)
--   outpoint_addresses:  28 rows  (CASCADE)
--   nym_access_events:    1 row   (NOT FK-linked, NOT wiped — survives)
--   rate_limit_events:    0 rows  (NOT FK-linked, NOT wiped — survives)
--
-- Cross-check before running (records 108 users; all clearly synthetic):
--   bullnym test cohorts: bs02-bs11 across 8 timestamps (~80 rows)
--   lifecycle: life01-03, int01, stuck01-03, brk01, inv-*, invs-test*
--   feature/expiry: e02-e06, f04, f05a, f15, pf01-03
--   race: r1race, r5storm
--   reverse-swap-flow: rsf01-03
--   dev: satoshi, satoshi1, satoshi12, francis, francistest, julie, store-test*
--   No real merchant data.
--
-- Apply manually:
--   scp migrations/020_pre_get_paid_user_wipe.sql ubuntu@bullpay:/tmp/
--   ssh ubuntu@bullpay 'sudo -u postgres psql payservice -f /tmp/020_pre_get_paid_user_wipe.sql'
--
-- NOT idempotent. Safe to skip on a fresh database.
-- ============================================================================

BEGIN;

-- Sanity assertion: refuse to run if any user nym does not match the synthetic
-- naming pattern (defense against accidental run on a populated production db).
DO $$
DECLARE
  unexpected_count INT;
BEGIN
  SELECT count(*) INTO unexpected_count
  FROM users
  WHERE nym !~ '^(satoshi[0-9]*|francis(test)?|julie|pf0[0-9]-[0-9]+|r[0-9]+(storm|race-[0-9]+)-[0-9]+|e0[0-9]-[0-9]+|bs[0-9]+-[0-9]+|f0?[0-9]+a?-[0-9]+|rsf0[0-9]-[0-9]+|stuck0[0-9]-[0-9]+|brk0[0-9]-[0-9]+|int0[0-9]-[0-9]+|life0[0-9]-[0-9]+|inv-[0-9]+|invs?-test(-[a-z]+)?|store-test(-[a-z]+)?|f[0-9]+-[0-9]+)$';

  IF unexpected_count > 0 THEN
    RAISE EXCEPTION 'Refusing to TRUNCATE: % user(s) do not match synthetic-test naming pattern. Inspect manually first.', unexpected_count;
  END IF;
END $$;

TRUNCATE users CASCADE;

COMMIT;

-- Post-wipe verification (run manually after COMMIT):
--   SELECT count(*) FROM users;              -- expect 0
--   SELECT count(*) FROM invoices;           -- expect 0
--   SELECT count(*) FROM swap_records;       -- expect 0
--   SELECT count(*) FROM donation_pages;     -- expect 0
--   SELECT count(*) FROM outpoint_addresses; -- expect 0
