-- Earlier upgrade hooks intentionally leave historical fixtures behind. Model
-- the documented production database reset at this test-only boundary; the
-- harness separately clones this empty state and proves that both 058 and 059
-- refuse even one newly inserted ownership row transactionally.
TRUNCATE TABLE users, donation_pages, invoices, swap_records,
    chain_swap_records, outpoint_addresses, swap_key_allocations,
    swap_key_legacy_high_water, recovery_address_commitments,
    rate_limit_events, nym_access_events, processed_webhook_events,
    watcher_lane_progress, fee_last_known_good_observations CASCADE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users)
       OR EXISTS (SELECT 1 FROM donation_pages)
       OR EXISTS (SELECT 1 FROM invoices)
       OR EXISTS (SELECT 1 FROM swap_records)
       OR EXISTS (SELECT 1 FROM chain_swap_records)
       OR EXISTS (SELECT 1 FROM outpoint_addresses)
       OR EXISTS (SELECT 1 FROM swap_key_allocations)
       OR EXISTS (SELECT 1 FROM swap_key_legacy_high_water)
       OR EXISTS (SELECT 1 FROM recovery_address_commitments)
       OR EXISTS (SELECT 1 FROM rate_limit_events)
       OR EXISTS (SELECT 1 FROM nym_access_events)
       OR EXISTS (SELECT 1 FROM processed_webhook_events)
       OR EXISTS (SELECT 1 FROM watcher_lane_progress)
       OR EXISTS (SELECT 1 FROM fee_last_known_good_observations) THEN
        RAISE EXCEPTION 'migration 058 test fixture is not empty';
    END IF;
END
$$;
