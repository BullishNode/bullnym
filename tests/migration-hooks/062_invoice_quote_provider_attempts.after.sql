-- Exercise the new face-only fiat invoice shape. The invoice carries no
-- mutable/current conversion; the immutable quote owns the exact rate and sat
-- target.
INSERT INTO invoices (
    id, nym_owner, npub_owner, origin,
    fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
    rate_locks_until, bitcoin_address,
    accept_btc, accept_ln, accept_liquid,
    status, pricing_mode, presentation_status, settlement_status, expires_at
) VALUES (
    '62000000-0000-0000-0000-000000000001',
    NULL, repeat('6', 64), 'wallet',
    1000, 'USD', 0, NULL,
    TIMESTAMPTZ '2030-01-01 00:00:00+00',
    'bc1q062faceonlyfiatinvoice00000000000000000000000',
    TRUE, FALSE, FALSE,
    'unpaid', 'fiat_fixed', 'unpaid', 'none',
    TIMESTAMPTZ '2030-01-01 00:00:00+00'
);

BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO invoice_quote_versions (
    invoice_id, rate_minor_per_btc, rate_source,
    rate_observed_at, rate_fetched_at, rate_fresh_until,
    merchant_amount_sat
) VALUES (
    '62000000-0000-0000-0000-000000000001',
    10000000, 'bullbitcoin-pricer:indexPrice',
    clock_timestamp() - INTERVAL '1 second',
    clock_timestamp(),
    clock_timestamp() + INTERVAL '5 minutes',
    10000
);
COMMIT;

INSERT INTO swap_key_allocations (
    root_fingerprint, key_epoch, derivation_scheme_version, child_index,
    purpose, public_key_hex, preimage_hash_hex
) VALUES (
    '6262626262626262', 1, 1, 62001, 'reverse_claim',
    '02' || repeat('62', 32), repeat('63', 32)
);

BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO invoice_quote_provider_attempts (
    invoice_id, quote_version_id, rail, request_key, provider, operation,
    merchant_amount_sat, claim_key_allocation_id, refund_key_allocation_id
)
SELECT q.invoice_id, q.id, 'lightning', repeat('a', 64), 'boltz',
       'fixed_checkout_reverse', q.merchant_amount_sat, a.id, NULL
  FROM invoice_quote_versions q
  CROSS JOIN swap_key_allocations a
 WHERE q.invoice_id = '62000000-0000-0000-0000-000000000001'
   AND a.child_index = 62001;
COMMIT;

DO $$
DECLARE runtime_role_oid OID; owner_oid OID;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'invoices'::regclass
           AND conname = 'invoices_pricing_amount_authority_check'
           AND contype = 'c'
           AND convalidated
    ) OR NOT EXISTS (
        SELECT 1 FROM invoices
         WHERE id = '62000000-0000-0000-0000-000000000001'
           AND pricing_mode = 'fiat_fixed'
           AND fiat_amount_minor = 1000
           AND fiat_currency = 'USD'
           AND amount_sat = 0
           AND rate_minor_per_btc IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 062 fiat amount authority contract is absent';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM invoice_quote_versions
         WHERE invoice_id = '62000000-0000-0000-0000-000000000001'
           AND fiat_face_amount_minor = 1000
           AND fiat_target_amount_minor = 1000
           AND merchant_amount_sat = 10000
    ) OR invoice_quote_credit_for_sats(1000, 10000, 10000000, 9999) <> 999
       OR invoice_quote_credit_for_sats(1000, 10000, 10000000, 10000) <> 1000
    THEN
        RAISE EXCEPTION 'migration 062 remaining-face/credit policy is incorrect';
    END IF;
    IF (SELECT count(*) FROM invoice_quote_provider_attempts) <> 1 THEN
        RAISE EXCEPTION 'migration 062 did not retain one exact provider intent';
    END IF;
    BEGIN
        UPDATE invoice_quote_provider_attempts SET rail = 'bitcoin';
        RAISE EXCEPTION 'migration 062 allowed intent mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL;
    END;
    SELECT oid INTO STRICT runtime_role_oid FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT owner_oid FROM pg_class
     WHERE oid = 'invoice_quote_provider_attempts'::regclass;
    IF runtime_role_oid = owner_oid
       OR pg_has_role(runtime_role_oid, owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, owner_oid, 'SET')
       OR NOT has_table_privilege('bullnym_app', 'invoice_quote_provider_attempts', 'SELECT')
       OR has_table_privilege('bullnym_app', 'invoice_quote_provider_attempts', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'invoice_quote_provider_attempts', 'DELETE')
       OR has_column_privilege('bullnym_app', 'invoice_quote_provider_attempts', 'created_at', 'INSERT')
       OR NOT has_column_privilege('bullnym_app', 'invoice_quote_provider_attempts', 'invoice_id', 'INSERT')
       OR NOT has_column_privilege('bullnym_app', 'invoice_quote_versions', 'fiat_target_amount_minor', 'INSERT')
       OR NOT has_column_privilege('bullnym_app', 'invoice_quote_offers', 'direct_address', 'INSERT')
       OR NOT has_table_privilege('bullnym_app', 'invoice_quote_active_fiat_projection', 'SELECT')
       OR NOT has_function_privilege(
           'bullnym_app',
           'invoice_quote_credit_for_sats(integer,bigint,bigint,bigint)',
           'EXECUTE'
       )
    THEN
        RAISE EXCEPTION 'migration 062 runtime ACL/owner boundary is unsafe';
    END IF;
END
$$;
