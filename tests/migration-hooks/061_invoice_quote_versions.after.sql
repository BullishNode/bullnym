DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM invoice_quote_versions) THEN
        RAISE EXCEPTION 'migration 061 fabricated quote versions from legacy rate caches';
    END IF;

    IF EXISTS (
        SELECT 1 FROM swap_records
         WHERE invoice_quote_version_id IS NOT NULL
            OR invoice_quote_offer_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE invoice_quote_version_id IS NOT NULL
            OR invoice_quote_offer_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM invoice_payment_events
         WHERE invoice_quote_version_id IS NOT NULL
            OR invoice_quote_offer_id IS NOT NULL
            OR quote_first_observed_at IS NOT NULL
            OR fiat_credited_minor IS NOT NULL
            OR fiat_credit_policy IS NOT NULL
            OR fiat_valued_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 061 invented legacy quote/offer attribution';
    END IF;
END
$$;

-- Exercise the exact least-privilege runtime insertion path. Database-owned
-- identity, sequence, snapshot, and five-minute times are deliberately omitted.
BEGIN;
SET LOCAL ROLE bullnym_app;

INSERT INTO invoice_quote_versions (
    invoice_id, rate_minor_per_btc, rate_source,
    rate_observed_at, rate_fetched_at, rate_fresh_until,
    merchant_amount_sat
) VALUES (
    '61000000-0000-0000-0000-000000000001',
    10000000, 'bullbitcoin-pricer:indexPrice',
    clock_timestamp() - INTERVAL '1 second',
    clock_timestamp(),
    clock_timestamp() + INTERVAL '5 minutes',
    10000
);

INSERT INTO invoice_quote_offers (
    invoice_id, quote_version_id, rail, offer_kind, request_key,
    provider, provider_offer_id, payer_amount_sat, expires_at
)
SELECT invoice_id, id, 'bitcoin', 'direct', repeat('6', 64),
       NULL, NULL, merchant_amount_sat, expires_at
  FROM invoice_quote_versions
 WHERE invoice_id = '61000000-0000-0000-0000-000000000001';

INSERT INTO invoice_payment_events (
    id, invoice_id, rail, source, event_key, amount_sat,
    txid, vout, address,
    invoice_quote_version_id, invoice_quote_offer_id,
    quote_first_observed_at
)
SELECT '61000000-0000-0000-0000-000000000002',
       q.invoice_id, 'bitcoin', 'bitcoin_direct',
       'bitcoin_direct:' || repeat('61', 32) || ':0',
       q.merchant_amount_sat, repeat('61', 32), 0,
       'bc1q061legacyfiatinvoice000000000000000000000000',
       q.id, o.id, clock_timestamp()
  FROM invoice_quote_versions q
  JOIN invoice_quote_offers o ON o.quote_version_id = q.id
 WHERE q.invoice_id = '61000000-0000-0000-0000-000000000001';

COMMIT;

DO $$
DECLARE
    quote_row RECORD;
    event_row RECORD;
    runtime_role_oid OID;
    owner_oid OID;
BEGIN
    SELECT version_number, fiat_face_amount_minor, fiat_currency,
           merchant_amount_sat, created_at, expires_at
      INTO STRICT quote_row
      FROM invoice_quote_versions
     WHERE invoice_id = '61000000-0000-0000-0000-000000000001';
    IF quote_row.version_number <> 1
       OR quote_row.fiat_face_amount_minor <> 1000
       OR quote_row.fiat_currency <> 'USD'
       OR quote_row.merchant_amount_sat <> 10000
       OR quote_row.expires_at <> quote_row.created_at + INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'migration 061 database-owned quote snapshot is incorrect';
    END IF;

    SELECT invoice_quote_version_id, invoice_quote_offer_id,
           quote_first_observed_at, fiat_credited_minor,
           fiat_credit_policy, fiat_valued_at
      INTO STRICT event_row
      FROM invoice_payment_events
     WHERE id = '61000000-0000-0000-0000-000000000002';
    IF event_row.invoice_quote_version_id IS NULL
       OR event_row.invoice_quote_offer_id IS NULL
       OR event_row.quote_first_observed_at IS NULL
       OR event_row.fiat_credited_minor IS NOT NULL
       OR event_row.fiat_credit_policy IS NOT NULL
       OR event_row.fiat_valued_at IS NOT NULL THEN
        RAISE EXCEPTION 'migration 061 did not retain policy-neutral payment attribution';
    END IF;

    BEGIN
        UPDATE invoice_quote_versions
           SET merchant_amount_sat = merchant_amount_sat + 1
         WHERE invoice_id = '61000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'migration 061 allowed quote mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        UPDATE invoice_payment_events
           SET invoice_quote_version_id = NULL,
               invoice_quote_offer_id = NULL,
               quote_first_observed_at = NULL
         WHERE id = '61000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 061 allowed payment attribution mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        UPDATE invoice_payment_events
           SET fiat_credited_minor = 1000,
               fiat_credit_policy = 'undecided_policy_v1',
               fiat_valued_at = clock_timestamp()
         WHERE id = '61000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 061 allowed fiat valuation before the product decision';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT owner_oid
      FROM pg_class WHERE oid = 'invoice_quote_versions'::REGCLASS;
    IF runtime_role_oid = owner_oid
       OR pg_has_role(runtime_role_oid, owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, owner_oid, 'SET')
       OR NOT has_table_privilege('bullnym_app', 'invoice_quote_versions', 'SELECT')
       OR has_table_privilege('bullnym_app', 'invoice_quote_versions', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'invoice_quote_versions', 'DELETE')
       OR has_table_privilege('bullnym_app', 'invoice_quote_versions', 'TRUNCATE')
       OR NOT has_column_privilege(
           'bullnym_app', 'invoice_quote_versions', 'invoice_id', 'INSERT'
       )
       OR has_column_privilege(
           'bullnym_app', 'invoice_quote_versions', 'version_number', 'INSERT'
       )
       OR has_column_privilege(
           'bullnym_app', 'invoice_quote_versions', 'created_at', 'INSERT'
       ) THEN
        RAISE EXCEPTION 'migration 061 quote runtime ACL/owner boundary is unsafe';
    END IF;
END
$$;
