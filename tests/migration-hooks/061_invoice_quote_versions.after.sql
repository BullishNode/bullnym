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
    30000000, 'bullbitcoin-pricer:indexPrice',
    clock_timestamp() - INTERVAL '1 second',
    clock_timestamp(),
    clock_timestamp() + INTERVAL '5 minutes',
    3334
);

COMMIT;

DO $$
DECLARE
    quote_row RECORD;
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
       OR quote_row.merchant_amount_sat <> 3334
       OR quote_row.expires_at <> quote_row.created_at + INTERVAL '5 minutes' THEN
        RAISE EXCEPTION 'migration 061 database-owned quote snapshot is incorrect';
    END IF;

    BEGIN
        UPDATE invoice_quote_versions
           SET merchant_amount_sat = merchant_amount_sat + 1
         WHERE invoice_id = '61000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'migration 061 allowed quote mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
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
