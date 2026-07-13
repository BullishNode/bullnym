-- Seed exact transaction bytes before migration 054 exists. The migration
-- must preserve these historical journals as replayable evidence without
-- inventing construction-time fee authority that was never recorded.
DO $$
BEGIN
    IF to_regclass('public.fee_last_known_good_observations') IS NOT NULL THEN
        RAISE EXCEPTION 'fee observation authority unexpectedly exists before migration 054';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'swap_records'
           AND column_name = 'claim_fee_decision_purpose'
    ) OR EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'chain_swap_tx_attempts'
           AND column_name = 'fee_decision_purpose'
    ) THEN
        RAISE EXCEPTION 'construction fee authority unexpectedly exists before migration 054';
    END IF;
    IF (
        SELECT COUNT(*)
          FROM chain_swap_records
         WHERE id IN (
             '53000000-0000-0000-0000-000000000012',
             '53000000-0000-0000-0000-000000000013'
         )
           AND claim_tx_hex IS NULL
    ) <> 2 THEN
        RAISE EXCEPTION 'migration 054 fresh journal fixtures are unavailable';
    END IF;

    UPDATE swap_records
       SET claim_tx_hex = '020000000154',
           claim_txid = repeat('54', 32),
           claim_path = 'script'
     WHERE id = '50000000-0000-0000-0000-000000000002'
       AND claim_tx_hex IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 054 historical Liquid fixture is unavailable';
    END IF;

    INSERT INTO chain_swap_tx_attempts (
        id, chain_swap_id, raw_tx_hex, txid, source_prevouts,
        destination_address, destination_script_hex, destination_vout,
        destination_amount_sat, fee_amount_sat, fee_rate_sat_vb
    ) VALUES (
        '54000000-0000-0000-0000-000000000001',
        '50000000-0000-0000-0000-000000000003',
        '020000000254', repeat('55', 32),
        jsonb_build_array(jsonb_build_object(
            'txid', repeat('56', 32), 'vout', 1
        )),
        'bc1qmigration054historicalrecovery000000000000000000',
        '001454', 0, 69000, 1000, 5.0
    );
END
$$;
