-- Historical journals keep their exact bytes and remain readable without
-- fabricated fee authority. Neither their bytes nor their absent authority
-- may be rewritten after the migration.
DO $$
DECLARE
    historical_liquid_hex TEXT;
    historical_bitcoin_hex TEXT;
    authority_value_count INTEGER;
BEGIN
    SELECT claim_tx_hex,
           num_nonnulls(
               claim_actual_fee_sat, claim_actual_fee_rate_sat_vb,
               claim_fee_decision_purpose, claim_fee_decision_rail,
               claim_fee_decision_target, claim_fee_decision_source,
               claim_fee_decision_rate_sat_vb,
               claim_fee_decision_quoted_at_unix,
               claim_fee_decision_evaluated_at_unix,
               claim_fee_decision_freshness_age_secs,
               claim_fee_decision_freshness_max_age_secs,
               claim_fee_decision_provenance,
               claim_fee_decision_policy_floor_sat_vb,
               claim_fee_decision_policy_cap_sat_vb,
               claim_fee_decision_policy_version
           )
      INTO STRICT historical_liquid_hex, authority_value_count
      FROM swap_records
     WHERE id = '50000000-0000-0000-0000-000000000002';
    IF historical_liquid_hex <> '020000000154'
       OR authority_value_count <> 0 THEN
        RAISE EXCEPTION 'migration 054 changed or fabricated historical Liquid authority';
    END IF;

    SELECT raw_tx_hex,
           num_nonnulls(
               fee_decision_purpose, fee_decision_rail,
               fee_decision_target, fee_decision_source,
               fee_decision_rate_sat_vb,
               fee_decision_quoted_at_unix,
               fee_decision_evaluated_at_unix,
               fee_decision_freshness_age_secs,
               fee_decision_freshness_max_age_secs,
               fee_decision_provenance,
               fee_decision_policy_floor_sat_vb,
               fee_decision_policy_cap_sat_vb,
               fee_decision_policy_version
           )
      INTO STRICT historical_bitcoin_hex, authority_value_count
      FROM chain_swap_tx_attempts
     WHERE id = '54000000-0000-0000-0000-000000000001';
    IF historical_bitcoin_hex <> '020000000254'
       OR authority_value_count <> 0 THEN
        RAISE EXCEPTION 'migration 054 changed or fabricated historical Bitcoin authority';
    END IF;

    BEGIN
        UPDATE swap_records
           SET claim_tx_hex = '02000000015400'
         WHERE id = '50000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 054 allowed historical Liquid byte mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE swap_records
           SET claim_actual_fee_sat = 210,
               claim_actual_fee_rate_sat_vb = 1.5,
               claim_fee_decision_purpose = 'reverse_liquid_claim',
               claim_fee_decision_rail = 'liquid',
               claim_fee_decision_target = '1',
               claim_fee_decision_source = 'liquid_live',
               claim_fee_decision_rate_sat_vb = 1.5,
               claim_fee_decision_quoted_at_unix = 1700000000,
               claim_fee_decision_evaluated_at_unix = 1700000005,
               claim_fee_decision_freshness_age_secs = 5,
               claim_fee_decision_freshness_max_age_secs = 60,
               claim_fee_decision_provenance = 'migration-054-fabricated',
               claim_fee_decision_policy_floor_sat_vb = 0.1,
               claim_fee_decision_policy_cap_sat_vb = 10.0,
               claim_fee_decision_policy_version = 'review25-v1'
         WHERE id = '50000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 054 allowed historical Liquid authority backfill';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_tx_attempts
           SET raw_tx_hex = '02000000025400'
         WHERE id = '54000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'migration 054 allowed historical Bitcoin byte mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_tx_attempts
           SET fee_decision_purpose = 'bitcoin_recovery',
               fee_decision_rail = 'bitcoin',
               fee_decision_target = 'fastestFee',
               fee_decision_source = 'bitcoin_live',
               fee_decision_rate_sat_vb = 5.0,
               fee_decision_quoted_at_unix = 1700000000,
               fee_decision_evaluated_at_unix = 1700000005,
               fee_decision_freshness_age_secs = 5,
               fee_decision_freshness_max_age_secs = 60,
               fee_decision_provenance = 'migration-054-fabricated',
               fee_decision_policy_floor_sat_vb = 1.0,
               fee_decision_policy_cap_sat_vb = 100.0,
               fee_decision_policy_version = 'review25-v1'
         WHERE id = '54000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'migration 054 allowed historical Bitcoin authority backfill';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    IF NOT EXISTS (
        SELECT 1
          FROM swap_records
         WHERE id = '50000000-0000-0000-0000-000000000002'
           AND claim_tx_hex = '020000000154'
           AND claim_fee_decision_purpose IS NULL
    ) OR NOT EXISTS (
        SELECT 1
          FROM chain_swap_tx_attempts
         WHERE id = '54000000-0000-0000-0000-000000000001'
           AND raw_tx_hex = '020000000254'
           AND fee_decision_purpose IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 054 historical journal refusal changed persisted evidence';
    END IF;
END
$$;

-- New Liquid bytes require one complete atomic authority packet. Once that
-- packet is accepted, both the bytes and every authority input are immutable.
DO $$
BEGIN
    BEGIN
        UPDATE chain_swap_records
           SET claim_tx_hex = '020000000354'
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 054 allowed new Liquid bytes without authority';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    IF EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012'
           AND claim_tx_hex IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 054 retained refused incomplete Liquid bytes';
    END IF;

    BEGIN
        UPDATE chain_swap_records
           SET claim_tx_hex = '020000000354',
               claim_fee_decision_purpose = 'chain_liquid_claim'
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 054 allowed a partial Liquid authority packet';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    UPDATE chain_swap_records
       SET claim_tx_hex = '020000000354',
           claim_txid = repeat('57', 32),
           claim_actual_fee_sat = 210,
           claim_actual_fee_rate_sat_vb = 1.5,
           claim_fee_decision_purpose = 'chain_liquid_claim',
           claim_fee_decision_rail = 'liquid',
           claim_fee_decision_target = '1',
           claim_fee_decision_source = 'liquid_live',
           claim_fee_decision_rate_sat_vb = 1.5,
           claim_fee_decision_quoted_at_unix = 1700000100,
           claim_fee_decision_evaluated_at_unix = 1700000105,
           claim_fee_decision_freshness_age_secs = 5,
           claim_fee_decision_freshness_max_age_secs = 60,
           claim_fee_decision_provenance = 'migration-054-liquid-live',
           claim_fee_decision_policy_floor_sat_vb = 0.1,
           claim_fee_decision_policy_cap_sat_vb = 10.0,
           claim_fee_decision_policy_version = 'review25-v1'
     WHERE id = '53000000-0000-0000-0000-000000000012';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 054 complete Liquid fixture is unavailable';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012'
           AND claim_tx_hex = '020000000354'
           AND claim_txid = repeat('57', 32)
           AND claim_actual_fee_sat = 210
           AND claim_actual_fee_rate_sat_vb = 1.5
           AND claim_fee_decision_purpose = 'chain_liquid_claim'
           AND claim_fee_decision_rail = 'liquid'
           AND claim_fee_decision_target = '1'
           AND claim_fee_decision_source = 'liquid_live'
           AND claim_fee_decision_rate_sat_vb = 1.5
           AND claim_fee_decision_quoted_at_unix = 1700000100
           AND claim_fee_decision_evaluated_at_unix = 1700000105
           AND claim_fee_decision_freshness_age_secs = 5
           AND claim_fee_decision_freshness_max_age_secs = 60
           AND claim_fee_decision_provenance = 'migration-054-liquid-live'
           AND claim_fee_decision_policy_floor_sat_vb = 0.1
           AND claim_fee_decision_policy_cap_sat_vb = 10.0
           AND claim_fee_decision_policy_version = 'review25-v1'
    ) THEN
        RAISE EXCEPTION 'migration 054 did not retain exact complete Liquid authority';
    END IF;

    BEGIN
        UPDATE chain_swap_records
           SET claim_tx_hex = '02000000035400'
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 054 allowed journaled Liquid byte mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_records
           SET claim_fee_decision_rate_sat_vb = 2.0
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 054 allowed Liquid authority mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

-- New Bitcoin recovery bytes obey the same atomic rule on the attempt
-- journal, including the exact upstream target and accepted LKG provenance.
DO $$
BEGIN
    BEGIN
        INSERT INTO chain_swap_tx_attempts (
            id, chain_swap_id, raw_tx_hex, txid, source_prevouts,
            destination_address, destination_script_hex, destination_vout,
            destination_amount_sat, fee_amount_sat, fee_rate_sat_vb
        ) VALUES (
            '54000000-0000-0000-0000-000000000002',
            '53000000-0000-0000-0000-000000000013',
            '020000000454', repeat('58', 32),
            jsonb_build_array(jsonb_build_object(
                'txid', repeat('59', 32), 'vout', 2
            )),
            'bc1qmigration054completerecovery0000000000000000000',
            '001554', 0, 24000, 1000, 5.0
        );
        RAISE EXCEPTION 'migration 054 allowed new Bitcoin bytes without authority';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    IF EXISTS (
        SELECT 1
          FROM chain_swap_tx_attempts
         WHERE id = '54000000-0000-0000-0000-000000000002'
    ) THEN
        RAISE EXCEPTION 'migration 054 retained refused incomplete Bitcoin bytes';
    END IF;

    BEGIN
        INSERT INTO chain_swap_tx_attempts (
            id, chain_swap_id, raw_tx_hex, txid, source_prevouts,
            destination_address, destination_script_hex, destination_vout,
            destination_amount_sat, fee_amount_sat, fee_rate_sat_vb,
            fee_decision_purpose
        ) VALUES (
            '54000000-0000-0000-0000-000000000002',
            '53000000-0000-0000-0000-000000000013',
            '020000000454', repeat('58', 32),
            jsonb_build_array(jsonb_build_object(
                'txid', repeat('59', 32), 'vout', 2
            )),
            'bc1qmigration054completerecovery0000000000000000000',
            '001554', 0, 24000, 1000, 5.0, 'bitcoin_recovery'
        );
        RAISE EXCEPTION 'migration 054 allowed a partial Bitcoin authority packet';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO chain_swap_tx_attempts (
        id, chain_swap_id, raw_tx_hex, txid, source_prevouts,
        destination_address, destination_script_hex, destination_vout,
        destination_amount_sat, fee_amount_sat, fee_rate_sat_vb,
        fee_decision_purpose, fee_decision_rail, fee_decision_target,
        fee_decision_source, fee_decision_rate_sat_vb,
        fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix,
        fee_decision_freshness_age_secs,
        fee_decision_freshness_max_age_secs, fee_decision_provenance,
        fee_decision_policy_floor_sat_vb, fee_decision_policy_cap_sat_vb,
        fee_decision_policy_version
    ) VALUES (
        '54000000-0000-0000-0000-000000000002',
        '53000000-0000-0000-0000-000000000013',
        '020000000454', repeat('58', 32),
        jsonb_build_array(jsonb_build_object(
            'txid', repeat('59', 32), 'vout', 2
        )),
        'bc1qmigration054completerecovery0000000000000000000',
        '001554', 0, 24000, 1000, 5.0,
        'bitcoin_recovery', 'bitcoin', 'fastestFee',
        'bitcoin_last_known_good', 5.0,
        1700000200, 1700000205, 5, 60,
        'migration-054-bitcoin-last-known-good',
        1.0, 100.0, 'review25-v1'
    );

    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_tx_attempts
         WHERE id = '54000000-0000-0000-0000-000000000002'
           AND chain_swap_id = '53000000-0000-0000-0000-000000000013'
           AND raw_tx_hex = '020000000454'
           AND txid = repeat('58', 32)
           AND fee_amount_sat = 1000
           AND fee_rate_sat_vb = 5.0
           AND fee_decision_purpose = 'bitcoin_recovery'
           AND fee_decision_rail = 'bitcoin'
           AND fee_decision_target = 'fastestFee'
           AND fee_decision_source = 'bitcoin_last_known_good'
           AND fee_decision_rate_sat_vb = 5.0
           AND fee_decision_quoted_at_unix = 1700000200
           AND fee_decision_evaluated_at_unix = 1700000205
           AND fee_decision_freshness_age_secs = 5
           AND fee_decision_freshness_max_age_secs = 60
           AND fee_decision_provenance =
               'migration-054-bitcoin-last-known-good'
           AND fee_decision_policy_floor_sat_vb = 1.0
           AND fee_decision_policy_cap_sat_vb = 100.0
           AND fee_decision_policy_version = 'review25-v1'
    ) THEN
        RAISE EXCEPTION 'migration 054 did not retain exact complete Bitcoin authority';
    END IF;

    BEGIN
        UPDATE chain_swap_tx_attempts
           SET raw_tx_hex = '02000000045400'
         WHERE id = '54000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 054 allowed journaled Bitcoin byte mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_tx_attempts
           SET fee_decision_rate_sat_vb = 6.0
         WHERE id = '54000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 054 allowed Bitcoin authority mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

-- The durable quote cache admits only exact rail/source/target combinations
-- at a non-future, live clock and only advances monotonically per rail.
DO $$
BEGIN
    BEGIN
        INSERT INTO fee_last_known_good_observations (
            rail, generation, rate_sat_per_vbyte, observed_at_unix,
            source, target, provenance, accepted_at_unix,
            live_max_age_secs, last_known_good_max_age_secs
        ) VALUES (
            'litecoin', 1, 5.0, 100, 'bitcoin_live', 'fastestFee',
            'migration-054-invalid-rail', 105, 10, 300
        );
        RAISE EXCEPTION 'migration 054 accepted an unknown fee rail';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO fee_last_known_good_observations (
            rail, generation, rate_sat_per_vbyte, observed_at_unix,
            source, target, provenance, accepted_at_unix,
            live_max_age_secs, last_known_good_max_age_secs
        ) VALUES (
            'bitcoin', 1, 5.0, 100, 'bitcoin_live', '1',
            'migration-054-invalid-target', 105, 10, 300
        );
        RAISE EXCEPTION 'migration 054 accepted a cross-rail fee target';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO fee_last_known_good_observations (
            rail, generation, rate_sat_per_vbyte, observed_at_unix,
            source, target, provenance, accepted_at_unix,
            live_max_age_secs, last_known_good_max_age_secs
        ) VALUES (
            'liquid', 1, 0.25, 200, 'bitcoin_live', '1',
            'migration-054-invalid-source', 205, 10, 300
        );
        RAISE EXCEPTION 'migration 054 accepted a cross-rail fee source';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO fee_last_known_good_observations (
            rail, generation, rate_sat_per_vbyte, observed_at_unix,
            source, target, provenance, accepted_at_unix,
            live_max_age_secs, last_known_good_max_age_secs
        ) VALUES (
            'bitcoin', 1, 5.0, 100, 'bitcoin_live', 'fastestFee',
            'migration-054-future-clock', 99, 10, 300
        );
        RAISE EXCEPTION 'migration 054 accepted a future fee observation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO fee_last_known_good_observations (
            rail, generation, rate_sat_per_vbyte, observed_at_unix,
            source, target, provenance, accepted_at_unix,
            live_max_age_secs, last_known_good_max_age_secs
        ) VALUES (
            'bitcoin', 1, 5.0, 100, 'bitcoin_live', 'fastestFee',
            'migration-054-stale-clock', 111, 10, 300
        );
        RAISE EXCEPTION 'migration 054 accepted a stale live fee observation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO fee_last_known_good_observations (
            rail, generation, rate_sat_per_vbyte, observed_at_unix,
            source, target, provenance, accepted_at_unix,
            live_max_age_secs, last_known_good_max_age_secs
        ) VALUES (
            'bitcoin', 2, 5.0, 100, 'bitcoin_live', 'fastestFee',
            'migration-054-invalid-first-generation', 105, 10, 300
        );
        RAISE EXCEPTION 'migration 054 accepted a noninitial first generation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO fee_last_known_good_observations (
        rail, generation, rate_sat_per_vbyte, observed_at_unix,
        source, target, provenance, accepted_at_unix,
        live_max_age_secs, last_known_good_max_age_secs
    ) VALUES
        (
            'bitcoin', 1, 5.0, 100, 'bitcoin_live', 'fastestFee',
            'migration-054-bitcoin-live', 105, 10, 300
        ),
        (
            'liquid', 1, 0.25, 200, 'liquid_live', '1',
            'migration-054-liquid-live', 205, 10, 300
        );

    BEGIN
        UPDATE fee_last_known_good_observations
           SET generation = 2,
               observed_at_unix = 100,
               accepted_at_unix = 105
         WHERE rail = 'bitcoin';
        RAISE EXCEPTION 'migration 054 allowed a nonadvancing fee observation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    UPDATE fee_last_known_good_observations
       SET generation = 2,
           rate_sat_per_vbyte = 6.0,
           observed_at_unix = 110,
           provenance = 'migration-054-bitcoin-live-next',
           accepted_at_unix = 115
     WHERE rail = 'bitcoin';

    IF (SELECT COUNT(*) FROM fee_last_known_good_observations) <> 2
       OR NOT EXISTS (
            SELECT 1
              FROM fee_last_known_good_observations
             WHERE rail = 'bitcoin'
               AND generation = 2
               AND rate_sat_per_vbyte = 6.0
               AND observed_at_unix = 110
               AND source = 'bitcoin_live'
               AND target = 'fastestFee'
               AND provenance = 'migration-054-bitcoin-live-next'
               AND accepted_at_unix = 115
               AND live_max_age_secs = 10
               AND last_known_good_max_age_secs = 300
       ) OR NOT EXISTS (
            SELECT 1
              FROM fee_last_known_good_observations
             WHERE rail = 'liquid'
               AND generation = 1
               AND rate_sat_per_vbyte = 0.25
               AND observed_at_unix = 200
               AND source = 'liquid_live'
               AND target = '1'
               AND provenance = 'migration-054-liquid-live'
               AND accepted_at_unix = 205
               AND live_max_age_secs = 10
               AND last_known_good_max_age_secs = 300
       ) THEN
        RAISE EXCEPTION 'migration 054 did not retain exact rail-local fee observations';
    END IF;
END
$$;
