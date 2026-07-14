-- Migration 055 must not fabricate a Liquid journal for historical bytes that
-- are no longer claimable.  The exact migration-054 packet remains intact and
-- can only acquire its original journal through a new, fully-authorized write.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012'
           AND status = 'user_lock_mempool'
           AND claim_tx_hex = '020000000354'
           AND claim_txid = repeat('57', 32)
           AND claim_fee_decision_purpose = 'chain_liquid_claim'
           AND claim_fee_decision_policy_version = 'review25-v1'
    ) OR EXISTS (
        SELECT 1
          FROM chain_swap_tx_attempts
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012'
           AND purpose IN ('liquid_claim', 'liquid_claim_replacement')
    ) THEN
        RAISE EXCEPTION 'migration 055 changed or fabricated historical Liquid evidence';
    END IF;
END
$$;

-- Every new attempt requires one complete Review-25 packet.  A complete but
-- divergent initial Liquid packet is also rejected: it must equal the parent
-- bytes, actual fee, and accepted fee decision written in the same transaction.
DO $$
BEGIN
    BEGIN
        INSERT INTO chain_swap_tx_attempts (
            id, chain_swap_id, purpose, raw_tx_hex, txid, source_prevouts,
            destination_address, destination_script_hex,
            destination_asset_id, destination_vout,
            destination_amount_sat, fee_amount_sat, fee_rate_sat_vb,
            liquid_blinding_key_hex
        )
        SELECT '55000000-0000-0000-0000-000000000001', id,
               'liquid_claim', claim_tx_hex, claim_txid,
               jsonb_build_array(jsonb_build_object(
                   'txid', repeat('61', 32), 'vout', 0
               )),
               merchant_liquid_destination, '001655', liquid_asset_id,
               0, 25000, claim_actual_fee_sat, claim_actual_fee_rate_sat_vb,
               repeat('62', 32)
          FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 055 allowed Liquid bytes without authority';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO chain_swap_tx_attempts (
            id, chain_swap_id, purpose, raw_tx_hex, txid, source_prevouts,
            destination_address, destination_script_hex,
            destination_asset_id, destination_vout,
            destination_amount_sat, fee_amount_sat, fee_rate_sat_vb,
            liquid_blinding_key_hex, fee_decision_purpose
        )
        SELECT '55000000-0000-0000-0000-000000000001', id,
               'liquid_claim', claim_tx_hex, claim_txid,
               jsonb_build_array(jsonb_build_object(
                   'txid', repeat('61', 32), 'vout', 0
               )),
               merchant_liquid_destination, '001655', liquid_asset_id,
               0, 25000, claim_actual_fee_sat, claim_actual_fee_rate_sat_vb,
               repeat('62', 32), 'chain_liquid_claim'
          FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 055 allowed a partial Liquid authority packet';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO chain_swap_tx_attempts (
            id, chain_swap_id, purpose, raw_tx_hex, txid, source_prevouts,
            destination_address, destination_script_hex,
            destination_asset_id, destination_vout,
            destination_amount_sat, fee_amount_sat, fee_rate_sat_vb,
            liquid_blinding_key_hex,
            fee_decision_purpose, fee_decision_rail, fee_decision_target,
            fee_decision_source, fee_decision_rate_sat_vb,
            fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix,
            fee_decision_freshness_age_secs,
            fee_decision_freshness_max_age_secs, fee_decision_provenance,
            fee_decision_policy_floor_sat_vb,
            fee_decision_policy_cap_sat_vb, fee_decision_policy_version
        )
        SELECT '55000000-0000-0000-0000-000000000001', id,
               'liquid_claim', claim_tx_hex, claim_txid,
               jsonb_build_array(jsonb_build_object(
                   'txid', repeat('61', 32), 'vout', 0
               )),
               merchant_liquid_destination, '001655', liquid_asset_id,
               0, 25000, claim_actual_fee_sat, claim_actual_fee_rate_sat_vb,
               repeat('62', 32),
               claim_fee_decision_purpose, claim_fee_decision_rail,
               claim_fee_decision_target, claim_fee_decision_source,
               claim_fee_decision_rate_sat_vb,
               claim_fee_decision_quoted_at_unix,
               claim_fee_decision_evaluated_at_unix,
               claim_fee_decision_freshness_age_secs,
               claim_fee_decision_freshness_max_age_secs,
               'migration-055-divergent',
               claim_fee_decision_policy_floor_sat_vb,
               claim_fee_decision_policy_cap_sat_vb,
               claim_fee_decision_policy_version
          FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 055 allowed divergent Liquid authority';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    IF EXISTS (
        SELECT 1
          FROM chain_swap_tx_attempts
         WHERE id = '55000000-0000-0000-0000-000000000001'
    ) THEN
        RAISE EXCEPTION 'migration 055 retained a refused Liquid attempt';
    END IF;
END
$$;

-- Exact initial Liquid authority, a fresh-authority linked replacement, and a
-- normal Bitcoin recovery authority all remain admissible.
INSERT INTO chain_swap_tx_attempts (
    id, chain_swap_id, purpose, raw_tx_hex, txid, source_prevouts,
    destination_address, destination_script_hex, destination_asset_id,
    destination_vout, destination_amount_sat, fee_amount_sat, fee_rate_sat_vb,
    liquid_blinding_key_hex,
    fee_decision_purpose, fee_decision_rail, fee_decision_target,
    fee_decision_source, fee_decision_rate_sat_vb,
    fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix,
    fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs,
    fee_decision_provenance, fee_decision_policy_floor_sat_vb,
    fee_decision_policy_cap_sat_vb, fee_decision_policy_version
)
SELECT '55000000-0000-0000-0000-000000000001', id,
       'liquid_claim', claim_tx_hex, claim_txid,
       jsonb_build_array(jsonb_build_object(
           'txid', repeat('61', 32), 'vout', 0
       )),
       merchant_liquid_destination, '001655', liquid_asset_id,
       0, 25000, claim_actual_fee_sat, claim_actual_fee_rate_sat_vb,
       repeat('62', 32),
       claim_fee_decision_purpose, claim_fee_decision_rail,
       claim_fee_decision_target, claim_fee_decision_source,
       claim_fee_decision_rate_sat_vb, claim_fee_decision_quoted_at_unix,
       claim_fee_decision_evaluated_at_unix,
       claim_fee_decision_freshness_age_secs,
       claim_fee_decision_freshness_max_age_secs,
       claim_fee_decision_provenance,
       claim_fee_decision_policy_floor_sat_vb,
       claim_fee_decision_policy_cap_sat_vb,
       claim_fee_decision_policy_version
  FROM chain_swap_records
 WHERE id = '53000000-0000-0000-0000-000000000012';

INSERT INTO chain_swap_tx_attempts (
    id, chain_swap_id, purpose, replaces_txid, raw_tx_hex, txid,
    source_prevouts, destination_address, destination_script_hex,
    destination_asset_id, destination_vout, destination_amount_sat,
    fee_amount_sat, fee_rate_sat_vb, liquid_blinding_key_hex,
    fee_decision_purpose, fee_decision_rail, fee_decision_target,
    fee_decision_source, fee_decision_rate_sat_vb,
    fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix,
    fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs,
    fee_decision_provenance, fee_decision_policy_floor_sat_vb,
    fee_decision_policy_cap_sat_vb, fee_decision_policy_version
) VALUES (
    '55000000-0000-0000-0000-000000000002',
    '53000000-0000-0000-0000-000000000012',
    'liquid_claim_replacement', repeat('57', 32),
    '020000000555', repeat('63', 32),
    jsonb_build_array(jsonb_build_object(
        'txid', repeat('64', 32), 'vout', 0
    )),
    'lq1qqmigration053merchantdestination0000000000000000000000000000000000',
    '001655', repeat('57', 32), 0, 25000, 310, 2.0, repeat('62', 32),
    'chain_liquid_claim', 'liquid', '1', 'liquid_last_known_good', 2.0,
    1700000300, 1700000305, 5, 60, 'migration-055-liquid-replacement',
    0.1, 10.0, 'review25-v1'
);

INSERT INTO chain_swap_tx_attempts (
    id, chain_swap_id, purpose, raw_tx_hex, txid, source_prevouts,
    destination_address, destination_script_hex, destination_vout,
    destination_amount_sat, fee_amount_sat, fee_rate_sat_vb,
    fee_decision_purpose, fee_decision_rail, fee_decision_target,
    fee_decision_source, fee_decision_rate_sat_vb,
    fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix,
    fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs,
    fee_decision_provenance, fee_decision_policy_floor_sat_vb,
    fee_decision_policy_cap_sat_vb, fee_decision_policy_version
) VALUES (
    '55000000-0000-0000-0000-000000000003',
    '53000000-0000-0000-0000-000000000012',
    'btc_recovery', '020000000655', repeat('65', 32),
    jsonb_build_array(jsonb_build_object(
        'txid', repeat('66', 32), 'vout', 1
    )),
    'bc1qmigration055bitcoinrecovery000000000000000000000',
    '001755', 0, 24000, 1000, 5.0,
    'bitcoin_recovery', 'bitcoin', 'fastestFee',
    'bitcoin_last_known_good', 5.0,
    1700000400, 1700000405, 5, 60, 'migration-055-bitcoin-recovery',
    1.0, 100.0, 'review25-v1'
);

DO $$
DECLARE
    runtime_role_oid OID;
    relation_name TEXT;
    relation_owner_oid OID;
    function_name TEXT;
    function_owner_oid OID;
BEGIN
    BEGIN
        UPDATE chain_swap_tx_attempts
           SET fee_decision_source = 'liquid_last_known_good'
         WHERE id = '55000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'migration 055 allowed attempt authority mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    IF (
        SELECT COUNT(*)
          FROM chain_swap_tx_attempts
         WHERE id IN (
             '55000000-0000-0000-0000-000000000001',
             '55000000-0000-0000-0000-000000000002',
             '55000000-0000-0000-0000-000000000003'
         )
           AND fee_decision_policy_version = 'review25-v1'
    ) <> 3 THEN
        RAISE EXCEPTION 'migration 055 did not retain all exact attempt authorities';
    END IF;

    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    FOREACH relation_name IN ARRAY ARRAY[
        'chain_swap_tx_attempts', 'invoice_payment_events',
        'merchant_settlement_checkpoints', 'merchant_settlement_retained_outputs'
    ] LOOP
        SELECT relowner INTO STRICT relation_owner_oid
          FROM pg_class
         WHERE oid = format('public.%I', relation_name)::REGCLASS;
        IF relation_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, relation_owner_oid, 'USAGE')
           OR pg_has_role(runtime_role_oid, relation_owner_oid, 'SET')
           OR NOT has_table_privilege('bullnym_app', format('public.%I', relation_name), 'SELECT')
           OR NOT has_table_privilege('bullnym_app', format('public.%I', relation_name), 'INSERT')
           OR NOT has_table_privilege('bullnym_app', format('public.%I', relation_name), 'UPDATE')
           OR has_table_privilege('bullnym_app', format('public.%I', relation_name), 'DELETE')
           OR has_table_privilege('bullnym_app', format('public.%I', relation_name), 'TRUNCATE')
           OR has_table_privilege('bullnym_app', format('public.%I', relation_name), 'REFERENCES')
           OR has_table_privilege('bullnym_app', format('public.%I', relation_name), 'TRIGGER') THEN
            RAISE EXCEPTION 'migration 055 retained unsafe owner/ACL for %', relation_name;
        END IF;
    END LOOP;

    FOREACH function_name IN ARRAY ARRAY[
        'guard_chain_swap_tx_attempt_immutable',
        'require_review25_bitcoin_attempt_fee_authority',
        'enforce_liquid_claim_replacement_lineage',
        'guard_invoice_payment_event_evidence',
        'reject_merchant_settlement_event_delete',
        'enforce_merchant_settlement_checkpoint_write',
        'enforce_merchant_settlement_retained_update',
        'reject_merchant_settlement_delete'
    ] LOOP
        SELECT proowner INTO STRICT function_owner_oid
          FROM pg_proc procedure_info
          JOIN pg_namespace namespace
            ON namespace.oid = procedure_info.pronamespace
         WHERE namespace.nspname = 'public'
           AND procedure_info.proname = function_name
           AND procedure_info.pronargs = 0;
        IF function_owner_oid = runtime_role_oid
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'USAGE')
           OR pg_has_role(runtime_role_oid, function_owner_oid, 'SET') THEN
            RAISE EXCEPTION 'migration 055 retained unsafe function owner for %',
                function_name;
        END IF;
    END LOOP;

    SELECT relowner INTO STRICT relation_owner_oid
      FROM pg_class
     WHERE oid = 'public.invoice_payment_events_accounting_sequence_seq'::REGCLASS
       AND relkind = 'S';
    IF relation_owner_oid = runtime_role_oid
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, relation_owner_oid, 'SET')
       OR NOT has_sequence_privilege(
           'bullnym_app',
           'public.invoice_payment_events_accounting_sequence_seq',
           'USAGE'
       )
       OR has_sequence_privilege(
           'bullnym_app',
           'public.invoice_payment_events_accounting_sequence_seq',
           'SELECT'
       )
       OR has_sequence_privilege(
           'bullnym_app',
           'public.invoice_payment_events_accounting_sequence_seq',
           'UPDATE'
       ) THEN
        RAISE EXCEPTION 'migration 055 retained unsafe accounting sequence owner/ACL';
    END IF;
END
$$;
