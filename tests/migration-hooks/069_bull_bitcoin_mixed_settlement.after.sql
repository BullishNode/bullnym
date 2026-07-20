DO $$
DECLARE
    allocation_id UUID;
    settlement_id UUID := '67000000-0000-4000-8000-000000000003';
    claim_txid TEXT := repeat('68', 32);
BEGIN
    IF EXISTS (
        SELECT 1 FROM (VALUES
            ('swap_fiat_settlement_policies'),
            ('bull_bitcoin_claim_outputs')
        ) required(table_name)
         WHERE to_regclass('public.' || required.table_name) IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 069 did not add its mixed-settlement tables';
    END IF;

    IF EXISTS (
        SELECT 1 FROM (VALUES
            ('bull_bitcoin_settlements',
             'bull_bitcoin_settlements_swap_binding_chk'),
            ('swap_fiat_settlement_policies',
             'swap_fiat_settlement_policies_source_chk'),
            ('swap_fiat_settlement_policies',
             'swap_fiat_settlement_policies_credential_owner_fkey'),
            ('bull_bitcoin_claim_outputs',
             'bull_bitcoin_claim_outputs_role_vout_chk'),
            ('bull_bitcoin_claim_outputs',
             'bull_bitcoin_claim_outputs_settlement_fkey'),
            ('invoice_payment_events',
             'invoice_payment_events_bull_bitcoin_shape_chk')
        ) required(table_name, constraint_name)
         WHERE NOT EXISTS (
            SELECT 1 FROM pg_constraint constraint_info
             WHERE constraint_info.conrelid =
                       to_regclass('public.' || required.table_name)
               AND constraint_info.conname = required.constraint_name
               AND constraint_info.convalidated
         )
    ) THEN
        RAISE EXCEPTION 'migration 069 is missing a validated mixed-settlement constraint';
    END IF;

    IF EXISTS (
        SELECT 1 FROM (VALUES
            ('swap_fiat_settlement_policies',
             'swap_fiat_settlement_policies_guard_insert'),
            ('swap_fiat_settlement_policies',
             'swap_fiat_settlement_policies_reject_mutation'),
            ('bull_bitcoin_settlements',
             'bull_bitcoin_settlements_guard_swap_binding'),
            ('bull_bitcoin_claim_outputs',
             'bull_bitcoin_claim_outputs_guard_insert'),
            ('bull_bitcoin_claim_outputs',
             'bull_bitcoin_claim_outputs_reject_mutation'),
            ('invoice_payment_events',
             'invoice_payment_events_guard_mixed_reverse')
        ) required(table_name, trigger_name)
         WHERE NOT EXISTS (
            SELECT 1 FROM pg_trigger trigger_info
             WHERE trigger_info.tgrelid =
                       to_regclass('public.' || required.table_name)
               AND trigger_info.tgname = required.trigger_name
               AND NOT trigger_info.tgisinternal
               AND trigger_info.tgenabled = 'O'
         )
    ) THEN
        RAISE EXCEPTION 'migration 069 is missing an enabled mixed-settlement trigger';
    END IF;

    IF NOT has_table_privilege(
               'bullnym_app', 'swap_fiat_settlement_policies', 'SELECT')
       OR NOT has_table_privilege(
               'bullnym_app', 'swap_fiat_settlement_policies', 'INSERT')
       OR has_table_privilege(
               'bullnym_app', 'swap_fiat_settlement_policies', 'UPDATE')
       OR has_table_privilege(
               'bullnym_app', 'swap_fiat_settlement_policies', 'DELETE')
       OR NOT has_table_privilege(
               'bullnym_app', 'bull_bitcoin_claim_outputs', 'SELECT')
       OR NOT has_table_privilege(
               'bullnym_app', 'bull_bitcoin_claim_outputs', 'INSERT')
       OR has_table_privilege(
               'bullnym_app', 'bull_bitcoin_claim_outputs', 'UPDATE')
       OR has_table_privilege(
               'bullnym_app', 'bull_bitcoin_claim_outputs', 'DELETE')
       OR has_table_privilege(
               'public', 'swap_fiat_settlement_policies', 'SELECT')
       OR has_table_privilege(
               'public', 'bull_bitcoin_claim_outputs', 'SELECT') THEN
        RAISE EXCEPTION 'migration 069 mixed-settlement ACL is broader or narrower than required';
    END IF;

    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('67', 8), 1, 1, 670000, 'reverse_claim',
        '02' || repeat('68', 32), repeat('68', 32)
    ) RETURNING id INTO allocation_id;

    INSERT INTO swap_records (
        id, nym, boltz_swap_id, amount_sat, invoice, preimage_hex,
        claim_key_hex, boltz_response_json, invoice_id,
        key_index, root_fingerprint, key_allocation_id, key_epoch,
        derivation_scheme_version, claim_public_key_hex, preimage_hash_hex
    ) VALUES (
        '67000000-0000-4000-8000-000000000001', NULL,
        'migration-069-mixed-reverse', 10000, 'lnbc-migration-069',
        repeat('69', 32), repeat('6a', 32), '{}',
        '66000000-0000-4000-8000-000000000005',
        670000, repeat('67', 8), allocation_id, 1, 1,
        '02' || repeat('68', 32), repeat('68', 32)
    );

    INSERT INTO swap_fiat_settlement_policies (
        reverse_swap_id, owner_npub, credential_id, product,
        fiat_percentage, fiat_currency
    ) VALUES (
        '67000000-0000-4000-8000-000000000001', repeat('6', 64),
        '66000000-0000-4000-8000-000000000001', 'invoice',
        40, 'CAD'
    );

    BEGIN
        UPDATE swap_fiat_settlement_policies
           SET fiat_percentage = 41
         WHERE reverse_swap_id = '67000000-0000-4000-8000-000000000001';
        RAISE EXCEPTION 'migration 069 allowed mixed policy mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO bull_bitcoin_settlements (
        id, owner_npub, invoice_id, reverse_swap_id, credential_id,
        product, purpose, payer_rail, request_key, fiat_percentage,
        fiat_currency, requested_bitcoin_sat
    ) VALUES (
        settlement_id, repeat('6', 64),
        '66000000-0000-4000-8000-000000000005',
        '67000000-0000-4000-8000-000000000001',
        '66000000-0000-4000-8000-000000000001',
        'invoice', 'mixed', 'lightning', 'migration-069-mixed-order',
        40, 'CAD', 4000
    );
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'dispatch_started', updated_at = now()
     WHERE id = settlement_id;
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'bound',
           bull_bitcoin_order_id = '67000000-0000-4000-8000-000000000004',
           instruction_kind = 'liquid',
           payer_instruction = 'VJL6fixtureConfidentialLiquidAddress',
           updated_at = now()
     WHERE id = settlement_id;

    BEGIN
        INSERT INTO bull_bitcoin_claim_outputs (
            settlement_id, role, txid, vout, script_pubkey_hex,
            authorized_amount_sat, asset_commitment_sha256,
            value_commitment_sha256, nonce_commitment_sha256,
            surjection_proof_sha256, rangeproof_sha256
        ) VALUES
        (
            settlement_id, 'merchant', claim_txid, 0,
            '0014' || repeat('70', 20), 5999,
            repeat('71', 32), repeat('72', 32), repeat('73', 32),
            repeat('74', 32), repeat('75', 32)
        ),
        (
            settlement_id, 'bull_bitcoin', claim_txid, 1,
            '0014' || repeat('76', 20), 4000,
            repeat('77', 32), repeat('78', 32), repeat('79', 32),
            repeat('7a', 32), repeat('7b', 32)
        );
        UPDATE bull_bitcoin_settlements
           SET funding_route = 'bull_bitcoin', funding_committed_at = now(),
               settlement_status = 'pending', instruction_kind = NULL,
               payer_instruction = NULL, updated_at = now()
         WHERE id = settlement_id;
        RAISE EXCEPTION 'migration 069 accepted a non-percentage mixed claim';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO bull_bitcoin_claim_outputs (
        settlement_id, role, txid, vout, script_pubkey_hex,
        authorized_amount_sat, asset_commitment_sha256,
        value_commitment_sha256, nonce_commitment_sha256,
        surjection_proof_sha256, rangeproof_sha256
    ) VALUES (
        settlement_id, 'merchant', claim_txid, 0,
        '0014' || repeat('70', 20), 6000,
        repeat('71', 32), repeat('72', 32), repeat('73', 32),
        repeat('74', 32), repeat('75', 32)
    );

    BEGIN
        UPDATE bull_bitcoin_settlements
           SET funding_route = 'bull_bitcoin', funding_committed_at = now(),
               settlement_status = 'pending', instruction_kind = NULL,
               payer_instruction = NULL, updated_at = now()
         WHERE id = settlement_id;
        RAISE EXCEPTION 'migration 069 committed a one-output mixed claim';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO bull_bitcoin_claim_outputs (
            settlement_id, role, txid, vout, script_pubkey_hex,
            authorized_amount_sat, asset_commitment_sha256,
            value_commitment_sha256, nonce_commitment_sha256,
            surjection_proof_sha256, rangeproof_sha256
        ) VALUES (
            settlement_id, 'bull_bitcoin', claim_txid, 1,
            '0014' || repeat('76', 20), 3999,
            repeat('77', 32), repeat('78', 32), repeat('79', 32),
            repeat('7a', 32), repeat('7b', 32)
        );
        RAISE EXCEPTION 'migration 069 accepted the wrong Bull Bitcoin output amount';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO bull_bitcoin_claim_outputs (
        settlement_id, role, txid, vout, script_pubkey_hex,
        authorized_amount_sat, asset_commitment_sha256,
        value_commitment_sha256, nonce_commitment_sha256,
        surjection_proof_sha256, rangeproof_sha256
    ) VALUES (
        settlement_id, 'bull_bitcoin', claim_txid, 1,
        '0014' || repeat('76', 20), 4000,
        repeat('77', 32), repeat('78', 32), repeat('79', 32),
        repeat('7a', 32), repeat('7b', 32)
    );

    UPDATE bull_bitcoin_settlements
       SET funding_route = 'bull_bitcoin', funding_committed_at = now(),
           settlement_status = 'pending', instruction_kind = NULL,
           payer_instruction = NULL, updated_at = now()
     WHERE id = settlement_id;

    BEGIN
        UPDATE bull_bitcoin_claim_outputs AS output
           SET authorized_amount_sat = 4001
         WHERE output.settlement_id = '67000000-0000-4000-8000-000000000003'
           AND output.role = 'bull_bitcoin';
        RAISE EXCEPTION 'migration 069 allowed claim-output mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO invoice_payment_events (
            invoice_id, rail, source, event_key, amount_sat, txid,
            boltz_swap_id, accounting_state, verification_state
        ) VALUES (
            '66000000-0000-4000-8000-000000000005', 'lightning',
            'lightning_boltz_reverse',
            'lightning_boltz_reverse:migration-069-mixed-reverse',
            10000, claim_txid, 'migration-069-mixed-reverse',
            'active', 'not_applicable'
        );
        RAISE EXCEPTION 'migration 069 accepted gross mixed merchant accounting';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO invoice_payment_events (
    invoice_id, rail, source, event_key, amount_sat, txid,
    boltz_swap_id, accounting_state, verification_state
) VALUES (
    '66000000-0000-4000-8000-000000000005', 'lightning',
    'lightning_boltz_reverse',
    'lightning_boltz_reverse:migration-069-mixed-reverse',
    6000, repeat('68', 32), 'migration-069-mixed-reverse',
    'active', 'not_applicable'
);
INSERT INTO invoice_payment_events (
    invoice_id, rail, source, event_key, amount_sat, txid, vout,
    accounting_state, verification_state, bull_bitcoin_settlement_id
) VALUES (
    '66000000-0000-4000-8000-000000000005', 'liquid',
    'bull_bitcoin_mixed_output',
    'bull_bitcoin_mixed_output:67000000-0000-4000-8000-000000000003',
    4000, repeat('68', 32), 1, 'active', 'not_applicable',
    '67000000-0000-4000-8000-000000000003'
);
COMMIT;

DO $$
BEGIN
    IF (SELECT COUNT(*) FROM invoice_payment_events
         WHERE event_key IN (
             'lightning_boltz_reverse:migration-069-mixed-reverse',
             'bull_bitcoin_mixed_output:67000000-0000-4000-8000-000000000003'
         )) <> 2
       OR (SELECT SUM(amount_sat) FROM invoice_payment_events
            WHERE event_key IN (
                'lightning_boltz_reverse:migration-069-mixed-reverse',
                'bull_bitcoin_mixed_output:67000000-0000-4000-8000-000000000003'
            )) <> 10000 THEN
        RAISE EXCEPTION 'migration 069 rejected its exact two-leg runtime accounting path';
    END IF;
END
$$;
