DO $$
DECLARE
    credential_id UUID := '66000000-0000-4000-8000-000000000001';
    settlement_id UUID := '66000000-0000-4000-8000-000000000002';
    other_credential_id UUID := '66000000-0000-4000-8000-000000000003';
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'bull_bitcoin_settlements'
           AND column_name = 'funding_committed_at'
           AND data_type = 'timestamp with time zone'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'invoice_payment_events'
           AND column_name = 'bull_bitcoin_settlement_id'
           AND data_type = 'uuid'
    ) THEN
        RAISE EXCEPTION 'migration 068 did not add its exact accounting columns';
    END IF;

    IF EXISTS (
        SELECT 1 FROM (VALUES
            ('invoices', 'invoices_id_npub_owner_key'),
            ('invoice_fiat_settlement_policies',
             'invoice_fiat_settlement_policies_invoice_owner_fkey'),
            ('bull_bitcoin_settlements',
             'bull_bitcoin_settlements_invoice_owner_fkey'),
            ('bull_bitcoin_settlements',
             'bull_bitcoin_settlements_funding_commitment_chk'),
            ('invoice_payment_events',
             'invoice_payment_events_bull_bitcoin_shape_chk'),
            ('invoice_payment_events',
             'invoice_payment_events_bull_bitcoin_fkey')
        ) required(table_name, constraint_name)
         WHERE NOT EXISTS (
            SELECT 1 FROM pg_constraint constraint_info
             WHERE constraint_info.conrelid =
                       to_regclass('public.' || required.table_name)
               AND constraint_info.conname = required.constraint_name
               AND constraint_info.convalidated
         )
    ) THEN
        RAISE EXCEPTION 'migration 068 is missing a validated accounting constraint';
    END IF;

    IF EXISTS (
        SELECT 1 FROM (VALUES
            ('bull_bitcoin_settlements',
             'bull_bitcoin_settlements_guard_funding_commitment'),
            ('bull_bitcoin_settlements',
             'bull_bitcoin_settlements_sync_invoice_status'),
            ('invoice_payment_events',
             'invoice_payment_events_guard_bull_bitcoin'),
            ('invoices', 'zz_invoices_compose_settlement_components')
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
        RAISE EXCEPTION 'migration 068 is missing an enabled accounting trigger';
    END IF;

    IF NOT has_table_privilege('bullnym_app', 'invoice_payment_events', 'SELECT')
       OR NOT has_table_privilege('bullnym_app', 'invoice_payment_events', 'INSERT')
       OR NOT has_table_privilege('bullnym_app', 'invoice_payment_events', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'invoice_payment_events', 'DELETE')
       OR has_table_privilege('bullnym_app', 'invoice_payment_events', 'TRUNCATE')
       OR has_table_privilege('public', 'invoice_payment_events', 'SELECT')
       OR has_table_privilege('public', 'bull_bitcoin_settlements', 'SELECT') THEN
        RAISE EXCEPTION 'migration 068 accounting ACL is broader or narrower than required';
    END IF;

    INSERT INTO invoices (
        id, nym_owner, npub_owner, origin, amount_sat,
        rate_locks_until, bitcoin_address,
        accept_btc, accept_ln, accept_liquid,
        status, pricing_mode, presentation_status, settlement_status, expires_at,
        client_request_id, client_request_digest, presentation_envelope
    ) VALUES (
        '66000000-0000-4000-8000-000000000005', NULL, repeat('6', 64),
        'wallet', 10000, TIMESTAMPTZ '2030-01-01 00:00:00+00',
        'bc1q068invoicefixture00000000000000000000000000',
        TRUE, FALSE, FALSE, 'unpaid', 'sat_fixed', 'unpaid', 'none',
        TIMESTAMPTZ '2030-01-01 00:00:00+00',
        '66000000-0000-4000-8000-000000000006',
        decode(repeat('66', 32), 'hex'),
        decode('01' || repeat('66', 4124), 'hex')
    );

    INSERT INTO bull_bitcoin_credentials (
        id, owner_npub, ciphertext, nonce, encryption_format
    ) VALUES (
        credential_id, repeat('6', 64),
        decode(repeat('11', 85), 'hex'), decode(repeat('22', 24), 'hex'), 1
    );
    INSERT INTO bull_bitcoin_credentials (
        id, owner_npub, ciphertext, nonce, encryption_format
    ) VALUES (
        other_credential_id, repeat('7', 64),
        decode(repeat('33', 85), 'hex'), decode(repeat('44', 24), 'hex'), 1
    );

    BEGIN
        INSERT INTO bull_bitcoin_settlements (
            owner_npub, invoice_id, credential_id, product, purpose,
            payer_rail, request_key, fiat_percentage, fiat_currency,
            terms_version, requested_bitcoin_sat
        ) VALUES (
            repeat('7', 64), '66000000-0000-4000-8000-000000000005',
            other_credential_id, 'invoice', 'fiat_only', 'bitcoin',
            'migration-068-cross-owner', 100, 'CAD',
            'bull-bitcoin-fiat-settlement-v1', 10000
        );
        RAISE EXCEPTION 'migration 068 accepted a cross-owner invoice settlement';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;

    INSERT INTO bull_bitcoin_settlements (
        id, owner_npub, invoice_id, credential_id, product, purpose,
        payer_rail, request_key, fiat_percentage, fiat_currency,
        terms_version, requested_bitcoin_sat
    ) VALUES (
        settlement_id, repeat('6', 64),
        '66000000-0000-4000-8000-000000000005', credential_id,
        'invoice', 'fiat_only', 'bitcoin', 'migration-068-accounting',
        100, 'CAD', 'bull-bitcoin-fiat-settlement-v1', 10000
    );
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'dispatch_started', updated_at = now()
     WHERE id = settlement_id;
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'bound', funding_route = 'bull_bitcoin',
           funding_committed_at = now(), settlement_status = 'pending',
           bull_bitcoin_order_id = '66000000-0000-4000-8000-000000000004',
           instruction_kind = 'bitcoin', payer_instruction = 'bc1q068fixture',
           updated_at = now()
     WHERE id = settlement_id;
    UPDATE bull_bitcoin_settlements
       SET order_status = 'Completed', payin_status = 'Completed',
           payout_status = 'Completed', actual_received_sat = 10000,
           credited_fiat_minor = 1234, provider_final = TRUE,
           settlement_status = 'settled', terminal_at = now(),
           payer_instruction = NULL, instruction_kind = NULL,
           updated_at = now()
     WHERE id = settlement_id;

    BEGIN
        UPDATE bull_bitcoin_settlements
           SET funding_committed_at = funding_committed_at + INTERVAL '1 second'
         WHERE id = settlement_id;
        RAISE EXCEPTION 'migration 068 allowed funding commitment mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO invoice_payment_events (
    invoice_id, rail, source, event_key, amount_sat,
    accounting_state, verification_state,
    bull_bitcoin_settlement_id, fiat_credited_minor,
    fiat_credit_policy, fiat_valued_at
) VALUES (
    '66000000-0000-4000-8000-000000000005', 'bitcoin',
    'bull_bitcoin_fiat',
    'bull_bitcoin_fiat:66000000-0000-4000-8000-000000000002',
    10000, 'active', 'not_applicable',
    '66000000-0000-4000-8000-000000000002', 1234,
    'bull_bitcoin_actual_v1', clock_timestamp()
);
COMMIT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM invoice_payment_events
         WHERE bull_bitcoin_settlement_id =
               '66000000-0000-4000-8000-000000000002'
           AND amount_sat = 10000
           AND fiat_credited_minor = 1234
    ) THEN
        RAISE EXCEPTION 'migration 068 rejected its exact runtime accounting path';
    END IF;
END
$$;
