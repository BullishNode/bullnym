DO $$
DECLARE
    invoice_id UUID := '73000000-0000-4000-8000-000000000001';
    settlement_id UUID := '73000000-0000-4000-8000-000000000002';
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
         WHERE trigger_info.tgrelid = 'bull_bitcoin_settlements'::regclass
           AND trigger_info.tgname =
               'bull_bitcoin_settlements_sync_invoice_status'
           AND trigger_info.tgenabled = 'O'
           AND NOT trigger_info.tgisinternal
           AND pg_get_triggerdef(trigger_info.oid) LIKE
               '%actual_received_sat%'
    ) THEN
        RAISE EXCEPTION 'migration 073 trigger does not react to money evidence';
    END IF;

    INSERT INTO invoices (
        id, nym_owner, npub_owner, origin, amount_sat,
        rate_locks_until, bitcoin_address,
        accept_btc, accept_ln, accept_liquid,
        status, pricing_mode, presentation_status, settlement_status, expires_at,
        client_request_id, client_request_digest, presentation_envelope
    ) VALUES (
        invoice_id, NULL, repeat('6', 64), 'wallet', 10000,
        TIMESTAMPTZ '2030-01-01 00:00:00+00',
        'bc1q073invoicefixture00000000000000000000000000',
        TRUE, FALSE, FALSE, 'unpaid', 'sat_fixed', 'unpaid', 'none',
        TIMESTAMPTZ '2030-01-01 00:00:00+00',
        '73000000-0000-4000-8000-000000000003',
        decode(repeat('73', 32), 'hex'),
        decode('01' || repeat('73', 4124), 'hex')
    );

    INSERT INTO bull_bitcoin_settlements (
        id, owner_npub, invoice_id, credential_id, product, purpose,
        payer_rail, request_key, fiat_percentage, fiat_currency,
        requested_bitcoin_sat
    ) VALUES (
        settlement_id, repeat('6', 64), invoice_id,
        '66000000-0000-4000-8000-000000000001',
        'invoice', 'fiat_only', 'bitcoin', 'migration-073-watch',
        100, 'CAD', 10000
    );
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'dispatch_started', updated_at = now()
     WHERE id = settlement_id;
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'bound', funding_route = 'bull_bitcoin',
           funding_committed_at = now(), settlement_status = 'pending',
           bull_bitcoin_order_id =
               '73000000-0000-4000-8000-000000000004',
           instruction_kind = 'bitcoin', payer_instruction = 'bc1q073fixture',
           retention_until = now() + INTERVAL '30 days',
           updated_at = now()
     WHERE id = settlement_id;

    IF (SELECT fiat_settlement_status FROM invoices WHERE id = invoice_id)
       <> 'pending' THEN
        RAISE EXCEPTION 'migration 073 changed active invoice projection';
    END IF;

    UPDATE invoices
       SET status = 'expired', fiat_settlement_status = 'none'
     WHERE id = invoice_id;
    UPDATE bull_bitcoin_settlements
       SET actual_received_sat = actual_received_sat
     WHERE id = settlement_id;

    IF (SELECT fiat_settlement_status FROM invoices WHERE id = invoice_id)
       <> 'none' THEN
        RAISE EXCEPTION 'migration 073 kept never-funded expired invoice active';
    END IF;

    UPDATE bull_bitcoin_settlements
       SET order_status = 'In progress', payin_status = 'In progress',
           payout_status = 'Initialized', actual_received_sat = 10000,
           updated_at = now()
     WHERE id = settlement_id;

    IF (SELECT fiat_settlement_status FROM invoices WHERE id = invoice_id)
       <> 'pending' THEN
        RAISE EXCEPTION 'migration 073 ignored late provider money evidence';
    END IF;
END
$$;
