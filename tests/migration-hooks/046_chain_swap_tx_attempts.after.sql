DO $$
DECLARE
    legacy_status TEXT;
    attempt_count BIGINT;
    attempt_id UUID;
BEGIN
    SELECT status INTO legacy_status
      FROM chain_swap_records
     WHERE id = '46000000-0000-0000-0000-000000000002';
    IF legacy_status <> 'refunding' THEN
        RAISE EXCEPTION 'migration 046 rewrote the legacy recovery lifecycle';
    END IF;

    SELECT COUNT(*) INTO attempt_count
      FROM chain_swap_tx_attempts
     WHERE chain_swap_id = '46000000-0000-0000-0000-000000000002';
    IF attempt_count <> 0 THEN
        RAISE EXCEPTION 'migration 046 fabricated bytes for a legacy recovery';
    END IF;

    INSERT INTO chain_swap_tx_attempts (
        chain_swap_id, raw_tx_hex, txid, source_prevouts,
        destination_address, destination_script_hex, destination_vout,
        destination_amount_sat, fee_amount_sat, fee_rate_sat_vb
    )
    VALUES (
        '46000000-0000-0000-0000-000000000002', '00', repeat('a', 64),
        '[{"txid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","vout":0,"amount_sat":100000,"script_pubkey_hex":"0014aa"}]'::jsonb,
        'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
        '5120aa', 0, 99000, 1000, 2.0
    )
    RETURNING id INTO attempt_id;

    BEGIN
        UPDATE chain_swap_tx_attempts
           SET destination_address = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
         WHERE id = attempt_id;
        RAISE EXCEPTION 'migration 046 allowed immutable intent mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_records
           SET refund_address = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
         WHERE id = '46000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 046 allowed parent destination drift';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO chain_swap_tx_attempts (
            chain_swap_id, raw_tx_hex, txid, source_prevouts,
            destination_address, destination_script_hex, destination_vout,
            destination_amount_sat, fee_amount_sat, fee_rate_sat_vb
        )
        SELECT chain_swap_id, raw_tx_hex, repeat('c', 64), source_prevouts,
               destination_address, destination_script_hex, destination_vout,
               destination_amount_sat, fee_amount_sat, fee_rate_sat_vb
          FROM chain_swap_tx_attempts WHERE id = attempt_id;
        RAISE EXCEPTION 'migration 046 allowed a second recovery intent';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_tx_attempts SET status = 'integrity_hold'
         WHERE id = attempt_id;
        RAISE EXCEPTION 'migration 046 allowed an unexplained integrity hold';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    UPDATE chain_swap_tx_attempts
       SET status = 'integrity_hold',
           integrity_reason = 'migration fixture',
           integrity_hold_at = NOW()
     WHERE id = attempt_id;
END
$$;
