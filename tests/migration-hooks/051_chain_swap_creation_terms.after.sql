DO $$
DECLARE
    claim_allocation UUID;
    refund_allocation UUID;
    persisted_quote TEXT;
    persisted_emergency TEXT;
    creation_value_count INTEGER;
BEGIN
    SELECT num_nonnulls(
               pinned_pair_hash,
               canonical_pair_quote_json,
               creation_response_sha256,
               btc_claim_script_sha256,
               btc_refund_script_sha256,
               liquid_claim_script_sha256,
               liquid_refund_script_sha256,
               btc_timeout_height,
               liquid_timeout_height,
               btc_network,
               liquid_network,
               liquid_asset_id,
               merchant_liquid_destination,
               merchant_emergency_btc_address
           )
      INTO STRICT creation_value_count
      FROM chain_swap_records
     WHERE id = '50000000-0000-0000-0000-000000000003';
    IF creation_value_count <> 0 THEN
        RAISE EXCEPTION 'migration 051 fabricated creation terms for a legacy row';
    END IF;

    -- Ordinary lifecycle writes to a legacy row remain valid.
    UPDATE chain_swap_records
       SET status = 'user_lock_mempool'
     WHERE id = '50000000-0000-0000-0000-000000000003';

    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('ef', 8), 1, 1, 8001, 'chain_claim',
        '02' || repeat('51', 32), repeat('52', 32)
    ) RETURNING id INTO claim_allocation;
    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('ef', 8), 1, 1, 8002, 'chain_refund',
        '03' || repeat('53', 32), NULL
    ) RETURNING id INTO refund_allocation;

    -- A post-051 writer cannot create another lineage-only row.
    BEGIN
        INSERT INTO chain_swap_records (
            id, invoice_id, nym, boltz_swap_id, from_chain, to_chain,
            lockup_address, user_lock_amount_sat, server_lock_amount_sat,
            preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json,
            claim_key_index, refund_key_index, root_fingerprint,
            claim_key_allocation_id, refund_key_allocation_id, key_epoch,
            derivation_scheme_version, claim_public_key_hex,
            refund_public_key_hex, preimage_hash_hex
        ) VALUES (
            '51000000-0000-0000-0000-000000000001',
            '46000000-0000-0000-0000-000000000001',
            'og-migration-fixture', 'migration-051-missing-terms', 'BTC', 'L-BTC',
            'bc1qmigration051missingterms0000000000000000000000',
            26000, 25000, repeat('54', 32), repeat('55', 32),
            repeat('56', 32), '{}', 8001, 8002, repeat('ef', 8),
            claim_allocation, refund_allocation, 1, 1,
            '02' || repeat('51', 32), '03' || repeat('53', 32),
            repeat('52', 32)
        );
        RAISE EXCEPTION 'migration 051 allowed a new row without creation terms';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    -- A partial creation packet is rejected as one atomic shape.
    BEGIN
        INSERT INTO chain_swap_records (
            id, invoice_id, nym, boltz_swap_id, from_chain, to_chain,
            lockup_address, user_lock_amount_sat, server_lock_amount_sat,
            preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json,
            claim_key_index, refund_key_index, root_fingerprint,
            claim_key_allocation_id, refund_key_allocation_id, key_epoch,
            derivation_scheme_version, claim_public_key_hex,
            refund_public_key_hex, preimage_hash_hex,
            pinned_pair_hash, canonical_pair_quote_json,
            creation_response_sha256, btc_claim_script_sha256,
            btc_refund_script_sha256, liquid_claim_script_sha256,
            liquid_refund_script_sha256, btc_timeout_height,
            liquid_timeout_height, btc_network, liquid_network,
            liquid_asset_id, merchant_liquid_destination
        ) VALUES (
            '51000000-0000-0000-0000-000000000002',
            '46000000-0000-0000-0000-000000000001',
            'og-migration-fixture', 'migration-051-partial-terms', 'BTC', 'L-BTC',
            'bc1qmigration051partialterms0000000000000000000000',
            26000, 25000, repeat('54', 32), repeat('55', 32),
            repeat('56', 32), '{}', 8001, 8002, repeat('ef', 8),
            claim_allocation, refund_allocation, 1, 1,
            '02' || repeat('51', 32), '03' || repeat('53', 32),
            repeat('52', 32), repeat('61', 32),
            '{"fees":{"percentage":0.1},"rate":1}', repeat('62', 32),
            repeat('63', 32), repeat('64', 32), repeat('65', 32),
            repeat('66', 32), 958033, 3972215, 'bitcoin', 'liquid',
            repeat('67', 32), NULL
        );
        RAISE EXCEPTION 'migration 051 allowed a partial creation packet';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO chain_swap_records (
        id, invoice_id, nym, boltz_swap_id, from_chain, to_chain,
        lockup_address, user_lock_amount_sat, server_lock_amount_sat,
        preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json,
        claim_key_index, refund_key_index, root_fingerprint,
        claim_key_allocation_id, refund_key_allocation_id, key_epoch,
        derivation_scheme_version, claim_public_key_hex,
        refund_public_key_hex, preimage_hash_hex,
        pinned_pair_hash, canonical_pair_quote_json,
        creation_response_sha256, btc_claim_script_sha256,
        btc_refund_script_sha256, liquid_claim_script_sha256,
        liquid_refund_script_sha256, btc_timeout_height,
        liquid_timeout_height, btc_network, liquid_network,
        liquid_asset_id, merchant_liquid_destination,
        merchant_emergency_btc_address
    ) VALUES (
        '51000000-0000-0000-0000-000000000003',
        '46000000-0000-0000-0000-000000000001',
        'og-migration-fixture', 'migration-051-complete-terms', 'BTC', 'L-BTC',
        'bc1qmigration051completeterms000000000000000000000',
        26000, 25000, repeat('54', 32), repeat('55', 32),
        repeat('56', 32), '{"id":"migration-051-complete-terms"}',
        8001, 8002, repeat('ef', 8), claim_allocation, refund_allocation,
        1, 1, '02' || repeat('51', 32), '03' || repeat('53', 32),
        repeat('52', 32), repeat('61', 32),
        '{"fees":{"percentage":0.1},"rate":1}', repeat('62', 32),
        repeat('63', 32), repeat('64', 32), repeat('65', 32),
        repeat('66', 32), 958033, 3972215, 'bitcoin', 'liquid',
        repeat('67', 32),
        'lq1qqmigration051merchantdestination0000000000000000000000000000000000',
        NULL
    );

    SELECT canonical_pair_quote_json, merchant_emergency_btc_address
      INTO STRICT persisted_quote, persisted_emergency
      FROM chain_swap_records
     WHERE id = '51000000-0000-0000-0000-000000000003';
    IF persisted_quote <> '{"fees":{"percentage":0.1},"rate":1}' THEN
        RAISE EXCEPTION 'migration 051 changed canonical pair quote bytes';
    END IF;
    IF persisted_emergency IS NOT NULL THEN
        RAISE EXCEPTION 'migration 051 did not preserve nullable emergency address';
    END IF;

    BEGIN
        UPDATE chain_swap_records
           SET pinned_pair_hash = repeat('68', 32)
         WHERE id = '51000000-0000-0000-0000-000000000003';
        RAISE EXCEPTION 'migration 051 allowed creation-term mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        UPDATE chain_swap_records
           SET merchant_emergency_btc_address =
               'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'
         WHERE id = '51000000-0000-0000-0000-000000000003';
        RAISE EXCEPTION 'migration 051 allowed late emergency-address mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    -- Lifecycle fields remain mutable on complete rows too.
    UPDATE chain_swap_records
       SET status = 'user_lock_mempool'
     WHERE id = '51000000-0000-0000-0000-000000000003';
END
$$;
