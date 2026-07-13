DO $$
DECLARE
    reverse_allocation UUID;
    chain_claim_allocation UUID;
    chain_refund_allocation UUID;
    legacy_reverse_new_values INTEGER;
    legacy_chain_new_values INTEGER;
    legacy_high_water BIGINT;
BEGIN
    SELECT num_nonnulls(
               key_allocation_id, key_epoch, derivation_scheme_version,
               claim_public_key_hex, preimage_hash_hex
           )
      INTO legacy_reverse_new_values
      FROM swap_records
     WHERE id = '50000000-0000-0000-0000-000000000001';
    IF legacy_reverse_new_values <> 0 THEN
        RAISE EXCEPTION 'migration 050 fabricated reverse lineage for a legacy row';
    END IF;

    SELECT num_nonnulls(
               claim_key_allocation_id, refund_key_allocation_id, key_epoch,
               derivation_scheme_version, claim_public_key_hex,
               refund_public_key_hex, preimage_hash_hex
           )
      INTO legacy_chain_new_values
      FROM chain_swap_records
     WHERE id = '46000000-0000-0000-0000-000000000002';
    IF legacy_chain_new_values <> 0 THEN
        RAISE EXCEPTION 'migration 050 fabricated chain lineage for a legacy row';
    END IF;

    SELECT max_child_index
      INTO STRICT legacy_high_water
      FROM swap_key_legacy_high_water
     WHERE root_fingerprint = repeat('ab', 8);
    IF legacy_high_water <> 5002 THEN
        RAISE EXCEPTION
            'migration 050 backfilled legacy high-water %, expected 5002',
            legacy_high_water;
    END IF;

    IF (
        SELECT COUNT(*)
          FROM pg_indexes
         WHERE schemaname = 'public'
           AND indexname IN (
               'swap_records_fingerprint_key_index_key',
               'chain_swap_records_fingerprint_claim_index_key',
               'chain_swap_records_fingerprint_refund_index_key'
           )
    ) <> 3 THEN
        RAISE EXCEPTION 'migration 050 removed a migration-044 legacy index';
    END IF;

    -- The preexisting migration-044 maximum is an immutable exclusion. A
    -- runtime rewind must be rejected synchronously at reservation, before a
    -- provider can see the derived key.
    BEGIN
        INSERT INTO swap_key_allocations (
            root_fingerprint, key_epoch, derivation_scheme_version, child_index,
            purpose, public_key_hex, preimage_hash_hex
        ) VALUES (
            repeat('ab', 8), 1, 1, 5002, 'reverse_claim',
            '02' || repeat('10', 32), repeat('a0', 32)
        );
        RAISE EXCEPTION 'migration 050 allowed allocation at the legacy high-water mark';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    -- Existing legacy rows remain nullable, but every post-050 insert requires
    -- the allocation registry, including an old writer that supplies no
    -- derivation metadata at all.
    BEGIN
        INSERT INTO swap_records (
            id, nym, boltz_swap_id, amount_sat, invoice, preimage_hex,
            claim_key_hex, boltz_response_json
        ) VALUES (
            '50000000-0000-0000-0000-000000000005',
            'og-migration-fixture', 'migration-050-new-legacy-reverse', 50000,
            'lnbc-migration-050-new-legacy', repeat('45', 32),
            repeat('56', 32), '{}'
        );
        RAISE EXCEPTION 'migration 050 allowed a new legacy derivation identity';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO chain_swap_records (
            id, invoice_id, nym, boltz_swap_id, from_chain, to_chain,
            lockup_address, user_lock_amount_sat, server_lock_amount_sat,
            preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json
        ) VALUES (
            '50000000-0000-0000-0000-000000000006',
            '46000000-0000-0000-0000-000000000001',
            'og-migration-fixture', 'migration-050-new-legacy-chain',
            'BTC', 'L-BTC',
            'bc1qmigration050newlegacychain000000000000000000',
            51000, 50000, repeat('46', 32), repeat('57', 32),
            repeat('68', 32), '{}'
        );
        RAISE EXCEPTION 'migration 050 allowed a new all-NULL legacy chain row';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    -- Signed purge may remove terminal secret-bearing migration-044 rows. The
    -- non-secret ledger must continue to exclude every index through the old
    -- maximum after all corresponding live rows are gone.
    DELETE FROM swap_records
     WHERE id = '50000000-0000-0000-0000-000000000001';
    DELETE FROM chain_swap_records
     WHERE id = '46000000-0000-0000-0000-000000000002';
    IF (
        SELECT max_child_index
          FROM swap_key_legacy_high_water
         WHERE root_fingerprint = repeat('ab', 8)
    ) <> 5002 THEN
        RAISE EXCEPTION 'migration 050 lost legacy high-water after swap-row deletion';
    END IF;
    BEGIN
        INSERT INTO swap_key_allocations (
            root_fingerprint, key_epoch, derivation_scheme_version, child_index,
            purpose, public_key_hex, preimage_hash_hex
        ) VALUES (
            repeat('ab', 8), 2, 1, 5001, 'reverse_claim',
            '02' || repeat('12', 32), repeat('a2', 32)
        );
        RAISE EXCEPTION 'migration 050 reused a purged migration-044 index';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('cd', 8), 1, 1, 7000, 'reverse_claim',
        '02' || repeat('11', 32), repeat('aa', 32)
    ) RETURNING id INTO reverse_allocation;

    -- The same identity cannot cross from reverse claim to chain refund.
    BEGIN
        INSERT INTO swap_key_allocations (
            root_fingerprint, key_epoch, derivation_scheme_version, child_index,
            purpose, public_key_hex, preimage_hash_hex
        ) VALUES (
            repeat('cd', 8), 1, 1, 7000, 'chain_refund',
            '03' || repeat('22', 32), NULL
        );
        RAISE EXCEPTION 'migration 050 allowed cross-purpose identity reuse';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    -- An epoch label cannot make the same root/index-derived public key safe
    -- to reuse. Public-key uniqueness remains global across epochs.
    BEGIN
        INSERT INTO swap_key_allocations (
            root_fingerprint, key_epoch, derivation_scheme_version, child_index,
            purpose, public_key_hex, preimage_hash_hex
        ) VALUES (
            repeat('cd', 8), 2, 1, 7000, 'reverse_claim',
            '02' || repeat('11', 32), repeat('bb', 32)
        );
        RAISE EXCEPTION 'migration 050 allowed epoch-only key reuse';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    INSERT INTO swap_records (
        id, nym, boltz_swap_id, amount_sat, invoice, preimage_hex,
        claim_key_hex, boltz_response_json, key_index, root_fingerprint,
        key_allocation_id, key_epoch, derivation_scheme_version,
        claim_public_key_hex, preimage_hash_hex
    ) VALUES (
        '50000000-0000-0000-0000-000000000002',
        'og-migration-fixture', 'migration-050-lineaged-reverse', 70000,
        'lnbc-migration-050-lineaged', repeat('66', 32), repeat('77', 32),
        '{}', 7000, repeat('cd', 8), reverse_allocation, 1, 1,
        '02' || repeat('11', 32), repeat('aa', 32)
    );

    BEGIN
        INSERT INTO swap_records (
            id, nym, boltz_swap_id, amount_sat, invoice, preimage_hex,
            claim_key_hex, boltz_response_json, key_index, root_fingerprint,
            key_allocation_id, key_epoch, derivation_scheme_version,
            claim_public_key_hex, preimage_hash_hex
        ) VALUES (
            '50000000-0000-0000-0000-000000000004',
            'og-migration-fixture', 'migration-050-reused-reverse', 70000,
            'lnbc-migration-050-reused', repeat('66', 32), repeat('77', 32),
            '{}', 7000, repeat('cd', 8), reverse_allocation, 1, 1,
            '02' || repeat('11', 32), repeat('aa', 32)
        );
        RAISE EXCEPTION 'migration 050 allowed one reverse allocation on two rows';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE swap_records
           SET preimage_hash_hex = repeat('bb', 32)
         WHERE id = '50000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 050 allowed reverse lineage mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    -- Ordinary lifecycle fields remain mutable.
    UPDATE swap_records
       SET status = 'lockup_mempool'
     WHERE id = '50000000-0000-0000-0000-000000000002';

    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('cd', 8), 1, 1, 7001, 'chain_claim',
        '02' || repeat('33', 32), repeat('cc', 32)
    ) RETURNING id INTO chain_claim_allocation;
    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('cd', 8), 1, 1, 7002, 'chain_refund',
        '03' || repeat('44', 32), NULL
    ) RETURNING id INTO chain_refund_allocation;

    INSERT INTO chain_swap_records (
        id, invoice_id, nym, boltz_swap_id, from_chain, to_chain,
        lockup_address, user_lock_amount_sat, server_lock_amount_sat,
        preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json,
        claim_key_index, refund_key_index, root_fingerprint,
        claim_key_allocation_id, refund_key_allocation_id, key_epoch,
        derivation_scheme_version, claim_public_key_hex,
        refund_public_key_hex, preimage_hash_hex
    ) VALUES (
        '50000000-0000-0000-0000-000000000003',
        '46000000-0000-0000-0000-000000000001',
        'og-migration-fixture', 'migration-050-lineaged-chain', 'BTC', 'L-BTC',
        'bc1qmigration050lineagedchain000000000000000000000', 71000, 70000,
        repeat('88', 32), repeat('99', 32), repeat('aa', 32), '{}',
        7001, 7002, repeat('cd', 8), chain_claim_allocation,
        chain_refund_allocation, 1, 1, '02' || repeat('33', 32),
        '03' || repeat('44', 32), repeat('cc', 32)
    );

    BEGIN
        UPDATE chain_swap_records
           SET refund_key_index = 7003
         WHERE id = '50000000-0000-0000-0000-000000000003';
        RAISE EXCEPTION 'migration 050 allowed chain lineage mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        UPDATE swap_key_allocations
           SET child_index = 9999
         WHERE id = reverse_allocation;
        RAISE EXCEPTION 'migration 050 allowed allocation mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        DELETE FROM swap_key_allocations WHERE id = reverse_allocation;
        RAISE EXCEPTION 'migration 050 allowed allocation deletion';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        UPDATE swap_key_legacy_high_water
           SET max_child_index = 9999
         WHERE root_fingerprint = repeat('ab', 8);
        RAISE EXCEPTION 'migration 050 allowed legacy high-water mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        DELETE FROM swap_key_legacy_high_water
         WHERE root_fingerprint = repeat('ab', 8);
        RAISE EXCEPTION 'migration 050 allowed legacy high-water deletion';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
END
$$;
