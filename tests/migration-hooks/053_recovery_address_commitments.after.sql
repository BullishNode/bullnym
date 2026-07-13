DO $$
DECLARE
    unexpected_privileges TEXT[] := ARRAY[]::TEXT[];
    ledger_owner TEXT;
BEGIN
    IF (SELECT COUNT(*) FROM recovery_address_commitments) <> 0 THEN
        RAISE EXCEPTION 'migration 053 fabricated recovery-address commitments';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'chain_swap_records'
           AND column_name = 'recovery_address_commitment_id'
           AND udt_name = 'uuid'
           AND is_nullable = 'YES'
    ) THEN
        RAISE EXCEPTION 'migration 053 omitted the legacy-nullable chain-swap commitment identity';
    END IF;
    IF EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE recovery_address_commitment_id IS NOT NULL
            OR merchant_emergency_btc_address IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 053 fabricated commitment evidence for a historical chain swap';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint fk
          JOIN pg_class source_relation ON source_relation.oid = fk.conrelid
          JOIN pg_class target_relation ON target_relation.oid = fk.confrelid
         WHERE source_relation.relname = 'chain_swap_records'
           AND target_relation.relname = 'recovery_address_commitments'
           AND fk.conname = 'chain_swap_records_recovery_commitment_fkey'
           AND fk.contype = 'f'
           AND fk.convalidated
           AND fk.confupdtype = 'r'
           AND fk.confdeltype = 'r'
           AND NOT fk.condeferrable
    ) THEN
        RAISE EXCEPTION 'migration 053 omitted the validated immutable chain-swap composite foreign key';
    END IF;
    IF (
        SELECT COUNT(*)
          FROM pg_trigger trigger_info
          JOIN pg_class relation ON relation.oid = trigger_info.tgrelid
         WHERE relation.relname = 'chain_swap_records'
           AND trigger_info.tgname IN (
               'chain_swap_records_require_recovery_commitment',
               'chain_swap_records_reject_recovery_commitment_update'
           )
           AND NOT trigger_info.tgisinternal
           AND trigger_info.tgenabled IN ('O', 'A')
    ) <> 2 THEN
        RAISE EXCEPTION 'migration 053 omitted an enabled chain-swap commitment trigger';
    END IF;

    SELECT pg_get_userbyid(relowner)
      INTO ledger_owner
      FROM pg_class
     WHERE oid = 'recovery_address_commitments'::REGCLASS;
    IF ledger_owner = 'payservice' THEN
        RAISE EXCEPTION 'migration 053 left the runtime role as ledger owner';
    END IF;

    IF NOT has_table_privilege('payservice', 'recovery_address_commitments', 'SELECT')
       OR NOT has_table_privilege('payservice', 'recovery_address_commitments', 'INSERT') THEN
        RAISE EXCEPTION 'migration 053 omitted runtime SELECT or INSERT privilege';
    END IF;
    IF has_table_privilege('payservice', 'recovery_address_commitments', 'UPDATE') THEN
        unexpected_privileges := array_append(unexpected_privileges, 'UPDATE');
    END IF;
    IF has_table_privilege('payservice', 'recovery_address_commitments', 'DELETE') THEN
        unexpected_privileges := array_append(unexpected_privileges, 'DELETE');
    END IF;
    IF has_table_privilege('payservice', 'recovery_address_commitments', 'TRUNCATE') THEN
        unexpected_privileges := array_append(unexpected_privileges, 'TRUNCATE');
    END IF;
    IF has_table_privilege('payservice', 'recovery_address_commitments', 'REFERENCES') THEN
        unexpected_privileges := array_append(unexpected_privileges, 'REFERENCES');
    END IF;
    IF has_table_privilege('payservice', 'recovery_address_commitments', 'TRIGGER') THEN
        unexpected_privileges := array_append(unexpected_privileges, 'TRIGGER');
    END IF;
    IF cardinality(unexpected_privileges) <> 0 THEN
        RAISE EXCEPTION 'migration 053 granted unexpected runtime privileges: %',
            unexpected_privileges;
    END IF;
END
$$;

CREATE FUNCTION migration_053_prove_chain_swap_binding() RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    first_claim_allocation UUID;
    first_refund_allocation UUID;
    second_claim_allocation UUID;
    second_refund_allocation UUID;
    refusal_constraint TEXT;
BEGIN
    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('53', 8), 1, 1, 5301, 'chain_claim',
        '02' || repeat('31', 32), repeat('41', 32)
    ) RETURNING id INTO first_claim_allocation;
    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('53', 8), 1, 1, 5302, 'chain_refund',
        '03' || repeat('32', 32), NULL
    ) RETURNING id INTO first_refund_allocation;

    -- No post-053 writer may retain the legacy NULL/NULL shape.
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
            '53000000-0000-0000-0000-000000000010',
            '46000000-0000-0000-0000-000000000001',
            'og-migration-fixture', 'migration-053-missing-commitment',
            'BTC', 'L-BTC', 'bc1qmigration053missingcommitment000000000000000000',
            26000, 25000, repeat('33', 32), repeat('34', 32),
            repeat('35', 32), '{"id":"migration-053-missing"}',
            5301, 5302, repeat('53', 8), first_claim_allocation,
            first_refund_allocation, 1, 1, '02' || repeat('31', 32),
            '03' || repeat('32', 32), repeat('41', 32), repeat('51', 32),
            '{"hash":"migration-053"}', repeat('52', 32), repeat('53', 32),
            repeat('54', 32), repeat('55', 32), repeat('56', 32),
            958033, 3972215, 'bitcoin', 'liquid', repeat('57', 32),
            'lq1qqmigration053merchantdestination0000000000000000000000000000000000'
        );
        RAISE EXCEPTION 'migration 053 allowed a new chain swap without a commitment pair';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint IS DISTINCT FROM 'chain_swap_records_recovery_commitment_pair_check' THEN
            RAISE EXCEPTION 'missing-pair refusal reported wrong constraint: %', refusal_constraint;
        END IF;
    END;

    -- Supplying both values is insufficient when the address belongs to a
    -- different immutable commitment.
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
            liquid_asset_id, merchant_liquid_destination,
            merchant_emergency_btc_address, recovery_address_commitment_id
        ) VALUES (
            '53000000-0000-0000-0000-000000000011',
            '46000000-0000-0000-0000-000000000001',
            'og-migration-fixture', 'migration-053-mismatched-commitment',
            'BTC', 'L-BTC', 'bc1qmigration053mismatchedcommitment00000000000000000',
            26000, 25000, repeat('33', 32), repeat('34', 32),
            repeat('35', 32), '{"id":"migration-053-mismatch"}',
            5301, 5302, repeat('53', 8), first_claim_allocation,
            first_refund_allocation, 1, 1, '02' || repeat('31', 32),
            '03' || repeat('32', 32), repeat('41', 32), repeat('51', 32),
            '{"hash":"migration-053"}', repeat('52', 32), repeat('53', 32),
            repeat('54', 32), repeat('55', 32), repeat('56', 32),
            958033, 3972215, 'bitcoin', 'liquid', repeat('57', 32),
            'lq1qqmigration053merchantdestination0000000000000000000000000000000000',
            '1BoatSLRHtKNngkdXEeobR76b53LETtpyT',
            '53000000-0000-0000-0000-000000000001'
        );
        RAISE EXCEPTION 'migration 053 allowed a mismatched commitment ID/address';
    EXCEPTION WHEN foreign_key_violation THEN
        GET STACKED DIAGNOSTICS refusal_constraint = CONSTRAINT_NAME;
        IF refusal_constraint IS DISTINCT FROM 'chain_swap_records_recovery_commitment_fkey' THEN
            RAISE EXCEPTION 'mismatch refusal reported wrong constraint: %', refusal_constraint;
        END IF;
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
        merchant_emergency_btc_address, recovery_address_commitment_id
    ) VALUES (
        '53000000-0000-0000-0000-000000000012',
        '46000000-0000-0000-0000-000000000001',
        'og-migration-fixture', 'migration-053-commitment-v1',
        'BTC', 'L-BTC', 'bc1qmigration053commitmentv10000000000000000000000000',
        26000, 25000, repeat('33', 32), repeat('34', 32),
        repeat('35', 32), '{"id":"migration-053-v1"}',
        5301, 5302, repeat('53', 8), first_claim_allocation,
        first_refund_allocation, 1, 1, '02' || repeat('31', 32),
        '03' || repeat('32', 32), repeat('41', 32), repeat('51', 32),
        '{"hash":"migration-053"}', repeat('52', 32), repeat('53', 32),
        repeat('54', 32), repeat('55', 32), repeat('56', 32),
        958033, 3972215, 'bitcoin', 'liquid', repeat('57', 32),
        'lq1qqmigration053merchantdestination0000000000000000000000000000000000',
        'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
        '53000000-0000-0000-0000-000000000001'
    );

    BEGIN
        UPDATE chain_swap_records
           SET recovery_address_commitment_id =
               '53000000-0000-0000-0000-000000000002',
               merchant_emergency_btc_address =
               '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'
         WHERE id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 053 allowed an existing swap to follow a rotation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    -- Non-evidence lifecycle mutation remains available.
    UPDATE chain_swap_records
       SET status = 'user_lock_mempool'
     WHERE id = '53000000-0000-0000-0000-000000000012';

    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('53', 8), 1, 1, 5303, 'chain_claim',
        '02' || repeat('36', 32), repeat('46', 32)
    ) RETURNING id INTO second_claim_allocation;
    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('53', 8), 1, 1, 5304, 'chain_refund',
        '03' || repeat('37', 32), NULL
    ) RETURNING id INTO second_refund_allocation;

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
        merchant_emergency_btc_address, recovery_address_commitment_id
    ) VALUES (
        '53000000-0000-0000-0000-000000000013',
        '46000000-0000-0000-0000-000000000001',
        'og-migration-fixture', 'migration-053-commitment-v2',
        'BTC', 'L-BTC', 'bc1qmigration053commitmentv20000000000000000000000000',
        26000, 25000, repeat('38', 32), repeat('39', 32),
        repeat('3a', 32), '{"id":"migration-053-v2"}',
        5303, 5304, repeat('53', 8), second_claim_allocation,
        second_refund_allocation, 1, 1, '02' || repeat('36', 32),
        '03' || repeat('37', 32), repeat('46', 32), repeat('58', 32),
        '{"hash":"migration-053-v2"}', repeat('59', 32), repeat('5a', 32),
        repeat('5b', 32), repeat('5c', 32), repeat('5d', 32),
        958034, 3972216, 'bitcoin', 'liquid', repeat('5e', 32),
        'lq1qqmigration053merchantdestination0000000000000000000000000000000000',
        '1BoatSLRHtKNngkdXEeobR76b53LETtpyT',
        '53000000-0000-0000-0000-000000000002'
    );

    IF NOT EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000012'
           AND recovery_address_commitment_id =
               '53000000-0000-0000-0000-000000000001'
           AND merchant_emergency_btc_address =
               'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
    ) OR NOT EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE id = '53000000-0000-0000-0000-000000000013'
           AND recovery_address_commitment_id =
               '53000000-0000-0000-0000-000000000002'
           AND merchant_emergency_btc_address =
               '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'
    ) THEN
        RAISE EXCEPTION 'migration 053 did not preserve per-swap commitment rotation identity';
    END IF;
END
$$;

SET ROLE payservice;

INSERT INTO recovery_address_commitments (
    commitment_id,
    npub,
    contract_format_version,
    commitment_version,
    canonical_btc_address,
    original_signature,
    signed_at_unix,
    registered_at
) VALUES (
    '53000000-0000-0000-0000-000000000001',
    '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    1,
    1,
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
    repeat('ab', 64),
    1700000000,
    '2099-01-01 00:00:00+00'
);

-- Exercise the granted read privilege, not only its catalog projection.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM recovery_address_commitments
         WHERE commitment_id = '53000000-0000-0000-0000-000000000001'
    ) THEN
        RAISE EXCEPTION 'runtime role could not read its inserted commitment';
    END IF;

    BEGIN
        UPDATE recovery_address_commitments
           SET canonical_btc_address = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'
         WHERE commitment_id = '53000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'runtime role unexpectedly updated a commitment';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;

    BEGIN
        DELETE FROM recovery_address_commitments
         WHERE commitment_id = '53000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'runtime role unexpectedly deleted a commitment';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END
$$;

RESET ROLE;

DO $$
DECLARE
    source_constraint TEXT;
BEGIN
    -- The client-supplied registration time above must have been replaced by
    -- database time at insertion.
    IF (SELECT registered_at > clock_timestamp()
          FROM recovery_address_commitments
         WHERE commitment_id = '53000000-0000-0000-0000-000000000001') THEN
        RAISE EXCEPTION 'migration 053 allowed a caller-forged registration time';
    END IF;

    BEGIN
        INSERT INTO recovery_address_commitments (
            commitment_id, npub, contract_format_version, commitment_version,
            canonical_btc_address, original_signature, signed_at_unix
        ) VALUES (
            '53000000-0000-0000-0000-000000000090',
            'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
            1, 1, '1BoatSLRHtKNngkdXEeobR76b53LETtpyT', repeat('90', 64),
            1700000090
        );
        RAISE EXCEPTION 'migration 053 accepted an unknown source identity';
    EXCEPTION WHEN foreign_key_violation THEN
        GET STACKED DIAGNOSTICS source_constraint = CONSTRAINT_NAME;
        IF source_constraint IS DISTINCT FROM 'recovery_address_commitment_source_exists' THEN
            RAISE EXCEPTION 'unknown-source refusal reported wrong constraint: %',
                source_constraint;
        END IF;
    END;

    BEGIN
        INSERT INTO recovery_address_commitments (
            commitment_id, npub, contract_format_version, commitment_version,
            canonical_btc_address, original_signature, signed_at_unix
        ) VALUES (
            '53000000-0000-0000-0000-000000000091',
            'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
            1, 1, '1BoatSLRHtKNngkdXEeobR76b53LETtpyT', repeat('91', 64),
            1700000091
        );
        RAISE EXCEPTION 'migration 053 accepted an inactive source identity';
    EXCEPTION WHEN foreign_key_violation THEN
        GET STACKED DIAGNOSTICS source_constraint = CONSTRAINT_NAME;
        IF source_constraint IS DISTINCT FROM 'recovery_address_commitment_source_exists' THEN
            RAISE EXCEPTION 'inactive-source refusal reported wrong constraint: %',
                source_constraint;
        END IF;
    END;

    BEGIN
        INSERT INTO recovery_address_commitments (
            commitment_id, npub, contract_format_version, commitment_version,
            canonical_btc_address, original_signature, signed_at_unix
        ) VALUES (
            '53000000-0000-0000-0000-000000000099',
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            1, 3, '1BoatSLRHtKNngkdXEeobR76b53LETtpyT', repeat('cd', 64),
            1700000001
        );
        RAISE EXCEPTION 'migration 053 allowed a per-npub version gap';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO recovery_address_commitments (
        commitment_id, npub, contract_format_version, commitment_version,
        canonical_btc_address, original_signature, signed_at_unix
    ) VALUES (
        '53000000-0000-0000-0000-000000000002',
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        1, 2, '1BoatSLRHtKNngkdXEeobR76b53LETtpyT', repeat('cd', 64),
        1700000001
    );

    -- Both immutable versions now exist while their source identity remains
    -- active. Prove exact binding and future-only rotation before testing the
    -- independent source-deactivation boundary below.
    PERFORM migration_053_prove_chain_swap_binding();

    BEGIN
        INSERT INTO recovery_address_commitments (
            commitment_id, npub, contract_format_version, commitment_version,
            canonical_btc_address, original_signature, signed_at_unix
        ) VALUES (
            '53000000-0000-0000-0000-000000000003',
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            1, 3, 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
            repeat('cd', 64), 1700000002
        );
        RAISE EXCEPTION 'migration 053 allowed one signature to back multiple commitments';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    UPDATE users
       SET is_active = FALSE
     WHERE npub = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
       AND is_active = TRUE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 053 active source fixture could not be deactivated';
    END IF;
    IF (SELECT COUNT(*)
          FROM recovery_address_commitments
         WHERE npub = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') <> 2 THEN
        RAISE EXCEPTION 'accepted recovery evidence did not survive source deactivation';
    END IF;
    IF (SELECT MAX(commitment_version)
          FROM recovery_address_commitments
         WHERE npub = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') <> 2 THEN
        RAISE EXCEPTION 'current recovery evidence changed during source deactivation';
    END IF;

    BEGIN
        INSERT INTO recovery_address_commitments (
            commitment_id, npub, contract_format_version, commitment_version,
            canonical_btc_address, original_signature, signed_at_unix
        ) VALUES (
            '53000000-0000-0000-0000-000000000004',
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            1, 3, 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
            repeat('ef', 64), 1700000003
        );
        RAISE EXCEPTION 'migration 053 accepted evidence after source deactivation';
    EXCEPTION WHEN foreign_key_violation THEN
        GET STACKED DIAGNOSTICS source_constraint = CONSTRAINT_NAME;
        IF source_constraint IS DISTINCT FROM 'recovery_address_commitment_source_exists' THEN
            RAISE EXCEPTION 'post-deactivation refusal reported wrong constraint: %',
                source_constraint;
        END IF;
    END;

    BEGIN
        UPDATE recovery_address_commitments
           SET canonical_btc_address = '1BitcoinEaterAddressDontSendf59kuE'
         WHERE commitment_id = '53000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 053 allowed owner-level commitment mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        DELETE FROM recovery_address_commitments
         WHERE commitment_id = '53000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 053 allowed owner-level commitment deletion';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;
END
$$;

DROP FUNCTION migration_053_prove_chain_swap_binding();
