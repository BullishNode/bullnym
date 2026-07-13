DO $$
DECLARE
    unexpected_privileges TEXT[] := ARRAY[]::TEXT[];
    ledger_owner TEXT;
BEGIN
    IF (SELECT COUNT(*) FROM recovery_address_commitments) <> 0 THEN
        RAISE EXCEPTION 'migration 053 fabricated recovery-address commitments';
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
