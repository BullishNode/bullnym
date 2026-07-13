DO $$
DECLARE
    first_manifest CONSTANT UUID := '52000000-0000-0000-0000-000000000001';
    second_manifest CONSTANT UUID := '52000000-0000-0000-0000-000000000002';
    first_swap CONSTANT UUID := '50000000-0000-0000-0000-000000000003';
    second_swap CONSTANT UUID := '51000000-0000-0000-0000-000000000003';
    first_envelope CONSTANT TEXT :=
        '{"ciphertext_hex":"51515151515151515151515151515151","encryption_algorithm":"xchacha20poly1305","encryption_key_id":"manifest-key-migration-052","format":"bullnym-chain-swap-manifest",' ||
        '"nonce_hex":"525252525252525252525252525252525252525252525252","signature_algorithm":"bip340-secp256k1-sha256","signer_xonly_public_key":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","version":1}';
    second_envelope CONSTANT TEXT :=
        '{"ciphertext_hex":"53535353535353535353535353535353","encryption_algorithm":"xchacha20poly1305","encryption_key_id":"manifest-key-migration-052","format":"bullnym-chain-swap-manifest",' ||
        '"nonce_hex":"545454545454545454545454545454545454545454545454","signature_algorithm":"bip340-secp256k1-sha256","signer_xonly_public_key":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","version":1}';
    mutated_envelope CONSTANT TEXT :=
        '{"ciphertext_hex":"55555555555555555555555555555555","encryption_algorithm":"xchacha20poly1305","encryption_key_id":"manifest-key-migration-052","format":"bullnym-chain-swap-manifest",' ||
        '"nonce_hex":"565656565656565656565656565656565656565656565656","signature_algorithm":"bip340-secp256k1-sha256","signer_xonly_public_key":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","version":1}';
    first_digest TEXT;
    second_digest TEXT;
    persisted_count BIGINT;
BEGIN
    first_digest := encode(digest(convert_to(first_envelope, 'UTF8'), 'sha256'), 'hex');
    second_digest := encode(digest(convert_to(second_envelope, 'UTF8'), 'sha256'), 'hex');

    BEGIN
        INSERT INTO chain_swap_manifest_deliveries (
            manifest_id, chain_swap_id, manifest_sequence,
            encrypted_envelope, envelope_sha256
        ) VALUES (
            '52000000-0000-0000-0000-000000000099',
            '52000000-0000-0000-0000-000000000098', 1,
            first_envelope, first_digest
        );
        RAISE EXCEPTION 'migration 052 accepted a nonexistent source swap';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO chain_swap_manifest_deliveries (
            manifest_id, chain_swap_id, manifest_sequence,
            encrypted_envelope, envelope_sha256
        ) VALUES (
            first_manifest, first_swap, 1, first_envelope, repeat('a', 64)
        );
        RAISE EXCEPTION 'migration 052 accepted a mismatched envelope digest';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO chain_swap_manifest_deliveries (
        manifest_id, chain_swap_id, manifest_sequence,
        encrypted_envelope, envelope_sha256
    ) VALUES (
        first_manifest, first_swap, 1, first_envelope, first_digest
    );

    BEGIN
        INSERT INTO chain_swap_manifest_deliveries (
            manifest_id, chain_swap_id, manifest_sequence,
            previous_manifest_id, encrypted_envelope, envelope_sha256
        ) VALUES (
            second_manifest, second_swap, 2,
            first_manifest, second_envelope, second_digest
        );
        RAISE EXCEPTION 'migration 052 allowed a later row past a pending delivery';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    UPDATE chain_swap_manifest_deliveries
       SET delivery_state = 'delivered', delivered_at = NOW()
     WHERE manifest_id = first_manifest;

    BEGIN
        INSERT INTO chain_swap_manifest_deliveries (
            manifest_id, chain_swap_id, manifest_sequence,
            previous_manifest_id, encrypted_envelope, envelope_sha256
        ) VALUES (
            second_manifest, second_swap, 3,
            first_manifest, second_envelope, second_digest
        );
        RAISE EXCEPTION 'migration 052 allowed a global sequence gap';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO chain_swap_manifest_deliveries (
        manifest_id, chain_swap_id, manifest_sequence,
        previous_manifest_id, encrypted_envelope, envelope_sha256
    ) VALUES (
        second_manifest, second_swap, 2,
        first_manifest, second_envelope, second_digest
    );

    BEGIN
        UPDATE chain_swap_manifest_deliveries
           SET encrypted_envelope = mutated_envelope,
               envelope_sha256 = encode(
                   digest(convert_to(mutated_envelope, 'UTF8'), 'sha256'),
                   'hex'
               )
         WHERE manifest_id = second_manifest;
        RAISE EXCEPTION 'migration 052 allowed envelope mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        DELETE FROM chain_swap_manifest_deliveries
         WHERE manifest_id = second_manifest;
        RAISE EXCEPTION 'migration 052 allowed witness deletion';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    UPDATE chain_swap_manifest_deliveries
       SET delivery_state = 'delivered', delivered_at = NOW()
     WHERE manifest_id = second_manifest;

    -- The ledger has only an insert-time source relationship. Operational
    -- cleanup must not erase or be blocked by an already-created witness.
    DELETE FROM chain_swap_records WHERE id = second_swap;
    SELECT COUNT(*) INTO STRICT persisted_count
      FROM chain_swap_manifest_deliveries
     WHERE manifest_id = second_manifest
       AND chain_swap_id = second_swap
       AND manifest_sequence = 2
       AND previous_manifest_id = first_manifest
       AND encrypted_envelope = second_envelope
       AND envelope_sha256 = second_digest
       AND delivery_state = 'delivered'
       AND delivered_at IS NOT NULL;
    IF persisted_count <> 1 THEN
        RAISE EXCEPTION 'migration 052 witness did not survive source cleanup';
    END IF;
END
$$;
