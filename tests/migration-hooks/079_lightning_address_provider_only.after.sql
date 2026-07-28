DO $$
DECLARE
    runtime_role_oid OID;
    owner_role_oid OID;
BEGIN
    IF EXISTS (
        SELECT 1
          FROM migration_078_fiat_only_snapshot snapshot
          JOIN bull_bitcoin_settlements settlement USING (id)
         WHERE ROW(
            settlement.owner_npub, settlement.invoice_id,
            settlement.reverse_swap_id, settlement.chain_swap_id,
            settlement.credential_id, settlement.product,
            settlement.purpose, settlement.payer_rail,
            settlement.request_key, settlement.fiat_percentage,
            settlement.fiat_currency, settlement.requested_bitcoin_sat,
            settlement.bull_bitcoin_order_id, settlement.provider_state,
            settlement.funding_route, settlement.funding_committed_at,
            settlement.settlement_status, settlement.instruction_kind,
            settlement.payer_instruction, settlement.actual_received_sat,
            settlement.credited_fiat_minor, settlement.provider_final,
            settlement.terminal_at, settlement.created_at, settlement.updated_at
         ) IS DISTINCT FROM ROW(
            snapshot.owner_npub, snapshot.invoice_id,
            snapshot.reverse_swap_id, snapshot.chain_swap_id,
            snapshot.credential_id, snapshot.product,
            snapshot.purpose, snapshot.payer_rail,
            snapshot.request_key, snapshot.fiat_percentage,
            snapshot.fiat_currency, snapshot.requested_bitcoin_sat,
            snapshot.bull_bitcoin_order_id, snapshot.provider_state,
            snapshot.funding_route, snapshot.funding_committed_at,
            snapshot.settlement_status, snapshot.instruction_kind,
            snapshot.payer_instruction, snapshot.actual_received_sat,
            snapshot.credited_fiat_minor, snapshot.provider_final,
            snapshot.terminal_at, snapshot.created_at, snapshot.updated_at
         )
    ) OR (
        SELECT COUNT(*) FROM migration_078_fiat_only_snapshot
    ) <> (
        SELECT COUNT(*) FROM bull_bitcoin_settlements
         WHERE purpose = 'fiat_only'
    ) THEN
        RAISE EXCEPTION 'migration 079 changed a historical direct-provider settlement';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'swap_fiat_settlement_policies'::REGCLASS
           AND conname = 'swap_fiat_settlement_policies_percentage_chk'
           AND convalidated
           AND pg_get_constraintdef(oid) LIKE '%fiat_percentage <= 100%'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'bull_bitcoin_settlements'::REGCLASS
           AND conname = 'bull_bitcoin_settlements_purpose_chk'
           AND convalidated
           AND pg_get_constraintdef(oid) LIKE '%provider_only%'
    ) THEN
        RAISE EXCEPTION 'migration 079 did not install the provider-only schema boundary';
    END IF;

    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT owner_role_oid
      FROM pg_class WHERE oid = 'bull_bitcoin_settlements'::REGCLASS;
    IF runtime_role_oid = owner_role_oid
       OR pg_has_role(runtime_role_oid, owner_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, owner_role_oid, 'SET')
       OR NOT has_table_privilege(
            'bullnym_app', 'swap_fiat_settlement_policies', 'SELECT,INSERT')
       OR NOT has_table_privilege(
            'bullnym_app', 'bull_bitcoin_settlements', 'SELECT,INSERT,UPDATE')
       OR NOT has_table_privilege(
            'bullnym_app', 'bull_bitcoin_claim_outputs', 'SELECT,INSERT')
       OR has_table_privilege(
            'bullnym_app', 'bull_bitcoin_claim_outputs', 'UPDATE,DELETE') THEN
        RAISE EXCEPTION 'migration 079 widened or broke the runtime-role boundary';
    END IF;
END
$$;

-- Since migration 059, a user row is valid only after its permanent nym has
-- been claimed by the same owner. Exercise the current registration invariant
-- rather than bypassing the trigger in this forward-migration fixture.
INSERT INTO public_names (name, owner_npub, kind)
VALUES ('migration078provider', repeat('8', 64), 'nym');

INSERT INTO users (nym, npub, ct_descriptor)
VALUES ('migration078provider', repeat('8', 64), 'migration-079-descriptor');

INSERT INTO bull_bitcoin_credentials (
    id, owner_npub, ciphertext, nonce, encryption_format
) VALUES (
    '78000000-0000-4000-8000-000000000001', repeat('8', 64),
    decode(repeat('83', 85), 'hex'), decode(repeat('84', 24), 'hex'), 1
);

WITH allocation AS (
    INSERT INTO swap_key_allocations (
        root_fingerprint, key_epoch, derivation_scheme_version, child_index,
        purpose, public_key_hex, preimage_hash_hex
    ) VALUES (
        repeat('88', 8), 1, 1, 780000, 'reverse_claim',
        '02' || repeat('85', 32), repeat('86', 32)
    ) RETURNING id
)
INSERT INTO swap_records (
    id, nym, boltz_swap_id, amount_sat, invoice, preimage_hex,
    claim_key_hex, boltz_response_json, invoice_id,
    key_index, root_fingerprint, key_allocation_id, key_epoch,
    derivation_scheme_version, claim_public_key_hex, preimage_hash_hex
)
SELECT
    '78000000-0000-4000-8000-000000000002', 'migration078provider',
    'migration-079-provider-only-reverse', 10000, 'lnbc-migration-079',
    repeat('87', 32), repeat('88', 32), '{}', NULL,
    780000, repeat('88', 8), allocation.id, 1, 1,
    '02' || repeat('85', 32), repeat('86', 32)
FROM allocation;

INSERT INTO swap_fiat_settlement_policies (
    reverse_swap_id, owner_npub, credential_id, product,
    fiat_percentage, fiat_currency
) VALUES (
    '78000000-0000-4000-8000-000000000002', repeat('8', 64),
    '78000000-0000-4000-8000-000000000001',
    'lightning_address', 100, 'CAD'
);

INSERT INTO bull_bitcoin_settlements (
    id, owner_npub, reverse_swap_id, credential_id, product, purpose,
    payer_rail, request_key, fiat_percentage, fiat_currency,
    requested_bitcoin_sat, expected_instruction_script_len
) VALUES (
    '78000000-0000-4000-8000-000000000003', repeat('8', 64),
    '78000000-0000-4000-8000-000000000002',
    '78000000-0000-4000-8000-000000000001',
    'lightning_address', 'provider_only', 'lightning',
    'mixed-reverse:78000000-0000-4000-8000-000000000002',
    100, 'CAD', 9999, 22
);

UPDATE bull_bitcoin_settlements
   SET provider_state = 'dispatch_started', updated_at = clock_timestamp()
 WHERE id = '78000000-0000-4000-8000-000000000003';
UPDATE bull_bitcoin_settlements
   SET provider_state = 'bound',
       bull_bitcoin_order_id = '78000000-0000-4000-8000-000000000004',
       order_correlation_source = 'provider_response',
       order_correlated_at = clock_timestamp(),
       instruction_kind = 'liquid',
       payer_instruction = 'VJL6migration078ConfidentialLiquidAddress',
       updated_at = clock_timestamp()
 WHERE id = '78000000-0000-4000-8000-000000000003';

DO $$
BEGIN
    BEGIN
        INSERT INTO bull_bitcoin_claim_outputs (
            settlement_id, role, txid, vout, script_pubkey_hex,
            authorized_amount_sat, asset_commitment_sha256,
            value_commitment_sha256, nonce_commitment_sha256,
            surjection_proof_sha256, rangeproof_sha256
        ) VALUES (
            '78000000-0000-4000-8000-000000000003', 'merchant',
            repeat('89', 32), 0, '0014' || repeat('8a', 20), 1,
            repeat('8b', 32), repeat('8c', 32), repeat('8d', 32),
            repeat('8e', 32), repeat('8f', 32)
        );
        RAISE EXCEPTION 'migration 079 accepted a merchant output for provider-only';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

INSERT INTO bull_bitcoin_claim_outputs (
    settlement_id, role, txid, vout, script_pubkey_hex,
    authorized_amount_sat, asset_commitment_sha256,
    value_commitment_sha256, nonce_commitment_sha256,
    surjection_proof_sha256, rangeproof_sha256
) VALUES (
    '78000000-0000-4000-8000-000000000003', 'bull_bitcoin',
    repeat('89', 32), 0, '0014' || repeat('90', 20), 9999,
    repeat('91', 32), repeat('92', 32), repeat('93', 32),
    repeat('94', 32), repeat('95', 32)
);

UPDATE bull_bitcoin_settlements
   SET funding_route = 'bull_bitcoin', funding_committed_at = clock_timestamp(),
       settlement_status = 'pending', instruction_kind = NULL,
       payer_instruction = NULL, updated_at = clock_timestamp()
 WHERE id = '78000000-0000-4000-8000-000000000003';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM bull_bitcoin_settlements settlement
          JOIN bull_bitcoin_claim_outputs output
            ON output.settlement_id = settlement.id
         WHERE settlement.id = '78000000-0000-4000-8000-000000000003'
           AND settlement.purpose = 'provider_only'
           AND settlement.payer_rail = 'lightning'
           AND settlement.fiat_percentage = 100
           AND settlement.funding_route = 'bull_bitcoin'
           AND settlement.funding_committed_at IS NOT NULL
           AND settlement.settlement_status = 'pending'
           AND output.role = 'bull_bitcoin'
           AND output.vout = 0
           AND output.authorized_amount_sat = 9999
    ) OR (SELECT COUNT(*) FROM bull_bitcoin_claim_outputs
           WHERE settlement_id = '78000000-0000-4000-8000-000000000003') <> 1 THEN
        RAISE EXCEPTION 'migration 079 rejected its exact one-output provider path';
    END IF;
END
$$;

DROP TABLE migration_078_fiat_only_snapshot;
