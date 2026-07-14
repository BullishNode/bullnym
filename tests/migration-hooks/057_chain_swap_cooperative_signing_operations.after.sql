-- Migration 057 must create no historical intent and must enforce one durable
-- request, canonical response evidence, immutable secrets, and append-only
-- terminal evidence at the schema boundary.
DO $$
BEGIN
    IF (SELECT COUNT(*) FROM chain_swap_cooperative_signing_operations) <> 0 THEN
        RAISE EXCEPTION 'migration 057 fabricated historical signing intent';
    END IF;
END
$$;

INSERT INTO chain_swap_cooperative_signing_operations (
    chain_swap_id, boltz_swap_id,
    source_txid, source_vout, source_amount_sat, source_script_pubkey_hex,
    destination_address, destination_script_pubkey_hex, destination_amount_sat,
    fee_amount_sat, fee_vbytes,
    fee_decision_purpose, fee_decision_rail, fee_decision_target,
    fee_decision_source, fee_decision_rate_sat_vb,
    fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix,
    fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs,
    fee_decision_provenance, fee_decision_policy_floor_sat_vb,
    fee_decision_policy_cap_sat_vb, fee_decision_policy_version,
    request_transaction_hex, request_transaction_sha256,
    request_transaction_txid, sighash_hex, aggregate_key_xonly_hex,
    client_public_nonce_hex, provider_request_sha256, session_sha256,
    secret_nonce_format, secret_nonce_encryption_algorithm,
    secret_nonce_key_id, secret_nonce_encryption_nonce,
    secret_nonce_ciphertext, secret_nonce_plaintext_sha256
)
SELECT
    parent.id, parent.boltz_swap_id,
    repeat('1', 64), 0, 1000, '51',
    'bc1pmigration057fixture', '51', 800,
    200, 100,
    'bitcoin_recovery', 'bitcoin', 'fastestFee',
    'bitcoin_live', 2.0,
    1000, 1000, 0, 120,
    'migration-057-upgrade-fixture', 1.0, 500.0, 'review25-v1',
    '00', encode(digest(decode('00', 'hex'), 'sha256'), 'hex'),
    repeat('2', 64), repeat('3', 64), repeat('4', 64),
    repeat('5', 132), repeat('6', 64), repeat('7', 64),
    'secp256k1-musig-secnonce-132-v1', 'xchacha20poly1305-v1',
    'migration-057-fixture', decode(repeat('8', 48), 'hex'),
    decode(repeat('9', 296), 'hex'), repeat('a', 64)
  FROM chain_swap_records parent
 WHERE parent.id = '53000000-0000-0000-0000-000000000012';

UPDATE chain_swap_cooperative_signing_operations
   SET state = 'requested', request_attempt_count = 1,
       requested_at = '2020-01-01 00:00:00+00', version = 2
 WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';

UPDATE chain_swap_cooperative_signing_operations
   SET state = 'response_received',
       provider_public_nonce_hex = repeat('b', 132),
       provider_partial_signature_hex = repeat('c', 64),
       provider_response_sha256 = encode(
           digest(
               convert_to(
                   'bullnym:cooperative-signing-provider-response:v1:', 'UTF8'
               ) || decode(repeat('b', 132), 'hex')
                 || decode(repeat('c', 64), 'hex'),
               'sha256'
           ), 'hex'
       ),
       response_received_at = '2020-01-01 00:00:00+00', version = 3
 WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';

DO $$
DECLARE
    original_response_sha256 TEXT;
BEGIN
    SELECT provider_response_sha256 INTO STRICT original_response_sha256
      FROM chain_swap_cooperative_signing_operations
     WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';

    BEGIN
        UPDATE chain_swap_cooperative_signing_operations
           SET provider_response_sha256 = repeat('d', 64),
               version = version + 1
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 057 allowed provider response overwrite';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    UPDATE chain_swap_cooperative_signing_operations
       SET state = 'integrity_hold',
           integrity_reason_sha256 = repeat('e', 64),
           integrity_hold_at = '2020-01-01 00:00:00+00',
           version = 4
     WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';

    BEGIN
        UPDATE chain_swap_cooperative_signing_operations
           SET secret_nonce_ciphertext = decode(repeat('f', 296), 'hex')
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 057 allowed encrypted nonce mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    BEGIN
        DELETE FROM chain_swap_cooperative_signing_operations
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012';
        RAISE EXCEPTION 'migration 057 allowed journal deletion';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        NULL;
    END;

    IF NOT EXISTS (
        SELECT 1
          FROM chain_swap_cooperative_signing_operations
         WHERE chain_swap_id = '53000000-0000-0000-0000-000000000012'
           AND state = 'integrity_hold'
           AND version = 4
           AND provider_response_sha256 = original_response_sha256
           AND requested_at > '2020-01-01 00:00:00+00'::TIMESTAMPTZ
           AND response_received_at > '2020-01-01 00:00:00+00'::TIMESTAMPTZ
           AND integrity_hold_at > '2020-01-01 00:00:00+00'::TIMESTAMPTZ
    ) THEN
        RAISE EXCEPTION 'migration 057 lost exact response or database-owned clocks';
    END IF;
END
$$;
