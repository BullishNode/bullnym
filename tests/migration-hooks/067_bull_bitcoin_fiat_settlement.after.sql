DO $$
DECLARE
    runtime_role_oid OID;
    owner_role_oid OID;
    credential_id UUID := '11111111-1111-4111-8111-111111111111';
    settlement_id UUID := '22222222-2222-4222-8222-222222222222';
    owner_npub TEXT := repeat('a', 64);
BEGIN
    IF to_regclass('public.bull_bitcoin_credentials') IS NULL
       OR to_regclass('public.fiat_settlement_settings') IS NULL
       OR to_regclass('public.invoice_fiat_settlement_policies') IS NULL
       OR to_regclass('public.bull_bitcoin_settlements') IS NULL THEN
        RAISE EXCEPTION 'migration 067 did not create its complete foundation';
    END IF;

    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT owner_role_oid
      FROM pg_class WHERE oid = 'bull_bitcoin_credentials'::REGCLASS;
    IF runtime_role_oid = owner_role_oid
       OR pg_has_role(runtime_role_oid, owner_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, owner_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 067 did not separate runtime and schema ownership';
    END IF;

    IF NOT has_table_privilege('bullnym_app', 'bull_bitcoin_credentials', 'SELECT')
       OR NOT has_table_privilege('bullnym_app', 'bull_bitcoin_credentials', 'INSERT')
       OR NOT has_table_privilege('bullnym_app', 'bull_bitcoin_credentials', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'bull_bitcoin_credentials', 'DELETE')
       OR NOT has_table_privilege('bullnym_app', 'fiat_settlement_settings', 'DELETE')
       OR has_table_privilege('bullnym_app', 'invoice_fiat_settlement_policies', 'UPDATE')
       OR has_table_privilege('bullnym_app', 'invoice_fiat_settlement_policies', 'DELETE')
       OR has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'DELETE')
       OR has_table_privilege('bullnym_app', 'bull_bitcoin_settlements', 'TRUNCATE') THEN
        RAISE EXCEPTION 'migration 067 runtime privileges are broader or narrower than required';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_class relation
          CROSS JOIN LATERAL aclexplode(COALESCE(
              relation.relacl, acldefault('r', relation.relowner)
          )) acl
         WHERE relation.oid IN (
             'bull_bitcoin_credentials'::REGCLASS,
             'fiat_settlement_settings'::REGCLASS,
             'invoice_fiat_settlement_policies'::REGCLASS,
             'bull_bitcoin_settlements'::REGCLASS
         )
           AND acl.grantee = 0
    ) THEN
        RAISE EXCEPTION 'migration 067 exposed private settlement state through PUBLIC';
    END IF;

    INSERT INTO bull_bitcoin_credentials (
        id, owner_npub, ciphertext, nonce, encryption_format
    ) VALUES (
        credential_id, owner_npub,
        decode(repeat('11', 85), 'hex'), decode(repeat('22', 24), 'hex'), 1
    );

    BEGIN
        INSERT INTO bull_bitcoin_credentials (
            id, owner_npub, ciphertext, nonce, encryption_format
        ) VALUES (
            gen_random_uuid(), owner_npub,
            decode(repeat('33', 85), 'hex'), decode(repeat('44', 24), 'hex'), 1
        );
        RAISE EXCEPTION 'migration 067 accepted two admitted credentials for one owner';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO fiat_settlement_settings (
            owner_npub, product, credential_id, fiat_percentage,
            fiat_currency, request_signed_at
        ) VALUES (
            owner_npub, 'invoice', credential_id, 0, 'CAD', now()
        );
        RAISE EXCEPTION 'migration 067 persisted percentage zero instead of row absence';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO bull_bitcoin_settlements (
        id, owner_npub, credential_id, product, purpose, payer_rail,
        request_key, fiat_percentage, fiat_currency,
        requested_bitcoin_sat
    ) VALUES (
        settlement_id, owner_npub, credential_id, 'lightning_address',
        'fiat_only', 'bitcoin', 'migration-067-fixture', 100, 'CAD',
        10000
    );
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'dispatch_started', updated_at = now()
     WHERE id = settlement_id;
    UPDATE bull_bitcoin_settlements
       SET provider_state = 'bound',
           bull_bitcoin_order_id = '33333333-3333-4333-8333-333333333333',
           funding_route = 'bull_bitcoin',
           settlement_status = 'pending',
           instruction_kind = 'bitcoin',
           payer_instruction = 'bc1qmigrationfixture',
           updated_at = now()
     WHERE id = settlement_id;

    BEGIN
        UPDATE bull_bitcoin_settlements
           SET bull_bitcoin_order_id = gen_random_uuid(), updated_at = now()
         WHERE id = settlement_id;
        RAISE EXCEPTION 'migration 067 allowed order-binding replacement';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    DELETE FROM bull_bitcoin_settlements WHERE id = settlement_id;
    DELETE FROM bull_bitcoin_credentials WHERE id = credential_id;
END
$$;
