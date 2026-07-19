DO $$
DECLARE
    wallet_id UUID := '65000000-0000-4000-8000-000000000001';
    checkout_id UUID := '65000000-0000-4000-8000-000000000002';
    request_id UUID := '65000000-0000-4000-8000-000000000003';
    rejected_constraint TEXT;
    constraint_expression TEXT;
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'invoices'
           AND column_name IN ('recipient_label', 'public_description', 'invoice_number')
    ) THEN
        RAISE EXCEPTION 'migration 065 retained plaintext invoice columns';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'invoices'
           AND column_name IN (
               'client_request_id', 'client_request_digest', 'presentation_envelope'
           )
           AND data_type IN ('uuid', 'bytea')
           AND is_nullable = 'YES'
         GROUP BY table_schema, table_name
        HAVING COUNT(*) = 3
    ) THEN
        RAISE EXCEPTION 'migration 065 installed the wrong private column shape';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.invoices'::REGCLASS
           AND conname = 'invoices_private_presentation_shape_check'
           AND contype = 'c'
           AND convalidated
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.invoices'::REGCLASS
           AND conname = 'invoices_owner_client_request_key'
           AND contype = 'u'
           AND convalidated
    ) THEN
        RAISE EXCEPTION 'migration 065 private presentation constraints are missing';
    END IF;
    SELECT regexp_replace(
               pg_get_expr(constraint_info.conbin, constraint_info.conrelid, TRUE),
               '[[:space:]]+', '', 'g'
           )
      INTO constraint_expression
      FROM pg_constraint constraint_info
     WHERE constraint_info.conrelid = 'public.invoices'::REGCLASS
       AND constraint_info.conname = 'invoices_private_presentation_shape_check';
    IF constraint_expression IS DISTINCT FROM
       'origin=''wallet''::textANDclient_request_idISNOTNULLANDclient_request_digestISNOTNULLANDoctet_length(client_request_digest)=32ANDpresentation_envelopeISNOTNULLANDCASEWHENoctet_length(presentation_envelope)=4125THENget_byte(presentation_envelope,0)=1ELSEfalseENDORorigin=''checkout''::textANDclient_request_idISNULLANDclient_request_digestISNULLANDpresentation_envelopeISNULL' THEN
        RAISE EXCEPTION 'migration 065 installed the wrong private shape: %',
            constraint_expression;
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
          JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
         WHERE trigger_info.tgrelid = 'public.invoices'::REGCLASS
           AND trigger_info.tgname = 'invoices_reject_private_presentation_update'
           AND trigger_info.tgtype = 19
           AND trigger_info.tgenabled = 'O'
           AND NOT trigger_info.tgisinternal
           AND function_info.proname = 'reject_invoice_private_presentation_update'
    ) THEN
        RAISE EXCEPTION 'migration 065 immutable presentation trigger is missing';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_index index_info
          JOIN pg_attribute attribute_info
            ON attribute_info.attrelid = index_info.indrelid
           AND attribute_info.attnum = ANY(index_info.indkey)
         WHERE index_info.indrelid = 'public.invoices'::REGCLASS
           AND attribute_info.attname = 'presentation_envelope'
    ) THEN
        RAISE EXCEPTION 'migration 065 made presentation ciphertext searchable';
    END IF;
    IF NOT has_column_privilege(
        'bullnym_app', 'public.invoices', 'presentation_envelope', 'INSERT'
    ) OR NOT has_column_privilege(
        'bullnym_app', 'public.invoices', 'presentation_envelope', 'SELECT'
    ) THEN
        RAISE EXCEPTION 'migration 065 omitted runtime envelope privileges';
    END IF;

    INSERT INTO invoices (
        id, nym_owner, npub_owner, origin,
        fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
        rate_locks_until, bitcoin_address,
        accept_btc, accept_ln, accept_liquid,
        status, pricing_mode, presentation_status, settlement_status, expires_at,
        client_request_id, client_request_digest, presentation_envelope
    ) VALUES (
        wallet_id,
        NULL, repeat('6', 64), 'wallet',
        NULL, NULL, 21000, NULL,
        TIMESTAMPTZ '2030-01-01 00:00:00+00',
        'bc1q065privatepresentation0000000000000000000000000',
        TRUE, FALSE, FALSE,
        'unpaid', 'sat_fixed', 'unpaid', 'none',
        TIMESTAMPTZ '2030-01-01 00:00:00+00',
        request_id, decode(repeat('31', 32), 'hex'),
        decode('01' || repeat('42', 4124), 'hex')
    );

    INSERT INTO invoices (
        id, nym_owner, npub_owner, origin, checkout_surface_kind,
        fiat_amount_minor, fiat_currency, amount_sat, rate_minor_per_btc,
        rate_locks_until, memo, liquid_address, liquid_blinding_key_hex,
        accept_btc, accept_ln, accept_liquid,
        status, pricing_mode, presentation_status, settlement_status, expires_at
    ) VALUES (
        checkout_id,
        NULL, repeat('7', 64), 'checkout', 'payment_page',
        NULL, NULL, 1000, NULL,
        TIMESTAMPTZ '2030-01-01 00:00:00+00',
        'private checkout note',
        'lq1migration065checkout000000000000000000000000000000',
        repeat('ab', 32),
        FALSE, FALSE, TRUE,
        'unpaid', 'sat_fixed', 'unpaid', 'none',
        TIMESTAMPTZ '2030-01-01 00:00:00+00'
    );

    BEGIN
        UPDATE invoices
           SET presentation_envelope = decode('01' || repeat('43', 4124), 'hex')
         WHERE id = wallet_id;
        RAISE EXCEPTION 'migration 065 allowed private presentation mutation';
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
        IF rejected_constraint IS DISTINCT FROM
           'invoices_private_presentation_immutable' THEN
            RAISE;
        END IF;
    END;

    DELETE FROM invoices WHERE id IN (wallet_id, checkout_id);
END
$$;
