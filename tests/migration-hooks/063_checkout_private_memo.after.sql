DO $$
DECLARE
    checkout_id UUID;
    rejected_constraint TEXT;
    constraint_expression TEXT;
BEGIN
    SELECT regexp_replace(
               pg_get_expr(constraint_info.conbin, constraint_info.conrelid, TRUE),
               '[[:space:]]+',
               '',
               'g'
           )
      INTO constraint_expression
      FROM pg_constraint constraint_info
     WHERE constraint_info.conrelid = 'public.invoices'::REGCLASS
       AND constraint_info.conname = 'invoices_checkout_no_metadata_chk'
       AND constraint_info.contype = 'c'
       AND constraint_info.convalidated;

    IF constraint_expression IS DISTINCT FROM
       'origin=''wallet''::textORrecipient_labelISNULLANDpublic_descriptionISNULLANDinvoice_numberISNULL' THEN
        RAISE EXCEPTION 'migration 063 installed the wrong checkout metadata expression: %',
            constraint_expression;
    END IF;

    INSERT INTO invoices (
        nym_owner,
        npub_owner,
        origin,
        fiat_amount_minor,
        fiat_currency,
        amount_sat,
        rate_minor_per_btc,
        rate_locks_until,
        memo,
        accept_btc,
        accept_ln,
        accept_liquid,
        bitcoin_address,
        liquid_address,
        pricing_mode,
        liquid_blinding_key_hex,
        expires_at,
        presentation_status,
        checkout_surface_kind
    ) VALUES (
        NULL,
        repeat('c', 64),
        'checkout',
        1000,
        'USD',
        0,
        NULL,
        clock_timestamp() + INTERVAL '5 minutes',
        'private checkout note',
        FALSE,
        FALSE,
        TRUE,
        NULL,
        'lq1migration063checkoutmemo000000000000000000000000000000',
        'fiat_fixed',
        repeat('ab', 32),
        clock_timestamp() + INTERVAL '30 days',
        'unpaid',
        'payment_page'
    )
    RETURNING id INTO checkout_id;

    IF (SELECT memo FROM invoices WHERE id = checkout_id)
       IS DISTINCT FROM 'private checkout note' THEN
        RAISE EXCEPTION 'migration 063 did not retain the checkout private memo';
    END IF;

    BEGIN
        UPDATE invoices SET recipient_label = 'forbidden' WHERE id = checkout_id;
        RAISE EXCEPTION 'migration 063 allowed checkout recipient_label';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
        IF rejected_constraint IS DISTINCT FROM 'invoices_checkout_no_metadata_chk' THEN
            RAISE;
        END IF;
    END;

    BEGIN
        UPDATE invoices SET public_description = 'forbidden' WHERE id = checkout_id;
        RAISE EXCEPTION 'migration 063 allowed checkout public_description';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
        IF rejected_constraint IS DISTINCT FROM 'invoices_checkout_no_metadata_chk' THEN
            RAISE;
        END IF;
    END;

    BEGIN
        UPDATE invoices SET invoice_number = 'forbidden' WHERE id = checkout_id;
        RAISE EXCEPTION 'migration 063 allowed checkout invoice_number';
    EXCEPTION WHEN check_violation THEN
        GET STACKED DIAGNOSTICS rejected_constraint = CONSTRAINT_NAME;
        IF rejected_constraint IS DISTINCT FROM 'invoices_checkout_no_metadata_chk' THEN
            RAISE;
        END IF;
    END;

    DELETE FROM invoices WHERE id = checkout_id;
END
$$;
