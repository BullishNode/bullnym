DO $$
BEGIN
    IF to_regclass('public.mixed_invoice_integrity_holds') IS NULL THEN
        RAISE EXCEPTION 'migration 072 did not create its operator hold view';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
          JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
         WHERE trigger_info.tgrelid =
                   'invoice_fiat_settlement_policies'::regclass
           AND trigger_info.tgname =
                   'invoice_fiat_policy_guard_mixed_blinding_key'
           AND trigger_info.tgenabled = 'O'
           AND NOT trigger_info.tgisinternal
           AND function_info.proname =
                   'guard_invoice_fiat_policy_mixed_blinding_key'
    ) THEN
        RAISE EXCEPTION 'migration 072 admission trigger is missing';
    END IF;

    BEGIN
        INSERT INTO invoice_fiat_settlement_policies (
            invoice_id, owner_npub, credential_id, product,
            fiat_percentage, fiat_currency, allowed_rail_mask
        ) VALUES (
            '66000000-0000-4000-8000-000000000005', repeat('6', 64),
            '66000000-0000-4000-8000-000000000001', 'invoice',
            40, 'CAD', 3
        );
        RAISE EXCEPTION 'migration 072 admitted mixed policy without Liquid key material';
    EXCEPTION WHEN check_violation THEN
        IF SQLERRM NOT LIKE '%complete Liquid destination material%' THEN
            RAISE;
        END IF;
    END;

    IF NOT has_table_privilege(
               'bullnym_app', 'mixed_invoice_integrity_holds', 'SELECT')
       OR has_table_privilege(
               'bullnym_app', 'mixed_invoice_integrity_holds', 'INSERT')
       OR has_table_privilege(
               'public', 'mixed_invoice_integrity_holds', 'SELECT') THEN
        RAISE EXCEPTION 'migration 072 operator hold ACL is unsafe';
    END IF;
END
$$;
