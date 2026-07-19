DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'swap_records'
           AND column_name = 'payment_first_observed_at'
           AND data_type = 'timestamp with time zone'
           AND is_nullable = 'YES'
    ) THEN
        RAISE EXCEPTION 'migration 066 history timestamp column is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
          JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
         WHERE trigger_info.tgrelid = 'swap_records'::regclass
           AND trigger_info.tgname = 'swap_records_stamp_payment_first_observed'
           AND trigger_info.tgenabled = 'O'
           AND NOT trigger_info.tgisinternal
           AND function_info.proname = 'stamp_payment_first_observed'
           AND function_info.proconfig = ARRAY['search_path=pg_catalog']
    ) THEN
        RAISE EXCEPTION 'migration 066 history timestamp trigger is missing or unsafe';
    END IF;
    IF to_regclass('public.swap_records_get_paid_history_idx') IS NULL
       OR to_regclass('public.invoices_get_paid_history_owner_idx') IS NULL THEN
        RAISE EXCEPTION 'migration 066 history indexes are missing';
    END IF;
END
$$;
