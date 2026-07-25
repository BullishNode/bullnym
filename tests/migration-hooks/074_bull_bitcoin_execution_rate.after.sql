DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'bull_bitcoin_settlements'
           AND column_name = 'execution_rate_minor_per_btc'
           AND data_type = 'bigint'
           AND is_nullable = 'YES'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'bull_bitcoin_settlements'::regclass
           AND conname = 'bull_bitcoin_settlements_execution_rate_chk'
           AND convalidated
    ) THEN
        RAISE EXCEPTION 'migration 074 execution-rate schema is incomplete';
    END IF;

    IF EXISTS (
        SELECT 1 FROM bull_bitcoin_settlements
         WHERE execution_rate_minor_per_btc IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 074 invented a legacy execution rate';
    END IF;

    BEGIN
        UPDATE bull_bitcoin_settlements
           SET execution_rate_minor_per_btc = 0
         WHERE id = '66000000-0000-4000-8000-000000000002';
        RAISE EXCEPTION 'migration 074 accepted a non-positive execution rate';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    IF NOT has_table_privilege(
               'bullnym_app', 'bull_bitcoin_settlements', 'UPDATE')
       OR has_table_privilege(
               'public', 'bull_bitcoin_settlements', 'SELECT') THEN
        RAISE EXCEPTION 'migration 074 changed settlement ACL safety';
    END IF;
END
$$;
