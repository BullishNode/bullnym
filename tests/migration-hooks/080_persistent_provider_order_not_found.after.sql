DO $$
DECLARE
    provider_columns INTEGER;
    provider_constraints INTEGER;
BEGIN
    SELECT COUNT(*) INTO provider_columns
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'bull_bitcoin_settlements'
       AND column_name IN (
           'provider_last_read_error_class',
           'provider_last_read_error_at',
           'provider_not_found_first_at',
           'provider_not_found_consecutive',
           'provider_missing_since',
           'provider_missing_last_resolved_at'
       );
    IF provider_columns <> 7 THEN
        RAISE EXCEPTION 'migration 080 did not create all provider-read state columns';
    END IF;

    SELECT COUNT(*) INTO provider_constraints
      FROM pg_constraint
     WHERE conrelid = 'bull_bitcoin_settlements'::REGCLASS
       AND convalidated
       AND conname IN (
           'bull_bitcoin_settlements_provider_read_error_chk',
           'bull_bitcoin_settlements_not_found_streak_chk',
           'bull_bitcoin_settlements_provider_missing_chk',
           'bull_bitcoin_settlements_provider_missing_resolution_chk'
       );
    IF provider_constraints <> 4 THEN
        RAISE EXCEPTION 'migration 080 provider-read constraints are incomplete';
    END IF;

    IF EXISTS (
        SELECT 1 FROM bull_bitcoin_settlements
         WHERE provider_last_read_error_class IS NOT NULL
            OR provider_last_read_error_at IS NOT NULL
            OR provider_not_found_first_at IS NOT NULL
            OR provider_not_found_consecutive <> 0
            OR provider_missing_since IS NOT NULL
            OR provider_missing_last_resolved_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 080 invented provider-read evidence for historical rows';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
         WHERE schemaname = 'public'
           AND tablename = 'bull_bitcoin_settlements'
           AND indexname = 'bull_bitcoin_settlements_provider_missing_due_idx'
           AND indexdef LIKE '%provider_missing_since IS NOT NULL%'
    ) THEN
        RAISE EXCEPTION 'migration 080 persistent-missing due-work index is absent';
    END IF;
END
$$;
