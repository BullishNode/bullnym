DO $$
DECLARE
    authority_columns INTEGER;
    authority_constraints INTEGER;
    authority_triggers INTEGER;
BEGIN
    SELECT COUNT(*) INTO authority_columns
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name IN ('swap_records', 'chain_swap_records')
       AND column_name IN ('mixed_claim_path', 'mixed_claim_fee_budget_sat');
    IF authority_columns <> 4 THEN
        RAISE EXCEPTION 'migration 078 did not create all claim authority columns';
    END IF;

    SELECT COUNT(*) INTO authority_constraints
      FROM pg_constraint
     WHERE conname IN (
         'swap_records_mixed_claim_fee_authority_chk',
         'chain_swap_records_mixed_claim_fee_authority_chk'
     )
       AND convalidated
       AND pg_get_constraintdef(oid) LIKE '%mixed_claim_path = ''script''%'
       AND pg_get_constraintdef(oid) LIKE '%mixed_claim_fee_budget_sat > 0%';
    IF authority_constraints <> 2 THEN
        RAISE EXCEPTION 'migration 078 claim authority constraints are incomplete';
    END IF;

    SELECT COUNT(*) INTO authority_triggers
      FROM pg_trigger
     WHERE tgname IN (
         'swap_records_mixed_claim_fee_authority_immutable',
         'chain_swap_records_mixed_claim_fee_authority_immutable'
     )
       AND NOT tgisinternal;
    IF authority_triggers <> 2 THEN
        RAISE EXCEPTION 'migration 078 claim authority triggers are incomplete';
    END IF;

    IF EXISTS (
        SELECT 1 FROM swap_records
         WHERE mixed_claim_path IS NOT NULL
            OR mixed_claim_fee_budget_sat IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE mixed_claim_path IS NOT NULL
            OR mixed_claim_fee_budget_sat IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 078 invented authority for historical rows';
    END IF;
END
$$;
