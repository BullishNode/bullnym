DO $$
DECLARE
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

    IF constraint_expression IS NULL
       OR constraint_expression NOT LIKE '%memoISNULL%' THEN
        RAISE EXCEPTION 'migration 063 fixture did not begin at the checkout-memo refusal boundary';
    END IF;
END
$$;
