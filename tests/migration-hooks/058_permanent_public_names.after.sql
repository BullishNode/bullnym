-- 058 is an empty-state guard, not a historical migration authority.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users)
       OR EXISTS (SELECT 1 FROM donation_pages)
       OR EXISTS (SELECT 1 FROM invoices)
       OR to_regclass('public.public_names') IS NOT NULL
       OR to_regclass('public.public_name_migration_choices') IS NOT NULL
       OR to_regclass('public.public_name_migration_merchant_communications') IS NOT NULL
       OR NOT EXISTS (
           SELECT 1
             FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'donation_pages'
              AND column_name = 'alias'
       ) THEN
        RAISE EXCEPTION 'migration 058 empty-state boundary changed';
    END IF;
END
$$;
