-- Migration 062's post-hook deliberately leaves a representative wallet row
-- and quote ledger behind after checking that cutover. Migration 065 is an
-- authorized empty-database reset, not a legacy-data conversion. Discard the
-- synthetic upgrade ledger here; test-db separately proves that migration 065
-- refuses a real nonempty wallet state transactionally.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM invoices
         WHERE id = '62000000-0000-0000-0000-000000000001'
           AND origin = 'wallet'
    ) THEN
        RAISE EXCEPTION 'migration 065 fixture lost the migration 062 wallet row';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'invoices'
           AND column_name IN ('recipient_label', 'public_description', 'invoice_number')
         GROUP BY table_schema, table_name
        HAVING COUNT(*) = 3
    ) THEN
        RAISE EXCEPTION 'migration 065 pre-cutover plaintext columns are missing';
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'invoices'
           AND column_name IN (
               'client_request_id', 'client_request_digest', 'presentation_envelope'
           )
    ) THEN
        RAISE EXCEPTION 'migration 065 private presentation columns already exist';
    END IF;
END
$$;

TRUNCATE TABLE invoices CASCADE;
