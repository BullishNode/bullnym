DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM invoices WHERE origin = 'wallet') THEN
        RAISE EXCEPTION 'migration 065 fixture requires no wallet-origin rows';
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
