DO $$
DECLARE
    stored_description TEXT;
    generated_key TEXT;
    template_version INTEGER;
    failure_count INTEGER;
    retry_after TIMESTAMPTZ;
BEGIN
    SELECT description, generated_og_key, generated_og_template_version,
           generated_og_failure_count, generated_og_retry_after
      INTO stored_description, generated_key, template_version,
           failure_count, retry_after
      FROM donation_pages
     WHERE nym = 'og-migration-fixture' AND kind = 'payment_page';

    IF octet_length(stored_description) <> 800
       OR generated_key IS NOT NULL
       OR template_version IS NOT NULL
       OR failure_count <> 0
       OR retry_after IS NOT NULL THEN
        RAISE EXCEPTION 'migration 045 did not preserve the representative row/defaults';
    END IF;
    IF to_regclass('public.donation_pages_og_reconcile_idx') IS NULL THEN
        RAISE EXCEPTION 'migration 045 reconciliation index is missing';
    END IF;

    -- The obsolete 280-scalar CHECK is gone; the application owns its tighter
    -- product contract while the database supplies a generous byte ceiling.
    UPDATE donation_pages
       SET description = repeat('a', 281)
     WHERE nym = 'og-migration-fixture' AND kind = 'payment_page';

    BEGIN
        UPDATE donation_pages
           SET generated_og_key = 'not-a-content-key'
         WHERE nym = 'og-migration-fixture' AND kind = 'payment_page';
        RAISE EXCEPTION 'migration 045 accepted an invalid generated OG key';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE donation_pages
           SET generated_og_template_version = 0
         WHERE nym = 'og-migration-fixture' AND kind = 'payment_page';
        RAISE EXCEPTION 'migration 045 accepted a non-positive template version';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE donation_pages
           SET description = repeat('😀', 513)
         WHERE nym = 'og-migration-fixture' AND kind = 'payment_page';
        RAISE EXCEPTION 'migration 045 accepted a description above 2048 bytes';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END $$;
