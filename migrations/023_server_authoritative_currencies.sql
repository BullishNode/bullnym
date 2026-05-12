-- Server-authoritative fiat currencies.
--
-- The accepted fiat list now lives in Config.pricer.supported_currencies and
-- is exposed at GET /api/v1/supported-currencies. Keep the database as a
-- format/coherence backstop, not a second hardcoded source of product truth.

BEGIN;

ALTER TABLE donation_pages
    DROP CONSTRAINT IF EXISTS donation_pages_display_currency_check;

ALTER TABLE donation_pages
    ADD CONSTRAINT donation_pages_display_currency_format_chk
    CHECK (display_currency ~ '^[A-Z]{3}$');

ALTER TABLE invoices
    DROP CONSTRAINT IF EXISTS invoices_fiat_currency_check;

ALTER TABLE invoices
    ADD CONSTRAINT invoices_fiat_currency_format_chk
    CHECK (fiat_currency IS NULL OR fiat_currency ~ '^[A-Z]{3}$');

COMMIT;
