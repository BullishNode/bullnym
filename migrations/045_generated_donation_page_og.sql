-- Server-owned Open Graph previews for Payment Pages.
--
-- `og_sha256` remains the hash of a historical merchant upload. Generated
-- images use a separate content-addressed key so old data and old social-card
-- URLs remain valid during the migration.

ALTER TABLE donation_pages
    ADD COLUMN generated_og_key TEXT
        CHECK (generated_og_key IS NULL OR generated_og_key ~ '^[0-9a-f]{64}$'),
    ADD COLUMN generated_og_template_version INTEGER
        CHECK (generated_og_template_version IS NULL OR generated_og_template_version > 0),
    ADD COLUMN generated_og_failure_count INTEGER NOT NULL DEFAULT 0
        CHECK (generated_og_failure_count >= 0),
    ADD COLUMN generated_og_retry_after TIMESTAMPTZ;

-- The API historically enforced 280 UTF-8 bytes while this database CHECK
-- counted Unicode scalar values. Replace that mismatched constraint with a
-- generous storage ceiling. The application enforces the tighter,
-- user-facing grapheme and byte limits for new Payment Page saves.
ALTER TABLE donation_pages
    DROP CONSTRAINT donation_pages_description_check,
    ADD CONSTRAINT donation_pages_description_storage_check
        CHECK (octet_length(description) <= 2048);

-- The repair worker only considers live Payment Pages and orders eligible
-- work by retry time and Page update time. Keep that scan bounded as the
-- merchant table grows.
CREATE INDEX donation_pages_og_reconcile_idx
    ON donation_pages
       (generated_og_retry_after, generated_og_template_version, updated_at, nym)
    WHERE kind = 'payment_page'
      AND enabled = TRUE
      AND archived_at IS NULL;
