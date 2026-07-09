-- Merchant-chosen alias slug for a donation-page surface, decoupled from the
-- nym that anchors the Lightning Address.
--
-- Each donation_pages row (one per (nym, kind)) may carry an optional alias.
-- The alias is the public URL segment under /a/<alias>, letting a merchant
-- publish a PoS or Payment Page whose link does not leak the nym they use for
-- their Lightning Address. A merchant can pick a different alias per surface.
--
-- Uniqueness is global (across all nyms and kinds): the alias is the sole
-- lookup key for /a/<alias>, so two surfaces cannot share one. The partial
-- unique index ignores NULL, so surfaces without an alias are unconstrained.
-- Charset/format is enforced in Rust (parity with header/twitter, which only
-- CHECK length here); the length bound is duplicated as a defence-in-depth
-- CHECK. donation_pages is a small merchant table (one or two rows per
-- registered merchant), so a plain (non-CONCURRENT) index build is instant and
-- online-safe -- CONCURRENTLY is unavailable anyway since sqlx wraps each
-- migration in a transaction.

ALTER TABLE donation_pages
    ADD COLUMN alias TEXT
        CHECK (alias IS NULL OR (length(alias) BETWEEN 1 AND 32));

CREATE UNIQUE INDEX donation_pages_alias_uidx
    ON donation_pages (alias) WHERE alias IS NOT NULL;
