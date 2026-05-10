-- Donation pages: public, server-rendered pages at https://bullpay.ca/<nym>
-- that share the same wallet/descriptor as the LNURL Lightning Address.
--
-- One row per nym (primary-key constraint enforces 1:1). Pages start with
-- enabled = FALSE; the mobile flips enabled = TRUE on first save. Deletion
-- is soft (archived_at = NOW()) so the public URL keeps resolving to a
-- "this page has been deleted" template instead of a broken 404.

CREATE TABLE donation_pages (
    nym                 TEXT PRIMARY KEY REFERENCES users(nym)
                        ON UPDATE CASCADE ON DELETE CASCADE,
    header              TEXT NOT NULL CHECK (length(header) <= 80),
    description         TEXT NOT NULL CHECK (length(description) <= 280),
    avatar_sha256       TEXT,
    og_sha256           TEXT,
    display_currency    TEXT NOT NULL
                        CHECK (display_currency IN
                            ('USD','CAD','EUR','CRC','MXN','ARS','COP','INR')),
    website             TEXT CHECK (website IS NULL OR length(website) <= 200),
    twitter             TEXT CHECK (twitter IS NULL OR length(twitter) <= 50),
    instagram           TEXT CHECK (instagram IS NULL OR length(instagram) <= 50),
    enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    archived_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot path for GET /<nym>: fetch only live (enabled, not-archived) rows.
CREATE INDEX donation_pages_live_idx ON donation_pages (enabled)
    WHERE enabled = TRUE AND archived_at IS NULL;

-- Donation address pinning: same browser/IP gets the same Liquid address back
-- on refresh. Anonymous visitors get a fresh UUID cookie on first GET /<nym>.
-- (nym, source_key, device_id) is the unique binding key.
CREATE TABLE donation_allocations (
    nym             TEXT NOT NULL REFERENCES users(nym)
                    ON UPDATE CASCADE ON DELETE CASCADE,
    source_key      TEXT NOT NULL,
    device_id       UUID NOT NULL,
    address_index   INTEGER NOT NULL,
    address         TEXT NOT NULL,
    allocated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (nym, source_key, device_id)
);

-- Per-source first-allocation gate: count rows where source_key = $1
-- AND allocated_at > now() - 1h. Index sorts by allocated_at DESC so the
-- LIMIT/COUNT can stop early.
CREATE INDEX donation_allocations_lookup_idx
    ON donation_allocations (nym, source_key, allocated_at DESC);

-- GC scan key: prune rows older than `donation_allocation_ttl_days`.
CREATE INDEX donation_allocations_gc_idx
    ON donation_allocations (last_used_at);
