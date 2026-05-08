-- Invoices: unified payment-intent abstraction across the store-page flow
-- and the wallet-creates-invoice flow.
--
-- Every payment on /<nym>/i/<id> goes through an `invoices` row. The two
-- creation paths are distinguished by `origin`:
--   - 'checkout': anonymous browser created the invoice (sender). No auth;
--                 server-rate-limited per source. 1h default outer expiry.
--   - 'wallet'  : the recipient created the invoice via mobile, signed
--                 with the v1 Schnorr scheme. 7d default outer expiry,
--                 cancellable by the recipient.
--
-- Fiat-denominated invoices have a 15-minute inner rate-lock; the status
-- endpoint refreshes the sat amount on-demand when the lock has elapsed.
-- Sat-denominated invoices set rate_locks_until = expires_at and never
-- refresh.
--
-- Lightning offers are 1:N — each rate refresh inserts a new swap_records
-- row pointing at the same invoice. The previous swap row stays so a
-- settlement on a stale BOLT11 still flips the invoice (lenient policy:
-- under/overpaid status reflects the rate mismatch).
--
-- Liquid offer is 1:1 — one address per invoice, allocated lazily on
-- first rail toggle.
--
-- This migration also folds donation_allocations into invoices.liquid_address
-- (DROP at the bottom). All call sites moving to invoices in the same Phase
-- B rollout, so direct cutover is safe.

CREATE TABLE invoices (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    nym                  TEXT         NOT NULL REFERENCES users(nym)
                                      ON UPDATE CASCADE ON DELETE CASCADE,

    -- Origin: who/how created the invoice. Drives auth, lifecycle, and
    -- dashboard display in mobile.
    origin               TEXT         NOT NULL
                                      CHECK (origin IN ('checkout', 'wallet')),

    -- Original fiat denomination (immutable; reflects the user's intent).
    -- NULL for sat-denominated invoices.
    fiat_amount_minor    INTEGER      CHECK (fiat_amount_minor IS NULL
                                              OR fiat_amount_minor > 0),
    fiat_currency        TEXT         CHECK (fiat_currency IS NULL
                                              OR fiat_currency IN
                                                 ('USD','CAD','EUR','CRC',
                                                  'MXN','ARS','COP','INR')),

    -- CURRENT sat amount. Recomputed on rate refresh for fiat-denominated
    -- invoices; immutable for sat-denominated.
    amount_sat           BIGINT       NOT NULL CHECK (amount_sat > 0),

    -- Rate-lock state. rate_minor_per_btc is NULL for sat-denominated
    -- invoices; rate_locks_until is set for both (== expires_at for
    -- sat-denominated, so the on-demand refresh check naturally skips them).
    rate_minor_per_btc   BIGINT       CHECK (rate_minor_per_btc IS NULL
                                              OR rate_minor_per_btc > 0),
    rate_locked_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    rate_locks_until     TIMESTAMPTZ  NOT NULL,

    -- Wallet-origin metadata. NULL for checkout-origin (anonymous senders
    -- have nothing to label or memo).
    memo                 TEXT         CHECK (memo IS NULL
                                              OR length(memo) <= 280),
    recipient_label      TEXT         CHECK (recipient_label IS NULL
                                              OR length(recipient_label) <= 100),

    -- Liquid offer (lazy-allocated; NULL until the sender toggles to Liquid).
    liquid_address       TEXT,
    liquid_address_index INTEGER,

    -- Lifecycle. Lightning offers attach 1:N via swap_records.invoice_id
    -- (added below). The CHECK at the bottom enforces paid_via coherence.
    status               TEXT         NOT NULL DEFAULT 'unpaid'
                                      CHECK (status IN (
                                          'unpaid',
                                          'paid',
                                          'underpaid',
                                          'overpaid',
                                          'expired',
                                          'cancelled'
                                      )),
    paid_via             TEXT         CHECK (paid_via IS NULL
                                              OR paid_via IN ('lightning',
                                                              'liquid')),
    paid_at              TIMESTAMPTZ,
    paid_amount_sat      BIGINT       CHECK (paid_amount_sat IS NULL
                                              OR paid_amount_sat > 0),
    cancelled_at         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ  NOT NULL,

    -- Liquid offer coherence: address and index travel together.
    CONSTRAINT invoices_liquid_pair_chk
        CHECK ((liquid_address IS NULL AND liquid_address_index IS NULL)
            OR (liquid_address IS NOT NULL AND liquid_address_index IS NOT NULL)),

    -- Fiat denomination coherence: minor amount and currency travel together.
    CONSTRAINT invoices_fiat_pair_chk
        CHECK ((fiat_amount_minor IS NULL AND fiat_currency IS NULL)
            OR (fiat_amount_minor IS NOT NULL AND fiat_currency IS NOT NULL)),

    -- Lifecycle coherence: paid_via is set iff status indicates payment.
    -- 'expired' and 'cancelled' are unpaid terminals.
    CONSTRAINT invoices_paid_via_chk
        CHECK (
            (status IN ('unpaid', 'expired', 'cancelled') AND paid_via IS NULL)
         OR (status IN ('paid', 'underpaid', 'overpaid') AND paid_via IS NOT NULL)
        ),

    -- Wallet-origin metadata is NEVER set on checkout-origin invoices.
    -- (Checkout invoices may legally have NULL memo/label; this only blocks
    -- the inverse — anonymous senders cannot inject a label.)
    CONSTRAINT invoices_checkout_no_metadata_chk
        CHECK (origin = 'wallet'
            OR (memo IS NULL AND recipient_label IS NULL))
);

-- Mobile dashboard hot path: list invoices for a nym filtered by status.
CREATE INDEX invoices_nym_status_idx
    ON invoices (nym, status);

-- GC scan: expired invoices past their outer deadline. Partial predicate
-- mirrors the GC query exactly so the planner can stop early.
CREATE INDEX invoices_unpaid_expiry_idx
    ON invoices (expires_at)
    WHERE status = 'unpaid';

-- Chain watcher hot path: scan unpaid invoices' liquid addresses for
-- a given nym, ordered by address_index for the lookahead loop. Mirrors
-- the existing donation_allocations index pattern (see 016).
CREATE INDEX invoices_unpaid_liquid_idx
    ON invoices (nym, liquid_address_index)
    WHERE status = 'unpaid' AND liquid_address_index IS NOT NULL;

-- Mobile dashboard "Invoices I created" timeline ordering.
CREATE INDEX invoices_nym_created_idx
    ON invoices (nym, created_at DESC);

-- Lightning offers attach 1:N to invoices. Each rate refresh inserts a
-- new swap_records row pointing at the same invoice; the previous row
-- stays so a settlement on a stale BOLT11 still flips the invoice.
-- ON DELETE SET NULL preserves payment history if an invoice is GC'd.
ALTER TABLE swap_records
    ADD COLUMN invoice_id UUID REFERENCES invoices(id) ON DELETE SET NULL;

-- Reverse-lookup hot path: given an invoice, list its swaps newest-first.
-- Used by the rate-refresh path to find the most recent BOLT11.
CREATE INDEX swap_records_invoice_idx
    ON swap_records (invoice_id, created_at DESC)
    WHERE invoice_id IS NOT NULL;

-- donation_allocations is fully replaced by invoices.liquid_address. All
-- call sites cut over in the same Phase B rollout, so the DROP is safe in
-- the same migration.
DROP TABLE donation_allocations;

-- Post-#45991 pattern: re-grant the runtime role explicitly so a fresh
-- table inherits the correct permissions even when the migration is
-- applied as `postgres`. Guarded so dev DBs without the role can still
-- apply the migration.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON invoices
            TO payservice;
    END IF;
END
$$;
