-- ============================================================================
-- 027: Invoice payment address reservations
-- ============================================================================
--
-- Invoice settlement is address-keyed for BTC and direct Liquid scans. Reusing
-- a receive address makes payment attribution ambiguous, especially once prior
-- chain history exists. Keep a durable reservation table with a global unique
-- constraint per rail/address so new wallet-origin invoices must use fresh
-- receive addresses.
--
-- Historical data may already contain duplicate test addresses. Backfill one
-- canonical reservation per (rail, address), choosing the oldest invoice, then
-- enforce uniqueness for all future inserts.
-- ============================================================================

BEGIN;

CREATE TABLE invoice_payment_addresses (
    invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    rail TEXT NOT NULL CHECK (rail IN ('bitcoin', 'liquid')),
    address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (invoice_id, rail)
);

INSERT INTO invoice_payment_addresses (invoice_id, rail, address, created_at)
SELECT DISTINCT ON (bitcoin_address)
       id, 'bitcoin', bitcoin_address, created_at
  FROM invoices
 WHERE bitcoin_address IS NOT NULL
 ORDER BY bitcoin_address, created_at ASC, id ASC;

INSERT INTO invoice_payment_addresses (invoice_id, rail, address, created_at)
SELECT DISTINCT ON (liquid_address)
       id, 'liquid', liquid_address, created_at
  FROM invoices
 WHERE liquid_address IS NOT NULL
 ORDER BY liquid_address, created_at ASC, id ASC;

CREATE INDEX invoice_payment_addresses_invoice_idx
  ON invoice_payment_addresses(invoice_id);

CREATE UNIQUE INDEX invoice_payment_addresses_bitcoin_address_key
  ON invoice_payment_addresses(address)
  WHERE rail = 'bitcoin';

CREATE UNIQUE INDEX invoice_payment_addresses_liquid_address_key
  ON invoice_payment_addresses(address)
  WHERE rail = 'liquid';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON invoice_payment_addresses
            TO payservice;
    END IF;
END
$$;

COMMIT;
