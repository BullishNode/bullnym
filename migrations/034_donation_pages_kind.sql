-- Decouple the Payment Page and POS surfaces so one nym can own both, each
-- with its own descriptor and address cursor.
--
-- Until now donation_pages was 1:1 with nym (nym as PRIMARY KEY), and POS was
-- a single row sharing one ct_descriptor. The
-- Get Paid model needs a Payment Page (BIP85 idx 102) AND a POS (idx 103) to
-- coexist under one identity with segregated funds. We relax the key to
-- (nym, kind) so each surface is its own row.
--
-- kind defaults to 'payment_page' so the existing single row per nym becomes
-- the Payment Page surface untouched; a POS surface is a second row with
-- kind = 'pos'. The FK on nym (REFERENCES users ON UPDATE CASCADE ON DELETE
-- CASCADE) is unaffected by the primary-key change and stays in force.

ALTER TABLE donation_pages
    DROP CONSTRAINT donation_pages_pkey;

ALTER TABLE donation_pages
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'payment_page'
        CHECK (kind IN ('payment_page', 'pos'));

ALTER TABLE donation_pages
    ADD PRIMARY KEY (nym, kind);
