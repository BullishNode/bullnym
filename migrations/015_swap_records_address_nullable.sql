-- MRH deprecation: address allocation moves from swap creation to claim time
-- on the cooperative MuSig2 path. New swap_records rows are inserted with
-- NULL address and NULL address_index; the claimer fills them in when the
-- HTLC is funded. Existing rows keep their values; legacy claim path
-- (claimer.rs) handles both shapes during the transition window.

ALTER TABLE swap_records ALTER COLUMN address       DROP NOT NULL;
ALTER TABLE swap_records ALTER COLUMN address_index DROP NOT NULL;
