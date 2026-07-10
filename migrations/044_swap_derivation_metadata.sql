-- 044: persist the derivation identity of each swap key.
--
-- Boltz swap keys are derived from a single master seed at monotonically
-- increasing indices handed out by `swap_key_seq`. Nothing on the row records
-- *which* index (or which seed) produced the key, so a database restore that
-- rewinds `swap_key_seq` behind already-issued indices would silently re-derive
-- and reuse a key for a brand-new swap. Recording (root_fingerprint, index) per
-- swap makes that reuse detectable at startup and gives operators the data
-- needed to reconcile a recovered backup.
--
-- root_fingerprint = first 8 bytes of SHA-256(pubkey at reserved index 0),
-- hex-encoded. It identifies the seed without exposing key material and lets us
-- scope the rollback check to keys derived from *this* deployment's seed.
--
-- All columns are nullable: rows written before this migration have no recorded
-- identity, and the rollback check treats "no post-migration rows" as safe.

ALTER TABLE swap_records
    ADD COLUMN key_index BIGINT,
    ADD COLUMN root_fingerprint TEXT;

ALTER TABLE chain_swap_records
    ADD COLUMN claim_key_index BIGINT,
    ADD COLUMN refund_key_index BIGINT,
    ADD COLUMN root_fingerprint TEXT;

-- A given (seed, index) pair must derive at most one live swap key. Partial
-- unique indexes enforce this only for rows that carry the new metadata, so
-- legacy NULL rows are exempt.
CREATE UNIQUE INDEX swap_records_fingerprint_key_index_key
    ON swap_records (root_fingerprint, key_index)
    WHERE key_index IS NOT NULL AND root_fingerprint IS NOT NULL;

CREATE UNIQUE INDEX chain_swap_records_fingerprint_claim_index_key
    ON chain_swap_records (root_fingerprint, claim_key_index)
    WHERE claim_key_index IS NOT NULL AND root_fingerprint IS NOT NULL;

CREATE UNIQUE INDEX chain_swap_records_fingerprint_refund_index_key
    ON chain_swap_records (root_fingerprint, refund_key_index)
    WHERE refund_key_index IS NOT NULL AND root_fingerprint IS NOT NULL;
