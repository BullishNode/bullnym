-- Allow re-registration after deletion.
-- Replace absolute npub unique with partial index (only active rows).
ALTER TABLE users DROP CONSTRAINT users_npub_key;
CREATE UNIQUE INDEX users_npub_active_key ON users (npub) WHERE is_active = TRUE;
