-- Make the NIP-05 verification key strictly opt-in.
--
-- Migration 031 backfilled `users.verification_npub = npub` and set the
-- column NOT NULL. Combined with the register handler's `unwrap_or(npub)`
-- fallback, that made the server-auth key (`npub`) double as the public
-- NIP-05 identity published at `/.well-known/nostr.json` whenever a client
-- omitted an explicit verification key — collapsing the ADR-004 role
-- separation between the auth key and any public NIP-05 identity.
--
-- NIP-05 is now opt-in: `verification_npub` is nullable, and a NULL value
-- means the nym publishes no NIP-05 record. Registration only stores it
-- when the client deliberately supplies a verification key.

ALTER TABLE users
    ALTER COLUMN verification_npub DROP NOT NULL;

-- Clear rows that only carry the auth-key fallback (the 031 backfill or the
-- register handler's `unwrap_or(npub)`). A row whose verification key equals
-- its auth key can only be a fallback artifact — a client that wants NIP-05
-- supplies a dedicated key distinct from its auth npub.
UPDATE users
SET verification_npub = NULL
WHERE verification_npub = npub;
