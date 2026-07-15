# Compatibility Ledger

This file tracks compatibility surfaces that intentionally remain in the
server. Code comments should point here instead of restating full removal
policy inline.

## Registration Verification Npub

- Current field: `verification_npub` (optional).
- Behavior: NIP-05 is opt-in. If omitted at registration time,
  `verification_npub` is stored as NULL and `/.well-known/nostr.json` returns
  no record for the nym. The server never falls back to the auth key (`npub`).
- Compatibility reason: earlier server builds backfilled and reused the
  auth key as the public NIP-05 identity when the field was omitted, which
  collapsed the ADR-004 role separation (the signing key was published at
  `/.well-known/nostr.json`). Migration 033 nulls those fallback-populated
  rows. Clients that never sent `verification_npub` are unaffected — they
  never consumed their own nostr.json.
- Removal condition: none — opt-in is the intended long-term contract.

## Donation Page Alias (public URL slug)

- Current field: `alias` on signed `PUT /donation-page` save requests. It is
  one optional permanent npub-level slug shared by Payment Page and POS,
  served at `/a/<alias>` and `/a/<alias>/pos`.
- Compatibility behavior: `alias` is the sole optional trailing signed field,
  appended after the required `pos_mode`, `ct_descriptor`, and `kind`. A client
  that omits it signs the current fixed field list. Omitted/null preserves the
  claim; `""` is signed but rejected
  as `DonationPageInvalid`; a first valid value claims permanently; the same
  owner/value is idempotent. A different value returns 409
  `AliasAlreadyAssigned`; a shared nym/alias collision returns 409 `NameTaken`.
- Storage/availability behavior: the claim lives only in `public_names`, never
  on a Page/POS row. Archiving either surface or taking the Lightning Address
  offline does not change the claim, the other surface, or owner authorization.
- Validation: `alias` is validated before signature verification. Its charset
  and reserved-name policy remain part of the permanent-name contract.
- Compatibility reason: clients may manage surfaces without claiming an alias;
  keeping it terminal and optional preserves that explicit product choice.
- Removal condition: none. Omission is a permanent no-op, not an
  ownership-state transition.

## Legacy Payment Page media hashes

- Current fields: `avatar_sha256` and `og_sha256` in Payment Page responses and
  their backing database columns/configuration.
- Compatibility behavior: existing values may be returned as read-only data.
  Bullnym does not accept image uploads and new clients must not depend on these
  fields being populated.
- Compatibility reason: older rows and clients may still reference stored
  hashes even though the upload feature was removed.
- Removal condition: production database and traffic audits prove no supported
  client or retained row needs the fields, followed by a reviewed data and file
  migration. Do not remove them based only on source-code search.
