# Compatibility Ledger

This file tracks compatibility surfaces that intentionally remain in the
server. Code comments should point here instead of restating full removal
policy inline.

## Boltz Webhook URL

- Current path: `/webhook/boltz/:secret`
- Compatibility path: `/webhook/boltz`
- Compatibility reason: dev and older deployments may not configure
  `BOLTZ_WEBHOOK_URL_SECRET`.
- Safety behavior: when `boltz_webhook_url_secret` is configured, the
  unauthenticated path refuses requests.
- Removal condition: all deployed environments set
  `BOLTZ_WEBHOOK_URL_SECRET`, and all in-flight swaps created before the
  secret rollout have either settled or expired.

## Boltz Webhook Env Var

- Current env var: `BOLTZ_WEBHOOK_URL_SECRET`
- Compatibility env var: `BOLTZ_WEBHOOK_SECRET`
- Compatibility reason: older configs used the HMAC-oriented name before the
  server switched to URL-path authentication.
- Removal condition: deployed secrets and runbooks no longer reference
  `BOLTZ_WEBHOOK_SECRET`.

## Invoice Liquid Offer Route

- Compatibility route: `POST /api/v1/invoices/:id/liquid`
- Current behavior: returns `410 Gone`.
- Compatibility reason: wallet-origin invoices now supply Liquid addresses at
  create time, but old clients should receive an actionable response instead
  of a generic 404.
- Removal condition: mobile/API clients no longer call this route.

## Invoice Status Rate-Limit Key

- Current key: `invoice_status_per_source_per_min`
- Compatibility key: `donation_status_per_source_per_min`
- Compatibility reason: existing deployed TOML may still use the old
  donation-era key.
- Removal condition: deployed configs have migrated to the current key.

## Registration Lookup Quota Fields

- Current field: `quota`
- Compatibility fields: `lifetime_nyms_used`, `lifetime_nyms_cap`
- Compatibility reason: older mobile clients read quota values from the flat
  fields.
- Removal condition: mobile versions that read `quota.used` and `quota.cap`
  have reached the agreed adoption threshold.

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

## Donation Page Descriptor

- Current field: `ct_descriptor` on signed `PUT /donation-page` requests.
- Compatibility behavior: if omitted or empty, the server preserves the
  existing page descriptor; checkout falls back to the nym's Lightning Address
  descriptor when no page descriptor exists.
- Compatibility reason: Get Paid now uses a page-specific deterministic
  descriptor with an independent address cursor, while older clients only knew
  about the nym descriptor.
- Removal condition: every supported client supplies the page descriptor before
  enabling checkout, and legacy donation pages have been migrated or archived.

## Donation Page POS Mode

- Current field: `pos_mode` on signed `PUT /donation-page` requests.
- Compatibility behavior: if omitted, the server verifies the legacy signed
  field list without `pos_mode`, preserves the existing page mode on update,
  and defaults to `false` on first insert.
- Compatibility reason: shipped Bull Wallet builds signed donation-page saves
  before POS mode existed, so requiring the field would reject otherwise valid
  page updates from those clients.
- Removal condition: all supported Bull Wallet builds include `pos_mode` in
  the signed donation-page payload, and legacy saves without it are no longer
  accepted by the API contract.

## Donation Page Kind (surface discriminator)

- Current field: `kind` on signed `PUT /donation-page` (save) and
  `DELETE /donation-page` (archive) requests, and as the `?kind=` query on
  `GET /donation-page/:nym`. Accepted values: `payment_page`, `pos`.
- Compatibility behavior (save): `kind` is an optional trailing signed field
  appended AFTER `ct_descriptor`. If omitted, the server verifies the legacy
  signed field list without it and writes the `payment_page` surface. `kind`
  is enum-validated before signature verification; a `pos` save additionally
  requires `ct_descriptor`.
- Compatibility behavior (archive): `kind` is the sole optional trailing signed
  field. If omitted, the legacy empty field list is verified and the
  `payment_page` row is archived.
- Compatibility behavior (read): `?kind=` defaults to `payment_page`.
- Compatibility reason: shipped Bull Wallet builds signed donation-page saves
  and archives before the Payment Page / POS split, so requiring the field
  would reject otherwise valid requests. Keeping `kind` trailing and optional
  preserves those signatures (the same maneuver as `pos_mode`).
- Removal condition: all supported Bull Wallet builds include `kind` in the
  signed donation-page payloads, and legacy requests without it are no longer
  accepted by the API contract.

## Donation Page Alias (public URL slug)

- Current field: `alias` on signed `PUT /donation-page` (save) requests. A
  merchant-chosen slug served at `/a/<alias>`, decoupled from the nym.
- Compatibility behavior: `alias` is the NEWEST optional trailing signed field,
  appended AFTER `kind` (order: `pos_mode?`, `ct_descriptor?`, `kind?`,
  `alias?`). Any client that omits it verifies against the older byte layout,
  which stays a strict prefix of the new one, so shipped Bull Wallet signatures
  keep verifying. Tri-state: absent leaves the stored alias unchanged, `""`
  clears it, a non-empty value claims it (409 `AliasTaken` on collision).
- Confusion guard (load-bearing): `alias` is validated BEFORE signature
  verification and its value domain is kept provably disjoint from the other
  optional trailing fields, so a captured legacy message whose sole trailing
  signed field was `pos_mode`/`ct_descriptor`/`kind` can never be byte-identical
  to a new alias-claiming message. Specifically: the alias charset
  (`[a-z0-9-]`, no leading/trailing hyphen) excludes `payment_page` (underscore)
  and CT descriptors (parentheses/commas), and the reserved-alias blocklist
  rejects `0`/`1` (the `pos_mode` domain) and `pos` (a `kind` value). See
  `reserved_nyms::is_reserved_alias` and `donation_page::save`.
- Compatibility reason: shipped Bull Wallet builds signed donation-page saves
  before aliases existed; keeping `alias` trailing and optional preserves those
  signatures (the same maneuver as `pos_mode` and `kind`).
- Removal condition: all supported Bull Wallet builds include `alias` in the
  signed donation-page payload, and legacy requests without it are no longer
  accepted by the API contract.

## Legacy Payment Page media hashes

- Current fields: `avatar_sha256` and `og_sha256` in Payment Page responses and
  their backing database columns. Existing files can still render, and assigning
  an alias can copy an existing file to its content-addressed legacy path.
- Compatibility behavior: existing values may be returned as read-only data.
  Bullnym does not accept image uploads and new clients must not depend on these
  fields being populated.
- Compatibility reason: older rows and clients may still reference stored
  hashes even though the upload feature was removed.
- Removal condition: production database and traffic audits prove no supported
  client or retained row needs the fields, followed by a reviewed data and file
  migration. Do not remove them based only on source-code search.
