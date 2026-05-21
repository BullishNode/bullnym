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

- Current field: `verification_npub`
- Compatibility behavior: if omitted at registration time, the server stores
  `verification_npub = npub`.
- Compatibility reason: older clients used one key for both Bullnym request
  authentication and public NIP-05 verification. Current Get Paid clients can
  keep the server-auth key separate from the key published in
  `/.well-known/nostr.json`.
- Removal condition: old clients that omit `verification_npub` are no longer
  supported, and the registration contract is intentionally made strict.

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
