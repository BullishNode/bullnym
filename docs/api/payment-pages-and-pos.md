# Payment Page and POS

## `PUT /donation-page`

Creates or updates one surface:

```json
{
  "nym": "alice",
  "npub": "<64 hex>",
  "header": "Alice's Shop",
  "description": "Coffee and hardware",
  "display_currency": "USD",
  "website": "https://example.com",
  "twitter": "alice",
  "instagram": null,
  "enabled": true,
  "kind": "payment_page",
  "ct_descriptor": "ct(...)#checksum",
  "alias": "alices-shop",
  "timestamp": 1760000000,
  "signature": "<128 hex>"
}
```

Options and implications:

| Field | Wire/update semantics | Consequence |
|---|---|---|
| `kind` | Non-null `payment_page` or `pos`; omitted/null defaults to `payment_page` and is not appended to the signature. | Selects an independent row, descriptor, alias, and public workflow. Explicitly send it in new clients. |
| `header` | Required, 1-80 UTF-8 bytes. | Replaces the stored value on every save. |
| `description` | Required JSON string. Payment Page saves require 1-120 user-perceived Unicode characters and at most 512 UTF-8 bytes, including when `kind` is omitted and therefore defaults to `payment_page`. POS keeps the optional 0-280-byte contract. | Replaces the stored short description and the text rendered into social-preview metadata/images. Omission is a framework deserialization error. |
| `display_currency` | Required canonical uppercase supported code. | Replaces the stored value and controls display/fiat checkout; fetch supported currencies first. |
| `website` | HTTPS URL up to 200 UTF-8 bytes, or empty/null/omitted. | Full-PUT field: empty, null, or omission clears the stored website. |
| `twitter` | ASCII letters/digits/underscore, 1-50 bytes, or empty/null/omitted. | Full-PUT field: empty, null, or omission clears the stored handle. Send the handle, not a URL. |
| `instagram` | ASCII letters/digits/dot/underscore, 1-50 bytes, or empty/null/omitted. | Full-PUT field: empty, null, or omission clears the stored handle. Send the handle, not a URL. |
| `enabled` | Required boolean; signed as `1` or `0`. | False retains configuration but public payment use is disabled. It is not archival deletion. |
| `ct_descriptor` | Non-empty descriptor replaces it; omitted/null/empty preserves it on update. POS creation requires non-empty; Payment Page creation may omit it and fall back to the nym descriptor. | Replacing a surface descriptor does not reset `next_addr_idx`; the new wallet must scan from the existing cursor and old returned addresses remain payable to the old wallet. Empty string is appended to the signature even though storage preserves the descriptor. |
| `pos_mode` | Legacy non-null boolean; omitted/null preserves it on update and is not appended to the signature. | New integrations should use `kind`; sending it changes the signed bytes. |
| `alias` omitted/null | Preserve the current alias; no trailing signed field. | Maintains old-client compatibility. |
| `alias: ""` | Clear; append an empty terminal signed field. | Removes the alias route. |
| non-empty `alias` | Claim/change; append it as the terminal field. | Globally unique 1-32 lowercase/digit/hyphen slug served at `/a/<alias>`. This is branding, not anonymity. |

Every successful save clears `archived_at`, so saving an archived surface
reactivates it. The request body limit is 8 KiB. Length checks use UTF-8 byte
length, not user-perceived character count.

Response is a `DonationPageView`:

```json
{
  "nym": "alice",
  "header": "Alice's Shop",
  "description": "Coffee and hardware",
  "display_currency": "USD",
  "website": "https://example.com",
  "twitter": "alice",
  "instagram": null,
  "kind": "payment_page",
  "pos_mode": false,
  "enabled": true,
  "is_archived": false,
  "avatar_sha256": null,
  "og_sha256": null,
  "alias": "alices-shop",
  "public_url": "https://pay.example.com/a/alices-shop"
}
```

Share `public_url`; do not compose paths client-side. Alias pages intentionally
omit the nym from rendered configuration and payment descriptions, but readable
aliases remain enumerable.

## `GET /donation-page/:nym?kind=payment_page|pos`

Public, rate-limited editor/read model returning `DonationPageView`. It may
include disabled or archived state for management UX; public rendering still
enforces availability.

## `DELETE /donation-page`

Body: `nym`, `npub`, optional `kind`, `timestamp`, `signature`. Archival is a
soft delete of only the selected surface. Omitted `kind` archives the Payment
Page for legacy compatibility. The nym and other surface are unaffected. A
later successful save of that `(nym, kind)` automatically unarchives it.

Bullnym does not provide an image-upload API. `avatar_sha256` and `og_sha256`
in a `DonationPageView` are legacy read-only fields for previously stored media.

## Public surface and checkout routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/:nym` | Payment Page PWA |
| `GET` | `/:nym/pos` | POS PWA |
| `GET` | `/a/:slug` | Alias-selected Payment Page or POS PWA |
| `GET` | `/:nym/manifest.webmanifest` | Payment Page manifest |
| `GET` | `/:nym/pos/manifest.webmanifest` | POS manifest |
| `GET` | `/a/:slug/manifest.webmanifest` | Alias-selected surface manifest |
| `GET` | `/sw.js` | Service worker from the configured PWA distribution |
| `GET` | `/pwa-assets/*` | Static PWA distribution files |
| `POST` | `/:nym/invoice` | Payment Page checkout |
| `POST` | `/:nym/pos/invoice` | POS checkout |
| `POST` | `/a/:slug/invoice` | Alias-selected checkout |
| `GET` | `/:nym/i/:id`, `/a/:slug/i/:id` | Linked payment page |

The page and manifest routes are registered only when `features.payment_pages`
is enabled. A manifest is returned only for an enabled, non-archived surface;
otherwise the route returns `404`. Successful manifest responses use
`Content-Type: application/manifest+json` and `Cache-Control: public,
max-age=300`.

`/sw.js` and `/pwa-assets/*` are registered independently of the Payment Page
feature flag, but return content only when the corresponding files exist below
`pwa.dist_dir`. The service worker is JavaScript with `Cache-Control: no-cache`.
Static files support precompressed gzip; successful responses add `Vary:
Accept-Encoding`. Files below `/pwa-assets/assets/` cache for one year with
`immutable`; other PWA assets cache for one hour. `/pwa-assets/apps/*` is
deliberately unavailable and always returns `404`.

Live Payment Page HTML includes complete Open Graph and Twitter large-card
metadata. The image is a versioned, content-addressed 1200×630 JPEG generated
by Bullnym from the Page title and short description; its fixed frame always
contains the Bull Bitcoin logo. A save persists Page content first and then
attempts a bounded render. Bullnym attaches the result only while that exact
content remains current. Rendering also runs in the background reconciler but
never on public GET. Permanent branded fallbacks embedded in the server binary
are served from `/og/fallback-*.jpg` whenever a generated file is unavailable.
HTML responses send `X-Robots-Tag: noindex` while `/robots.txt` still permits
preview crawlers to fetch public Pages.

Checkout accepts exactly one amount representation:

```json
{ "amount_sat": 10000 }
```

or:

```json
{ "fiat_amount_minor": 2500, "fiat_currency": "USD" }
```

Fiat minor units follow the precision endpoint (`2500` is USD 25.00, while
CRC has zero decimal places). Fiat is converted and locked to sats at creation;
the response/payment state records the rate. Sat-fixed avoids exchange-rate
risk and is preferable when the merchant's obligation is denominated in BTC.

Response:

```json
{
  "invoice_id": "00000000-0000-0000-0000-000000000000",
  "lightning_pr": "lnbc...",
  "liquid_address": "lq1...",
  "bitcoin_chain_address": "bc1...",
  "bitcoin_chain_bip21": "bitcoin:bc1...?amount=0.0001",
  "expires_at_unix": 1760604800
}
```

Checkout invoices have a fixed outer lifetime of seven days. The example
`expires_at_unix` is illustrative; clients must use the returned value. Bitcoin
fields may be null. When present on checkout they are Boltz BTC-to-Liquid
chain-swap addresses, not direct merchant BTC addresses. `lightning_pr` is a
non-null string but can be empty when eager Boltz reverse-swap creation fails;
the Liquid checkout remains valid and the client should later call
`POST /api/v1/invoices/:id/lightning` to obtain a BOLT11. Creating a checkout
allocates payment resources and is rate-limited; do not create one merely to
preview an amount.
