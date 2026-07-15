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
| `kind` | Required `payment_page` or `pos`; always appended to the signature after `ct_descriptor`. | Selects an independent row, descriptor, and public workflow. Both rows derive the owner's one optional permanent alias. |
| `header` | Required, 1-80 UTF-8 bytes. | Replaces the stored value on every save. |
| `description` | Required JSON string. Payment Page saves require 1-120 user-perceived Unicode characters and at most 512 UTF-8 bytes. POS keeps the optional 0-280-byte contract. | Replaces the stored short description and the text rendered into social-preview metadata/images. Omission is a framework deserialization error. |
| `display_currency` | Required canonical uppercase supported code. | Replaces the stored value and controls display/fiat checkout; fetch supported currencies first. |
| `website` | HTTPS URL up to 200 UTF-8 bytes, or empty/null/omitted. | Full-PUT field: empty, null, or omission clears the stored website. |
| `twitter` | ASCII letters/digits/underscore, 1-50 bytes, or empty/null/omitted. | Full-PUT field: empty, null, or omission clears the stored handle. Send the handle, not a URL. |
| `instagram` | ASCII letters/digits/dot/underscore, 1-50 bytes, or empty/null/omitted. | Full-PUT field: empty, null, or omission clears the stored handle. Send the handle, not a URL. |
| `enabled` | Required boolean; signed as `1` or `0`. | False retains configuration but public payment use is disabled. It is not archival deletion. |
| `ct_descriptor` | Required non-empty valid descriptor; always signed and replaces the stored surface descriptor. | Replacing a surface descriptor does not reset `next_addr_idx`; the new wallet must scan from the existing cursor and old returned addresses remain payable to the old wallet. |
| `alias` omitted/null | Preserve the permanent owner-level claim; no trailing signed field. | Does not create a synthetic alias. |
| `alias: ""` | Append the empty terminal signed field, then reject with `DonationPageInvalid`. | Empty is never a clear/release operation. |
| non-empty `alias` | Append it as the terminal field; first claim wins permanently and exact same-owner retries are idempotent. | Globally shared nym/alias namespace. A different value from the same owner returns `AliasAlreadyAssigned` with `details.alias` set to the owner's permanent alias; a name owned by anyone else returns `NameTaken` without ownership details. |

Every successful save clears `archived_at`, so saving an archived surface makes
that surface available again. The request body limit is 8 KiB. Length checks
use UTF-8 byte length, not user-perceived character count.

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
  "enabled": true,
  "is_archived": false,
  "alias": "alices-shop",
  "public_url": "https://pay.example.com/a/alices-shop"
}
```

Share `public_url`; do not compose paths client-side. Alias pages intentionally
omit the nym from rendered configuration and payment descriptions, but readable
aliases remain enumerable. A POS response uses `/a/<alias>/pos`; a Payment Page
response uses `/a/<alias>`.

## `GET /donation-page/:nym?kind=payment_page|pos`

Public, rate-limited editor/read model returning `DonationPageView`. It may
include disabled or archived state for management UX; public rendering still
enforces availability.

## `DELETE /donation-page`

Body: `nym`, `npub`, required signed `kind`, `timestamp`, `signature`. Archival
is a soft delete of only the selected surface. The nym and other surface are
unaffected. A later successful save of that `(nym, kind)` automatically
unarchives it.
Archival never mutates permanent nym/alias ownership or the other surface.
Page/POS management and checkout remain authorized while the owner's Lightning
Address is offline.

Payment Page appearance is defined by its text and links. Bullnym does not
provide a merchant-media upload endpoint or media-hash response fields;
social-preview images are generated and branded by the server.

## Public surface and checkout routes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/:nym` | Payment Page PWA |
| `GET` | `/:nym/pos` | POS PWA |
| `GET` | `/a/:slug` | Alias-selected Payment Page PWA |
| `GET` | `/a/:slug/pos` | Alias-selected POS PWA |
| `GET` | `/:nym/manifest.webmanifest` | Payment Page manifest |
| `GET` | `/:nym/pos/manifest.webmanifest` | POS manifest |
| `GET` | `/a/:slug/manifest.webmanifest` | Alias-selected Payment Page manifest |
| `GET` | `/a/:slug/pos/manifest.webmanifest` | Alias-selected POS manifest |
| `GET` | `/sw.js` | Service worker from the configured PWA distribution |
| `GET` | `/pwa-assets/*` | Static PWA distribution files |
| `POST` | `/:nym/invoice` | Payment Page checkout |
| `POST` | `/:nym/pos/invoice` | POS checkout |
| `POST` | `/a/:slug/invoice` | Alias-selected Payment Page checkout |
| `POST` | `/a/:slug/pos/invoice` | Alias-selected POS checkout |
| `GET` | `/:nym/i/:id`, `/a/:slug/i/:id`, `/a/:slug/pos/i/:id` | Linked payment page |

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

Checkout accepts exactly one amount representation and an optional private
`note`:

```json
{ "amount_sat": 10000, "note": "Table 4" }
```

or:

```json
{
  "fiat_amount_minor": 2500,
  "fiat_currency": "USD",
  "note": "Thank you"
}
```

The optional note is trimmed; whitespace-only input is absent and a nonempty
note is limited to 280 Unicode characters. Schema `063_checkout_private_memo` stores it
as the invoice's private `memo`, exposed only by the owning merchant's signed
invoice list. Public status and rendered invoice routes never return it.
Checkout-supplied `recipient_label`, `public_description`, and `invoice_number`
are outside this request contract and must not be accepted or persisted. The
schema constraint rejects any checkout row that carries those wallet-only
fields even though it permits `memo`.

Fiat minor units follow the precision endpoint (`2500` is USD 25.00, while
CRC has zero decimal places). Fiat checkout creation stores the exact
minor-unit face value and currency without converting it or calling a provider.
An explicit payer-demand quote later creates the five-minute conversion and
rail instruction. Sat-fixed avoids exchange-rate risk and is preferable when
the merchant's obligation is denominated in BTC.

Response:

```json
{
  "invoice_id": "00000000-0000-0000-0000-000000000000",
  "lightning_pr": "lnbc...",
  "lightning_amount_sat": 10050,
  "liquid_address": "lq1...",
  "liquid_amount_sat": 10000,
  "bitcoin_chain_address": "bc1...",
  "bitcoin_chain_bip21": "bitcoin:bc1...?amount=0.0001",
  "bitcoin_chain_amount_sat": 10000,
  "expires_at_unix": 1762592000
}
```

Checkout invoices have a fixed outer lifetime of 30 days. The example
`expires_at_unix` is illustrative; clients must use the returned value. Every
payload and typed amount is adopted or withdrawn as one instruction.
For fiat-fixed checkout, the creation response does not contain a payment
instruction; request one with `POST /api/v1/invoices/:id/quote` for the selected
rail.
`lightning_amount_sat` is the exact BOLT11 principal and includes the
provider-side reverse-swap costs needed for the merchant to net the checkout
face value; a payer wallet can add its own Lightning routing fee.
`liquid_amount_sat` is the exact direct-Liquid amount. Bitcoin fields may be
null. `bitcoin_chain_address` and
`bitcoin_chain_amount_sat` are an all-or-none payer instruction; the amount is
the exact validated Bitcoin user lock and may exceed the merchant invoice
amount because the payer bears the swap cost. `bitcoin_chain_bip21` normally
carries that same amount, but clients must use `bitcoin_chain_amount_sat` when
constructing a fallback URI or displaying a manual-send instruction. These are
Boltz BTC-to-Liquid chain-swap addresses, not direct merchant BTC addresses.
`lightning_pr` is a non-null string but can be empty (with a null typed amount)
when eager Boltz reverse-swap creation fails;
the Liquid checkout remains valid and the client should later call
`POST /api/v1/invoices/:id/lightning` to obtain a BOLT11. Creating a checkout
allocates payment resources and is rate-limited; do not create one merely to
preview an amount.
