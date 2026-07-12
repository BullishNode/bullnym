# Bullnym API Reference

This document is the integration contract for wallet, merchant, payer, and
operations clients. It describes the choices exposed by the API and the
consequences of each choice. The Rust route table and serde types remain the
ultimate source of truth: `src/main.rs`, `src/auth.rs`, `src/registration.rs`,
`src/lnurl.rs`, `src/donation_page.rs`, and `src/invoice.rs`.

## 1. Scope and Concepts

Bullnym is a non-custodial payment coordination server. It does not hold a
recipient's spend keys, but it is trusted to derive the correct recipient
address and construct swaps honestly.

| Concept | Meaning | Important implication |
|---|---|---|
| `npub` | 64-character hex x-only secp256k1 authentication public key. Despite the field name, this is not a bech32 `npub1...`. | Possession of its private key controls registration, surfaces, and wallet invoices. Use a dedicated deterministically recoverable key. |
| `verification_npub` | Optional, separate 64-character hex key published through NIP-05. | Keeping it separate prevents the server authentication identity from becoming a public social identity. |
| nym | A 1-32 character public namespace and Lightning Address local part. | A deactivated nym remains reserved to its original identity. It is not released for reuse. |
| CT descriptor | Liquid confidential descriptor from which the server derives fresh addresses. | The server can derive and unblind payments in that descriptor. Use a dedicated Bullnym wallet, not a general-purpose wallet. |
| Payment Page | Public `/<nym>` or `/a/<alias>` checkout surface. | Can use a dedicated descriptor; legacy rows may fall back to the Lightning Address descriptor. |
| POS | Public `/<nym>/pos` or `/a/<alias>` terminal. | Requires its own descriptor and never falls back to the Lightning Address descriptor. |
| wallet invoice | Signed recipient-created receivable. | Recipient supplies unique BTC/Liquid addresses; the server does not derive them from a descriptor. |
| checkout invoice | Anonymous payer-created session from Payment Page/POS. | Destination and enabled rails are controlled by the configured surface. |

All examples use `https://pay.example.com` as the base URL. Production clients
should discover or configure the operator's HTTPS origin and must not assume a
particular Bullnym deployment.

## 2. Availability and Transport

All JSON requests use `Content-Type: application/json`. Timestamps are Unix
seconds. UUIDs are canonical UUID strings. Public page routes return HTML and
`/qr.svg` returns SVG.

The server permits cross-origin origins and methods but allows only the
`Content-Type` request header in browser preflights. Authentication does not
use cookies. The certification token is therefore intended for same-origin or
non-browser harnesses unless the deployment's reverse proxy adds a narrower
CORS policy for it.

### Feature gates

An operator may disable product groups. A disabled route is absent, not a JSON
feature error.

| Configuration | Routes enabled |
|---|---|
| `features.lightning_address` | LNURL metadata/callback, `/register*`, reservations |
| `features.nip05` plus `lightning_address` | `/.well-known/nostr.json` |
| `features.payment_pages` | surface CRUD, Payment Page/POS/alias pages and anonymous checkout |
| `features.invoices` | signed wallet-invoice create/list/cancel and `/invoice/:id` |
| `invoices` or `payment_pages` | invoice status and Lightning/Liquid offer routes; recoverable-swaps detection (`GET /api/v1/invoices/recoverable`) |
| `features.chain_swap_merchant_recovery` | merchant BTC refund recovery **action**; default off. Detection stays available regardless and reports this flag as `recovery_enabled`. |

Always use `GET /version` during deployment/certification to identify the
build. Do not infer feature availability only from the crate version; probe the
required route in the target environment.

### Error contract

Most application errors deliberately return HTTP `200` in an LNURL-compatible
envelope:

```json
{
  "status": "ERROR",
  "code": "InvoiceNotFound",
  "reason": "Invoice not found."
}
```

Clients must decode the body and check `status == "ERROR"` for every JSON API
response, including HTTP 2xx responses.

| HTTP status | Meaning |
|---|---|
| `200` | Success or most coded application errors; inspect the body. |
| `201` | Successful nym registration. |
| `400` | Framework query/path or malformed-JSON rejection; generally not a Bullnym error envelope. |
| `401` | `AuthError`: malformed key/signature, bad signature, or timestamp outside the allowed window. |
| `409` | A supplied Bitcoin/Liquid address is already assigned, or an alias is taken. Generate another value; blind retry is wrong. |
| `410` | Deprecated Liquid-offer endpoint. |
| `413` | Axum request-body limit exceeded before the handler. |
| `404`, `405` | Route not found or method not allowed; may be HTML/plain text rather than JSON. |
| `415` | Missing or unsupported JSON `Content-Type`; framework response, not a Bullnym envelope. |
| `422` | JSON syntax was valid but could not deserialize into the request type; framework response. |
| `503` | Hard configured capacity, or readiness failure on `/ready`. |

Only errors produced after a request reaches a Bullnym handler use the stable
`status`/`code`/`reason` envelope. Axum extractor, routing, and body-limit
rejections can be plain text or HTML. Clients should first branch on HTTP
status/content type, then parse a Bullnym envelope when the body is JSON.

Stable error `code` values include `NymNotFound`, `NymTaken`, `NymInvalid`,
`NymReserved`, `KeyAlreadyRegistered`, `NymQuotaExceeded`,
`InvalidDescriptor`, `AuthError`, `DonationPageInvalid`,
`DonationPageNotFound`, `AliasTaken`, `InvoiceNotFound`, `InvalidAmount`,
`BitcoinAddressAlreadyUsed`, `LiquidAddressAlreadyUsed`,
`ProofOfFundsRequired`, `ProofOfFundsInvalid`, `UtxoNotFound`, `UtxoSpent`,
`PubkeyUtxoMismatch`, `RateLimitedSender`, `RateLimitedRecipient`,
`RateLimitedNetwork`, `BackendThrottled`, `TooManyPendingReservations`,
`ServiceUnavailable`, `PurgeBlocked`, `RecoveryAddressInvalid`,
`RecoveryNotAvailable`, `RecoveryInProgress`, `ElectrumError`, `BoltzError`,
`ClaimError`, and `InternalError`.

`details` is optional. Currently useful shapes include:

```json
{ "details": { "nym": "alice", "domain": "pay.example.com" } }
{ "details": { "quota": { "used": 3, "cap": 3, "remaining": 0 } } }
{ "details": { "pending_count": 2 } }
{ "details": { "min_sat": 1000 } }
```

Use `code` for program logic and localization. `reason` is user-facing text and
may evolve.

## 3. Authentication

Signed APIs use BIP-340 Schnorr over the SHA-256 digest of this byte sequence:

```text
bullpay-la-v2 NUL action NUL npub_hex NUL nym_or_empty NUL
field_1 NUL ... field_n NUL timestamp_decimal
```

There is no trailing NUL after the timestamp. Strings are UTF-8, absent
fixed-position optionals are empty strings, and the timestamp must be within
300 seconds of server time. Boolean encoding is endpoint-specific: surface
fields (`enabled` and legacy `pos_mode`) use `"1"`/`"0"`, while the three
invoice-creation acceptance fields use `"true"`/`"false"`. The 64-byte Schnorr
signature is lowercase or uppercase hex in the JSON `signature` field.

Pseudocode:

```text
message = join_with_nul([
  "bullpay-la-v2", action, npub_hex, nym_or_empty,
  ...fields
]) + NUL + decimal(timestamp)
signature = hex(BIP340_sign(private_key, SHA256(UTF8(message))))
```

Do not serialize JSON and sign it. Sign the exact ordered logical fields below.
For linked operations, the nym binds the signature to one namespace. For
unlinked invoice operations it is the empty string.

| Operation | Action | Ordered fields after nym |
|---|---|---|
| register | `register` | `ct_descriptor`, then `verification_npub` only when its JSON value is non-null |
| update registration | `update` | `ct_descriptor` |
| deactivate/purge | `delete` or `purge` | none |
| save surface | `donation-page-save` | `header`, `description`, `display_currency`, `website_or_empty`, `twitter_or_empty`, `instagram_or_empty`, `enabled`; then each of `pos_mode`, `ct_descriptor`, `kind`, `alias` only when its JSON value is non-null (`alias: ""` is non-null and is signed) |
| archive surface | `donation-page-archive` | `kind` only when its JSON value is non-null |
| create invoice | `invoice-create` | `amount_sat`, `fiat_amount_minor`, `fiat_currency`, `public_description`, `recipient_name`, `invoice_number`, `accept_btc` (`true`/`false`), `accept_ln` (`true`/`false`), `accept_liquid` (`true`/`false`), `bitcoin_address`, `liquid_address`, `liquid_blinding_key_hex`, `expires_at_unix` |
| cancel invoice | `invoice-cancel` | `invoice_id` |
| list invoices | `invoice-list` | `page`, `pageSize`, `status_or_empty` |
| recover chain swap | `invoice-recover` | `invoice_id`, `btc_address` |
| list recoverable swaps | `invoice-recovery-list` | none — zero payload fields, and the nym slot is the empty string |

Invoice optionals always occupy their fixed signing position as `""`. Amounts
and timestamps use decimal strings. This distinction from the surface API's
append-only compatibility fields is critical.

Reservation inspection is the sole legacy signing exception. Sign the
SHA-256 digest of UTF-8 `reservations:<nym>:<ts>` and send it as `sig`.

### Retry implications

Sign immediately before sending. A retry within the 300-second window may
reuse the request; after that, rebuild the timestamp and signature. Registration
reactivation, cancellation, same-address completed recovery, and most reads are
safe to retry. Invoice creation can create another receivable if the first
response was lost; clients should reconcile through the signed list endpoint
before creating a replacement.

## 4. Discovery and Pricing

### `GET /.well-known/lnurlp/:nym`

Returns LUD-06 metadata:

```json
{
  "tag": "payRequest",
  "callback": "https://pay.example.com/lnurlp/callback/alice",
  "minSendable": 100000,
  "maxSendable": 25000000000,
  "metadata": "[[\"text/identifier\",\"alice@pay.example.com\"],[\"text/plain\",\"Sats for alice\"]]",
  "commentAllowed": 144,
  "payment_methods": ["L-BTC"]
}
```

Amounts are millisatoshis. The numbers above are the shipped defaults and may
be changed by the operator, so treat the returned limits as authoritative.
`payment_methods` lists alternate methods and therefore contains `L-BTC`, not
the implicit default Lightning method. Generic LNURL clients can ignore the
extension and use Lightning.

### `GET /lnurlp/callback/:nym`

Common query fields:

| Field | Required | Meaning |
|---|---|---|
| `amount` | yes | Requested millisatoshis, within metadata limits and divisible by 1,000 (whole sats). |
| `comment` | no | LNURL comment. The server rejects more than `commentAllowed` Unicode characters. |
| `payment_method` | no | Omit for Lightning; `L-BTC` requests direct Liquid through LUD-22. |

The default response is:

```json
{
  "pr": "lnbc...",
  "routes": [],
  "disposable": false,
  "successAction": {
    "tag": "message",
    "message": "Payment received to alice@pay.example.com"
  }
}
```

This creates a Boltz reverse swap. The recipient settles to a freshly derived
Liquid address. It works with standard LNURL wallets but incurs swap/network
fees and trusts Bullnym to supply the correct destination.

LUD-22 also requires `outpoint`, `pubkey`, `sig`, `value`, `value_bf`, and
`asset_bf`. These prove ownership and rebind the supplied clear value and
blinding factors to a confidential, unspent L-BTC output meeting the configured
minimum (default 1,000 sats). The exact proof
format is specified in [LUD-22 Currency Negotiation](lud-22-currency-negotiation.md).
Successful LUD-22 returns a direct Liquid address instead of a BOLT11:

```json
{ "L-BTC": { "address": "lq1..." } }
```

Choose LUD-22 when the payer can send Liquid: it avoids two swaps and their
fees. The proof reveals one payer UTXO and blinding material to Bullnym, so it
has a larger privacy surface. Mapping `(nym, outpoint)` is idempotent; a UTXO
can target only a bounded number of distinct nyms. On rate-limit/backend
throttle errors the implementation may fall back to Lightning, so clients must
inspect the response type rather than assume the requested rail was selected.

### `GET /.well-known/nostr.json?name=:nym`

Returns `{ "names": { "alice": "<verification key hex>" } }`. It exists only
when NIP-05 is enabled and the nym opted in with a separate
`verification_npub`. Missing names do not fall back to the authentication key.

### Pricing

`GET /api/v1/supported-currencies` returns:

```json
{ "currencies": [{ "code": "USD", "precision": 2 }, { "code": "CRC", "precision": 0 }] }
```

`GET /api/v1/rate?currency=USD` returns:

```json
{ "minor_per_btc": 6500000, "last_known_rate": false }
```

`minor_per_btc` uses the currency's minor unit. Convert sats with
`sats * minor_per_btc / 100000000`. A value of `0` means no rate is available.
`last_known_rate: true` means the upstream is unavailable and the response is
stale. Display it cautiously. Invoice creation locks the selected rate, but it
may accept a last-known cached rate for up to 300 seconds after an upstream
failure; older stale rates cause `ServiceUnavailable`. Merchants therefore
retain bounded short-term exchange-rate exposure during a pricer outage.

## 5. Nym Lifecycle

### `POST /register`

```json
{
  "nym": "alice",
  "ct_descriptor": "ct(...)#checksum",
  "verification_npub": "<optional 64 hex>",
  "npub": "<64 hex auth key>",
  "timestamp": 1760000000,
  "signature": "<128 hex>"
}
```

Nyms allow lowercase ASCII letters, digits, and internal hyphens. Reserved
route/product names are rejected. A key may have only one active nym and a
configured lifetime quota (default deployment value: three). Deactivation does
not restore quota. Registering a formerly owned nym reactivates it.

Response (`201`):

```json
{
  "nym": "alice",
  "lightning_address": "alice@pay.example.com",
  "nip05": "alice@pay.example.com",
  "quota": { "used": 1, "cap": 3, "remaining": 2 }
}
```

`nip05` is null unless both client opt-in and server feature flag are present.
Sending a CT descriptor gives the server the ability to derive and unblind all
payments for this purpose wallet. It does not give the server spend keys.

### `PUT /register`

Body fields are `npub`, `nym`, `ct_descriptor`, `timestamp`, and `signature`.
It changes the descriptor used for future derivations, including unresolved
work that stores only an address index or has not allocated a destination yet:

- A repeated LUD-22 reservation lookup derives its cached index from the new
  descriptor, so it can return a different address after rotation.
- A Lightning Address reverse swap with no persisted claim address derives
  from the new descriptor when it is claimed.
- A swap whose concrete destination is already persisted keeps that address.

Treat rotation as a coordinated wallet migration. Keep scanning the old wallet
for addresses already handed to payers, ensure the new descriptor is controlled
and recoverable, and avoid rotating while payments are in flight.

Response: `{ "nym": "alice", "lightning_address": "alice@pay.example.com" }`.

### `DELETE /register`

```json
{
  "npub": "<64 hex>",
  "nym": "alice",
  "purge": false,
  "timestamp": 1760000000,
  "signature": "<128 hex>"
}
```

Omit/false `purge` for normal soft deactivation (`delete` action). It stops new
payments but preserves history and allows reactivation. `purge: true` uses the
`purge` action and deletes swap/reservation state only when no payment is in
flight. Purge never makes the nym claimable by another identity and does not
restore lifetime quota.

Response: `{ "quota": { "used": 2, "cap": 3, "remaining": 1 } }`.

### `GET /register/lookup?npub=<64-hex>`

Public and rate-limited. A successful response is:

```json
{
  "nym": "alice",
  "active": false,
  "quota": { "used": 2, "cap": 3, "remaining": 1 },
  "previous_nyms": [
    { "nym": "alice", "created_at": "2026-07-09T12:00:00Z" }
  ],
  "lifetime_nyms_used": 2,
  "lifetime_nyms_cap": 3
}
```

`nym` is the active nym, or the most recently deactivated nym when none is
active. `previous_nyms` is newest first. The two `lifetime_*` fields are legacy;
new clients use `quota`. Because lookup is public, an authentication key is
linkable to its Bullnym names; clients needing identity separation should use
a dedicated auth key.

### `GET /api/reservations/:nym`

Query: `npub`, `ts`, and legacy `sig`. Returns
`{ "reservations": [{ "outpoint", "addr_index", "fulfilled" }],
"next_addr_idx": 42 }`. This is an owner diagnostics API, not a
payment-status API. GC can delete an unfulfilled reservation after its TTL even
though expiry is not exposed in this view. Deletion releases pending-state
capacity; it does not rewind `next_addr_idx`. A later proof creates a new mapping
at whatever descriptor index is current then.

## 6. Payment Page and POS

### `PUT /donation-page`

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
| `header` | Required, nonblank, 1-80 UTF-8 bytes. | Replaces the stored value on every save. |
| `description` | Explicit `kind=payment_page`: required, 1-120 Unicode grapheme clusters and at most 512 UTF-8 bytes. Legacy requests omitting `kind`, and explicit POS requests: optional, at most 280 bytes. | Used on the Page and in its generated social preview; omission is a framework deserialization error. The omitted-kind exception preserves shipped-client compatibility and should not be copied by new clients. |
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
reactivates it. The request body limit is 8 KiB. Header/link limits use UTF-8
bytes; Payment Page descriptions additionally use grapheme-aware visible
character counting. New clients must send `kind=payment_page`; omitting `kind`
is supported only as a compatibility signal for the historical 280-byte
description contract.

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

### `GET /donation-page/:nym?kind=payment_page|pos`

Public, rate-limited editor/read model returning `DonationPageView`. It may
include disabled or archived state for management UX; public rendering still
enforces availability.

### `DELETE /donation-page`

Body: `nym`, `npub`, optional `kind`, `timestamp`, `signature`. Archival is a
soft delete of only the selected surface. Omitted `kind` archives the Payment
Page for legacy compatibility. The nym and other surface are unaffected. A
later successful save of that `(nym, kind)` automatically unarchives it.

Bullnym does not provide an image-upload API. `avatar_sha256` and `og_sha256`
in a `DonationPageView` are legacy read-only fields for previously stored media.
Bullnym generates the Page's branded 1200×630 Open Graph image automatically
from `header` and `description`; this does not add a signed request field.

### Public surface and checkout routes

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

## 7. Wallet-Origin Invoices

### Create

`POST /api/v1/:nym/invoices` creates a nym-linked invoice.
`POST /api/v1/invoices` creates an unlinked invoice; sign with an empty nym.

```json
{
  "npub": "<64 hex>",
  "amount_sat": 10000,
  "fiat_amount_minor": null,
  "fiat_currency": null,
  "public_description": "Order 42",
  "recipient_name": "Alice",
  "invoice_number": "42",
  "accept_btc": true,
  "accept_ln": true,
  "accept_liquid": true,
  "bitcoin_address": "bc1...",
  "liquid_address": "lq1...",
  "liquid_blinding_key_hex": "<32-byte hex>",
  "expires_at_unix": 1760003600,
  "timestamp": 1760000000,
  "signature": "<128 hex>"
}
```

Amount rules match checkout: exactly one of sat-fixed or fiat amount/currency.
The amount and fiat constraints listed below apply to checkout creation too.
Rail choices have these implications:

| Choice | Required destination | Settlement behavior |
|---|---|---|
| `accept_btc` | unique mainnet `bitcoin_address` | Direct BTC; credited only after configured confirmations. Reorg observations can change before final credit. |
| `accept_liquid` | unique `liquid_address` and blinding key | Direct Liquid observation and unblinding. Bullnym learns payment amounts. |
| `accept_ln` | unique Liquid address; no blinding key required unless `accept_liquid` is also true | Boltz reverse swap settles Lightning receipts to that Liquid address. |
| multiple rails | all corresponding fields | First and partial payments across rails are aggregated; `paid_via` may become `mixed`. Do not reuse any receive address. |

At least one rail must be enabled. Supplying Lightning without a Liquid
destination is invalid because reverse swaps settle to Liquid. Unique addresses
are an accounting invariant; reuse returns HTTP 409. Generate destinations from
a dedicated wallet and retain keys/blinding data for recovery.

Additional create constraints:

| Input | Constraint |
|---|---|
| `amount_sat` | Positive and within the server's configured LNURL min/max after converting those limits from msat. |
| `fiat_amount_minor` | `1..=1,000,000,000`; the converted sat amount must also fit the configured min/max. |
| `fiat_currency` | Case-normalized by the server and present in `/api/v1/supported-currencies`. |
| `public_description` | At most 1,000 bytes. |
| `recipient_name` | At most 100 bytes. `recipient_label` is accepted as a compatibility alias on input. |
| `invoice_number` | At most 50 bytes. |
| `expires_at_unix` | Omit for seven days, or set between 60 seconds and seven days in the future at processing time. |
| addresses | Valid canonical Bitcoin mainnet addresses or confidential Liquid mainnet addresses. The signature commits to the raw submitted strings before server canonicalization. |
| `liquid_blinding_key_hex` | Required and checked against the address only when `accept_liquid` is true. |

Omit address and blinding-key fields for disabled rails. Any address supplied
in the JSON is validated, stored, and reserved in the global uniqueness table
even when its corresponding `accept_*` flag is false. An unnecessary stale
address can therefore cause a validation error or HTTP 409 conflict.

Linked invoices render at `/:nym/i/:id`; `/invoice/:id` is a generic route that
renders both linked and unlinked invoices. The nym-specific route verifies that
the path nym owns the invoice, while the generic route looks up by UUID alone.
Linking provides merchant branding/routing but reveals the nym. Unlinked
invoices remain associated with the signing `npub` internally and in the signed
list API.

The response's `share_url` follows the creation route:

| Create route | `share_url` |
|---|---|
| `POST /api/v1/:nym/invoices` | `https://pay.example.com/:nym/i/:invoice_id` |
| `POST /api/v1/invoices` | `https://pay.example.com/invoice/:invoice_id` |

Example unlinked response:

```json
{
  "invoice_id": "00000000-0000-0000-0000-000000000000",
  "share_url": "https://pay.example.com/invoice/00000000-0000-0000-0000-000000000000"
}
```

### List

`GET /api/v1/invoices?npub=...&timestamp=...&signature=...&page=1&pageSize=20&status=unpaid`

The signature fields are the exact decimal `page`, exact decimal `pageSize`,
and status or empty string. This returns linked and unlinked invoices owned by
the identity. It includes both `wallet` and `checkout` origins.

| Response field | Type and meaning |
|---|---|
| `invoices` | Array of invoice list items described below |
| `page` | Effective one-based page number |
| `pageSize` | Effective page size after the server cap |
| `has_more` | `true` when the returned item count is at least `pageSize` |

Each `invoices` item contains:

| Field | Type and meaning |
|---|---|
| `id` | Invoice UUID |
| `nym_owner` | Owning nym, or `null` for an unlinked invoice |
| `origin` | `wallet` or `checkout` |
| `status` | Invoice status from the table below |
| `pricing_mode` | `sat_fixed` or `fiat_fixed` |
| `settlement_status` | Settlement state from the table below |
| `amount_sat` | Locked invoice amount in sats |
| `remaining_amount_sat` | Amount still due in sats |
| `fiat_amount_minor` | Original fiat minor-unit amount, or `null` |
| `fiat_currency` | Original ISO currency code, or `null` |
| `public_description` | Payer-visible description, or `null` |
| `recipient_name` | Recipient display label, or `null` |
| `invoice_number` | Merchant invoice reference, or `null` |
| `accept_btc` | Whether direct/on-chain Bitcoin was enabled |
| `accept_ln` | Whether Lightning was enabled |
| `accept_liquid` | Whether Liquid was enabled |
| `bitcoin_address` | Direct Bitcoin address, or `null` |
| `liquid_address` | Liquid address, or `null` |
| `created_at_unix` | Creation time in Unix seconds |
| `expires_at_unix` | Payment deadline in Unix seconds |
| `paid_via` | Credited payment rail, or `null` |
| `paid_at_unix` | Credited payment time in Unix seconds, or `null` |
| `paid_amount_sat` | Credited amount in sats, or `null` |

`page` must be 1-1000. `pageSize` must be positive and is capped by the server
at 100; sign the capped value if requesting more than 100. Supported status
filters are listed below. `has_more` is not based on a look-ahead query: an
exactly full final page still reports `true`. Continue until the API returns a
short or empty page. Use this endpoint to reconcile a timed-out create request.

### Cancel

`DELETE /api/v1/:nym/invoices/:id` or `DELETE /api/v1/invoices/:id` with body
`npub`, `timestamp`, `signature`. Sign the invoice UUID. Only an `unpaid`
invoice transitions to `cancelled`. For idempotency, any other current state is
returned unchanged with HTTP success; cancellation cannot undo an already
broadcast transaction or a payment in progress. Always inspect `status` in the
response.

Response after a successful transition:
`{ "invoice_id": "...", "status": "cancelled" }`. A request against a paid
invoice, for example, returns the same shape with `"status": "paid"`.

## 8. Payment Offers and State

### `GET /api/v1/invoices/:id/status`

Public and rate-limited. Invoice UUID possession is the access capability, so
descriptions are not in this response but payment addresses and observations
are. Treat invoice URLs as shareable secrets.

```json
{
  "status": "unpaid",
  "pricing_mode": "sat_fixed",
  "settlement_status": "none",
  "amount_sat": 10000,
  "fiat_amount_minor": null,
  "fiat_currency": null,
  "remaining_amount_sat": 10000,
  "payment_tolerance_sat": 1,
  "rate_minor_per_btc": null,
  "rate_locks_until_unix": 1760003600,
  "expires_at_unix": 1760003600,
  "paid_via": null,
  "paid_at_unix": null,
  "paid_amount_sat": null,
  "lightning_pr": "lnbc...",
  "liquid_address": "lq1...",
  "bitcoin_address": "bc1...",
  "bitcoin_direct_observations": [],
  "bitcoin_chain_address": null,
  "bitcoin_chain_bip21": null,
  "accept_btc": true,
  "accept_ln": true,
  "accept_liquid": true
}
```

`payment_tolerance_sat` is a conservative display value: the minimum configured
tolerance among all enabled rails, capped at one percent of the invoice amount
with a one-sat floor. With the shipped BTC/Liquid/Lightning tolerances and all
three rails enabled, it is therefore `1`. Payment accounting applies the
configured tolerance for the rail of the credited event; do not independently
recompute invoice status from this display field.

Invoice `status` values:

| Status | Client interpretation |
|---|---|
| `unpaid` | No credited value. Offers may still be payable before expiry. |
| `in_progress` | Payment detected or swap underway; continue polling and do not request duplicate payment. |
| `partially_paid` | Credited amount is below the terminal threshold. Show remaining amount. Checkout partials terminalize after a configured grace period. |
| `paid` | Within configured rail-specific tolerance. Fulfilled. |
| `underpaid` | Terminal payment remained below required tolerance. Requires merchant policy/manual resolution. |
| `overpaid` | More than requested was credited. Fulfilled, with possible merchant refund policy. |
| `expired` | Payment window ended. Do not pay cached offers. |
| `cancelled` | Recipient cancelled. Do not pay cached offers. |

Settlement status is independent:

| Value | Meaning |
|---|---|
| `none` | No separate swap settlement is pending. |
| `pending` | A swap/payment exists but funds are not yet settled. |
| `settled` | Settlement completed. |
| `claim_stuck` | Automated claim exhausted retries; operator intervention required. |
| `refunded` | Chain-swap lockup was refunded. |
| `failed` | Settlement failed terminally. |

Do not equate `status: paid` with `settlement_status: settled` for swap rails.
Merchant fulfillment policy should normally wait for both the desired accounting
and settlement guarantees. Direct Bitcoin observations expose txid/vout,
amount, confirmations, block height, state, and observation timestamps; only
the configured confirmation threshold creates the accounting event.

### `POST /api/v1/invoices/:id/lightning`

Returns `{ "pr": "lnbc..." }`. It lazily creates or refreshes the current
BOLT11 and is public/rate-limited. The invoice must accept Lightning and have
status `unpaid` or `partially_paid`. Call it only when the cached offer is
absent or expired. A new BOLT11 does not create a new invoice.

Offer creation uses a non-blocking per-invoice advisory lock. If another request
is creating the offer and no reusable BOLT11 is visible yet, this endpoint can
return the normal HTTP `200` `InvalidAmount` error envelope with reason
`invoice expired; no Lightning offer available`. The same envelope is used when
the invoice deadline has actually passed. If status remains payable and local
time is before `expires_at_unix`, refresh status and retry after a short
backoff; do not treat that reason alone as proof of permanent expiry.

### `POST /api/v1/invoices/:id/liquid`

Always returns `410 Gone`. Wallet-origin invoices must supply their Liquid
address at creation; checkout invoices already have one. Remove calls to this
route rather than retrying it.

### Polling and expiry

Use bounded polling with backoff and stop at a terminal status. A reasonable UI
starts at 2-3 seconds while visible, backs off, and suspends in the background.
`expires_at_unix` is the immediate payability boundary, but the stored status is
terminalized asynchronously by periodic GC (every 10 minutes with the shipped
configuration). Consequently, status can remain `unpaid`, `in_progress`, or
`partially_paid` briefly after the deadline; a partial becomes `underpaid`, and
the other eligible states become `expired` on the sweep.

The status endpoint independently suppresses an expired reusable Lightning
offer, and the Lightning offer endpoint refuses to mint one after the deadline.
Clients should stop presenting payment options once local time reaches
`expires_at_unix`, even if the returned status has not caught up. Continue
polling when late payment detection or settlement matters, and use terminal
server state as the accounting authority. Never pay a BOLT11, BIP21, or address
copied from an expired or cancelled invoice without obtaining fresh server
state.

## 9. Chain-Swap Recovery

Checkout invoices (Payment Page/POS) settle Bitcoin through BTC-to-LBTC chain
swaps. When a funded swap fails, the server parks it in `refund_due`: the
payer's BTC sits in the lockup until the invoice-owning merchant recovers it.
Recovery has two halves — a signed detection read and a signed recover action.

### Detecting recoverable swaps

```text
GET /api/v1/invoices/recoverable?npub=<64 hex>&timestamp=<unix>&signature=<128 hex>
```

Signed `invoice-recovery-list` with an **empty nym** and **zero payload
fields** (the message is `bullpay-la-v2 NUL invoice-recovery-list NUL npub NUL
NUL timestamp`). The response is npub-scoped: every chain swap of the caller's
identity currently in a recovery lifecycle state, one row **per swap** (an
invoice can carry more than one), `refund_due` first, oldest first:

```json
{
  "recovery_enabled": false,
  "items": [
    {
      "invoice_id": "3f6f0f6e-...",
      "nym": "merchant-nym",
      "recovery_status": "refund_due",
      "user_lock_amount_sat": 105000,
      "server_lock_amount_sat": 100000,
      "lockup_address": "bc1p...",
      "refund_address": null,
      "refund_txid": null,
      "swap_created_at_unix": 1767000000,
      "swap_updated_at_unix": 1767003600,
      "invoice": {
        "status": "expired",
        "amount_sat": 100000,
        "fiat_amount_minor": 5000,
        "fiat_currency": "CAD",
        "public_description": "Order 123",
        "invoice_number": "INV-42",
        "created_at_unix": 1766990000
      }
    }
  ],
  "count": 1,
  "has_more": false
}
```

- `recovery_status` is `refund_due` (recoverable now), `refunding` (a recovery
  broadcast is in flight; poll this endpoint), or `refunded` (terminal;
  `refund_txid` set). Treat unknown values as in-flight and take no action.
- `recovery_enabled` mirrors `features.chain_swap_merchant_recovery`. Detection
  is **always available** behind the signature (registered under `invoices` or
  `payment_pages`), so clients can show stranded funds even while the recover
  action is disabled; offer the recover action only when this flag is true.
- `refund_address`/`refund_txid` echo the committed first-write-wins
  destination. This is the reconciliation source of truth: a reinstalled client
  must adopt the echoed address and retry with exactly those bytes rather than
  deriving a new destination.
- `user_lock_amount_sat` is the payer's recoverable lockup;
  `server_lock_amount_sat` is the renegotiation-aware invoice-side amount. They
  legitimately differ.
- The row cap is 100 with `has_more: true` on overflow — treat overflow as an
  operator incident, not a pagination cue.
- The endpoint does not require an active registration, so a merchant whose
  nym lapsed can still see stranded funds. Build the recover URL from each
  row's `nym`.
- Availability: servers built before this endpoint return `404`/`405` here.
  Fail closed — show no recovery state — and never infer recovery state from
  the public status endpoint, which deliberately never exposes it.

### Recovering

`POST /api/v1/:nym/invoices/:id/recover` exists only when the default-off
merchant recovery feature is enabled (`recovery_enabled` above).

```json
{
  "npub": "<64 hex>",
  "timestamp": 1760000000,
  "signature": "<128 hex>",
  "btc_address": "bc1..."
}
```

The invoice must be linked to the signing nym and have a chain swap in
`refund_due`. The address must be Bitcoin mainnet. Address selection is
first-write-wins and is included in the signature. Same-address retries after
completion return the same txid; a different address is rejected.

Response: `{ "status": "recovered", "txid": "<bitcoin txid>" }`.

This endpoint signs and broadcasts real Bitcoin. Clients should show the full
destination for confirmation and persist the chosen address before submission.
`RecoveryInProgress` is retryable after waiting; `RecoveryNotAvailable` is not
a signal to create another recovery request with a different address.

`"recovered"` means the refund transaction was **broadcast**, not confirmed.
Treat the returned txid as pending until it confirms on-chain; a low-fee
transaction can remain unconfirmed or be evicted. Poll the detection endpoint
(or the txid) rather than presenting broadcast as final settlement.

## 10. Utility and Operations APIs

| Method and path | Response/use | Implication |
|---|---|---|
| `GET /qr.svg?data=...` | Deterministic 256px-minimum SVG, input 1-4096 UTF-8 bytes | Public/rate-limited. Encode only payment payloads; arbitrary untrusted data may produce unusable dense QRs. |
| `GET /health` | Liveness response | Proves the process serves HTTP, not that DB/schema/dependencies work. |
| `GET /ready` | Component JSON and HTTP 200/503 | Checks DB and expected schema marker. Use for load-balancer readiness. |
| `GET /version` | crate/build commit/branch/time/dirty/runtime/schema metadata | Use for rollout preflight and support reports. Some fields may be `unknown` if build metadata was not injected. |
| `GET /robots.txt` | Indexing policy | Privacy aid, not access control. |
| `GET /certification/preflight?scopes=...` | Certification readiness | Test-harness endpoint; not end-user authentication. |
| `POST /webhook/boltz/:secret` | Boltz status delivery | Operator integration. Path secret is sensitive and may appear in proxy logs. |
| `POST /webhook/boltz` | Legacy/development webhook | Rejected when a webhook URL secret is configured. Do not deploy as the production target. |

Certification scopes are comma-separated values from `registration_setup`,
`metadata_lookup`, `invoice_create`, `invoice_status`, and `live_money_offer`.
Authorized harnesses send `x-bullnym-certification-token`. The response reports
`enabled`, source/token validity, requested/configured/missing scopes, and
`ready`. It only bypasses selected rate limits from configured source networks;
it does not bypass signatures, ownership, validation, or money invariants.

## 11. Integration Decisions

### Descriptor or explicit address

Use descriptors for long-lived Lightning Address/Payment Page/POS products that
need a fresh address per payment. Use explicit unique addresses for one-off
wallet invoices. Descriptors improve address-reuse privacy but give the server
visibility across the dedicated wallet; explicit addresses reduce server
derivation power but make the client responsible for uniqueness and recovery.

### Linked or unlinked invoice

Link when the payer benefits from the recipient's stable name/branding and the
recipient owns an active nym. Use unlinked invoices for a minimally branded
share URL or identities without a nym. Neither mode hides the invoice from the
server, and the UUID remains a public bearer capability for status.

### Lightning, Liquid, or Bitcoin

Lightning maximizes payer compatibility but adds Boltz dependency, fees, and
asynchronous settlement. Direct Liquid is fast and inexpensive but requires a
Liquid-capable payer and exposes unblinding data to Bullnym. Direct Bitcoin is
widely verifiable but confirmation-latent and reorg-sensitive. Enabling all
rails improves conversion but requires clients to handle mixed/partial payment
accounting and retain keys for every destination.

### Alias or nym URL

Alias URLs decouple public branding from the Lightning Address nym and can
scrub it from page/payment presentation. They are globally unique, public, and
enumerable, so they are not an anonymity boundary. HTTP management clients
receive `public_url` in `DonationPageView` and should use it for sharing. The
server-injected PWA configuration also has `invoice_base` for browser clients;
it is not returned by the management API.

## 12. Production Client Checklist

1. Pin HTTPS and configure the deployment origin; never accept a base URL from
   an invoice response without an explicit trust policy.
2. Use a dedicated BIP-85-derived auth key and dedicated Liquid purpose
   wallets/descriptors; back them up through the wallet's documented recovery.
3. Build signing bytes independently of JSON serialization and test byte-exact
   vectors, especially empty fields and optional trailing surface fields.
4. Parse coded error envelopes on every status, including HTTP 200.
5. Fetch supported currencies, preserve integer minor units, and avoid
   floating-point money calculations.
6. Generate a fresh Bitcoin/Liquid address for every wallet invoice and retain
   its spend/blinding material before calling create.
7. Treat invoice URLs/UUIDs as bearer-readable, stop polling terminal states,
   and distinguish payment accounting from swap settlement.
8. Reconcile ambiguous create/cancel outcomes through signed list/status APIs
   before repeating state-changing operations.
9. Validate `/version` and `/ready` during rollout; feature-probe optional
   routes such as NIP-05 and recovery.
10. Localize by stable error `code`, log build metadata and request context,
    and never log private keys, descriptors, blinding keys, signatures, BOLT11s,
    webhook secrets, or complete payment URLs at broad log levels.
