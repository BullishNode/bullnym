# HTTP API

This is a compact route and component map. The canonical, endpoint-by-endpoint
client wire contract is the [Complete API Reference](../api-reference.md),
including exact signing encodings, validation limits, response variants, and
integration implications. Route registration lives in `src/main.rs`; request
and response structs live in the handler modules named below.

## Conventions

All custom endpoints use JSON unless marked as multipart or HTML. UUID path
segments are lowercase canonical UUID strings.

Most failures return an LNURL-style error envelope, often with HTTP `200`:

```json
{
  "status": "ERROR",
  "code": "InvoiceNotFound",
  "reason": "Invoice not found."
}
```

Clients must inspect response bodies for `status: "ERROR"` even when the HTTP
status is successful. The main non-200 cases are:

| HTTP status | Cases |
|---|---|
| `400`, `415`, `422` | Axum query/JSON extraction failures; not a Bullnym error envelope. |
| `401` | Signature/authentication failure. |
| `404`, `405` | Missing route or unsupported method; response may be HTML/plain text. |
| `409` | Wallet-origin Bitcoin/Liquid address reuse or alias collision. |
| `410` | Deprecated Liquid offer route. |
| `413` | Request body exceeds the route/global limit. |
| `503` | Hard service capacity or configured unavailable state. |

Signed requests use:

```text
bullpay-la-v2\0<action>\0<npub_hex>\0<nym_or_empty>\0(<field>\0)*<timestamp>
```

The server verifies a BIP-340 Schnorr signature over `SHA-256(message)`.
Optional signed fields use empty strings unless the endpoint explicitly says
the field is optional-trailing for compatibility.

## Status Values

Invoice `status`:

```text
unpaid
in_progress
partially_paid
paid
underpaid
overpaid
expired
cancelled
```

Invoice `settlement_status`:

```text
none
pending
settled
claim_stuck
refunded
failed
```

`paid_via` is `lightning`, `liquid`, `bitcoin`, `mixed`, or `null`.

## Public Discovery

| Method | Path | Handler | Notes |
|---|---|---|---|
| `GET` | `/.well-known/lnurlp/:nym` | `lnurl::metadata` | LNURL-pay metadata. Includes `payment_methods` when LUD-22 is enabled by the server behavior. |
| `GET` | `/.well-known/nostr.json?name=:nym` | `nostr::nostr_json` | Served only when `[features].nip05 = true`. Returns `verification_npub` only when the nym registered one. |
| `GET` | `/lnurlp/callback/:nym` | `lnurl::callback` | Returns BOLT11 by default, or a LUD-22 Liquid address when the payer supplies the proof fields. |

`/lnurlp/callback/:nym` query:

| Field | Required | Notes |
|---|---|---|
| `amount` | yes | Millisats, within metadata limits and divisible by 1,000. |
| `comment` | no | Optional LNURL comment. |
| `payment_method` | no | `L-BTC` selects LUD-22 Liquid. |
| `outpoint`, `pubkey`, `sig`, `value`, `value_bf`, `asset_bf` | for LUD-22 | Approach B proof-of-funds fields. |

## Nym Lifecycle

| Method | Path | Action/Auth | Handler |
|---|---|---|---|
| `POST` | `/register` | `register` | `registration::register` |
| `PUT` | `/register` | `update` | `registration::update_registration` |
| `DELETE` | `/register` | `delete` or `purge` | `registration::delete_registration` |
| `GET` | `/register/lookup?npub=...` | public, rate-limited | `registration::lookup_by_npub` |
| `GET` | `/api/reservations/:nym?npub=...&ts=...&sig=...` | legacy reservation signature | `registration::list_reservations` |

`POST /register` body:

| Field | Notes |
|---|---|
| `nym` | Lowercase letters, numbers, hyphen; no leading/trailing hyphen. |
| `ct_descriptor` | Lightning Address Liquid descriptor. |
| `verification_npub` | Optional NIP-05 public key. |
| `npub`, `timestamp`, `signature` | Signed owner fields. |

Response:

```json
{
  "nym": "alice",
  "lightning_address": "alice@example.com",
  "nip05": null,
  "quota": { "used": 1, "cap": 3, "remaining": 2 }
}
```

`DELETE /register` defaults to soft deactivate. `purge: true` also deletes
swap and reservation state when no in-flight swaps exist.

## Payment Page and POS Surfaces

The `donation_pages` table stores two surface kinds:

| Kind | Public URL | Invoice create route | Descriptor behavior |
|---|---|---|---|
| `payment_page` | `/:nym` | `POST /:nym/invoice` | Uses the Payment Page descriptor, with legacy fallback to the Lightning Address descriptor. |
| `pos` | `/:nym/pos` | `POST /:nym/pos/invoice` | Requires its own descriptor. No Lightning Address fallback. |

### Management API

| Method | Path | Action/Auth | Notes |
|---|---|---|---|
| `PUT` | `/donation-page` | `donation-page-save` | Create or update one surface. |
| `DELETE` | `/donation-page` | `donation-page-archive` | Archive one surface. |
| `GET` | `/donation-page/:nym?kind=payment_page\|pos` | public, rate-limited | Read surface state for clients. |

`PUT /donation-page` body:

| Field | Notes |
|---|---|
| `nym`, `npub`, `timestamp`, `signature` | Owner and signature fields. |
| `header`, `description`, `display_currency` | Public display fields. |
| `website`, `twitter`, `instagram` | Optional links/handles. |
| `enabled` | Public route serves only enabled, non-archived rows. |
| `ct_descriptor` | Required for `kind = "pos"`. Optional for legacy Payment Pages. |
| `pos_mode` | Legacy optional-trailing flag. New clients use `kind`. |
| `kind` | Optional-trailing field: `payment_page` default or `pos`. Sent after `ct_descriptor` when present. |
| `alias` | Newest optional-trailing field. Omit to preserve, send `""` to clear, or send a globally unique slug. Must be last when present. |

Save signing field order after `nym_or_empty`:

```text
header
description
display_currency
website
twitter
instagram
enabled
[pos_mode if sent]
[ct_descriptor if sent]
[kind if sent]
[alias if sent]
```

### Public PWA Routes

| Method | Path | Notes |
|---|---|---|
| `GET` | `/:nym` | Payment Page PWA shell or archived/not-found page. |
| `GET` | `/:nym/manifest.webmanifest` | Payment Page manifest. |
| `GET` | `/:nym/pos` | POS terminal PWA shell. |
| `GET` | `/:nym/pos/manifest.webmanifest` | POS manifest. |
| `GET` | `/a/:slug` | Alias-selected Payment Page or POS shell. |
| `GET` | `/a/:slug/manifest.webmanifest` | Alias-selected surface manifest. |
| `GET` | `/sw.js` | Root-scoped service worker. |
| `GET` | `/pwa-assets/*` | Built PWA assets. |

The server injects `bullnym-config` into the shell. PWA shell responses carry
`x-bullnym-pwa-shell: donation` or `x-bullnym-pwa-shell: pos`; the service
worker uses that header to avoid caching invoice pages.

## Anonymous Checkout

| Method | Path | Surface | Handler |
|---|---|---|---|
| `POST` | `/:nym/invoice` | Payment Page | `invoice::create_anonymous` |
| `POST` | `/:nym/pos/invoice` | POS | `invoice::create_anonymous_pos` |
| `POST` | `/a/:slug/invoice` | Alias-selected Payment Page or POS | `invoice::create_anonymous_alias` |
| `GET` | `/:nym/i/:id` | Linked checkout or linked wallet invoice | `invoice::render_payment` |
| `GET` | `/a/:slug/i/:id` | Alias-linked checkout invoice | `invoice::render_payment_alias` |

Request body must provide exactly one amount form:

```json
{ "amount_sat": 10000 }
```

or:

```json
{ "fiat_amount_minor": 2500, "fiat_currency": "USD" }
```

Response:

```json
{
  "invoice_id": "00000000-0000-0000-0000-000000000000",
  "lightning_pr": "lnbc...",
  "liquid_address": "lq1...",
  "bitcoin_chain_address": "bc1...",
  "bitcoin_chain_bip21": "bitcoin:bc1...?amount=...",
  "expires_at_unix": 1760000000
}
```

`bitcoin_chain_address` and `bitcoin_chain_bip21` are nullable. They represent
BTC-to-LBTC Boltz chain swaps, not direct Bitcoin settlement. `lightning_pr`
can be an empty string when eager Boltz offer creation fails; use
`POST /api/v1/invoices/:id/lightning` to obtain it later.

## Wallet-Origin Invoices

| Method | Path | Action/Auth | Notes |
|---|---|---|---|
| `POST` | `/api/v1/:nym/invoices` | `invoice-create` | Create a nym-linked invoice. |
| `POST` | `/api/v1/invoices` | `invoice-create` with empty nym | Create an unlinked invoice. |
| `GET` | `/api/v1/invoices?npub=...&timestamp=...&signature=...&page=...&pageSize=...` | `invoice-list` | List linked and unlinked invoices. |
| `DELETE` | `/api/v1/:nym/invoices/:id` | `invoice-cancel` | Cancel a linked unpaid invoice. |
| `DELETE` | `/api/v1/invoices/:id` | `invoice-cancel` with empty nym | Cancel an unlinked unpaid invoice. |
| `GET` | `/invoice/:id` | public | Generic UUID route; renders linked or unlinked invoices. |

Create body:

| Field | Notes |
|---|---|
| `npub`, `timestamp`, `signature` | Owner and signature fields. |
| `amount_sat` or `fiat_amount_minor` + `fiat_currency` | Exactly one amount mode. |
| `public_description`, `recipient_name`, `invoice_number` | Optional public metadata. |
| `accept_btc`, `accept_ln`, `accept_liquid` | Accepted direct/payment rails. |
| `bitcoin_address` | Required when direct Bitcoin is accepted. Must be unique. |
| `liquid_address` | Required when direct Liquid or Lightning is accepted. Must be unique. |
| `liquid_blinding_key_hex` | Required only for direct Liquid (`accept_liquid = true`), and must match the confidential address. |
| `expires_at_unix` | Optional explicit expiry. |

Create signing field order:

```text
amount_sat
fiat_amount_minor
fiat_currency
public_description
recipient_name
invoice_number
accept_btc
accept_ln
accept_liquid
bitcoin_address
liquid_address
liquid_blinding_key_hex
expires_at_unix
```

The three acceptance booleans are signed as `true` or `false`. This differs
from Payment Page/POS surface booleans, which use `1` or `0`.

Create response:

```json
{
  "invoice_id": "00000000-0000-0000-0000-000000000000",
  "share_url": "https://example.com/alice/i/00000000-0000-0000-0000-000000000000"
}
```

`GET /api/v1/invoices` signs `[page, pageSize, status_or_empty]` with empty
`nym_or_empty`. `status` may be omitted or one of the invoice statuses.

## Invoice Payment State

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/invoices/:id/status` | public, rate-limited | Poll payment state, settlement state, offers, addresses, and observations. |
| `POST` | `/api/v1/invoices/:id/lightning` | public, rate-limited | Create or refresh the current BOLT11 offer. |
| `POST` | `/api/v1/invoices/:id/liquid` | public compatibility | Always returns `410 Gone`. |
| `GET` | `/api/v1/supported-currencies` | public | Fiat currencies accepted for server-side pricing. |
| `GET` | `/api/v1/rate?currency=USD` | public | Current or last-known fiat rate view. |

Status response:

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
  "bitcoin_address": null,
  "bitcoin_direct_observations": [],
  "bitcoin_chain_address": "bc1...",
  "bitcoin_chain_bip21": "bitcoin:bc1...",
  "accept_btc": false,
  "accept_ln": true,
  "accept_liquid": true
}
```

Direct Bitcoin observations are not accounting events until they reach the
configured confirmation threshold.

## Chain-Swap Recovery

| Method | Path | Action/Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/invoices/recoverable?npub=...&timestamp=...&signature=...` | `invoice-recovery-list` | List the npub's chain swaps in `refund_due`/`refunding`/`refunded`, one row per swap, with the committed `refund_address`/`refund_txid` echo and a `recovery_enabled` flag. Always-on (registered under `invoices` or `payment_pages`); not gated by the recovery flag. Zero signed payload fields; the nym slot is empty. |
| `POST` | `/api/v1/:nym/invoices/:id/recover` | `invoice-recover` | Recover a `refund_due` BTC lockup to a merchant-supplied Bitcoin address. Feature-gated by `features.chain_swap_merchant_recovery`. |

Detection is the only client path that exposes recovery state; the public
`GET /api/v1/invoices/:id/status` endpoint deliberately never carries it. The
detection response schema and reconciliation semantics live in the
[Complete API Reference](../api-reference.md) §9.

Request:

```json
{
  "npub": "<owner npub hex>",
  "timestamp": 1760000000,
  "signature": "<schnorr signature>",
  "btc_address": "bc1..."
}
```

Signing fields are `[invoice_id, btc_address]`. `btc_address` is signed exactly
as sent and must be a valid Bitcoin mainnet address.

Response:

```json
{ "status": "recovered", "txid": "<bitcoin txid>" }
```

Recovery is first-write-wins on `btc_address`. Retrying a completed request
with the same address returns the same transaction id. A different address is
rejected.

## Webhooks and Operator Endpoints

| Method | Path | Notes |
|---|---|---|
| `POST` | `/webhook/boltz/:secret` | Boltz webhook endpoint. Secret is a URL-path secret, not an HMAC. |
| `POST` | `/webhook/boltz` | Development/legacy route. Refused when a URL secret is configured. |
| `GET` | `/qr.svg` | QR SVG generator for payment payloads. |
| `GET` | `/robots.txt` | Allows public Page metadata fetches; Page responses prevent indexing with `X-Robots-Tag`. |
| `GET` | `/health` | Process liveness. |
| `GET` | `/ready` | Database and schema readiness. |
| `GET` | `/version` | Build provenance and expected schema marker. |
| `GET` | `/certification/preflight` | Scoped certification readiness check. |
