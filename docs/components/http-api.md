# HTTP API

Bullnym is an Axum service. Routes are registered in `src/main.rs`; handlers
live in feature modules such as `registration`, `lnurl`, `donation_page`, and
`invoice`.

## Public LNURL and Discovery

| Method | Path | Component | Purpose |
|---|---|---|---|
| `GET` | `/.well-known/lnurlp/:nym` | Lightning Address | LNURL-pay metadata with callback URL, min/max sendable, and advertised payment methods. |
| `GET` | `/.well-known/nostr.json?name=:nym` | NIP-05 | Optional endpoint. Returns the public `verification_npub` only for nyms that supplied one and when NIP-05 is enabled. |
| `GET` | `/lnurlp/callback/:nym` | Lightning Address | Returns either a BOLT11 Lightning invoice or a LUD-22 Liquid address. |

## Nym Lifecycle

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/register` | Schnorr signed | Register a nym, Lightning Address descriptor, and optional `verification_npub`. |
| `PUT` | `/register` | Schnorr signed | Update the Lightning Address descriptor for the caller's nym. |
| `DELETE` | `/register` | Schnorr signed | Deactivate a nym while preserving the reservation. |
| `GET` | `/register/lookup?npub=...` | Public, rate-limited | Return active and inactive nyms for an owner key. |
| `GET` | `/api/reservations/:nym` | Public, rate-limited | Inspect pending LUD-22 reservations for a nym. |

## Donation Pages

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `PUT` | `/donation-page` | Schnorr signed | Create or update page content, display currency, links, and optional page CT descriptor. |
| `DELETE` | `/donation-page` | Schnorr signed | Archive the page; existing checkout invoices continue to expire naturally. |
| `POST` | `/donation-page/image` | Schnorr signed multipart | Upload avatar or OpenGraph image. Server normalizes to WebP. |
| `GET` | `/donation-page/:nym` | Public | JSON state used by mobile and clients. |
| `GET` | `/:nym` | Public fallback | Server-rendered donation page. |
| `POST` | `/:nym/invoice` | Public | Create a payer checkout invoice from the page amount. Allocates one Liquid settlement address for the checkout session. |
| `GET` | `/:nym/i/:id` | Public | Render the payment page for a linked checkout or linked wallet invoice. |

## Invoices

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/:nym/invoices` | Schnorr signed | Create a wallet-origin invoice linked to a nym. |
| `POST` | `/api/v1/invoices` | Schnorr signed | Create an unlinked wallet-origin invoice. |
| `GET` | `/api/v1/invoices?npub=...` | Schnorr signed | List wallet-origin invoices for mobile dashboard state. |
| `DELETE` | `/api/v1/:nym/invoices/:id` | Schnorr signed | Cancel a linked unpaid invoice. |
| `DELETE` | `/api/v1/invoices/:id` | Schnorr signed | Cancel an unlinked unpaid invoice. |
| `GET` | `/invoice/:id` | Public | Render an unlinked payment page. |
| `GET` | `/api/v1/invoices/:id/status` | Public | Poll invoice status, offers, and payment observations. |
| `POST` | `/api/v1/invoices/:id/lightning` | Public | Create or refresh a reusable Lightning offer. |
| `POST` | `/api/v1/invoices/:id/liquid` | Public compatibility | Returns `410 Gone`; wallet-origin Liquid addresses are supplied at invoice creation. |
| `GET` | `/api/v1/supported-currencies` | Public | Return server-supported fiat currencies. |

## Webhooks and Utility Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/webhook/boltz/:secret` | Authenticated Boltz reverse-swap and chain-swap webhook endpoint. |
| `POST` | `/webhook/boltz` | Development/legacy webhook endpoint; refused when a URL secret is configured. |
| `GET` | `/qr.svg` | Generate QR SVGs for payment data. |
| `GET` | `/robots.txt` | Prevent indexing of payment pages. |
| `GET` | `/health` | Liveness probe only. |
| `GET` | `/ready` | Operator readiness probe for database connectivity and expected schema marker. |
| `GET` | `/version` | Build provenance and expected schema marker. |
| `GET` | `/certification/preflight` | Scoped certification readiness check. |
