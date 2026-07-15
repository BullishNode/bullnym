# Availability and Transport

All JSON requests use `Content-Type: application/json`. Timestamps are Unix
seconds. UUIDs are canonical UUID strings. Public page routes return HTML and
`/qr.svg` returns SVG.

The server permits cross-origin origins and methods but allows only the
`Content-Type` request header in browser preflights. Authentication does not
use cookies. The certification token is therefore intended for same-origin or
non-browser harnesses unless the deployment's reverse proxy adds a narrower
CORS policy for it.

## Feature gates

An operator may disable product groups. A disabled route is absent, not a JSON
feature error.

| Configuration | Routes enabled |
|---|---|
| `features.lightning_address` | LNURL metadata/callback, `/register*`, reservations |
| `features.nip05` plus `lightning_address` | `/.well-known/nostr.json` |
| `features.payment_pages` | surface CRUD, Payment Page/POS/alias pages and anonymous checkout |
| `features.invoices` | signed wallet-invoice create/list/cancel and `/invoice/:id` |
| `invoices` or `payment_pages` | invoice status and Lightning/Liquid offer routes; recoverable-swaps detection (`GET /api/v1/invoices/recoverable`) |

Always use `GET /version` during deployment/certification to identify the
build. Do not infer feature availability only from the crate version; probe the
required route in the target environment.

## Error contract

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
| `409` | A supplied Bitcoin/Liquid address is already assigned, a public name is permanently reserved, or this npub already owns another permanent nym/alias. Blind retry is wrong. |
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
`DonationPageNotFound`, `NameTaken`, `NymAlreadyAssigned`,
`AliasAlreadyAssigned`, `InvoiceNotFound`, `InvalidAmount`,
`BitcoinAddressAlreadyUsed`, `LiquidAddressAlreadyUsed`,
`ProofOfFundsRequired`, `ProofOfFundsInvalid`, `UtxoNotFound`, `UtxoSpent`,
`PubkeyUtxoMismatch`, `RateLimitedSender`, `RateLimitedRecipient`,
`RateLimitedNetwork`, `BackendThrottled`, `TooManyPendingReservations`,
`ServiceUnavailable`, `PurgeBlocked`, `RecoveryAddressInvalid`,
`RecoveryNotAvailable`, `ElectrumError`, `BoltzError`,
`ClaimError`, and `InternalError`.

`details` is optional. Currently useful shapes include:

```json
{ "details": { "nym": "alice", "domain": "pay.example.com" } }
{ "details": { "alias": "coffee" } }
{ "details": { "quota": { "used": 1, "cap": 1, "remaining": 0 } } }
{ "details": { "pending_count": 2 } }
{ "details": { "min_sat": 1000 } }
```

Use `code` for program logic and localization. `reason` is user-facing text and
may evolve.
