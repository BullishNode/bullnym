# Availability and Transport

All JSON requests use `Content-Type: application/json`. Timestamps are Unix
seconds. UUIDs are canonical UUID strings. Public page routes return HTML and
JSON routes use the response shapes documented below. Private payment pages
render their QR codes locally in the browser; payment payloads are not sent to
a server-side QR endpoint.

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

JSON API application errors return a truthful non-2xx status with a stable
envelope:

```json
{
  "status": "ERROR",
  "code": "InvoiceNotFound",
  "reason": "Invoice not found."
}
```

LNURL metadata/callback endpoints are the deliberate protocol exception: LUD-06
errors retain HTTP `200` with the same envelope. During a rolling deployment,
clients should continue checking `status == "ERROR"` on successful responses so
they remain compatible with a pre-0.3 server.

| HTTP status | Meaning |
|---|---|
| `200` | Success, or a coded error only on an LNURL/LUD-06 endpoint. |
| `201` | Successful nym registration. |
| `400` | Request validation failure, or a framework query/path/malformed-JSON rejection. Framework responses may not use the Bullnym envelope. |
| `401` | Authentication/signature failure or an invalid/revoked scoped credential. |
| `404` | A requested nym, donation page, invoice, or UTXO does not exist. Route-level 404s may be HTML/plain text. |
| `409` | A durable ownership, policy, state, or resource conflict. Blind retry without refreshing/changing state is wrong. |
| `410` | Deprecated Liquid-offer endpoint. |
| `413` | Axum request-body limit exceeded before the handler. |
| `429` | Sender/recipient/network/pending-reservation rate limit. |
| `405` | Method not allowed; may be HTML/plain text rather than JSON. |
| `415` | Missing or unsupported JSON `Content-Type`; framework response, not a Bullnym envelope. |
| `422` | JSON syntax was valid but could not deserialize into the request type; framework response. |
| `500` | Unexpected database/internal/claim failure; the message is sanitized. |
| `503` | Transient dependency/readiness/capacity failure, or typed quote contention. |

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
`ServiceUnavailable`, `QUOTE_BUSY`, `PurgeBlocked`, `RecoveryAddressInvalid`,
`RecoveryNotAvailable`, `ElectrumError`, `BoltzError`,
`ClaimError`, and `InternalError`.

The wallet-backup API uses its own strict error shape/status mapping. Its
additional stable codes are
`BackupInvalidRequest`, `BackupAuthError`, `BackupHeadConflict`,
`BackupBlobTooLarge`, and `BackupCapacityExceeded`; see
[Opaque wallet backups](wallet-backups.md).

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
