# Wallet-Origin Invoices

## Create

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
| `accept_btc` | unique mainnet `bitcoin_address` | Direct BTC is presented at zero confirmations, activates accounting at one, and reaches configured finality at three by default. |
| `accept_liquid` | unique `liquid_address` and blinding key | Exact verified L-BTC is presented at zero confirmations, activates accounting at one, and reaches configured finality at two by default. |
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

## List

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
| `presentation_status` | Server-computed `unpaid`, `partial`, `payment_received`, or `overpaid`; nullable/unknown rollout values are conservative |
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
The optional `status` filter remains accounting-based; provisional
`payment_received` does not enter the `paid` filter before one confirmation.

## Cancel

`DELETE /api/v1/:nym/invoices/:id` or `DELETE /api/v1/invoices/:id` with body
`npub`, `timestamp`, `signature`. Sign the invoice UUID. Only an `unpaid`
invoice transitions to `cancelled`. For idempotency, any other current state is
returned unchanged with HTTP success; cancellation cannot undo an already
broadcast transaction or a payment in progress. Always inspect `status` in the
response.

Response after a successful transition:
`{ "invoice_id": "...", "status": "cancelled" }`. A request against a paid
invoice, for example, returns the same shape with `"status": "paid"`.

## Payment offers and state

## `GET /api/v1/invoices/:id/status`

Public and rate-limited. Invoice UUID possession is the access capability, so
descriptions are not in this response but payment addresses and observations
are. Treat invoice URLs as shareable secrets.

```json
{
  "status": "unpaid",
  "presentation_status": "unpaid",
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

`presentation_status` is independent from confirmed-accounting `status` and
`paid_amount_sat`:

| Value | Client interpretation |
|---|---|
| `unpaid` | No valid active or provisional direct value contributes. |
| `partial` | Active plus verified provisional value remains below the server tolerance; top-up rails remain payable. |
| `payment_received` | Active plus verified provisional value satisfies the invoice; hide new instructions. |
| `overpaid` | Active plus verified provisional value exceeds the target; hide new instructions. |

The server owns value, mixed-rail, fiat, and tolerance calculations. A null or
unknown presentation value is non-final and non-cancellable, hides payment
instructions, and must not be mapped to `unpaid`.
`remaining_amount_sat` is likewise server-owned: it subtracts exact active plus
verified provisional presentation value so partial top-up instructions and new
Lightning offers cannot request the already-observed amount again.

Settlement status is independent:

| Value | Meaning |
|---|---|
| `none` | No separate swap settlement is pending. |
| `pending` | A swap/payment exists but funds are not yet settled. |
| `settled` | The current settlement boundary completed. For swap claims this currently means successful broadcast, not confirmation. |
| `resolution_pending` | Previously accepted direct evidence regressed and is visibly being checked. |
| `claim_stuck` | Fast claim retries were exhausted; slow automated recovery continues on a longer backoff and operators should investigate. |
| `refunded` | Chain-swap lockup was refunded. |
| `failed` | Settlement failed terminally. |

Do not interpret `settlement_status: settled` as confirmed finality for swap
rails. Merchant fulfillment policy must account for the current broadcast
boundary and verify chain confirmation when finality is required. Direct
Bitcoin and Liquid accounting begins at one confirmation; configured finality
defaults to three Bitcoin and two Liquid confirmations. Zero-confirmation
evidence changes only presentation and settlement. Bitcoin observation details
expose txid/vout, amount, confirmations, block height, state, and timestamps.

## `POST /api/v1/invoices/:id/lightning`

Returns `{ "pr": "lnbc..." }`. It lazily creates or refreshes the current
BOLT11 and is public/rate-limited. The invoice must accept Lightning and the
combined server projection must remain payable: known `unpaid` with no
settlement evidence, or known `partial` presentation. Sufficient, overpaid,
incident, terminal, and unknown projections cannot mint a new offer. Call it
only when a payable invoice's cached offer is absent or expired. A new BOLT11
does not create a new invoice.

Offer creation uses a non-blocking per-invoice advisory lock. If another request
or a payment-state reducer currently owns that lock, this endpoint returns HTTP
`503` with the normal error envelope and code `ServiceUnavailable`. Treat this
as transient: refresh status, then retry with a short backoff only if the fresh
projection remains payable and local time is before `expires_at_unix`.

A non-payable invoice or one whose deadline has passed instead returns the
normal HTTP `200` `InvalidAmount` error envelope. Do not treat lock contention
as invoice expiry, and do not retry either response from cached state alone.
The integration suite exercises the offer-lock contention response.

## `POST /api/v1/invoices/:id/liquid`

Always returns `410 Gone`. Wallet-origin invoices must supply their Liquid
address at creation; checkout invoices already have one. Remove calls to this
route rather than retrying it.

## Polling and expiry

Use bounded polling with backoff and stop only when the combined presentation
and settlement projection is final. Accounting `paid` with settlement
`pending` continues polling; `resolution_pending`, unknown values, and a
settled-but-partial payable projection also keep polling. Settled
sufficient/overpaid projections plus `claim_stuck`, `refunded`, and `failed`
stop the automatic detail loop under the current contract. A reasonable UI
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
