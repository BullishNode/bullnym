# Chain-Swap Recovery

Checkout invoices (Payment Page/POS) settle Bitcoin through BTC-to-LBTC chain
swaps. When a funded swap fails, the server parks it in `refund_due`: the
payer's BTC sits in the lockup until the invoice-owning merchant recovers it.
Recovery has two halves — a signed detection read and a signed recover action.

## Detecting recoverable swaps

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

## Recovering

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

