# Chain-Swap Recovery

Checkout invoices (Payment Page/POS) settle Bitcoin through BTC-to-LBTC chain
swaps. When a funded swap fails, the server parks it in `refund_due`: the
payer's BTC sits in the lockup until Bullnym's internal automatic executor can
recover it to the immutable merchant policy bound before payer exposure.
Clients can register and look up that policy and read signed lifecycle status;
they cannot trigger a broadcast or choose a destination for an existing swap.

## Registering the merchant recovery address

Before creating a chain swap, a merchant client registers its private Bitcoin
recovery policy:

```text
PUT /api/v1/recovery-address
```

```json
{
  "version": 1,
  "npub": "<64 lowercase hex>",
  "btc_address": "bc1...",
  "timestamp": 1760000000,
  "signature": "<128 lowercase hex>"
}
```

Sign the LA-v2 action `recovery-address-set` in the identity-wide **empty nym**
domain. The two ordered payload fields are the literal string `1`, then the
exact canonical Bitcoin-mainnet address from `btc_address`:

```text
bullpay-la-v2 NUL recovery-address-set NUL npub NUL NUL
1 NUL canonical_btc_address NUL timestamp
```

The endpoint accepts an address only, not a BIP21 URI, label, amount, or
payment-provider substitute. It rejects non-mainnet and non-canonical address
encodings, unknown JSON fields, non-canonical npubs, and uppercase signatures.
The lowercase-only signature rule is specific to this commitment contract;
other LA-v2 endpoints retain the general case-insensitive signature parsing
described in [Authentication](authentication.md). The request body limit is
1 KiB.

A successful response contains acceptance metadata only:

```json
{
  "version": 1,
  "recovery_address_registered": true,
  "signed_at_unix": 1760000000
}
```

The write response never returns the address, npub, signature, commitment ID,
or commitment version. Missing and inactive identities produce the same
generic authentication response, so the write endpoint is not an identity
oracle.

An exact signed-request retry (the same five logical values and signature)
within the 300-second authentication window is idempotent: it resolves to the
original immutable commitment and returns the same public response. Any other
valid signed request, including one with a new timestamp for the same address,
appends a new commitment version and becomes the policy for future swaps.
Address rotation never rewrites a swap that was already bound to an earlier
commitment. If a response is lost, retry the exact request while it is fresh;
otherwise use the signed lookup below before deciding whether registration is
needed. Do not re-sign a write merely to poll, because that would create a new
immutable version.

## Looking up the current recovery address

Setup and seed-restore flows read the current private policy with:

```text
GET /api/v1/recovery-address?npub=<64 lowercase hex>&timestamp=<unix>&signature=<128 hex>
```

Sign LA-v2 action `recovery-address-get` in the identity-wide empty-nym domain
with zero payload fields:

```text
bullpay-la-v2 NUL recovery-address-get NUL npub NUL NUL timestamp
```

When a commitment exists, the authenticated response is:

```json
{
  "version": 1,
  "recovery_address_registered": true,
  "btc_address": "bc1...",
  "commitment_version": 1,
  "signed_at_unix": 1760000000
}
```

When none exists, the three commitment-specific fields are `null` and
`recovery_address_registered` is `false`. The lookup does not require an
active nym: a restored wallet must still adopt the immutable address governing
existing swaps after registration expiry. The caller must verify that its
default Bitcoin wallet recognizes the returned mainnet address and reapply its
local recovery label; it must not register a replacement merely because local
label state was lost.

The address is available only after a fresh signature from its owning npub.
Anonymous Page, POS, invoice-status, registration-write, and error responses
never expose it. The lookup also withholds the npub, commitment UUID, original
authorization signature, and server registration time.

## Reading recovery lifecycle status

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

- `recovery_status` is `refund_due` (automatic recovery is pending),
  `refunding` (an automatic attempt is in flight), or `refunded` (terminal;
  `refund_txid` set). Treat unknown values as in-flight and take no action.
- This endpoint is read-only. Clients must never infer a writable recovery
  action, submit a destination, or trigger a broadcast from these fields.
- `refund_address`/`refund_txid` expose the immutable automatic destination and
  its terminal transaction, when materialized. A restored client should adopt
  the displayed address as existing policy; it must not derive a replacement
  for this swap.
- `user_lock_amount_sat` is the payer's recoverable lockup;
  `server_lock_amount_sat` is the renegotiation-aware invoice-side amount. They
  legitimately differ.
- The row cap is 100 with `has_more: true` on overflow — treat overflow as an
  operator incident, not a pagination cue.
- The endpoint does not require an active registration, so a merchant whose
  nym lapsed can still see stranded funds. Each row's `nym` is read-only
  ownership context.
- Availability: servers built before this endpoint return `404`/`405` here.
  Fail closed — show no recovery state — and never infer recovery state from
  the public status endpoint, which deliberately never exposes it.

## Automatic execution

Bullnym alone schedules and executes recovery. Before a network call it reloads
the immutable address commitment, lifecycle journal, provider evidence, and
agreed Bitcoin/Liquid chain snapshots under the swap lock. It defers when
readiness or finality is insufficient and enters an integrity hold when exact
evidence conflicts. A client request is never an execution input.

`refund_txid` means the journal has identified the exact Bitcoin transaction;
confirmation and finality remain chain lifecycle facts. Continue polling the
signed status endpoint and do not present broadcast as final settlement.
