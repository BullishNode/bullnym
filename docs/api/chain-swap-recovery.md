# Chain-swap recovery

Checkout invoices from Payment Pages and POS settle Bitcoin through BTC-to-LBTC
chain swaps. When a funded payer lockup cannot complete merchant settlement,
Bullnym can park the swap in `refund_due` rather than terminalizing it as lost.

The current API provides a per-invoice recovery action. It does **not** provide
a merchant-wide endpoint for listing recoverable swaps, and the public invoice
status response deliberately does not expose the internal recovery state. A
merchant client must therefore already know the affected linked invoice ID, or
an operator must identify `refund_due` rows and coordinate recovery with the
merchant. Bulk signed recovery discovery remains proposed work, not a shipped
API.

## `POST /api/v1/:nym/invoices/:id/recover`

This route exists only when `features.chain_swap_merchant_recovery = true`. It
uses the `invoice-recover` signing action with `btc_address` as the sole payload
field.

```json
{
  "npub": "<64 hex>",
  "timestamp": 1760000000,
  "signature": "<128 hex>",
  "btc_address": "bc1..."
}
```

The invoice must:

- be linked to the `:nym` in the route;
- be owned by the signing `npub`;
- have a chain swap currently in `refund_due`.

The destination must be a Bitcoin mainnet address and is included in the
signature. Destination persistence is first-write-wins: same-address retries
can reconcile idempotently, while a different address is rejected after one
has been committed.

Success response:

```json
{ "status": "recovered", "txid": "<bitcoin txid>" }
```

`recovered` means the recovery transaction was broadcast and recorded, not
confirmed. Track the returned transaction ID independently until confirmation.
Do not interpret a request timeout as proof that no broadcast occurred.

## Errors and retry policy

- `RecoveryAddressInvalid`: correct the network/address before retrying.
- `RecoveryInProgress`: wait and retry with the identical address.
- `RecoveryNotAvailable`: the swap is not in a recoverable state, another
  address was already committed, or merchant settlement may already exist.
  Do not try another destination.
- `InvoiceNotFound`: the invoice is absent or does not belong to the signed
  route identity; the response intentionally does not reveal which.

The server refuses recovery when provider/claim evidence indicates that the
merchant-side claim may already have happened. An ambiguous provider response
defers recovery rather than risking a claim and refund for the same payment.
