# Payment Rails

Bullnym presents product-level payment instructions and maps them onto
Lightning, Liquid, Bitcoin, and Boltz settlement flows.

## Rail Matrix

| Rail | Products | Payer sends | Recipient receives | Settlement destination |
|---|---|---|---|---|
| Lightning via Boltz reverse swap | Lightning Address, Payment Pages, POS, Invoices | BOLT11 payment | LBTC after MuSig2 claim | Descriptor-derived or wallet-supplied Liquid address. |
| LUD-22 Liquid shortcut | Lightning Address | Direct LBTC | LBTC | Current nym descriptor index gated by UTXO proof; unpaid reservations can share the address until payment advances the cursor. |
| Direct Liquid | Payment Pages, POS, Invoices | Direct LBTC | LBTC | Surface descriptor address or wallet-supplied Liquid address. |
| Direct Bitcoin | Invoices | Bitcoin on-chain | BTC | Wallet-supplied Bitcoin address. |
| Bitcoin-to-Liquid chain swap | Payment Pages, POS | Bitcoin on-chain to Boltz lockup | LBTC | Surface descriptor address. |

## Lightning Reverse Swaps

Lightning offers are Boltz reverse swaps. The payer pays a BOLT11 invoice.
Boltz locks LBTC, and Bullnym cooperatively claims to the recipient settlement
address. Accounting records `lightning_boltz_reverse:<swap_id>` only after the
recipient-side claim succeeds or is recoverably proven.

Payment Page, POS, and wallet-origin invoice pages use
`POST /api/v1/invoices/:id/lightning` to create or refresh the current offer.
Status polling reports the offer state but should not be treated as the primary
swap-creation path.

## Direct Liquid

Direct Liquid payments are watched through Liquid Electrum, not the Bitcoin
mempool API. Public checkout uses the selected surface descriptor address;
wallet-origin invoices use a Liquid address and blinding key supplied by
mobile at creation time.

For Payment Pages and POS, the direct Liquid address is allocated when the
checkout invoice is created. Rendering `GET /:nym` or `GET /:nym/pos` does not
allocate an address; status polling or page refresh does not allocate a second
address.

Liquid accounting uses idempotent event keys:

```text
liquid_direct:<txid>:<vout>
```

## Direct Bitcoin

Direct Bitcoin is invoice-only. The recipient supplies a Bitcoin address at
invoice creation time. The Bitcoin watcher uses the configured
mempool.space-shaped API to record non-accounting observations for mempool and
below-threshold confirmed outputs, then records accounting events after the
configured confirmation policy is satisfied.

Bitcoin accounting uses output-specific event keys:

```text
bitcoin_direct:<txid>:<vout>
```

## Bitcoin-to-Liquid Chain Swaps

Payment Pages and POS can offer Bitcoin payment through Boltz chain swaps. The
payer sends BTC to a Boltz lockup address; Bullnym claims LBTC to the checkout
session's Liquid address. This rail is distinct from direct Bitcoin invoices
and must not be used as proof that direct Bitcoin invoice watching works.

Chain-swap accounting uses:

```text
bitcoin_boltz_chain:<swap_id>
```

## Tolerances

Shortfall tolerances are configured by rail under `invoice_accounting`:
Bitcoin direct, Liquid direct, Lightning reverse swap, and Bitcoin chain swap
can each have different tolerances. Small shortfalls within tolerance become
`paid`; excess value remains visible as `overpaid`.
