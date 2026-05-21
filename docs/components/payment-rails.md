# Payment Rails

Bullnym presents product-level payment instructions and maps them onto
Lightning, Liquid, Bitcoin, and Boltz settlement flows.

## Rail Matrix

| Rail | Products | Payer sends | Recipient receives | Settlement destination |
|---|---|---|---|---|
| Lightning via Boltz reverse swap | Lightning Address, Donation Pages, Invoices | BOLT11 payment | LBTC after MuSig2 claim | Descriptor-derived or wallet-supplied Liquid address. |
| LUD-22 Liquid shortcut | Lightning Address | Direct LBTC | LBTC | Fresh nym descriptor address gated by UTXO proof. |
| Direct Liquid | Donation Pages, Invoices | Direct LBTC | LBTC | Page descriptor address or wallet-supplied Liquid address. |
| Direct Bitcoin | Invoices | Bitcoin on-chain | BTC | Wallet-supplied Bitcoin address. |
| Bitcoin-to-Liquid chain swap | Donation Pages | Bitcoin on-chain to Boltz lockup | LBTC | Page descriptor address. |

## Lightning Reverse Swaps

Lightning offers are Boltz reverse swaps. The payer pays a BOLT11 invoice.
Boltz locks LBTC, and Bullnym cooperatively claims to the recipient settlement
address. Accounting records `lightning_boltz_reverse:<swap_id>` only after the
recipient-side claim succeeds or is recoverably proven.

Donation-page and wallet-origin invoice pages use
`POST /api/v1/invoices/:id/lightning` to create or refresh the current offer.
Status polling reports the offer state but should not be treated as the primary
swap-creation path.

## Direct Liquid

Direct Liquid payments are watched through Liquid Electrum, not the Bitcoin
mempool API. Donation-page checkout uses a page descriptor address when
present; wallet-origin invoices use a Liquid address and blinding key supplied
by mobile at creation time.

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

Donation pages can offer Bitcoin payment through Boltz chain swaps. The payer
sends BTC to a Boltz lockup address; Bullnym claims LBTC to the checkout
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
