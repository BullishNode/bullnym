# 006 Payment Rails and Settlement

- Status: Accepted
- Amended: 2026-07-28 — added the Bull Bitcoin fiat settlement rail and the
  mixed-invoice chain-swap scope (#274)
- Scope: `bullnym` payment rails

## Decision

Bullnym supports multiple payer rails. Absent a fiat settlement policy, every
rail settles to wallet-owned receiver descriptors or merchant-supplied
addresses:

- Lightning Address Lightning payments use Boltz reverse swaps and, for a
  merchant without a fiat settlement policy, settle to the receiver's Liquid
  descriptor.
- LUD-22 direct Liquid payments return a Liquid address only after a UTXO
  ownership proof gates allocation.
- Direct Liquid invoice payments are watched through Liquid Electrum.
- Direct Bitcoin invoice payments are watched through the Bitcoin mempool API.
- Payment Page/POS Bitcoin chain swaps send BTC to Boltz and settle LBTC to the
  checkout Liquid destination.
- Payment Page/POS Lightning payments use Boltz and settle LBTC to the checkout
  Liquid destination.
- Linked wallet invoices under a mixed fiat settlement policy expose Bitcoin
  through the same Boltz BTC-to-LBTC chain-swap rail, settling to the
  invoice's Liquid address.

Bull Bitcoin fiat settlement is an opt-in, per-product policy
(`lightning_address`, `payment_page`, `pos`, `invoice`) captured at payment
time. A 100% allocation settles the funded swap to one confidential Bull
Bitcoin output with no merchant output; a 1–99% split adds Bull Bitcoin legs
beside the merchant output. The merchant then receives that portion as a Bull
Bitcoin fiat credit rather than on-chain funds.

Swap settlement is currently recorded after a successful claim broadcast, not
after confirmation. Direct Bitcoin and Liquid instead separate verified
zero-confirmation presentation from accounting at one confirmation and
configurable finality (three Bitcoin, two Liquid by default). These are current
implementation boundaries rather than guarantees against arbitrary reorgs.

The current server does not use the mempool API for Liquid detection. Liquid
watching needs Electrum-style history/raw-transaction access and unblinding
support through the Liquid wallet stack.

## Rationale

Bullnym has a receiver-centric model: mobile owns descriptors; Bullnym allocates
addresses from those descriptors and observes/claims payments. Different payer
rails have different infrastructure requirements. For merchants without a fiat
settlement policy, all successful flows must produce receiver-controlled
funds; a captured fiat policy deliberately redirects the allocated share to
Bull Bitcoin settlement outputs in exchange for a fiat credit.

## Consequences

- BDK senders are appropriate for Bitcoin direct invoice and Bitcoin-to-Liquid
  chain-swap tests.
- LWK senders are appropriate for direct Liquid tests.
- Jungle senders are appropriate for Lightning/Boltz tests.
- Chain swaps are not direct Bitcoin invoice observation; they are a distinct
  Boltz-backed rail serving Payment Page/POS checkout and linked mixed-fiat
  wallet invoices.
- Rail tests should target the changed rail rather than rerunning unrelated
  known-good payment volume.
