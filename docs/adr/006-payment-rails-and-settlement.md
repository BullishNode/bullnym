# 006 Payment Rails and Settlement

- Status: Accepted
- Scope: `bullnym` payment rails

## Decision

Bullnym supports multiple payer rails while settling to wallet-owned receiver
descriptors:

- Lightning Address default Lightning payments use Boltz reverse swaps and
  settle to the receiver's Liquid descriptor.
- LUD-22 direct Liquid payments return a Liquid address only after a UTXO
  ownership proof gates allocation.
- Direct Liquid invoice payments are watched through Liquid Electrum.
- Direct Bitcoin invoice payments are watched through the Bitcoin mempool API.
- Payment Page/POS Bitcoin chain swaps send BTC to Boltz and settle LBTC to the
  checkout Liquid destination.
- Payment Page/POS Lightning payments use Boltz and settle LBTC to the checkout
  Liquid destination.

Swap settlement is currently recorded after a successful claim broadcast, not
after confirmation. Direct Liquid is currently credited from Electrum history,
including mempool history. These are current implementation boundaries rather
than finality guarantees.

The current server does not use the mempool API for Liquid detection. Liquid
watching needs Electrum-style history/raw-transaction access and unblinding
support through the Liquid wallet stack.

## Rationale

Bullnym has a receiver-centric model: mobile owns descriptors; Bullnym allocates
addresses from those descriptors and observes/claims payments. Different payer
rails have different infrastructure requirements, but all successful flows must
produce receiver-controlled funds.

## Consequences

- BDK senders are appropriate for Bitcoin direct invoice and Bitcoin-to-Liquid
  chain-swap tests.
- LWK senders are appropriate for direct Liquid tests.
- Jungle senders are appropriate for Lightning/Boltz tests.
- Chain swaps are not direct Bitcoin invoice observation; they are a distinct
  Boltz-backed donation-page rail.
- Rail tests should target the changed rail rather than rerunning unrelated
  known-good payment volume.
