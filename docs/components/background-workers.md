# Background Workers

Bullnym runs several background tasks from `main`. They share a
`CancellationToken` and are designed to be restart-safe through durable
database state and idempotent updates.

## Claimer

The claimer drains claimable Boltz swaps and performs MuSig2 cooperative
claims. It handles both Lightning reverse swaps and donation-page chain swaps.

Responsibilities:

- claim LBTC to the invoice, donation-page, or nym settlement address
- record payment events after successful recipient-side settlement
- persist claim transaction state
- mark exhausted retry budgets as `claim_stuck`

## Reconciler

The reconciler polls Boltz for non-terminal swaps. It repairs missed webhook
delivery and state drift by comparing database state with Boltz's view.

It should be considered part of normal operation, not only an incident tool:
Boltz webhook delivery is best-effort, and webhooks can be missed during
network issues or deploys.

## Liquid Chain Watcher

The Liquid watcher uses the Liquid Electrum backend, not the Bitcoin mempool
API. It calls the `UtxoBackend` implementation in `utxo::ElectrumClient`,
which uses Electrum scripthash history and raw transaction fetches.

It uses that backend to:

- verify LUD-22 proof UTXOs
- detect direct Liquid invoice payments
- detect donation-page checkout payments
- advance descriptor cursors when funded addresses are observed
- release unfunded LUD-22 reservations after TTL

Callback proof verification and settlement detection use separate buckets so a
callback storm cannot starve payment detection.

## Bitcoin Watcher

The Bitcoin watcher polls the configured mempool.space-shaped HTTP API for
direct Bitcoin invoice addresses. It records unconfirmed and below-threshold
observations for status visibility, then records accounting events once the
configured confirmation threshold is met.

This worker is for wallet-origin direct Bitcoin invoices. Donation-page
Bitcoin checkout uses Boltz chain swaps and is tracked through chain-swap
state instead.

## Garbage Collection

The GC task prunes sliding-window rate-limit rows, expires invoices past their
deadline, and terminalizes stale checkout partials after the configured grace
period.

## In-Memory Rate-Limit Sweep

The in-memory sweep evicts idle per-IP buckets from process memory. Persistent
rate-limit tables are handled by GC; this task bounds process memory under
unique-IP bursts.
