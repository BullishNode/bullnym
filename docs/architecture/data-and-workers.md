# Data and workers

Postgres is Bullnym's source of truth. Migrations are plain SQL under
`migrations/` and are applied outside the process.

## Core Tables

| Table | Ownership | Purpose |
|---|---|---|
| `users` | Nym lifecycle | One row per nym. Stores owner `npub`, public `verification_npub`, Lightning Address descriptor, nym status, and Lightning Address cursor. |
| `donation_pages` | Public payment surfaces | One row per `(nym, kind)`, where `kind` is `payment_page` or `pos`. Stores display content, legacy read-only media hashes, descriptor, address cursor, alias, and archive state. |
| `invoices` | Payment sessions | Stores checkout sessions and wallet-origin invoices, accepted rails, settlement addresses, pricing, status, expiry, and cumulative paid amount. |
| `invoice_payment_events` | Accounting | Idempotent counted payment evidence keyed by rail-specific event keys. |
| `invoice_payment_observations` | Non-accounting evidence | Direct Bitcoin sightings that are unconfirmed or below the confirmation threshold. |
| `swap_records` | Boltz reverse swaps | Lightning Address and invoice reverse-swap state, claim status, and payment association. |
| `chain_swap_records` | Boltz chain swaps | Payment Page/POS Bitcoin-to-Liquid state, lockup and claim data, refund data, retry state, and derivation metadata. |
| `outpoint_addresses` | LUD-22 reservations | `(nym, outpoint)` to descriptor index cache for Liquid shortcut idempotency and TTL cleanup of unfulfilled rows. |
| `nym_access_events` | Abuse controls | Sliding-window distinct-nym access counters. |
| `processed_webhook_events` | Webhook idempotency | Prevents duplicate Boltz webhook processing. |
| Rate-limit tables | Abuse controls | Persistent sliding-window counters for selected limits. |

## Descriptor Cursors

`users.next_addr_idx` belongs to Lightning Address receive flows. It is used by
LNURL Lightning claims and LUD-22 Liquid allocation.

`donation_pages.next_addr_idx` belongs to public checkout surfaces. It is
advanced when `POST /:nym/invoice` or `POST /:nym/pos/invoice` creates a
checkout invoice and the selected `(nym, kind)` row has a `ct_descriptor`.
Plain page render does not advance it. Legacy Payment Pages without a
descriptor use the nym descriptor and cursor until migrated. POS requires its
own descriptor.

Wallet-origin invoices store concrete addresses and do not advance either
descriptor cursor.

## Invoice Origins

| Origin | Created by | Routes | Settlement addresses |
|---|---|---|---|
| `checkout` | Anonymous payer from a Payment Page or POS | `POST /:nym/invoice`, `POST /:nym/pos/invoice`, `/:nym/i/:id` | Derived from the selected surface descriptor, with legacy nym fallback only for Payment Pages. |
| `wallet` | Recipient mobile client | `/api/v1/:nym/invoices`, `/api/v1/invoices` | Supplied by the client at creation time. |

Both origins share status projection, payment accounting, Lightning offer
refresh, and public payment-page rendering.

Checkout invoices store one Liquid settlement address at creation time. That
address backs Lightning reverse-swap claims, direct Liquid, and donation-page
Bitcoin chain-swap claims.

## Status Fields

`status` tracks payer/payment accounting: `unpaid`, `in_progress`,
`partially_paid`, `paid`, `underpaid`, `overpaid`, `expired`, or `cancelled`.

`settlement_status` tracks recipient-side settlement for rails that have an
asynchronous claim step: `none`, `pending`, `settled`, `claim_stuck`,
`refunded`, or `failed`.

## Payment Evidence

Payment events are counted accounting evidence and update invoice totals.
Payment observations are status evidence only and must never update
`paid_amount_sat`, `paid_via`, or `paid_at`.

## Worker responsibilities

| Worker | Durable input | Responsibility |
|---|---|---|
| Reverse-swap claim sweep | retryable `swap_records` | Construct or reuse a claim, persist transaction evidence, broadcast, and update settlement. |
| Chain-swap claim sweep | retryable `chain_swap_records` | Claim provider LBTC to the committed checkout destination. |
| Reverse/chain reconcilers | non-terminal swap rows | Poll provider state to recover missed webhooks and schedule guarded transitions. |
| Slow recovery | funded `claim_stuck` rows | Revive claims on a long exponential backoff after the fast budget is exhausted. |
| Settlement repair | claimed reverse swaps | Idempotently recreate a missing invoice payment event after a crash between claim and invoice updates. |
| Liquid watcher | persisted blinded destinations | Detect matching Liquid outputs and advance descriptor observations. |
| Bitcoin watcher | direct-Bitcoin invoice destinations | Persist observations, count outputs after the configured confirmation threshold, and detect disappearance before credit. |
| GC | terminal and rate-limit rows | Apply retention and partial-checkout expiry policies. |

Provider webhooks are latency hints, not the only recovery trigger. Reconciler
queries and chain evidence allow progress after webhook loss. Provider status
is also not independent proof that a transaction confirmed.

## Competing-spend safety

Claim/refund operations use guarded status transitions and per-swap advisory
locks. A chain swap in `refunding` is excluded from claim paths, and refund
execution refuses to proceed when a claim transaction exists or provider state
indicates a completed claim. The emergency refund destination is persisted
first-write-wins.

Persisted transaction hex, transaction IDs, swap keys, and derivation metadata
are recovery artifacts. Operational procedures must preserve them until chain
evidence proves an outcome.

## Current finality boundary

The claim paths mark swaps claimed and update invoice accounting after a
successful transaction broadcast; they do not wait for a confirmation. Direct
Liquid is credited from Electrum history, including mempool transactions.
Direct Bitcoin alone has a modeled confirmation threshold and non-accounting
observations. See the [trust model](trust-model.md) for the residual risk.
