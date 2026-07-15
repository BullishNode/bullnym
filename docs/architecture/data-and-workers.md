# Data and workers

Postgres is Bullnym's source of truth. Migrations are plain SQL under
`migrations/` and are applied outside the process.

## Core Tables

| Table | Ownership | Purpose |
|---|---|---|
| `users` | Permanent nym / Lightning Address availability | One row per nym. Stores owner `npub`, public `verification_npub`, Lightning Address descriptor, availability status, and Lightning Address cursor. |
| `donation_pages` | Public payment surfaces | One row per `(nym, kind)`, where `kind` is `payment_page` or `pos`. Stores display content, generated social-card key/version/retry state, legacy read-only media hashes, descriptor, address cursor, alias, and archive state. |
| `invoices` | Payment sessions | Stores checkout sessions and wallet-origin invoices, accepted rails, settlement addresses, pricing, status, expiry, and cumulative paid amount. |
| `invoice_payment_events` | Accounting | Idempotent payment evidence keyed by rail-specific event keys, with explicit countable/inactive/superseded state and stable accounting order. |
| `invoice_payment_observations` | Non-accounting evidence | Durable exact Bitcoin and Liquid direct-output identity, confirmation, block, verification, and lifecycle evidence written by both live watchers. |
| `invoice_direct_scan_heads` | Direct-payment ordering | One bounded generation row per invoice/source so an older network completion cannot overwrite a newer-started scan. |
| `invoice_direct_payment_transitions` | Direct-payment audit | Append-only lifecycle evidence written atomically by the live direct-payment reducer and by compatibility-safe Boltz supersession. |
| `watcher_lane_progress` | Direct-watcher scheduling | Last fully visited `(created_at, invoice id)` rotation offset per direct worker and recent/historical lane. It is never worker-health evidence. |
| `swap_records` | Boltz reverse swaps | Lightning Address and invoice reverse-swap state, claim status, and payment association. |
| `chain_swap_records` | Boltz chain swaps | Payment Page/POS Bitcoin-to-Liquid state, lockup and claim data, refund data, retry state, and derivation metadata. |
| `chain_swap_tx_attempts` | Chain-swap recovery journal | Durable Bitcoin recovery transaction attempts, raw transaction evidence, broadcast outcome, and competing-spend recovery state. |
| `outpoint_addresses` | LUD-22 reservations | `(nym, outpoint)` to descriptor index cache for Liquid shortcut idempotency and TTL cleanup of unfulfilled rows. |
| `nym_access_events` | Abuse controls | Sliding-window distinct-nym access counters. |
| `processed_webhook_events` | Webhook idempotency | Prevents duplicate Boltz webhook processing. |
| Rate-limit tables | Abuse controls | Persistent sliding-window counters for selected limits. |

## Descriptor Cursors

`users.next_addr_idx` belongs to Lightning Address receive flows. It is used by
LNURL Lightning claims and LUD-22 Liquid allocation. Direct LUD-22 history does
not fulfill its reservation or advance this durable cursor until Electrum
reports a positive confirmation height; mempool-only history may be evicted.

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

`status` retains the invoice lifecycle/accounting token: `unpaid`, `in_progress`,
`partially_paid`, `paid`, `underpaid`, `overpaid`, `expired`, or `cancelled`.
For a cancelled or expired invoice, the terminal lifecycle token remains in
`status`; `presentation_status`, `paid_via`, `paid_amount_sat`, and settlement
fields independently expose any money observed afterward. Both direct watchers
retain closed addresses so cancellation/expiry cannot erase chain evidence.

Migration 047 adds separate `direct_settlement_status` and
`swap_settlement_status` component caches. The existing top-level
`settlement_status` is their live public aggregate. Direct watcher writes run
through the transactional reducer; swap compatibility writers maintain their
own component. The aggregate uses `none`, `pending`, `settled`,
`resolution_pending`, `claim_stuck`, `refunded`, and `failed`, with existing
swap incident tokens taking priority.

## Payment Evidence

Payment events are immutable accounting evidence. Only `active` and
`legacy_unverified` events contribute to invoice totals; inactive and
superseded rows remain durable but non-countable. Payment observations are
status evidence only and must never update `paid_amount_sat`, `paid_via`, or
`paid_at` by themselves.

Migration 047 separates direct-payment presentation, accounting activation, and
operational finality in durable schema. Existing direct events remain countable
as `legacy_unverified` until a live watcher positively revalidates them. Both
direct watchers reserve a database generation before chain I/O and atomically
apply verified observation, event, transition, presentation, settlement, and
accounting projections. Omission from address history is not invalidation
evidence; the unresolved ambiguous-absence policy remains disabled.

## Worker responsibilities

| Worker | Durable input | Responsibility |
|---|---|---|
| Reverse-swap claim sweep | retryable `swap_records` | Construct or reuse a claim, persist transaction evidence, broadcast, and update settlement. |
| Chain-swap claim sweep | retryable `chain_swap_records` | Claim provider LBTC to the committed checkout destination. |
| Reverse/chain reconcilers | non-terminal swap rows | Poll provider state to recover missed webhooks and schedule guarded transitions. |
| Slow recovery | funded `claim_stuck` rows | Revive claims on a long exponential backoff after the fast budget is exhausted. |
| Settlement repair | claimed reverse and chain swaps | Idempotently recreate a missing invoice payment event after a crash between claim and invoice updates. |
| Payment Page OG reconciler | live `payment_page` rows | Generate versioned, content-addressed social cards; backfill legacy rows; retry render/write failures; and verify referenced files exist on the serving host. |
| Liquid watcher | persisted blinded destinations | Preserve signed Electrum heights and block identity, verify exact LBTC outputs, present at zero confirmations, account at one, and track configured finality or explicit reorg evidence. Direct-invoice work uses durable, disjoint recent and historical rotation lanes. |
| Bitcoin watcher | direct-Bitcoin invoice destinations and known observations | Use address history for discovery plus tx-specific follow-up, present at zero confirmations, account at one, and track configured finality or explicit block regression. |
| GC | terminal and rate-limit rows | Apply retention and partial-checkout expiry policies. |

Provider webhooks are latency hints, not the only recovery trigger. Reconciler
queries and chain evidence allow progress after webhook loss. Provider status
is also not independent proof that a transaction confirmed.

## Worker liveness and admission

Money-moving workers report progress and cycle outcomes to an in-process,
per-rail admission snapshot. The snapshot is intentionally not persisted: a
new process must prove its own dependencies and complete its own startup scans
instead of inheriting another process's health. Liquid and Bitcoin watchers run
an immediate startup scan, and the claimer/reconciler/recovery workers run an
immediate startup cycle before admission can open their dependent rail.
For direct Liquid invoices, the fast lane contains newly-created targets plus
any target with partial presentation or pending/resolution-pending direct
settlement; the historical lane is the exact eligible complement. Cancelled,
expired, and invoices from subsequently archived surfaces remain eligible for
late-money and reorg observation. Each fully applied or explicitly isolated
invoice advances only its own durable lane offset. That offset is restart
scheduling input, never inherited health: every new process must traverse from
the offset to the frozen lane end and wrap through the saved boundary before
that lane can report healthy. Lightning Address nym lookahead keeps its
separate process-local recent/all cadence. Each Liquid watcher poll gives both
incomplete phases one bounded turn and alternates which runs first, so nym
backlog or a phase-local failure cannot defer direct-invoice work by the slow
historical cadence.
Direct watcher backends, the retained Liquid claim-client factory, the reused
Bitcoin recovery-evidence client, and the Boltz client are initialized as
separate rail facts. A direct backend cannot stand in for a swap claim or
recovery path merely because both use the same configured provider fallback.

One or two consecutive failed cycles leave the worker suspect while service
continues. Three consecutive failures, three missed worker cadences,
or an unexpected task stop closes the affected rail. Two successful cycles are
required to reopen after a failure or stale closure. Whole-process intentional
shutdown is distinguished from an unexpected task drop.

A rate-budget deferral that leaves a watcher scan incomplete is not a successful
cycle. Active- and idle-tier outcomes are latched independently, so success in
one tier cannot erase failures in the other. Malformed or business-local rows
remain isolated, while all-provider failures and required database writes that
fail make the worker cycle unhealthy.

Watcher startup covers both active and idle tiers. Each tier freezes a snapshot
from the database clock and advances through deterministic keyset pages. The
direct invoice watchers persist their most recently completed row after every
fully applied or explicitly isolated obligation. A new epoch starts after that
offset, wraps once through the beginning up to its frozen starting offset, and
only then completes. A crash before the offset write repeats an idempotent
obligation; it cannot skip one. The recent lane prioritizes age-new invoices,
`presentation_status = partial`, and direct settlement that is pending or in
resolution. Historical is the exact complement inside the eligible set, so the
lanes are disjoint and old cancelled/expired destinations remain eligible.
The persisted offset controls rotation only: every new process starts with
unknown tier health and must complete its own tail-and-wrap traversal. The
Liquid watcher latches completed nym and invoice phases across ticks; neither
incomplete phase can restart or gate the other. Each nym also freezes one
bounded descriptor/lookahead range and
retains its exact address subcursor across deferral; payments that advance the
live descriptor cursor cannot extend that epoch or starve later nyms.
Intermediate pages report progress only; an empty page still probes the
configured chain backend, and a token-limited page that makes no forward
progress fails the cycle. Admission opens only after the complete snapshot
drains successfully.

Capped reconciler and repair scans likewise retain a process-local database-time
epoch with deterministic keyset cursors across intermediate pages. Multi-rail
workers latch each completed subset so one large subset cannot continually
restart or starve another. Draining or a systemic failure discards the local
epoch and cursors. No persisted row marker is used as scan-completion or health
evidence, so another process cannot make a restarted process inherit successful
admission.

These signals gate only the publication of new payment instructions. Worker
execution itself is never gated, so an admission closure cannot prevent the
claims, reconciliation, settlement repair, or recovery needed for existing
obligations.

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
Bitcoin and Liquid instead present verified mempool outputs without accounting,
activate exact accounting at one confirmation, and remain settlement-pending
until configured finality (defaults: three Bitcoin, two Liquid). Explicit block
regression can atomically demote or re-observe the same evidence while retaining
append-only audit history. Ambiguous absence does nothing until its separate
threshold is approved. See the [trust model](trust-model.md) for residual risk.
