# Data Model

Postgres is Bullnym's source of truth. Migrations are plain SQL under
`migrations/` and are applied outside the process.

## Core Tables

| Table | Ownership | Purpose |
|---|---|---|
| `users` | Nym lifecycle | One row per nym. Stores owner `npub`, public `verification_npub`, Lightning Address descriptor, nym status, and Lightning Address cursor. |
| `donation_pages` | Public payment surfaces | One row per `(nym, kind)`, where `kind` is `payment_page` or `pos`. Stores display content, display currency, links, legacy image hashes, the generated social-card key/version, retry count/time, descriptor, address cursor, and archive state. |
| `invoices` | Payment sessions | Stores donation checkout sessions and wallet-origin invoices, accepted rails, settlement addresses, pricing, status, expiry, and cumulative paid amount. |
| `invoice_payment_events` | Accounting | Idempotent counted payment evidence keyed by rail-specific event keys. |
| `invoice_payment_observations` | Non-accounting evidence | Direct Bitcoin sightings that are unconfirmed or below the confirmation threshold. |
| `swap_records` | Boltz reverse swaps | Lightning Address and invoice reverse-swap state, claim status, and payment association. |
| `chain_swap_records` | Boltz chain swaps | Donation-page Bitcoin-to-Liquid chain-swap state, lockup address, claim address, and lifecycle. |
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
