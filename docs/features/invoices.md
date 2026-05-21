# Invoices

Invoices are recipient-created receivables exposed through signed mobile APIs
and public payment URLs.

## Invoice Types

| Type | Origin | Created by | Public URL |
|---|---|---|---|
| Linked wallet invoice | `wallet` | Recipient mobile client | `/:nym/i/:id` |
| Unlinked wallet invoice | `wallet` | Recipient mobile client | `/invoice/:id` |
| Donation checkout invoice | `checkout` | Anonymous payer from a donation page | `/:nym/i/:id` |

Wallet-origin invoices use recipient-supplied settlement addresses. Checkout
invoices use the donation-page settlement address derived by the server.

## Creation

Wallet-origin invoices are created by signed requests:

- `POST /api/v1/:nym/invoices`
- `POST /api/v1/invoices`

The mobile client supplies accepted rails, amount, metadata, expiry, and
concrete recipient addresses for Bitcoin and/or Liquid. The server validates
the request, creates the invoice, and may create an initial Lightning offer.

## Listing

`GET /api/v1/invoices?npub=...` is signed with `invoice-list`. It returns
linked and unlinked invoices for the owner key. Linked invoices carry
`nym_owner`; unlinked invoices carry `null`.

## Cancellation

Cancellation is signed with `invoice-cancel`. Unpaid invoices can be cancelled.
Terminal invoices are not mutated by cancel requests. Partially paid or
in-progress cancellation policy must remain conservative because payment
evidence may already exist.

## Status

`GET /api/v1/invoices/:id/status` returns public payment state, settlement
state, remaining amount, reusable offers, and direct Bitcoin observations.

Payment status is accounting state:

- `unpaid`
- `in_progress`
- `partially_paid`
- `paid`
- `underpaid`
- `overpaid`
- `expired`
- `cancelled`

Settlement status tracks recipient-side completion for asynchronous rails:

- `none`
- `pending`
- `settled`
- `claim_stuck`
- `refunded`
- `failed`

## Direct Address Settlement

Wallet-origin direct Bitcoin uses a mobile-supplied Bitcoin address and the
Bitcoin watcher.

Wallet-origin direct Liquid uses a mobile-supplied Liquid address and matching
single-address blinding key. The Liquid watcher detects matching outputs and
records idempotent payment events.

Wallet-origin Lightning offers settle to the mobile-supplied Liquid address.
