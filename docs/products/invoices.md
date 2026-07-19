# Invoices

Invoices are recipient-created receivables exposed through signed mobile APIs
and public payment URLs.

## Invoice Types

| Type | Origin | Created by | Public URL |
|---|---|---|---|
| Linked wallet invoice | `wallet` | Recipient mobile client | `/:nym/i/:id` |
| Unlinked wallet invoice | `wallet` | Recipient mobile client | `/invoice/:id` |
| Checkout invoice | `checkout` | Anonymous payer/cashier from Payment Page or POS | `/:nym/i/:id` |

Wallet-origin invoices use recipient-supplied settlement addresses. Checkout
invoices use the selected surface settlement address derived by the server.

## Creation

Wallet-origin invoices are created by signed requests:

- `POST /api/v1/:nym/invoices`
- `POST /api/v1/invoices`

The mobile client supplies accepted rails, amount, expiry, concrete recipient
addresses for Bitcoin and/or Liquid, and one fixed-size encrypted presentation.
Bullnym validates only the opaque envelope framing; payer, payee, and invoice
document fields are decrypted and rendered by the payer browser. The server
creates the invoice and may create an initial Lightning offer.

The server response contains a fragmentless `invoice_url`. Mobile appends its
locally generated viewing key and exposes only the resulting private link
through Copy, Share, and QR. There is no server or wallet-backup recovery path
for that key. See [private invoice presentation v1](../protocols/private-invoice-v1.md).

## Lifetime and quote windows

Every checkout invoice has an exact 30-day outer lifetime. A wallet-origin
invoice also defaults to 30 days when `expires_at_unix` is omitted and may
choose an earlier deadline, but never one beyond 30 days from processing.

The outer invoice deadline is independent of payer instructions. Versioned
fiat quotes expire after exactly five minutes, and BOLT11/provider instructions
may have their own shorter validity. Refreshing or replacing one of those
instructions never extends the invoice's 30-day deadline.

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
