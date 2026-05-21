# Donation Pages

Donation Pages are public Get Paid pages at `https://<domain>/<nym>`. A payer
enters an amount and receives a payment page with Lightning, Liquid, and
Bitcoin payment instructions.

## Page Ownership

A donation page belongs to a nym and is managed by the same `npub` that owns
the nym. Management actions are signed with `donation-page-*` actions.

The page stores:

- display text and links
- display currency
- enabled/archive state
- avatar and OpenGraph image hashes
- optional Get Paid CT descriptor
- independent address cursor for page checkout

## Descriptor Use

Current clients should save a page-specific `ct_descriptor`. Checkout derives
the session Liquid address from this descriptor and advances
`donation_pages.next_addr_idx`.

Legacy pages without a page descriptor fall back to the nym Lightning Address
descriptor and cursor.

Opening or rendering the donation page does not allocate a Liquid address and
does not advance the descriptor cursor. Allocation happens when the payer
submits an amount and creates a checkout invoice with `POST /:nym/invoice`.
That checkout invoice gets one Liquid settlement address up front because all
customer-facing rails settle to the same Liquid destination:

- Lightning reverse swaps claim to it.
- Direct Liquid pays it.
- Bitcoin chain swaps claim LBTC to it.

The current implementation does not wait for a later Liquid-specific click
before deriving that checkout settlement address. The anti-abuse boundary for
this cursor is therefore checkout-invoice creation rate limiting, not donation
page HTML rendering.

## Checkout Flow

1. Payer opens `GET /:nym`.
2. The rendered page fetches fiat rate data if needed.
3. Payer submits an amount to `POST /:nym/invoice`.
4. Bullnym allocates one Liquid settlement address and creates an
   `origin = 'checkout'` invoice.
5. Bullnym renders `GET /:nym/i/:id`.
6. The payment page exposes Lightning, Liquid, and eligible Bitcoin options.
7. The page polls `/api/v1/invoices/:id/status`.

## Payment Rails

| Rail | Payer sees | Recipient settlement |
|---|---|---|
| Lightning | BOLT11 offer | LBTC claimed from Boltz reverse swap to the checkout Liquid address. |
| Liquid | Liquid address | Direct LBTC to the checkout Liquid address. |
| Bitcoin | Boltz lockup address | LBTC claimed from chain swap to the checkout Liquid address. |

Donation-page Bitcoin is a BTC-to-LBTC chain swap. It is not the same as
direct Bitcoin invoices.

## Images

`POST /donation-page/image` accepts signed multipart uploads for avatar and
OpenGraph images. The server normalizes images to WebP and stores hashes on
the page row. nginx can serve normalized files directly from disk.

## Archiving

Archiving disables new page sessions but does not mutate existing checkout
invoices. Existing sessions expire or settle according to invoice rules.
