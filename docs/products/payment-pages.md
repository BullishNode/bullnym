# Payment Pages

Payment Pages are public Get Paid pages at `https://<domain>/<nym>`. A payer
enters an amount and receives Lightning, Liquid, and eligible Bitcoin payment
instructions.

The backing table is still named `donation_pages`. The current surface kind is
`payment_page`.

## Ownership

A Payment Page belongs to a nym and is managed by the same `npub` that owns the
nym. Management actions use:

- `donation-page-save`
- `donation-page-archive`

The row stores display text, display currency, links, enabled/archive state, an
optional Liquid CT descriptor, an independent address cursor, and the current
generated social-card key/template version. Legacy media hashes may be returned
for old rows, but Bullnym no longer accepts image uploads and clients must treat
those fields as read-only compatibility data.

## Social previews

Every live Payment Page publishes complete Open Graph and Twitter large-card
metadata. Bullnym renders a 1200×630 JPEG when the Page is saved; the only
merchant-specific elements are the Page title and short description, while the
Bull Bitcoin logo and visual frame are fixed in every generated image.

New clients use the short-description contract defined by the
[Payment Page API](../api/payment-pages-and-pos.md). Older requests that omit
`kind` retain their compatible wire contract and are safely truncated in
metadata and generated cards.

Generated files are immutable and content-addressed under
`/img/og/v<template-version>/<content-key>.jpg`. Rendering never occurs on a
public Page GET. Save-time generation has a short timeout; permanent branded
fallback images keep previews valid on failure, and the background worker
backfills old rows, retries failures with durable backoff, and repairs missing
host-local files. Page responses are `noindex` but remain fetchable by social
link-preview crawlers.

## Descriptor Use

Current clients save a Payment Page `ct_descriptor`. Checkout derives the
session Liquid address from this descriptor and advances
`donation_pages.next_addr_idx`.

Legacy Payment Pages without a descriptor fall back to the nym's Lightning
Address descriptor and cursor. POS does not have this fallback.

Rendering `GET /:nym` does not allocate a Liquid address. Allocation happens
when the payer creates a checkout invoice with `POST /:nym/invoice`.

Each checkout invoice gets one Liquid settlement address. All Payment Page
rails settle to that address:

- Lightning reverse swaps claim LBTC to it.
- Direct Liquid pays it.
- Bitcoin chain swaps claim LBTC to it.

## Flow

1. Payer opens `GET /:nym`.
2. Server returns the Payment Page PWA shell with injected config and complete
   social-preview metadata.
3. Payer submits an amount to `POST /:nym/invoice`.
4. Bullnym creates an `origin = 'checkout'` invoice and allocates one Liquid
   settlement address.
5. The PWA navigates to `/#/pay/:id` and polls
   `/api/v1/invoices/:id/status`.

The public payment page for a linked checkout remains `GET /:nym/i/:id`.

## Payment Rails

| Rail | Payer sees | Recipient settlement |
|---|---|---|
| Lightning | BOLT11 offer | LBTC claimed from Boltz reverse swap to the checkout Liquid address. |
| Liquid | Liquid address | Direct LBTC to the checkout Liquid address. |
| Bitcoin | Boltz BTC lockup address | LBTC claimed from the chain swap to the checkout Liquid address. |

Payment Page Bitcoin is a BTC-to-LBTC Boltz chain swap. It is not direct
Bitcoin invoice settlement.

## Archiving

Archiving disables new Payment Page sessions. Existing checkout invoices keep
their stored settlement addresses and expire or settle under invoice rules.
