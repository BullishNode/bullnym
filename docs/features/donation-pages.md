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

The row stores display text, display currency, links, enabled/archive state,
legacy image hashes, a server-generated social-card key, an optional Liquid CT
descriptor, and an independent address cursor.

## Social previews

Each Payment Page save pre-publishes a deterministic 1200×630 JPEG containing
the official Bull Bitcoin logo, the Page title, and its short description. No
other merchant data is rendered into the image. The URL is immutable and
content-addressed under `/img/og/v<template-version>/<key>.jpg`; identical
content is reused. A template upgrade keeps advertising the last valid stored
version until its replacement has been published.

Rendering failure never fails the Page save. The Page instead advertises a
permanent branded fallback and the bounded background reconciler retries. The
public Page GET only reads the stored key and cached pricing state: it performs
no image generation and no live Pricer HTTP call. Archived Pages advertise a
fixed branded unavailable card.

Generated files are durable application data, not a disposable build artifact.
Every Bullnym host must use a persistent image volume; horizontally scaled
hosts either share that volume/object store or let each host's verification
sweep materialize its own copy. Public rendering verifies a stored path before
advertising it and falls back to the branded card when the file is absent. The
worker periodically verifies current references and regenerates missing files.

Immutable cards are retained indefinitely so already-shared social posts do not
lose their image. Operators must monitor and provision the image volume for
that retention policy; larger deployments should place `/img/og` on durable
storage and plan an object-storage/CDN-backed implementation rather than
applying an age-based deletion policy. The current renderer writes through a
filesystem path and therefore requires a mounted/shared filesystem abstraction.

Open Graph and Twitter metadata is present in the initial PWA/fallback HTML.
Page HTML sends `X-Robots-Tag: noindex, nofollow, noarchive`; `robots.txt`
allows the Page fetch so link-preview crawlers can see that metadata.

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
2. Server returns the Payment Page PWA shell with injected config.
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
