# POS

POS is a public terminal surface at `https://<domain>/<nym>/pos`. It uses the
same payment-session engine as Payment Pages, but it has a separate
`donation_pages` row with `kind = 'pos'`.

## Surface Contract

| Item | Value |
|---|---|
| Public shell | `GET /:nym/pos` |
| Manifest | `GET /:nym/pos/manifest.webmanifest` |
| Invoice creation | `POST /:nym/pos/invoice` |
| Surface row | `donation_pages(nym, kind = 'pos')` |
| Settlement descriptor | POS `ct_descriptor` |

The POS row requires `ct_descriptor`. It does not fall back to the Lightning
Address descriptor. This keeps POS receipts separate from Lightning Address and
Payment Page receive paths.

## Checkout Flow

1. Cashier opens or installs `/:nym/pos`.
2. The PWA reads injected `bullnym-config`.
3. Cashier enters an amount.
4. The PWA calls `POST /:nym/pos/invoice`.
5. Bullnym creates an `origin = 'checkout'` invoice using the POS descriptor
   and cursor.
6. The payment screen polls `/api/v1/invoices/:id/status`.
7. Paid and overpaid terminal states can be stored in local POS history and
   printed as browser receipts.

The server database is the accounting source of truth. POS history is local
browser state and can be cleared or lost without mutating invoices.

## Local Controls

The POS PWA includes local settings for currency, receipt paper size, Bolt
Card visibility, local history clearing, and terminal reset. The PIN gate
protects local settings on the device only; it is not server authentication.

## Offline Behavior

The service worker can reopen a previously visited POS shell offline. Payment
actions remain network-dependent:

- invoice creation
- Lightning offer refresh
- status polling
- chain-swap recovery
- supported-currency and rate fetches

Offline terminals should show the shell but fail payment actions cleanly until
network access returns.

## Payment Rails

POS checkout exposes the same customer-facing rails as Payment Pages when the
server can create the payloads:

- Lightning via Boltz reverse swap
- Direct Liquid
- Bitcoin via BTC-to-LBTC Boltz chain swap

The Bitcoin tab may use `bitcoin_chain_address` even when `accept_btc` is
false, because chain-swap Bitcoin is distinct from wallet-origin direct
Bitcoin invoices.
