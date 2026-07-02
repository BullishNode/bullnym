# bullnym POS — Implementation Overview

## What we're building

A Svelte 5 PWA that replaces bullnym's current static Askama-rendered donation page with a
Square-grade payment terminal. The backend stays Rust/Axum/Postgres. The PWA is the only
new thing.

Two modes, one nym, one server:

- **Donation mode** — payer-initiated. Visitor arrives, enters an amount, scans QR, pays.
  Same UX as today but dramatically better.
- **POS mode** — cashier-initiated. Merchant enters amount on a keypad, QR appears,
  customer pays in person. Receipt prints. Transaction history persists locally.

## What does NOT change

- Rust server, all routes, all business logic
- `POST /<nym>/invoice` — the anonymous invoice creation endpoint the PWA calls
- `GET /api/v1/invoices/:id/status` — status polling
- LNURL endpoints (`/.well-known/lnurlp/:nym`, `/lnurlp/callback/:nym`)
- Boltz swap lifecycle (claimer, chain_watcher, reconciler workers)
- Schnorr auth (bullpay-la-v2) for wallet-side management endpoints
- Postgres schema — one additive migration only (see `02-backend.md`)

## Key design decisions

**No client-side signing keys in the PWA.** Invoice creation via `POST /<nym>/invoice` is
already anonymous and rate-limited. The PWA cashier calls it directly, no auth required.
Bull Wallet (native app) handles all signed operations (nym registration, descriptor
binding, page config).

**nostr-pos as UI/UX reference only.** We copy the visual design, component patterns,
UX flows, and print CSS. We do not copy any Nostr, IndexedDB crypto, gift-wrap, or relay
logic — that complexity doesn't exist in our architecture.

**Mode flag in DB.** One new column on `donation_pages`: `pos_mode BOOLEAN NOT NULL DEFAULT
FALSE`. Server reads it and serves either the donation PWA shell or the POS PWA shell.
Same nym, same descriptor, same invoice flow.

## File layout (target)

```
apps/bullnym/
  src/           ← Rust server (unchanged)
  migrations/    ← +1 migration for pos_mode column
  pwa/           ← new Svelte 5 PWA
    apps/
      donation/  ← donation-mode entry point
      pos/       ← POS-mode entry point
    lib/
      api/       ← typed client for bullnym REST endpoints
      components/ ← shared UI: QR, keypad, status, receipt
      stores/    ← Svelte stores: current invoice, history
    package.json
    vite.config.ts
    svelte.config.js
    tailwind.config.ts
```

## Plan documents

- `01-pwa-architecture.md` — PWA tech stack, build, serving strategy
- `02-backend.md` — backend changes (minimal)
- `03-donation-mode.md` — donation-mode PWA spec
- `04-pos-mode.md` — POS-mode PWA spec (keypad, receipt, history)
- `05-shared-components.md` — component specs shared by both modes
- `06-bolt-card.md` — Bolt Card / NFC tap-to-pay
- `07-receipt-printing.md` — print CSS and receipt layout
- `08-implementation-sequence.md` — build order, milestones
