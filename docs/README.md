# Bullnym Documentation

This directory documents the current Bullnym system by component and product
feature. Historical test-review material lives under `archive/testing-evidence`
so it does not get confused with the product contract.

## Components

- [Architecture](architecture.md): system boundary, runtime shape, module
  layout, request flow, payment flow, reliability model, and config boundary.
- [HTTP API](components/http-api.md): public routes, signed routes, webhooks,
  request fields, response fields, signing order, and error envelopes.
- [Authentication and Identity](components/auth-identity.md): `npub`,
  `verification_npub`, signed payloads, nyms, and reservation rules.
- [PWA Runtime](components/pwa-runtime.md): Svelte entry points, injected
  config, service-worker caching, and proxy requirements.
- [Payment Rails](components/payment-rails.md): Lightning via Boltz reverse
  swaps, direct Liquid, direct Bitcoin, and Bitcoin-to-Liquid chain swaps.
- [Data Model](components/data-model.md): tables, ownership, descriptor
  cursors, invoices, swaps, payment events, and observations.
- [Background Workers](components/background-workers.md): claimer, reconciler,
  Liquid watcher, Bitcoin watcher, GC, and rate-limit sweeps.

## Features

- [Lightning Address](features/lightning-address.md): LNURL metadata,
  callback behavior, LUD-22 Liquid shortcut, and descriptor allocation.
- [Payment Pages](features/donation-pages.md): Payment Page management,
  public checkout, descriptors, images, and PWA behavior.
- [POS](features/pos.md): POS terminal routes, descriptor isolation, local
  history, offline shell behavior, and payment rails.
- [Invoices](features/invoices.md): wallet-created receivables, linked and
  unlinked routes, payment status, cancellation, and direct-address
  settlement.
- [Rate Limits and Certification](features/rate-limits-certification.md):
  abuse controls, scoped certification, and test harness boundaries.
- [Testing Boundaries](features/testing.md): what local tests, bullnym-test,
  and mobile validation each prove.

## Decisions

- [Decision Repository](decisions/README.md): cross-repository architecture and
  product decisions for Bullnym, Bull Bitcoin Mobile, Get Paid, deterministic
  wallets, Nostr roles, and payment rails.

## Reference

- [Payment Architecture](payment-architecture.md): cross-product payment
  semantics and rail accounting model.
- [Compatibility Ledger](compatibility-ledger.md): compatibility behavior that
  remains intentionally supported.
- [LUD-22 Currency Negotiation](lud-22-currency-negotiation.md): protocol
  extension notes.
- [LUD-22 vs MRH](lud-22-vs-mrh-research.md): rationale for not using Magic
  Routing Hint as the on-chain shortcut.
- [Stuck Swap Runbook](runbook-stuck-swap.md): operator recovery reference.
- [nginx snippet](nginx-bullpay.conf.snippet): reverse-proxy reference for
  donation-page images and route rate limits.
