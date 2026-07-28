# 001 Product and Feature Boundaries

- Status: Accepted
- Amended: 2026-07-28 — mobile boundary map updated to the shipping feature
  layout (#274)
- Scope: Cross-repository; verify mobile paths against `bullbitcoin-mobile`

## Decision

Bullnym is the server-side payment and identity service. Bull Bitcoin Mobile
owns the wallet UX, local wallet creation, seed recovery, and product screens.
Get Paid is the mobile product shell that coordinates Lightning Address,
Payment Page, POS, Invoices, and BTCPay without absorbing their implementation
boundaries.

Mobile feature boundaries (all top-level under `lib/features/`):

- `features/bullnym` owns the Bullnym HTTP client, DTOs, signing helpers,
  constants, and transport errors.
- `features/get_paid` owns the dashboard shell and routing into Get Paid
  products; `features/get_paid_settings` owns the Get Paid settings screens.
- `features/lightning_address` owns Lightning Address product state and NIP-05
  profile behavior.
- `features/payment_page` owns the payment-page editor and page-management
  use cases.
- `features/invoices` owns invoice list/create/detail routes.
- `features/pos` owns POS product state and its reserved wallet preparation.
- `features/btcpay` owns SamRock URL parsing, local wallet preparation, and
  server pairing state; its entry point is Bitcoin Settings.
- `features/deterministic_wallets` owns shared BIP85 child-wallet
  materialization primitives; `features/bip85_registry` owns reserved
  derivation-path policy.
- `features/keychain_manifest`, `features/keychain_recovery`, and
  `features/wallet_backup` own deterministic wallet-inventory recovery and
  encrypted backup publish/fetch (see ADR 003).
- `features/nostr_identity` owns Bull's reserved Nostr role mapping.

Server boundaries:

- Bullnym stores identity, descriptors, invoices, swaps, payment observations,
  public surface rows, and rate-limit state.
- Bullnym derives server-side receive addresses only from descriptors supplied
  by the mobile wallet.
- Bullnym does not own the user's seed, wallet manifest, local wallet inventory,
  or mobile recovery flow.

## Rationale

The Get Paid feature set started as product-specific exceptions: Lightning
Address needed a Liquid receive wallet, Payment Page needed a page descriptor,
Invoices needed fresh wallet-owned addresses, and BTCPay needed server pairing.
Keeping those as separate one-off implementations would duplicate descriptor,
wallet ownership, signing, and recovery rules.

The accepted boundary separates product UX from shared deterministic-wallet
infrastructure. Product features consume shared facades; shared infrastructure
does not import product flows.

## Consequences

- Product screens must not duplicate Bullnym wire logic.
- Keychain-manifest restore must not import product features; wallet creation
  flows through `deterministic_wallets`, so restore cannot create a feature
  cycle.
- Get Paid can orchestrate dashboard state and settings, but feature-specific
  server pairing, page editing, invoice state, and Lightning Address actions
  stay in their owning features.
- Architecture docs should describe current component contracts, not testing
  history.
