# 001 Product and Feature Boundaries

Status: Accepted

## Decision

Bullnym is the server-side payment and identity service. Bull Bitcoin Mobile
owns the wallet UX, local wallet creation, seed recovery, and product screens.
Get Paid is the mobile product shell that coordinates Lightning Address,
Payment Page, Invoices, and BTCPay without absorbing their implementation
boundaries.

Mobile feature boundaries:

- `features/bullnym` owns the Bullnym HTTP client, DTOs, signing helpers,
  constants, and transport errors.
- `features/get_paid` owns the dashboard shell, Get Paid settings, and routing
  into Get Paid sub-features.
- `features/lightning_address` owns Lightning Address product state and NIP-05
  profile behavior.
- `features/get_paid/payment_page` owns the payment-page editor and
  page-management use cases.
- `features/get_paid/invoices` owns invoice list/create/detail routes.
- `features/get_paid/btcpay` owns SamRock URL parsing, local wallet
  preparation, and server pairing state.
- `features/external_receive_wallets` owns shared external receive wallet
  lifecycle primitives.
- `features/wallet_manifest` owns neutral deterministic wallet recovery and
  encrypted manifest publish/fetch.
- `features/nostr_identity` owns Bull's reserved Nostr role mapping.

Server boundaries:

- Bullnym stores identity, descriptors, invoices, swaps, payment observations,
  donation pages, and rate-limit state.
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
- Wallet manifest restore must not call `external_receive_wallets`, because
  that would create a feature cycle.
- Get Paid can orchestrate dashboard state and settings, but feature-specific
  server pairing, page editing, invoice state, and Lightning Address actions
  stay in their owning sub-features.
- Architecture docs should describe current component contracts, not testing
  history.
