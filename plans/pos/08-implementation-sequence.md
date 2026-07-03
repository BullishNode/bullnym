# Implementation Sequence

Build in this order. Each milestone is independently testable.

## Milestone 1: PWA scaffold + donation mode (1–2 days)

Goal: replace the current Askama HTML template with a working Svelte 5 PWA for
donation mode. Feature-parity with today, much better UX.

Steps:
1. Init `pwa/` workspace: `npm create vite@latest pwa -- --template svelte-ts`
2. Add Tailwind, vite-plugin-pwa, svelte-spa-router
3. Add design tokens (colors, radius) from nostr-pos
4. Implement `AmountDisplay` component
5. Implement `QrCode` component
6. Implement `ApiClient` (`createInvoice`, `getInvoiceStatus`, `getSupportedCurrencies`)
7. Implement `PaymentScreen` component with Lightning + Liquid tabs and status polling
8. Implement `SuccessScreen` component (confetti, sound)
9. Wire donation mode entry point: amount keypad → payment screen → success
10. Add config injection to Rust `donation_render.rs` (replace Askama render)
11. Add `ServeDir` for PWA static assets in `main.rs`
12. Test end-to-end on dev server against live bullnym

Deliverable: `pay.bull-wallet.com/<nym>` loads the new PWA donation page.

## Milestone 2: POS mode scaffold + DB migration (1 day)

Goal: `pos_mode = true` nyms get the POS keypad shell.

Steps:
1. Migration `0032_pos_mode.sql` — add `pos_mode` column
2. Update `UpsertDonationPage` struct + SQL
3. Update `PUT /donation-page/:nym` handler to accept `pos_mode`
4. Add `pos_mode` to bullpay-la-v2 signed field list
5. Implement POS entry point: `/#/` keypad screen
6. Wire keypad → `createInvoice` → navigate to shared `PaymentScreen`
7. Test with `pos_mode = true` nym on dev server

Deliverable: POS keypad works, creates invoices, shows QR.

## Milestone 3: Transaction history + receipt (1–2 days)

Goal: cashier can see recent transactions and print receipts.

Steps:
1. Implement `localStorageStore` for history (keyed by nym)
2. Write history record on invoice paid
3. Implement `/#/history` sheet — list of recent transactions
4. Implement `/#/receipt/:id` route and receipt layout
5. Add print CSS (58mm + 80mm + A4 via body class from settings)
6. Add "Print" and "Share" buttons
7. Add "Reprint" from history row
8. Test print on physical 80mm thermal via browser dialog

Deliverable: Full sale → paid → receipt print works.

## Milestone 4: Bolt Card (1 day)

Goal: third "Tap Card" tab on payment screen, NFC works on Android Chrome.

Steps:
1. Implement `lib/bolt-card/reader.ts` (Web NFC + LNURL-withdraw client)
2. Add "Tap Card" tab to `PaymentScreen` (hidden if `!navigator.nfc`)
3. Wire NFC read → LNURL fetch → invoice submission → status polling
4. Add Bolt Card toggle to settings (disable tab if turned off)
5. Test on Android Chrome with a real Bolt Card

Deliverable: Bolt Card tap-to-pay works on Android Chrome.

## Milestone 5: Settings + PIN gate (0.5 days)

Goal: cashier settings are PIN-protected.

Steps:
1. Implement `/#/settings` route
2. Implement PIN setup flow (first entry = set PIN, hash to localStorage)
3. Implement PIN challenge gate for settings access
4. Settings: display currency, paper size, Bolt Card toggle, clear history, reset
5. "About" screen: nym, server domain, version

Deliverable: Settings gated by PIN, currency and paper size configurable.

## Milestone 6: PWA install + offline shell (0.5 days)

Goal: PWA installs on Android, opens offline (but fails payment gracefully).

Steps:
1. Configure `vite-plugin-pwa` manifest: name, icons, theme_color, display: standalone
2. Ensure app shell pre-cached, API calls network-first (no cache)
3. Add "Server unreachable" error state on `createInvoice` failure
4. Test install on Android Chrome
5. Test offline open (app loads, "Charge" shows server error, doesn't crash)

Deliverable: PWA installable, works offline for UI, fails gracefully on network.

## Milestone 7: Polish pass (1 day)

- Haptics (`navigator.vibrate`) on paid
- Success sound (short chime, `AudioContext`, respects `prefers-reduced-motion`)
- Confetti tuning (burst direction, colors)
- Dark mode (already in design tokens, ensure system preference respected)
- Loading skeletons instead of blank states
- Error handling polish (rate limit messages, server errors, expired invoice)
- Mobile viewport testing (iPad, Android tablet, phone portrait/landscape)
- Accessibility pass: focus management, tap target sizes ≥ 48px

## Total estimate

| Milestone | Days |
|---|---|
| 1 — Donation PWA | 1–2 |
| 2 — POS scaffold | 1 |
| 3 — History + receipt | 1–2 |
| 4 — Bolt Card | 1 |
| 5 — Settings + PIN | 0.5 |
| 6 — PWA install | 0.5 |
| 7 — Polish | 1 |
| **Total** | **6–8 days** |

## What comes after (v1.1)

- Full transaction history backed by server (signed endpoint, Bull Wallet auth)
- Covenant mode for Lightning swaps (remove server-side claim race)
- Lightning Address UI in Bull Wallet (nym setup, descriptor binding)
- Product catalog / line items
- Multi-currency fiat display
- WebUSB ESC/POS printer driver
