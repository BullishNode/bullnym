# POS Mode PWA

The cashier-initiated flow. Merchant has a tablet at the counter. Cashier enters an
amount, customer scans QR or taps Bolt Card, payment completes, receipt prints.

## Routes

```
/#/          → keypad (main cashier screen)
/#/pay/:id   → payment screen for invoice :id
/#/receipt/:id → receipt for paid invoice :id
/#/history   → transaction history sheet
/#/settings  → settings (PIN-gated)
```

## Keypad screen (`/#/`)

```
┌─────────────────────────────────┐
│  Seguras Butcher        [≡ Menu]│
│                                 │
│  ₡ 0                            │
│                                 │
│  [1] [2] [3]                    │
│  [4] [5] [6]                    │
│  [7] [8] [9]                    │
│  [00] [0] [⌫]                   │
│                                 │
│  [Add note]                     │
│                                 │
│  [Charge]                       │
│                                 │
│  Recent Transactions ▴          │
└─────────────────────────────────┘
```

- Amount display: large, clear, formatted in display currency
- Keypad: `1–9`, `00`, `0`, `⌫`. No decimal entry for CRC/whole-unit currencies;
  decimal enabled for USD/CAD/EUR (two decimal places)
- "Add note": optional text field (stored locally with the invoice record)
- "Charge": disabled until amount > 0 and rate is fresh (< 5 min)
- Recent Transactions: pull-up sheet handle (see history section)
- [≡ Menu]: PIN-gated settings

## Charging flow

1. Cashier presses "Charge"
2. PWA calls `POST /<nym>/invoice` with amount
3. Navigate to `/#/pay/:id` with the invoice response
4. Show QR and status

## Payment screen (`/#/pay/:id`)

See `05-shared-components.md` — shared with donation mode.

On paid:
1. Navigate to `/#/receipt/:id`
2. Save to localStorage history
3. Play success sound + confetti + haptic

"New sale" button → back to `/#/`

## Receipt screen (`/#/receipt/:id`)

```
┌─────────────────────────────────┐
│         Seguras Butcher         │
│           Counter 1             │
│                                 │
│  ₡8,500                         │
│  0.00010800 BTC                 │
│  Rate: ₡78,703,124/BTC          │
│                                 │
│  Paid via: Lightning            │
│  2026-07-01  14:32              │
│                                 │
│  Note: Mesa 4                   │
│                                 │
│  [🖨 Print]  [↗ Share]          │
│                                 │
│  [New Sale]                     │
└─────────────────────────────────┘
```

Fields:
- Merchant header (from config)
- Fiat amount + currency
- Sats amount
- Exchange rate used (from invoice response)
- Rail (Lightning / Liquid / Bolt Card)
- Timestamp
- Note (if any)
- Print and Share CTAs
- New Sale

Receipt data stored in localStorage alongside invoice record so reprinting works
from history without a server round-trip.

## Transaction history (`/#/history`)

Pull-up sheet accessible from the keypad screen. Also a full-page route for
navigation from the receipt screen.

```
Recent Transactions
───────────────────────────────────
14:32  ₡8,500   ✓ Paid     Lightning
14:18  ₡2,000   ✓ Paid     Liquid
13:55  ₡3,300   ✗ Expired  Lightning
13:44  ₡1,200   ✓ Paid     Bolt Card
```

- Source: localStorage, keyed by nym
- Stored fields per record: `id`, `amount_fiat`, `currency`, `amount_sat`, `rail`,
  `status`, `paid_at`, `note`, `rate_used`
- Tap row → receipt screen for that invoice (if paid) or status (if pending)
- Renders within 100ms from localStorage (no API call on open)
- Max 200 records kept; oldest pruned on write

## Settings screen (`/#/settings`) — PIN-gated

PIN gate: 4-digit PIN stored in `localStorage` as bcrypt hash (or scrypt — keep it
simple; this is a local-only check, not server auth). If no PIN set, settings are
unlocked with a single tap confirmation.

Settings contents:
- Display currency selector
- "About this terminal" (nym, server domain)
- "Clear history" (with confirmation)
- Bolt Card toggle (show/hide NFC tab on payment screen)
- "Reset terminal" (clears all localStorage)

No relay config, no descriptor, no Nostr — none of that exists here.

## State management

Three Svelte stores:

```ts
// stores/config.ts
// Read from injected JSON at boot, immutable
export const config = readable<BullnymConfig>(parseConfig())

// stores/invoice.ts
// Current in-flight invoice; cleared on paid/cancelled
export const currentInvoice = writable<Invoice | null>(null)

// stores/history.ts
// localStorage-backed, reactive
export const history = localStorageStore<HistoryRecord[]>('bullnym:history:' + nym, [])
```

No IndexedDB, no encryption, no key material. Just plain localStorage.
