# Shared Components

Components used by both donation mode and POS mode.

## PaymentScreen

The core payment component. Used after invoice creation in both modes.

### Props

```ts
interface PaymentScreenProps {
  invoice: Invoice        // from POST /<nym>/invoice response
  nym: string
  onPaid: (invoice: Invoice) => void
  onExpired: () => void
  onCancel: () => void
  showBoltCard?: boolean  // POS only
}
```

### Layout

```
┌─────────────────────────────────┐
│  ← Back                ₡8,500  │
│                                 │
│  [Lightning] [Liquid] [Tap Card]│
│                                 │
│         ▓▓▓▓▓▓▓▓               │
│         ▓▓ QR ▓▓               │
│         ▓▓▓▓▓▓▓▓               │
│                                 │
│     [📋 Copy]                   │
│                                 │
│  Waiting for payment...         │
│                                 │
│  Expires in 14:32               │
└─────────────────────────────────┘
```

### Rail tabs

- **Lightning**: shows Bolt11 QR from invoice response (`ln_offer` field)
- **Liquid**: shows BIP21 Liquid address QR (`liquid_offer.address` field)
- **Tap Card** (POS only, Android Chrome only): shows NFC prompt (see `06-bolt-card.md`)

Active tab persisted to localStorage per-nym so the cashier's preferred rail is
remembered across sales.

### Status states

Polled via `GET /api/v1/invoices/:id/status` every 3 seconds:

| Server status | Display label |
|---|---|
| `pending` | "Waiting for payment..." |
| `partially_paid` | "Partial payment received. Waiting for remainder..." |
| `paid` / `overpaid` | → trigger `onPaid` callback |
| `expired` | → trigger `onExpired` callback |
| `cancelled` | → trigger `onExpired` callback |

Poller stops on paid/expired/cancelled. Timeout: invoice's own `expires_at` + 30s buffer.

### QR component

```svelte
<!-- lib/components/QrCode.svelte -->
<script lang="ts">
  import QRCode from 'qrcode'
  let { value, size = 240 }: { value: string, size?: number } = $props()
  let canvas: HTMLCanvasElement
  $effect(() => QRCode.toCanvas(canvas, value, { width: size, margin: 1 }))
</script>
<canvas bind:this={canvas} />
```

Error correction level: M. Border: minimal (1 module). Background: white (for camera
contrast regardless of dark mode).

## SuccessScreen

Shown after `onPaid` fires.

```
┌─────────────────────────────────┐
│                                 │
│           ✅  Paid              │
│                                 │
│           ₡8,500                │
│        via Lightning            │
│                                 │
│      [🖨 Print Receipt]         │
│                                 │
│        [New Sale]               │
└─────────────────────────────────┘
```

- Confetti on mount (`canvas-confetti`)
- Success sound on mount (short chime, respects `prefers-reduced-motion`)
- Haptic on mount (`navigator.vibrate([200])` if available)
- "Print Receipt" → navigate to `/#/receipt/:id` and trigger `window.print()`
- "New Sale" / "Send another" → `onDismiss` callback

## AmountDisplay

Large formatted amount display used on keypad and payment screens.

```svelte
<!-- lib/components/AmountDisplay.svelte -->
<!-- Formats 8500 CRC as "₡8,500", 1234 USD as "$12.34" -->
```

Currency formatting: `Intl.NumberFormat` with locale-aware grouping. Minor-unit
handling per currency (CRC, CLP, JPY: integer; USD, EUR, CAD: two decimal places).

## RateBar

Small status bar showing current exchange rate and freshness.

```
Rate: ₡78,703,124/BTC  (updated 12s ago)
```

Shown on keypad screen. Turns amber if rate is 2–5 min old. "Charge" disables if
rate is > 5 min old with message "Rate unavailable — try again."

## ApiClient

Typed wrapper around `fetch`. No dependencies.

```ts
// lib/api/client.ts

export interface CreateInvoiceRequest {
  amount_sat?: number
  fiat_amount_minor?: number
  fiat_currency?: string
  note?: string
}

export interface Invoice {
  id: string
  nym: string
  amount_sat: number
  fiat_amount_minor: number | null
  fiat_currency: string | null
  status: 'pending' | 'partially_paid' | 'paid' | 'overpaid' | 'expired' | 'cancelled'
  ln_offer: string | null        // Bolt11
  liquid_offer: { address: string } | null
  expires_at: string             // ISO 8601
  paid_at: string | null
  paid_via: 'lightning' | 'liquid' | null
}

export async function createInvoice(nym: string, req: CreateInvoiceRequest): Promise<Invoice> {
  const res = await fetch(`/${nym}/invoice`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
  if (!res.ok) throw new ApiError(res.status, await res.text())
  return res.json()
}

export async function getInvoiceStatus(id: string): Promise<Invoice> {
  const res = await fetch(`/api/v1/invoices/${id}/status`)
  if (!res.ok) throw new ApiError(res.status, await res.text())
  return res.json()
}

export async function getSupportedCurrencies(): Promise<Currency[]> {
  const res = await fetch('/api/v1/supported-currencies')
  if (!res.ok) throw new ApiError(res.status, await res.text())
  return res.json()
}
```

## Design tokens (from nostr-pos)

```css
/* Lifted from nostr-pos's design system */
:root {
  --bg:      #0E0E0E;
  --fg:      #F5F5F5;
  --accent:  #F7931A;   /* Bitcoin orange */
  --muted:   #888888;
  --card:    #1A1A1A;
  --border:  #2A2A2A;
  --success: #22C55E;
  --error:   #EF4444;
  --radius:  12px;
}
```

Tailwind config extends these as custom colors so components use `bg-card`,
`text-accent`, etc.
