# Receipt Printing

Browser `window.print()` only in v1. No WebUSB, no Web Bluetooth, no ESC/POS.

## Trigger

- From the success screen: "Print Receipt" button
- From history: "Reprint" button on any paid invoice row

Both navigate to `/#/receipt/:id` and call `window.print()`. The receipt route is
a dedicated full-page route with print-optimized layout.

## Receipt content

```
┌────────────────────────────┐  58mm thermal
│      Seguras Butcher       │
│        Counter 1           │
│                            │
│  2026-07-01   14:32        │
│  Receipt #  AB-4821        │
│                            │
│  Note: Mesa 4              │
│  ─────────────────────     │
│  ₡8,500.00                 │
│  ─────────────────────     │
│  0.00010800 BTC            │
│  Rate: ₡78,703,124/BTC     │
│                            │
│  Paid via Lightning        │
│                            │
│  Thanks for your payment!  │
│  pay.bull-wallet.com/alice  │
└────────────────────────────┘
```

Fields:
- Merchant header (from config)
- Terminal name (from config, or "POS" if unset)
- Date/time (local timezone, formatted)
- Receipt number (last 6 chars of invoice ID, dash-separated)
- Note (if any)
- Fiat amount + currency
- Sats amount (8 decimal places)
- Exchange rate used at invoice creation
- Rail (Lightning / Liquid / Bolt Card)
- Footer: nym URL for follow-up payments

## Print CSS

Three layouts via `@media print` + `@page`:

### 58mm thermal

```css
@media print {
  @page { size: 58mm auto; margin: 4mm; }

  body { font-family: monospace; font-size: 11px; color: #000; }

  .receipt-merchant { text-align: center; font-size: 13px; font-weight: bold; }
  .receipt-divider  { border-top: 1px dashed #000; margin: 4px 0; }
  .receipt-amount   { font-size: 18px; font-weight: bold; text-align: center; }
  .receipt-sats     { font-size: 10px; text-align: center; color: #333; }
  .receipt-footer   { font-size: 9px; text-align: center; margin-top: 8px; }

  /* Hide everything except the receipt */
  nav, button, .no-print { display: none !important; }
}
```

### 80mm thermal

```css
@media print {
  @page { size: 80mm auto; margin: 5mm; }
  /* Same as 58mm but slightly larger font */
  body { font-size: 12px; }
  .receipt-amount { font-size: 20px; }
}
```

### A4 fallback

```css
@media print {
  @page { size: A4; margin: 20mm; }
  body { font-size: 12pt; font-family: sans-serif; }
  .receipt-wrapper { max-width: 80mm; margin: 0 auto; border: 1px solid #ccc; padding: 8mm; }
}
```

### Width detection

User selects paper width in settings (default: 80mm). Selected width stored in
localStorage. The receipt route adds a body class (`paper-58` / `paper-80` / `paper-a4`)
and CSS targets the right `@page` block via that class.

Alternatively: detect via `window.matchMedia` on `print` event and apply dynamically.
Keep it simple — a settings dropdown is fine for v1.

## Share

"Share" button uses `navigator.share()` if available, with:

```ts
navigator.share({
  title: `Receipt — ${config.header}`,
  text: `₡${amount} paid via ${rail} on ${date}`,
  url: window.location.href,  // /#/receipt/:id
})
```

Falls back to copy-to-clipboard of the receipt URL if `navigator.share` unavailable.

## Data source

Receipt reads from localStorage (the history store). Does NOT make a server API call
to reprint. This means reprinting works offline, and also means if localStorage is
cleared, old receipts are gone. Acceptable for v1.

If the invoice ID is not in localStorage (e.g., direct navigation to `/#/receipt/:id`),
fall back to `GET /api/v1/invoices/:id/status` to get basic invoice data, then render
a minimal receipt (no note, no rate info if not stored).
