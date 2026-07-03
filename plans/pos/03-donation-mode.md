# Donation Mode PWA

The payer-initiated flow. Someone arrives at `pay.bull-wallet.com/alice`, wants to
send money, chooses an amount, scans a QR. Replaces the current `store_amount.html`
Askama template.

## Route: `/#/`

Single route. The page has two states:

### State 1: Amount entry

```
┌─────────────────────────────────┐
│  [Avatar]  Alice                │
│  Tips appreciated               │
│                                 │
│  ₡ 0                            │
│                                 │
│  [1] [2] [3]                    │
│  [4] [5] [6]                    │
│  [7] [8] [9]                    │
│  [.] [0] [⌫]                    │
│                                 │
│  Currency: [USD ▾]              │
│                                 │
│  [Pay]                          │
│                                 │
│  [🌐 website] [𝕏 twitter]       │
└─────────────────────────────────┘
```

- Keypad identical to POS mode but default state is `0` (no amount yet)
- Currency selector dropdown using `GET /api/v1/supported-currencies`
- "Pay" disabled until amount > 0 and rate available
- Header, description, avatar, social links from the injected config JSON

### State 2: Payment screen (after "Pay")

PWA calls `POST /<nym>/invoice` with `{ amount_sat }` (or fiat amount + currency).
On success, transitions to payment screen — same component as POS mode.

See `05-shared-components.md` for the payment screen spec.

On paid → success screen → "Send another?" → back to amount entry.

## Config injection

Server injects into the HTML shell:

```json
{
  "nym": "alice",
  "mode": "donation",
  "currency": "USD",
  "header": "Alice",
  "description": "Tips appreciated",
  "avatar_url": "/img/abc123.jpg",
  "website": "https://example.com",
  "twitter": "alice",
  "instagram": null
}
```

PWA reads `document.getElementById('bullnym-config').textContent` at boot. No API
call needed for page metadata.

## Rate display

Current rate fetched via `GET /api/v1/supported-currencies` (or a new lightweight
`GET /api/v1/rate?currency=USD` endpoint). Rate refreshes every 60s. "Pay" button
shows a warning if rate is stale (> 5 min old).

## What's different from POS mode

- No persistent transaction history (donation visitors are one-shot)
- No receipt printing
- No Bolt Card
- No PIN gate
- Simpler amount entry (no keypad presets, just free-form)
- Social links displayed
- "Send another" instead of "New sale"

## OG / social meta

Server still injects OG tags in the HTML shell for link previews — same data,
moved from Askama to the shell template:

```html
<meta property="og:title" content="{{ header }}">
<meta property="og:description" content="{{ description }}">
<meta property="og:image" content="{{ og_url }}">
```

These are static in the shell; the PWA doesn't need to touch them.
