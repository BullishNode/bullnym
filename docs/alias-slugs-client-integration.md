# Alias slugs — client integration guide

Merchant-chosen slugs let a donation-page surface be served at `/a/<slug>`,
decoupled from the `nym` that anchors the merchant's Lightning Address. The
public link and the served page never expose the nym. A merchant may pick a
different slug for each surface (Payment Page vs PoS).

This guide is the contract a client (mobile editor, web, etc.) implements. The
server change is additive and backward-compatible: a client that never sends an
alias keeps working unchanged.

Related: [`compatibility-ledger.md`](compatibility-ledger.md) (Donation Page
Alias entry).

---

## 1. Signed save payload — the exact byte layout

`alias` is a new **optional trailing signed field** on `PUT /donation-page`.
The Schnorr signature will fail to verify if the byte layout is wrong, so this
is the make-or-break part.

The signed message is `SHA-256`-digested and signed BIP340/Schnorr with the
nym's Nostr key. `\0` is a NUL byte. There is **no trailing NUL** after the
timestamp:

```
bullpay-la-v2\0donation-page-save\0<npub_hex>\0<nym>\0<f1>\0<f2>\0…\0<fN>\0<timestamp>
```

`<npub_hex>` and `<nym>` occupy dedicated slots (they are NOT part of the
`f1..fN` field list). The fields, in this exact order:

| # | field | rule |
|---|-------|------|
| 1 | `header` | always |
| 2 | `description` | always (may be `""` — description is optional) |
| 3 | `display_currency` | always |
| 4 | `website` | `""` when not set |
| 5 | `twitter` | `""` when not set |
| 6 | `instagram` | `""` when not set |
| 7 | `enabled` | `"1"` or `"0"` |
| 8 | `pos_mode` | **only if the JSON key is present** (`"1"`/`"0"`) |
| 9 | `ct_descriptor` | **only if the JSON key is present** |
| 10 | `kind` | **only if the JSON key is present** (`"payment_page"`/`"pos"`) |
| 11 | **`alias`** | **only if the JSON key is present** — MUST be last |

**Iron rule:** a field appears in the signed list **if and only if** its key is
present in the request JSON. If you send `alias` in the body you must append it
(last, after `kind`) to the signed fields; if you omit it from the body, do not
sign it. This is the same append-only-terminal maneuver as `pos_mode`,
`ct_descriptor`, and `kind`, so signatures from clients that predate `alias`
stay valid.

Server reference: `src/donation_page.rs::save_payload_fields`, and the
byte-exact contract tests in `src/donation_page/tests.rs`.

## 2. Request

`PUT /donation-page`, `Content-Type: application/json`:

```json
{
  "nym": "alice",
  "npub": "<64-hex x-only pubkey>",
  "header": "Alice's Shop",
  "description": "",
  "display_currency": "USD",
  "kind": "payment_page",
  "ct_descriptor": "<required only when kind=pos>",
  "alias": "alices-shop",
  "timestamp": 1700000000,
  "signature": "<hex schnorr sig over the message in §1>"
}
```

`alias` is **tri-state**:

- **omit the `alias` key** → leave the stored alias unchanged (and do not sign it).
- `"alias": ""` → **clear** the slug (sign `""` as the terminal field).
- `"alias": "myslug"` → **claim / change** (sign `"myslug"`).

A different slug per surface: issue one save with `kind:"payment_page"` + its
alias, and another with `kind:"pos"` + its alias.

## 3. Slug rules

Enforced server-side; mirror them client-side for immediate feedback.

- Charset: `^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,30}[a-z0-9])$` — 1–32 chars,
  lowercase letters, digits, hyphens, no leading or trailing hyphen (identical
  to the nym rules).
- Reserved (rejected): `0`, `1`, `pos`, `a`, the brand names `bull`,
  `bullbitcoin`, `bull-bitcoin`, `bullpay`, `bullnym`, `bitcoin`, and all
  reserved route slugs.
- Aliases are **globally unique** across all merchants and surfaces.

## 4. Responses

**200 OK** → `DonationPageView`. Use `public_url` as the share link — it is
`https://<domain>/a/<slug>` when a slug is set, otherwise the nym path:

```json
{
  "nym": "alice",
  "kind": "payment_page",
  "alias": "alices-shop",
  "public_url": "https://pay2.bull-wallet.com/a/alices-shop"
}
```

**409 Conflict**, body:

```json
{ "status": "ERROR", "code": "AliasTaken",
  "reason": "This link name is already taken. Choose a different one." }
```

→ the slug is taken by another surface. Prompt for a different one (a suffix
usually works).

**200 + LNURL error envelope**:

```json
{ "status": "ERROR", "code": "DonationPageInvalid", "reason": "…" }
```

→ invalid charset or reserved slug. Note that this API returns **HTTP 200 with
an error envelope** for most validation failures (LNURL/LUD-06 convention);
`AliasTaken` is one of the few that is a real non-200. A client's envelope
parser must handle a non-200 status on this endpoint.

## 5. Reading current state & sharing

- Pre-fill the editor: `GET /donation-page/<nym>?kind=<payment_page|pos>`
  returns the same `DonationPageView`, including `alias` and `public_url`.
- Share `public_url`. The page at `/a/<slug>` is a self-contained PWA (donation
  or PoS shell) served by the server — the client shares the link; there is
  nothing to render client-side.

## 6. Rollout / version skew

The server tolerates an absent alias indefinitely, so this can ship
independently of any coordinated release. The only hard requirement is §1:
never send `alias` in the JSON without signing it as the terminal field, and
never sign it without sending it.

## 7. Scope & honest UX copy

A readable slug decouples the public link from the nym and scrubs the nym from
the served page and from the payment payloads (bolt11 description and BIP21
`message=`). It is **not** anonymity: a readable slug is guessable and
enumerable, so treat it as branding. The Lightning Address is unchanged
(`nym@domain`). Do not present the slug as "anonymous."

## 8. Consuming the served page (web clients only)

The mobile editor does not need this — it applies only to a client that renders
the served surface (the bundled PWA already does). The server-injected
`bullnym-config` block now carries:

- `invoice_base` — POST checkout invoices to `<invoice_base>/invoice` and
  navigate to `<invoice_base>/i/<id>`; do not compose these from the nym.
- `page_key` — the namespace for client-side storage (settings, history, PIN).
- `nym` — **omitted entirely on alias pages** (present on nym pages for
  installed-PWA back-compat). Never derive URLs or storage keys from it.

Server reference: `src/donation_render.rs` (`PublicBase`, `render_live`).
