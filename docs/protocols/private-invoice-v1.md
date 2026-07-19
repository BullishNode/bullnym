# Private invoice presentation v1

Private invoice presentation v1 is used only by native merchant invoices
created in Bull Bitcoin Mobile. Mobile encrypts the presentation before the
create request. Bullnym stores and returns one fixed-size opaque envelope; it
never receives the viewing key or presentation plaintext.

Donation, Payment Page, POS, and Lightning Address checkout are outside this
protocol.

## Threat model

Bullnym is assumed to serve the documented browser code honestly. Encryption
protects presentation fields from database access, backups, database-only
compromise, server-side search, logs, analytics, and support tooling. An active
Bullnym deployment that replaces the browser JavaScript is outside the threat
model.

There is no recovery protocol. A wallet may retain the complete private link
on its current device, but the server stores no recovery capsule or
wallet-derived key material.

## Presentation schema

The decrypted UTF-8 JSON object has this shape:

```json
{
  "schema": "bullnym-private-invoice",
  "version": 1,
  "payer": {
    "name": "Jane Smith",
    "corporate_name": "Example Corporation",
    "address": "123 Main Street\nMontréal, QC",
    "email": "jane@example.com",
    "phone": "+1 514 555 0100"
  },
  "invoice": {
    "description": "Website design services",
    "number": "INV-2026-0042",
    "purchase_order_reference": "PO-9182",
    "invoice_date": "2026-07-18",
    "payment_deadline": "2026-08-18"
  },
  "payee": {
    "name": "John Merchant",
    "corporate_name": "Merchant Studio Inc."
  }
}
```

`schema` and `version` are required. Every section and every field inside a
section is optional. Empty strings and empty sections are omitted. Unknown
fields are rejected by the payer browser.

The complete compact JSON encoding must be between 1 and 4094 UTF-8 bytes so
it fits after the two-byte length prefix. Field limits are enforced before
this aggregate encoding limit; JSON escaping counts toward the aggregate.

`invoice_date` and `payment_deadline` are valid Gregorian dates encoded as
`YYYY-MM-DD`. The payment deadline is informational only. It does not modify
Bullnym's technical invoice lifetime, quote lifetime, payment status, or rail
availability.

Maximum UTF-8 byte lengths:

| Field | Maximum |
|---|---:|
| payer/payee `name` | 120 |
| payer/payee `corporate_name` | 160 |
| payer/payee `address` | 500 |
| payer/payee `email` | 254 |
| payer/payee `phone` | 64 |
| invoice `description` | 1000 |
| invoice `number` | 128 |
| invoice `purchase_order_reference` | 128 |
| invoice dates | 10 |

The browser renders values as text. The schema cannot contain HTML, styling,
scripts, links, or merchant-selected layout instructions.

## Cryptographic encoding

- Cipher: AES-256-GCM
- Viewing key: 32 random bytes
- Nonce: 12 random bytes, unique for the viewing key
- Authentication tag: 16 bytes
- Additional authenticated data: UTF-8 bytes of
  `bullnym-private-invoice-presentation-v1`
- Compression: none

The plaintext is exactly 4096 bytes:

1. Two-byte unsigned big-endian JSON byte length.
2. The UTF-8 JSON bytes.
3. CSPRNG-generated padding to byte 4096.

The binary envelope is exactly 4125 bytes:

| Offset | Length | Value |
|---:|---:|---|
| 0 | 1 | envelope version `0x01` |
| 1 | 12 | AES-GCM nonce |
| 13 | 4112 | ciphertext followed by the GCM tag |

The API encodes the envelope using canonical RFC 4648 base64url without
padding. A v1 envelope is therefore exactly 5500 characters.

## Private link

Bullnym returns its normal fragmentless invoice URL as `invoice_url`. Mobile
appends the canonical 43-character base64url viewing key:

```text
https://<origin>/invoice/<invoice-id>#v1.<viewing-key>
https://<origin>/<nym>/i/<invoice-id>#v1.<viewing-key>
```

URL fragments are not included in HTTP requests. Mobile's Copy, Share, and QR
actions operate on this complete link.

The payer browser validates the fragment, retains the key in tab-scoped
`sessionStorage`, and removes the fragment with `history.replaceState`. It
does not use cookies, `localStorage`, IndexedDB, service-worker storage,
analytics, or telemetry.

## Signed create request

`invoice-create` has 12 signed fields in this exact order:

1. `amount_sat` or empty
2. `fiat_amount_minor` or empty
3. `fiat_currency` or empty
4. `client_request_id`
5. `presentation_envelope`
6. `accept_btc`
7. `accept_ln`
8. `accept_liquid`
9. `bitcoin_address` or empty
10. `liquid_address` or empty
11. `liquid_blinding_key_hex` or empty
12. `expires_at_unix` or empty

`client_request_id` is a random UUID v4 generated before the first network
attempt. It is operational idempotency data, not presentation data. A retry
with the same owner, identifier, and exact payload returns the original
invoice. Reusing the identifier with a different payload returns
`InvoiceCreateConflict`.

The request does not accept any plaintext presentation field.

The deterministic cross-language fixture is
`tests/fixtures/private_invoice_v1.json`. Its key, nonce, and zero padding are
test values only and must never be reused by an implementation.

## Presentation retrieval and failure

`GET /api/v1/invoices/<id>/presentation` returns only:

```json
{ "presentation_envelope": "<canonical-base64url>" }
```

The endpoint never returns a key or recovery value.

If the key is absent, malformed, wrong, or authentication/schema validation
fails, the browser hides the entire private presentation and shows a generic
warning. The existing Bullnym amount, status, and payment instructions remain
available subject to the normal invoice lifecycle. There is no plaintext
fallback.
