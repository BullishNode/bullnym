# Private LNURL Payer-Comment History

Bullnym retains an accepted LNURL payer comment as immutable private payment
metadata. An intent without authoritative payment evidence is never presented
as received money. Comments do not appear in public LNURL metadata/callback
responses, invoice status/list responses, Payment Page/POS HTML, Open Graph
content, provider descriptions, logs, or metric labels.

## Signed history request

```http
GET /api/v1/lnurl/comments?npub=<64-lowercase-hex>&timestamp=<unix>&signature=<128-hex>&page=1&pageSize=20
```

Sign the identity-wide LA-v2 action `lnurl-comment-history` with an empty nym
slot. The ordered fields after the empty nym are the canonical decimal `page`
and `pageSize` values. `page` is bounded to 1-1000 and `pageSize` to 1-100;
values outside those ranges are rejected rather than clamped.

The signing bytes are:

```text
bullpay-la-v2 NUL lnurl-comment-history NUL npub NUL NUL
page NUL pageSize NUL timestamp
```

The authenticated identity does not need to remain active. This lets a
merchant recover immutable received-payment history after restart or Lightning
Address deactivation while still requiring fresh proof of the merchant key.

## Response

```json
{
  "comments": [
    {
      "intent_id": "4de539d7-b0f2-4d4a-a308-d0f31dc111b5",
      "nym": "merchant",
      "amount_msat": 42000,
      "comment": "Coffee for Ana ☕",
      "received_at_unix": 1784041200
    }
  ],
  "page": 1,
  "pageSize": 20,
  "has_more": false
}
```

Rows are ordered by payment-evidence time descending, then intent UUID
descending as a deterministic tie-break. The response omits the owner key,
intent digest, payment rail, provider/instruction references, payment-evidence
reference, and pre-payment creation time. It is returned with
`Cache-Control: private, no-store, max-age=0` and `Pragma: no-cache`.

`comment` preserves the exact validated UTF-8 text. JSON may escape characters
on the wire, but decoding yields the original bytes. Treat it as untrusted
plain text; never interpret it as markup or a clickable message.
