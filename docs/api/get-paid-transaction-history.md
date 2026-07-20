# Get Paid transaction history

`GET /api/v1/get-paid/transactions` is the authenticated, identity-wide
payment history for the Get Paid product. It composes existing evidence; it
does not create a second accounting ledger.

The LA-v2 action is `get-paid-transaction-list`. Sign the empty nym slot,
followed by exactly `cursor_or_empty` and decimal `limit`. `npub` must be
canonical lowercase x-only hex. `limit` is `1..=100`.

```text
GET /api/v1/get-paid/transactions
  ?npub=<64-hex>
  &timestamp=<unix-seconds>
  &signature=<128-hex>
  &cursor=<opaque-or-empty>
  &limit=50
```

```json
{
  "transactions": [
    {
      "transaction_id": "6864e89d-7883-4ebf-922f-c08f249a0b4c",
      "source": "lightning_address",
      "invoice_id": null,
      "amount_sat": 2100,
      "received_at_unix": 1760000000,
      "rail": "lightning",
      "settlement_state": "settled",
      "settlement_kind": "bitcoin",
      "late": false,
      "comment": "optional private payer text"
    }
  ],
  "next_cursor": "opaque-or-null"
}
```

`source` is one of `lightning_address`, `invoice`, `payment_page`, or
`point_of_sale`. `rail` is `lightning`, `liquid`, or `bitcoin`.
`settlement_state` is:

- `pending`: payment evidence exists, but merchant settlement or direct-chain
  confirmation is not final.
- `settled`: authoritative evidence says the payment is settled.
- `problem`: previously observed payment evidence is inactive, stuck, or
  refunded and must not be presented as successful settlement.

## Merchant settlement projection

Every transaction has an explicit `settlement_kind`:

- `bitcoin`: Bullnym has authoritative evidence that the merchant settlement
  remains Bitcoin. A pre-funding fiat-conversion override may additionally
  provide `fiat_conversion`.
- `fiat`: the transaction has one or more Bull Bitcoin fiat settlement legs.
- `mixed`: the transaction has both a Bitcoin merchant leg and one or more
  Bull Bitcoin fiat settlement legs.
- `unavailable`: Bullnym recognizes the transaction but cannot produce a
  trustworthy settlement projection from its durable evidence.

The classification concerns where the merchant receives value. It is distinct
from `settlement_state`, which describes the lifecycle of the received payment.
Clients must not derive `bitcoin` from absent, malformed, or unknown fields.
Unknown enum values and inconsistent detail shapes fail closed to the client's
unavailable presentation.

`settlement_details` is present only when `settlement_kind` is `fiat` or
`mixed`. Its tagged `kind` must equal `settlement_kind`.

```json
{
  "kind": "mixed",
  "bitcoin": [
    {
      "amount_sat": 60000,
      "network": "liquid",
      "status": "settled"
    }
  ],
  "fiat": [
    {
      "amount_minor": 12345,
      "currency": "CAD",
      "order_id": "40000000-0000-4000-8000-000000000001",
      "status": "settled"
    }
  ]
}
```

The detail invariants are:

- A `fiat` projection has a non-empty `fiat` array and no `bitcoin` array.
- A `mixed` projection has non-empty `bitcoin` and `fiat` arrays.
- `amount_sat` is a strictly positive integer. `network` is `liquid` in
  version 1. Bitcoin-leg `status` is `pending`, `settled`, or `problem`.
- `currency` is an uppercase supported fiat currency and `order_id` is a
  non-nil UUID on every fiat leg.
- Fiat-leg `status` is `pending`, `settled`, or `unavailable`.
  `amount_minor` is a strictly positive integer only for `settled`; it is JSON
  `null` for `pending` and `unavailable`. Zero is never a pending sentinel.
- An invalid or internally inconsistent set of legs produces the top-level
  `unavailable` classification without partial details.

`fiat_conversion` is present only with `settlement_kind: "bitcoin"` when an
attempted conversion was overridden before a Bull Bitcoin destination became
authoritative:

```json
{
  "status": "overridden",
  "reason": "below_minimum"
}
```

The version-one reasons are `below_minimum`, `invalid_split`, and
`conversion_unavailable`. Raw provider errors are never returned. Ordinary
Bitcoin settlement has neither `settlement_details` nor `fiat_conversion`.
`unavailable` also has neither field, because untrusted partial details must
not be presented as authoritative.

A mixed settlement is one payer payment and therefore one history item.
Internal Bitcoin and fiat accounting events are nested legs, not additional
history items. `amount_sat` remains the total payer payment amount and must not
be replaced by an individual settlement leg amount. The endpoint similarly
returns one item for a fiat-only payment, fallback, retry, or replay of the
same payment evidence.

Existing rows created before fiat settlement are classified `bitcoin` only
when their durable payment evidence proves ordinary Bitcoin settlement.
Ambiguous or inconsistent historical rows are `unavailable`; field absence is
not used as an implicit classification.

The canonical version-one response fixtures are in
[`fixtures/get-paid-transactions-settlement-v1.json`](fixtures/get-paid-transactions-settlement-v1.json).
Server and client contract tests must parse those values without rewriting the
field names, enum strings, nulls, or array shapes.

`transaction_id` is a stable server-selected identity for the user payment.
Ordinary Lightning Address rows use `swap_records.id`, and ordinary
invoice-backed rows use `invoice_payment_events.id`. A payment composed from
multiple internal accounting events may instead use its canonical aggregate
identity. Clients must treat the ID as opaque and deduplicate by
`(source, transaction_id)`, never by amount or time. An invoice payment retains
its `invoice_id`, including late payments. `comment` is optional private data,
not transaction identity; a Lightning Address payment without a comment is
still present. Abandoned comments, unfunded instructions, and invoices without
payment evidence are absent. Direct observations superseded by their canonical
Boltz settlement event are also absent so one receipt cannot appear twice.

Ordering is stable newest-first by immutable first-observation time, source
rank, and UUID. The cursor is a strict versioned encoding of that tuple. Treat
it as opaque, sign it exactly as received, and restart from an empty cursor on
refresh. A newly recorded payment normally appears before an existing cursor.
Recovery can also persist older first-observation evidence after a page was
read; that row can then appear on a continuation page. The cursor prevents
already-returned rows from moving behind it, but it is not a database snapshot.

Each list item is the authenticated transaction detail currently exposed by
this API. Invoice-backed items carry `invoice_id`; clients may use the existing
invoice status surface for current payment state, but private comments remain
available only here. Lightning Address items have no invoice and no separate
public detail route. `transaction_id` is an opaque stable identity, not a
public lookup token.

The request signature authenticates the merchant query; the response is not a
separately signed message. Settlement details are protected by the same
merchant-authenticated HTTPS and no-store boundary as comments. They must not
be added to public invoice status, payer pages, LNURL responses, logs, metrics,
or provider descriptions.

Bullnym does not autonomously garbage-collect these payment-evidence rows.
Soft-deactivating a Lightning Address preserves its history. An explicitly
signed hard purge deletes that nym's terminal Lightning Address swap history;
invoice-backed evidence remains subject to the invoice lifecycle and is not
deleted by that nym purge.

Successful responses use `Cache-Control: private, no-store, max-age=0`,
`Pragma: no-cache`, `Referrer-Policy: no-referrer`, and
`X-Robots-Tag: noindex, nofollow`. Comments must not be exposed through public
invoice, LNURL, Page/POS, log, metric, or provider-description surfaces. The
older `/api/v1/lnurl/comments` route remains available for compatibility, but
new clients use this transaction resource.
