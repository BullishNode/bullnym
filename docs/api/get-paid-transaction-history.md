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

Lightning Address rows are keyed by `swap_records.id`; invoice-backed rows are
keyed by `invoice_payment_events.id`. Clients must deduplicate by
`(source, transaction_id)`, never by amount or time. An invoice payment retains
its `invoice_id`, including late payments. `comment` is optional private data,
not transaction identity; a Lightning Address payment without a comment is
still present. Abandoned comments, unfunded instructions, and invoices without
payment events are absent. Direct observations superseded by their canonical
Boltz settlement event are also absent so one receipt cannot appear twice.

Ordering is stable newest-first by immutable first-observation time, source
rank, and UUID. The cursor is a strict versioned encoding of that tuple. Treat
it as opaque, sign it exactly as received, and restart from an empty cursor on
refresh. New payments may appear before the first page but cannot reshuffle
continuation pages behind an existing cursor.

Successful responses use `Cache-Control: private, no-store, max-age=0` and
`Pragma: no-cache`. Comments must not be exposed through public invoice,
LNURL, Page/POS, log, metric, or provider-description surfaces. The older
`/api/v1/lnurl/comments` route remains available for compatibility, but new
clients use this transaction resource.
