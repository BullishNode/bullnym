# Authentication

Signed APIs use BIP-340 Schnorr over the SHA-256 digest of this byte sequence:

```text
bullpay-la-v2 NUL action NUL npub_hex NUL nym_or_empty NUL
field_1 NUL ... field_n NUL timestamp_decimal
```

There is no trailing NUL after the timestamp. Strings are UTF-8, absent
fixed-position optionals are empty strings, and the timestamp must be within
300 seconds of server time. Boolean encoding is endpoint-specific: surface
fields (`enabled` and legacy `pos_mode`) use `"1"`/`"0"`, while the three
invoice-creation acceptance fields use `"true"`/`"false"`. The 64-byte Schnorr
signature is lowercase or uppercase hex in the JSON `signature` field.

Pseudocode:

```text
message = join_with_nul([
  "bullpay-la-v2", action, npub_hex, nym_or_empty,
  ...fields
]) + NUL + decimal(timestamp)
signature = hex(BIP340_sign(private_key, SHA256(UTF8(message))))
```

Do not serialize JSON and sign it. Sign the exact ordered logical fields below.
For linked operations, the nym binds the signature to one namespace. For
unlinked invoice operations it is the empty string.

| Operation | Action | Ordered fields after nym |
|---|---|---|
| register | `register` | `ct_descriptor`, then `verification_npub` only when its JSON value is non-null |
| update registration | `update` | `ct_descriptor` |
| deactivate/purge | `delete` or `purge` | none |
| save surface | `donation-page-save` | `header`, `description`, `display_currency`, `website_or_empty`, `twitter_or_empty`, `instagram_or_empty`, `enabled`; then each of `pos_mode`, `ct_descriptor`, `kind`, `alias` only when its JSON value is non-null (`alias: ""` is non-null and is signed) |
| archive surface | `donation-page-archive` | `kind` only when its JSON value is non-null |
| create invoice | `invoice-create` | `amount_sat`, `fiat_amount_minor`, `fiat_currency`, `public_description`, `recipient_name`, `invoice_number`, `accept_btc` (`true`/`false`), `accept_ln` (`true`/`false`), `accept_liquid` (`true`/`false`), `bitcoin_address`, `liquid_address`, `liquid_blinding_key_hex`, `expires_at_unix` |
| cancel invoice | `invoice-cancel` | `invoice_id` |
| list invoices | `invoice-list` | `page`, `pageSize`, `status_or_empty` |
| recover chain swap | `invoice-recover` | `invoice_id`, `btc_address` |
| list recoverable swaps | `invoice-recovery-list` | none — zero payload fields, and the nym slot is the empty string |

Invoice optionals always occupy their fixed signing position as `""`. Amounts
and timestamps use decimal strings. This distinction from the surface API's
append-only compatibility fields is critical.

Reservation inspection is the sole legacy signing exception. Sign the
SHA-256 digest of UTF-8 `reservations:<nym>:<ts>` and send it as `sig`.

## Retry implications

Sign immediately before sending. A retry within the 300-second window may
reuse the request; after that, rebuild the timestamp and signature. Registration
reactivation, cancellation, same-address completed recovery, and most reads are
safe to retry. Invoice creation can create another receivable if the first
response was lost; clients should reconcile through the signed list endpoint
before creating a replacement.

