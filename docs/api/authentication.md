# Authentication

Signed APIs use BIP-340 Schnorr over the SHA-256 digest of this byte sequence:

```text
bullpay-la-v2 NUL action NUL npub_hex NUL nym_or_empty NUL
field_1 NUL ... field_n NUL timestamp_decimal
```

There is no trailing NUL after the timestamp. Strings are UTF-8, absent
fixed-position optionals are empty strings, and the timestamp must be within
300 seconds of server time. Boolean encoding is endpoint-specific: surface
fields (`enabled` and `pos_mode`) use `"1"`/`"0"`, while the three
invoice-creation acceptance fields use `"true"`/`"false"`. The 64-byte Schnorr
signature is lowercase or uppercase hex in the JSON `signature` field except
for recovery-address registration, whose evidence-preserving v1 contract
requires canonical lowercase hex.

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
| take Lightning Address offline/purge | `delete` or `purge` | none |
| save surface | `donation-page-save` | `header`, `description`, `display_currency`, `website_or_empty`, `twitter_or_empty`, `instagram_or_empty`, `enabled`, required `pos_mode`, required `ct_descriptor`, required `kind`; then `alias` only when its JSON value is non-null (`alias: ""` is non-null and is signed) |
| archive surface | `donation-page-archive` | required `kind` |
| create invoice | `invoice-create` | `amount_sat`, `fiat_amount_minor`, `fiat_currency`, `public_description`, `recipient_name`, `invoice_number`, `accept_btc` (`true`/`false`), `accept_ln` (`true`/`false`), `accept_liquid` (`true`/`false`), `bitcoin_address`, `liquid_address`, `liquid_blinding_key_hex`, `expires_at_unix` |
| cancel invoice | `invoice-cancel` | `invoice_id` |
| list invoices | `invoice-list` | `page`, `pageSize`, `status_or_empty` |
| list received LNURL comments | `lnurl-comment-history` | `page`, then `pageSize`; the nym slot is the empty string and `npub` must be canonical lowercase hex |
| list recoverable swaps | `invoice-recovery-list` | none — zero payload fields, and the nym slot is the empty string |
| register recovery address | `recovery-address-set` | `1`, then the canonical Bitcoin-mainnet `btc_address`; the nym slot is the empty string and the signature must be lowercase hex |
| look up recovery address | `recovery-address-get` | none — zero payload fields, and the nym slot is the empty string |
| list LUD-22 reservations | `reservation-list` | none — zero payload fields, with the route nym in the nym slot |

Invoice optionals always occupy their fixed signing position as `""`. Amounts
and timestamps use decimal strings. Surface social fields similarly occupy
fixed empty-string positions; only the terminal alias is omitted when absent.

## Retry implications

Sign immediately before sending. A retry within the 300-second window may
reuse the request; after that, rebuild the timestamp and signature. Registering
an owned name to bring its Lightning Address online, cancellation, and most
reads are safe to retry. A lost invoice creation response may hide a newly
created receivable; clients should reconcile through the signed list endpoint
before creating a replacement.
Recovery-address registration is idempotent only
for the exact signed request: rebuilding its timestamp or signature appends a
new immutable policy version, even when the address is unchanged.
