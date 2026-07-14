# Lightning Address

Lightning Address is the original Bullnym product surface. It exposes a
public `nym@domain` LNURL-pay address backed by Liquid settlement.

## User Model

The recipient registers a nym and a Lightning Address CT descriptor. The nym
becomes both:

- an LNURL-pay username at `/.well-known/lnurlp/:nym`
- a public Lightning Address as `nym@domain`

The descriptor is stored in `users.ct_descriptor` and uses
`users.next_addr_idx` for address allocation.

## Sender Flow

1. Sender wallet resolves `nym@domain` to `/.well-known/lnurlp/:nym`.
2. Bullnym returns LNURL metadata and supported payment methods.
3. Sender calls the complete opaque `/lnurlp/callback/:nym/:comment_intent`
   URL returned by metadata. The tokenless route remains a no-comment
   compatibility path.
4. Bullnym returns either:
   - a BOLT11 invoice backed by a Boltz reverse swap, or
   - a LUD-22 direct Liquid address if the sender proves Liquid UTXO ownership.

## Lightning Settlement

For standard Lightning senders, Bullnym creates a Boltz reverse swap. The
sender pays Lightning; Bullnym claims LBTC to a fresh address from the nym
descriptor. Payment accounting is tied to successful recipient-side claim, not
only to payer-side Lightning payment.

Optional payer comments are preserved exactly under a 120-grapheme/512-byte
private contract before the BOLT11 is returned. Exact callback retries reuse
the same bound swap. The comment becomes received history only after the
merchant-side claim transaction is durable; it is never placed in public
payment responses or provider descriptions. Direct-Liquid comments currently
fail closed until that rail has the same atomic instruction/evidence binding.

## LUD-22 Liquid Shortcut

LUD-22 lets compatible senders request direct Liquid by passing
`payment_method=L-BTC` plus proof fields. The proof binds the request to a real
Liquid UTXO, which makes descriptor-exhaustion attacks costly.

The server caches `(nym, outpoint)` to address index, so repeated requests for
the same outpoint and nym reuse the index instead of advancing the cursor. A
mempool sighting remains observational; only confirmed Liquid history fulfills
the reservation and advances the durable descriptor cursor.
Replacing the nym descriptor can change the address derived at that cached
index; descriptor rotation must be coordinated with in-flight payments.

## Deactivation

Deleting a registration deactivates the nym for new payment instructions.
Existing swaps remain claimable and must still settle. The nym remains
reserved to the original owner.
