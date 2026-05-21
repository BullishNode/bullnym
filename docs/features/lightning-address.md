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
3. Sender calls `/lnurlp/callback/:nym`.
4. Bullnym returns either:
   - a BOLT11 invoice backed by a Boltz reverse swap, or
   - a LUD-22 direct Liquid address if the sender proves Liquid UTXO ownership.

## Lightning Settlement

For standard Lightning senders, Bullnym creates a Boltz reverse swap. The
sender pays Lightning; Bullnym claims LBTC to a fresh address from the nym
descriptor. Payment accounting is tied to successful recipient-side claim, not
only to payer-side Lightning payment.

## LUD-22 Liquid Shortcut

LUD-22 lets compatible senders request direct Liquid by passing
`payment_method=L-BTC` plus proof fields. The proof binds the request to a real
Liquid UTXO, which makes descriptor-exhaustion attacks costly.

The server caches `(nym, outpoint)` to address index, so repeated requests for
the same outpoint and nym return the same address instead of advancing the
cursor.

## Deactivation

Deleting a registration deactivates the nym for new payment instructions.
Existing swaps remain claimable and must still settle. The nym remains
reserved to the original owner.
