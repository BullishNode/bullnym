# 007 Public Checkout Allocation and Rate Limits

Status: Accepted

## Decision

Rendering a public checkout shell with `GET /:nym` or `GET /:nym/pos` does not
allocate a Liquid address and does not advance a surface descriptor cursor.

Creating a checkout invoice with `POST /:nym/invoice` or
`POST /:nym/pos/invoice` allocates exactly one Liquid settlement address from
the selected surface descriptor. That address backs the checkout's Liquid,
Lightning, and Bitcoin-chain-swap settlement paths.

Status polling, page rendering, and later payment-method refreshes must not
allocate additional descriptor addresses for the same checkout.

## Rationale

Plain page views are cheap to generate and easy to automate. Allocating a fresh
Liquid address on every page view would expose the descriptor cursor to trivial
exhaustion attacks. Checkout creation is a stronger intent signal and is
covered by checkout rate limits.

Checkout creation allocates one settlement address so all accepted rails share
the same invoice settlement record.

## Consequences

- The anti-abuse boundary for surface descriptors is checkout invoice
  creation, not shell render.
- Tests must assert no cursor movement on `GET /:nym` and `GET /:nym/pos`.
- Tests must assert exactly one cursor movement on `POST /:nym/invoice` and
  `POST /:nym/pos/invoice`.
- Tests must assert status polling and refreshes do not allocate additional
  addresses.
- LUD-22 Lightning Address allocation remains stricter than public checkout:
  it requires sender UTXO proof before a direct Liquid address is returned.
