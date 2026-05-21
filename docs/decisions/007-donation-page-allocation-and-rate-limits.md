# 007 Donation Page Allocation and Rate Limits

Status: Accepted

## Decision

Rendering a public donation page with `GET /:nym` does not allocate a Liquid
address and does not advance the page descriptor cursor.

Creating a checkout invoice with `POST /:nym/invoice` allocates exactly one
Liquid settlement address from the page descriptor. That address backs the
checkout's Liquid, Lightning, and Bitcoin-chain-swap settlement paths.

Status polling, page rendering, and later payment-method refreshes must not
allocate additional descriptor addresses for the same checkout.

## Rationale

Plain page views are cheap to generate and easy to automate. Allocating a fresh
Liquid address on every page view would expose the descriptor cursor to trivial
exhaustion attacks. Checkout creation is a stronger intent signal and is
covered by checkout rate limits.

The earlier idea of waiting until the payer explicitly clicked the Liquid rail
was not preserved in the current implementation. The current contract allocates
one settlement address at checkout creation so all accepted rails can share the
same invoice settlement record.

## Consequences

- The anti-abuse boundary for page descriptors is checkout invoice creation,
  not HTML render.
- Tests must assert no cursor movement on `GET /:nym`.
- Tests must assert exactly one cursor movement on `POST /:nym/invoice`.
- Tests must assert status polling and refreshes do not allocate additional
  addresses.
- LUD-22 Lightning Address allocation remains stricter than donation checkout:
  it requires sender UTXO proof before a direct Liquid address is returned.
