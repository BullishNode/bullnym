# ADR 009: Payment coordination trust boundary

- Status: Accepted
- Date: 2026-07-11
- Scope: `bullnym`

## Context

The merchant wallet must remain offline during payment, payers may use ordinary
wallets, and no independent policy operator participates. Bullnym therefore
cannot provide payer-verifiable destination policy or merchant co-signing while
preserving the existing flow.

## Decision

Bullnym is non-custodial payment coordination infrastructure, but it remains a
trusted coordinator. Merchant wallet spending keys never enter the service.
Bullnym may hold swap-specific keys and must commit concrete merchant
destinations, persist recovery artifacts, and drive settlement automatically.

Chain-swap failure recovery uses one merchant-configured emergency Bitcoin
address, not a server-derived destination descriptor. Claims and refunds are
mutually excluded and all operator decisions require database, chain, and
provider evidence.

## Consequences

Compromise of Bullnym can redirect newly negotiated payments or suppress
recovery, although it cannot spend the offline merchant wallet. Durable state,
idempotent workers, monitoring, backups, and artifact-preserving procedures are
part of the security boundary. Stronger trustlessness would require a payer,
merchant, or second operator to enforce policy and is outside the current flow.
