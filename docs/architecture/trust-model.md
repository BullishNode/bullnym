# Trust model

Bullnym is designed as non-custodial payment coordination software, not as a
service that accepts and transmits customer funds. Recipient wallet keys remain
offline. Bullnym creates payment instructions, watches external systems, and
uses swap-specific keys to deliver funds to recipient-controlled destinations.

That design reduces custody but does not make the server trustless. A payer can
use any compatible wallet and therefore cannot verify Bullnym-specific policy.
The merchant wallet is offline during payment. Bullnym is the only policy
operator and must be trusted to negotiate honestly, persist recovery material,
and submit transactions to the intended destination.

## Assets and principals

| Principal | Controls | Relies on Bullnym for |
|---|---|---|
| Merchant | Offline wallet keys, receive descriptors or concrete destinations, optional emergency Bitcoin refund address | Correct address allocation, swap construction, payment reporting, and recovery execution |
| Payer | Funds and an ordinary Lightning, Liquid, or Bitcoin wallet | Honest payment instructions and status reporting |
| Bullnym | Database, swap-specific keys, worker policy, provider/API credentials | Durable coordination and transaction execution |
| Swap provider | Its side of Boltz swaps and cooperative signing | Swap execution and provider state |

Wallet-backup clients additionally rely on Bullnym only for best-effort opaque
blob availability. Separate seed-derived signing and encryption keys identify
each backup stream. Bullnym observes the source IP, pseudonymous stream key,
timing, and ciphertext size, but it does not receive the seed, encryption key,
or plaintext metadata.

Compromise of the swap provider is outside Bullnym's chosen threat model. Its
responses are nevertheless not sufficient proof of chain state; operators and
workers should correlate them with independent chain evidence.

## What Bullnym cannot spend

- the merchant's offline wallet balance;
- funds already delivered to merchant-controlled Bitcoin or Liquid outputs;
- payer funds that were never sent to an instruction issued by Bullnym.
- correctly client-encrypted wallet-backup plaintext or the wallet seed from
  which its independent encryption key is derived.

## What a malicious or compromised Bullnym could do

- substitute its own settlement destination while creating a swap;
- issue a dishonest payment instruction or lie about its status;
- leak descriptors, addresses, invoice metadata, IP-derived metadata, or the
  linkage among payment rails;
- suppress, delay, or mishandle claims and refunds;
- misuse swap-specific private keys or destroy recovery artifacts;
- allocate addresses incorrectly, causing reuse or missed wallet discovery.
- delete, withhold, replay, or selectively make opaque wallet-backup objects
  unavailable, and correlate stream keys with source/timing/size observations.

For direct payments, the payer's wallet displays the destination but cannot
know whether it belongs to the merchant. For swap payments, the payer sees a
provider instruction and cannot inspect the eventual merchant output. These
risks cannot be eliminated without changing the payer or merchant interaction
model.

## Risk-reduction controls

- Merchant destinations are committed when the payment session or swap is
  created and are not resolved from mutable profile state during settlement.
- Descriptor cursors and swap state transitions are persisted in Postgres and
  guarded by transactions, uniqueness constraints, idempotency keys, and
  advisory locks where competing spends are possible.
- Claim and refund transactions and their IDs are persisted before or around
  broadcast so retries can reuse evidence rather than invent a new outcome.
- Webhooks are supplemented by provider reconciliation, chain watchers,
  settlement repair, and slow recovery for funded `claim_stuck` swaps.
- Chain-swap refunds use one merchant-configured emergency Bitcoin address,
  first-write-wins persistence, and claim/refund exclusion gates.
- Signed merchant actions bind the relevant fields with domain-separated
  payloads. Public invoice URLs remain bearer-readable by design.
- Operators preserve artifacts and reconcile database, provider, and chain
  evidence before changing state.
- Opaque backup writes use signed, stream-separated compare-and-swap heads;
  short tombstones outlive the signed-request replay window, and responses are
  marked private/no-store. Clients authenticate and decrypt before applying.

## Residual risks

Bullnym still represents a single operational and policy failure domain. The
database contains sensitive linkage and recovery secrets. Some successful
broadcasts are currently recorded as terminal settlement before confirmation;
an interrupted or replaced transaction therefore requires monitoring and
reconciliation. Direct Bitcoin and Liquid present verified mempool evidence
immediately, activate exact accounting at one confirmation, and retain
reversible evidence through configurable finality (three Bitcoin, two Liquid
by default). The explicitly accepted zero-confirmation display still carries
rare conflict/reorg risk and is not a financial guarantee. These are documented
boundaries, not guarantees supplied by the architecture.

No design can promise zero loss under simultaneous server compromise,
destruction of all durable state, invalid merchant configuration, or failures
outside the defined threat model. Backups, key protection, monitoring, and
tested recovery procedures remain part of the security boundary.

Opaque wallet backups are a convenience service, not a fund-recovery
guarantee. A malicious or unavailable Bullnym can deny or roll back whatever
blob it serves, so clients must enforce authenticated generations, protective
conflict/version behavior, and non-blocking seed recovery. Confidentiality also
depends on correct client-side key separation and authenticated encryption.
