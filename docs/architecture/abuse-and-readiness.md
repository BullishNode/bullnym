# Rate Limits and Certification

Bullnym rate limits protect descriptors, public lookup endpoints, expensive
external calls, webhooks, and signed write paths.

## Rate-Limit Surfaces

| Surface | Purpose |
|---|---|
| Registration | Prevent nym squatting and expensive descriptor/signature floods. |
| Metadata and NIP-05 lookup | Limit public probing of nyms and owner keys. |
| LNURL callback | Protect Boltz and Liquid Electrum calls. |
| LUD-22 proof checks | Bound Liquid UTXO verification and descriptor-index allocation. |
| Payment Page/POS render | Protect public HTML fallback. |
| Checkout creation | Protect surface descriptor cursor allocation and eager offer creation. |
| Invoice create/list/status | Protect signed dashboard and public polling surfaces. |
| Webhook | Bound webhook-bombing from a single source. |
| Opaque wallet backups | Bound fetches and mutations per source, mutations per authenticated stream key, distinct keys per source, object size, and global live ciphertext. |

## LUD-22 Descriptor Protection

LUD-22 protects descriptor cursors with:

- UTXO ownership proof
- minimum UTXO value
- `(nym, outpoint)` idempotency
- per-outpoint fan-out caps
- optional per-pubkey cap (disabled by default)
- pending reservation TTL cleanup

These controls make address allocation costly to abuse and prevent repeated
requests for the same outpoint from advancing the cursor.

Public-surface descriptor allocation is different from LUD-22. Opening the page
does not allocate an address, but `POST /:nym/invoice` currently allocates the
checkout settlement address immediately. Protecting that cursor depends on the
anonymous invoice-create rate limit and certification preflight, not on a
Liquid-specific proof-of-funds request.

Wallet backup source gates run before JSON parsing and body allocation. The
authenticated per-key and distinct-key gates run only after signature
verification. Store signatures are verified before ciphertext decoding and
hashing. The service additionally enforces a 3 MiB request-body ceiling, a
2 MiB decoded-object ceiling, and a configured global live-byte ceiling;
fetch and conditional delete remain available at capacity.

## IP Whitelist

`rate_limit.ip_whitelist` bypasses all rate limits and the LUD-22 proof gate.
It is intentionally broad and should be reserved for known infrastructure that
needs full bypass behavior.

## Certification Allowlist

`[certification]` is narrower than the IP whitelist. It requires:

- enabled certification mode
- allowed source IP/CIDR
- `X-Bullnym-Certification-Token`
- explicit scopes

Certification scopes are for deterministic server/payment-rail tests. They do
not turn bullnym-test into a mobile test environment.

Neither certification nor the IP whitelist bypasses money admission. A caller
with every certification scope still cannot make Bullnym publish a new payment
instruction while that rail is closed.

## Money Admission

Money admission is a process-local, per-rail safety boundary for creating new
monetary obligations. Every process starts closed and must observe a successful
current-process cycle from each worker required by the requested rail before it
can publish new payer instructions.

| Rail | Required runtime signals |
|---|---|
| Direct Liquid | Current schema, enabled workers, initialized direct-Liquid backend, and Liquid watcher. |
| Direct Bitcoin | Current schema, enabled workers, initialized direct-Bitcoin watcher client, and Bitcoin watcher. |
| Lightning reverse swap | Current schema, enabled workers, initialized Liquid-claim factory and Boltz client, safe swap-key lineage, an admitted fee policy, reverse claimer/reconciler, settlement repair, and slow recovery. |
| Bitcoin chain swap | Current schema, enabled workers, initialized Liquid-claim factory, Bitcoin recovery-evidence client, and Boltz client, safe swap-key lineage, writable recovery journal, an admitted fee policy, a merchant-specific recovery commitment, chain claimer/reconciler, settlement repair, and slow recovery. |

Direct-observation clients and swap settlement/evidence clients are independent
hard facts. Bullnym retains the exact validated Liquid claim factory and
Bitcoin evidence client that existing-obligation paths use; it never infers
their readiness from a different backend or from a merely nonempty endpoint
list. Before an empty claimer scan can succeed, the process retries the exact
Liquid claim socket construction and genesis probe until its first success,
then latches that initialization for the process. Later provider reachability
remains transient worker evidence rather than a permanent startup fact.

Hard prerequisite loss closes the affected rail immediately. A worker becomes
suspect after one failed cycle, closes its rails after three consecutive failed
cycles or at three missed cadences, and needs two successful
cycles to reopen after either closure. A stopped worker closes its rails.

Admission is checked immediately before the first irreversible mutation, such
as advancing a descriptor/key cursor, inserting a new payable invoice, or
creating a provider obligation. Existing payment instructions, status reads,
webhooks, claims, reconciliation, settlement repair, and recovery continue
while new-money admission is closed.

The Boltz creation circuit is reported alongside this private operations view,
but remains a load-shedding mechanism rather than another admission policy.
Its fixed `closed`, `suspect`, `open`, and `half_open` states and monotonic
transition count cover only new provider-dependent offer creation. Direct
Liquid and existing claim, refund, status, reconciliation, and recovery work
never consult it. `/ready` does not serialize circuit details.

An admission rejection is HTTP 503 with the fixed public message `This payment
method is temporarily unavailable. Try again later.` Detailed rail and
dependency reason codes appear only in transition logs. This prevents callers
from learning internal backend, key-lineage, worker, fee-policy, or recovery
state.

At startup, each process restores only validated same-rail persisted fee
evidence, refreshes the configured live sources, and durably accepts current
Bitcoin and Liquid decisions before setting `fee_policy_ready`. Configured
Bitcoin source bases are queried only at `/v1/fees/precise`; there is no
`/fees/recommended` fallback. Accepted live decisions contribute to readiness
only after persistence succeeds or a newer authoritative durable row wins the
ordering race. Background per-rail refreshes and the process-local freshness
loop keep the admission fact current. If either rail has no current durable
decision, `fee_policy_ready` becomes false and reverse- and chain-swap creation
fail closed until current durable evidence is available again.

Chain-swap admission additionally remains closed for an individual merchant
until the request is bound to that merchant's current committed recovery
destination before an offer is created. Direct rails can remain available
independently when their own prerequisites are healthy.

## Preflight

Broad certification should call `/certification/preflight` before setup or
money movement. If source, token, scope, balances, or server provenance are not
ready, the run should fail preflight instead of producing skipped scenarios.
Preflight success does not override a closed money rail.
