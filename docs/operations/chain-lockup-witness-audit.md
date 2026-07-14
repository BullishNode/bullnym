# Chain lockup witness audit boundary

`chain_lockup_witness_audit` is a pure, unwired issue-#87 comparison layer. It
cross-references authenticated manifest-v1 records with public Bitcoin
user-lock observations. It performs no database query, object-store read,
network request, provider request, reconstruction, admission change, or write.

## Required adapter contract

The adapter that supplies `PrevalidatedChainLockupObservationV1` owns the chain
trust boundary. Before calling the audit it must:

- finish a complete Bitcoin-mainnet scan for every signed lockup script;
- fetch and decode exact raw transaction bytes and recompute each txid;
- verify `vout`, scriptPubKey, and amount directly from those bytes;
- verify mempool or block inclusion, including height and block hash;
- inspect each outpoint and validate the spending transaction identity when it
  is spent;
- apply the configured authoritative-backend/agreement policy; and
- fail the scan on unavailable, truncated, stale, or disagreeing evidence.

An adapter failure or incomplete scan must not become an empty observation
slice. `Missing` is meaningful only after a successful complete scan found no
output. The audit defensively checks canonical field shapes and address/script
coherence, but those checks do not replace raw-chain validation.

Both manifest UUID and chain-swap UUID are association tags supplied by the
adapter. They are not facts encoded in a Bitcoin transaction. The audit resolves
both independently and rejects unknown, partial, or crossed associations. It
also rejects repeated `(chain, txid, vout)` identities rather than merging
potentially contradictory records.

## Classification only

For each manifest, findings are ordered by `(txid, vout)` and classified as:

- `Missing`: the completed scan found no output;
- `Unconfirmed`: an exact target output is in the mempool and unspent;
- `Confirmed`: an exact target output has coherent block evidence and is
  unspent;
- `Spent`: an exact target output has a validated spending transaction; or
- `Conflicting`: chain, canonical address/script, or original requested amount
  disagrees with the signed manifest.

The summary priority is `Conflicting > Spent > Confirmed > Unconfirmed >
Missing`, while every bounded finding is retained. An amount mismatch is not
discarded and is not declared a loss: underpayments, overpayments, repeated
funding, and monetary action belong to the later obligation reducer.

## Startup admission semantics

A successfully validated amount mismatch is chain evidence for one existing,
persisted obligation. It is not a failure of the manifest store, PostgreSQL,
provider restore inventory, or Bitcoin authority, and therefore does not close
new chain-swap creation globally. The existing obligation remains visible to
the primary-source projection and runtime reducer, which must reconcile its
underpayment, overpayment, renegotiation, or recovery without crediting stale
amounts.

This distinction does not weaken the chain trust boundary. Adapter failures,
incomplete scans, invalid observations, unknown or crossed identities, and
chain/address/script target conflicts still fail closed. The startup report
also verifies that every conflicting manifest was accounted for as either an
amount-only mismatch or a structural conflict; unknown conflict shapes close
admission. Opening unrelated creation neither mutates nor discards the existing
obligation or its append-only witness.

## Deliberate v1 limit

This slice covers only the payer's Bitcoin user lock because manifest v1 signs
its exact mainnet address, derivable scriptPubKey, and original amount. It does
not infer a Liquid server-lock amount after renegotiation, its confidential
asset/value evidence, or an exact merchant settlement output. Those facts must
come from the persisted #83 merchant-output lifecycle. Adding guessed fields
here would make stale-restore evidence less trustworthy, not more complete.
