# Runbook: swaps requiring attention

This runbook covers swaps whose normal fast retry path has stopped making
progress. Its purpose is to preserve evidence, avoid conflicting spends, and
restore the automatic recovery path. It is not a license to rewrite payment
history.

## Safety rules

1. Never delete or replace persisted transaction hex, transaction IDs, swap
   keys, derivation metadata, provider responses, or refund destinations during
   initial triage.
2. Never infer settlement from a provider status alone. Correlate the database,
   Bitcoin or Liquid chain state, and the provider response.
3. Never move a swap backward in the state machine while a claim or refund may
   already have been broadcast.
4. Never refund a chain swap if a Liquid claim transaction exists or the
   provider reports that the merchant side was claimed. The server enforces
   these gates; do not bypass them with SQL.
5. Take a row snapshot before any intervention and record the operator, reason,
   timestamp, and resulting state in the incident log.

## Detect

```sql
SELECT id, invoice_id, nym, boltz_swap_id, status,
       claim_attempts, slow_attempts,
       next_claim_attempt_at, next_slow_attempt_at,
       claim_txid, last_claim_error, last_claim_error_at,
       updated_at
FROM swap_records
WHERE status IN ('claim_stuck', 'lockup_refunded')
ORDER BY updated_at ASC;

SELECT id, invoice_id, nym, boltz_swap_id, status,
       claim_attempts, slow_attempts,
       next_claim_attempt_at, next_slow_attempt_at,
       claim_txid, refund_txid, last_claim_error, last_claim_error_at,
       updated_at
FROM chain_swap_records
WHERE status IN ('claim_stuck', 'refund_due', 'refunding')
ORDER BY updated_at ASC;
```

Also alert on these structured events:

| Event | Meaning |
|---|---|
| `swap_claim_stuck` | Reverse swap exhausted its fast retry budget. |
| `chain_swap_claim_stuck` | Chain swap exhausted its fast retry budget. |
| `slow_recovery_revived` | Slow recovery returned a funded swap to the claim sweep. |
| `swap_lockup_refunded` | Provider spent the reverse-swap Liquid lockup before Bullnym claimed it. |
| `chain_swap_refund_due` | Payer BTC is recoverable but merchant settlement did not complete. |
| `chain_swap_claimed_while_refunding` | Conflicting provider/refund evidence; investigate immediately. |
| `chain_swap_refund_blocked_claim_in_flight` | Refund correctly refused because merchant settlement may exist. |

## Collect evidence

Before changing anything, capture the complete rows for the invoice and swap,
the latest service logs, the provider response, and independent chain evidence
for every known transaction and lockup address.

```sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

SELECT * FROM invoices WHERE id = '<invoice-id>';
SELECT * FROM invoice_payment_events WHERE invoice_id = '<invoice-id>' ORDER BY created_at;
SELECT * FROM swap_records WHERE id = '<swap-id>';
SELECT * FROM chain_swap_records WHERE id = '<swap-id>';

COMMIT;
```

Query the configured provider endpoint, but retain the raw response as one item
of evidence rather than treating it as authoritative:

```bash
curl -sS "$BOLTZ_API_URL/swap/$BOLTZ_SWAP_ID" | jq .
```

For each known Bitcoin or Liquid transaction ID, determine whether it is in the
mempool, confirmed, replaced, or absent. Verify that the relevant lockup output
is unspent before constructing any new transaction.

## Classify the incident

### A. `claim_stuck`, claim transaction already present

Do not clear `claim_tx_hex` or `claim_txid`. Determine whether the transaction
is already visible, rejected for a permanent reason, or merely absent after an
infrastructure failure. Rebroadcasting the identical transaction is
idempotent. Rebuilding it is a separate recovery operation that requires proof
that the original cannot confirm or conflict.

The slow-recovery worker automatically revives funded `claim_stuck` rows with a
capped backoff. A row is therefore an alert state, not an abandoned terminal
state. Confirm that the worker is running and that `next_slow_attempt_at`
advances.

### B. `claim_stuck`, no claim transaction present

Inspect `last_claim_error` and address the dependency failure first: database,
provider API, Electrum endpoint, malformed persisted swap data, or fee policy.
Once the dependency is healthy, allow slow recovery to revive the row. Manual
rescheduling should be exceptional and must use the same guarded database
transition as the worker; do not improvise a multi-column reset in production.

### C. reverse swap `lockup_refunded`

Verify the Liquid spending transaction and the Lightning-side result. If the
provider spent its lockup and the payer's Lightning payment settled, Bullnym no
longer has an on-chain recovery path. Preserve the row as the audit record and
handle merchant remediation as an incident. Do not relabel it to make accounting
appear settled.

### D. chain swap `refund_due`

This means the payer's BTC lockup is recoverable but merchant settlement did not
complete. Recovery requires the single merchant-configured emergency Bitcoin
address already committed to the swap. Bullnym's automatic worker reloads that
commitment, the exact primary Bitcoin source, and independently agreed Liquid
evidence under the shared swap lock before it can journal or broadcast. The
signed endpoint documented in
[Chain-swap recovery](../../api/chain-swap-recovery.md) is read-only lifecycle
status; it cannot select a destination or trigger execution.

Do not issue a refund if a claim transaction was constructed or broadcast. An
ambiguous provider response is a reason to defer, not a reason to risk paying
both sides.

### E. chain swap `refunding`

Check `refund_txid` and chain state before retrying anything. A process crash can
occur after broadcast but before the database records success. Prove whether the
persisted transaction or lockup output was spent, then reconcile the database
to chain evidence. Never move the row back to `refund_due` merely because the
worker or a chain backend timed out. The automatic worker replays only the exact
journaled bytes after a fresh authoritative recheck.

## Verify resolution

Resolution requires all three views to agree:

- chain evidence shows the merchant claim or payer refund outcome;
- the swap row contains the corresponding transaction ID and terminal state;
- invoice payment events and `settlement_status` represent that same outcome.

For a merchant claim, the expected path is `claim_stuck` to a revived claim
state to `claimed`, followed by idempotent settlement repair if the invoice flip
was interrupted. For payer recovery, the expected chain-swap path is
`refund_due` to `refunding` to `refunded`.

Keep the incident open if any view disagrees. Database state alone is not proof
that funds moved.

## Escalation criteria

Page an operator immediately when:

- a funded swap is past its expected recovery time and slow recovery is not
  advancing it;
- chain evidence conflicts with the database or provider response;
- a claim and refund both appear possible;
- a broadcast transaction is absent and rebuilding it would change its inputs,
  outputs, destination, or fee;
- settlement repair repeatedly fails after a confirmed merchant claim.

The preferred intervention is to restore the failed dependency and let the
idempotent workers continue. Manual state mutation is the last resort and must
be implemented as a reviewed, guarded operation rather than copied SQL.
