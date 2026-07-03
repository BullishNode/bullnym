# Runbook: stuck and lost-fund swaps

Two operator-attention statuses exist on `swap_records`:

- **`claim_stuck`** — auto-retry budget exhausted. The swap is recoverable
  if the underlying problem is fixed; this status just means "stop
  hammering Boltz/Electrum, ask a human."
- **`lockup_refunded`** — Boltz auto-refunded its on-chain lockup before
  we claimed. The user paid the LN invoice and got nothing back. **Fund
  loss.** Not recoverable by us; this runbook helps document the
  incident.

Both are terminal in the state machine — the background sweep and the
reconciler ignore them — so a row in either status sits there until an
operator acts.

---

## Detect

```sql
-- Any rows currently parked for human attention.
SELECT id, nym, boltz_swap_id, status, claim_attempts,
       last_claim_error, last_claim_error_at, claim_path,
       cooperative_refused, current_fee_rate
FROM swap_records
WHERE status IN ('claim_stuck', 'lockup_refunded')
ORDER BY last_claim_error_at DESC NULLS LAST;
```

Or, scoped at the two log events the claim path emits:

```bash
journalctl -u pay-service | grep -E 'swap_claim_stuck|swap_lockup_refunded'
```

---

## `claim_stuck`: diagnose and rescue

### 1. Read `last_claim_error` first

It's the operator-facing surface. Common shapes:

- `broadcast failed: <electrum-protocol-error>` — Electrum URL wrong,
  network partition, mempool refused for some non-fee reason.
- `broadcast failed: ... min relay fee not met` — Liquid relay floor
  drifted above our `claim_fee_sat_per_vb` (currently hardcoded at
  `0.1 sat/vB`). Fix the config and retry.
- `construct_claim failed: ...` — Boltz API returned an error during
  cooperative MuSig2 signing or during fetch_utxo / fetch_lockup. Check
  Boltz status page first.
- `decode persisted claim_tx: ...` — `claim_tx_hex` is corrupt. Wipe
  it and let the next attempt rebuild.

### 2. Cross-check against Boltz

```bash
curl -s "$BOLTZ_API_URL/swap/$BOLTZ_SWAP_ID" | jq .
```

Take Boltz's `status` as truth. If Boltz says `transaction.refunded`,
this row should be `lockup_refunded`, not `claim_stuck` — fix the row
status manually:

```sql
UPDATE swap_records
SET status = 'lockup_refunded', updated_at = NOW()
WHERE id = '<id>';
```

### 3. Rescue: reset and retry

The standard rescue resets `claim_attempts`, schedules an immediate
retry, and clears the persisted claim tx so the next attempt rebuilds
from scratch:

```sql
UPDATE swap_records
SET status            = 'lockup_confirmed',
    claim_attempts    = 0,
    next_claim_attempt_at = NOW(),
    claim_tx_hex      = NULL,
    claim_txid        = NULL,
    last_claim_error  = NULL,
    last_claim_error_at = NULL
WHERE id = '<id>';
```

The next sweep tick (<=10s) picks it up.

### 4. Variants

**Force the script-path** (skip cooperative MuSig2 — useful if Boltz
cooperative is broken or the swap has crossed `swap.expired`):

```sql
UPDATE swap_records
SET status            = 'lockup_confirmed',
    claim_attempts    = 0,
    next_claim_attempt_at = NOW(),
    claim_tx_hex      = NULL,
    claim_txid        = NULL,
    last_claim_error  = NULL,
    last_claim_error_at = NULL,
    cooperative_refused = TRUE     -- <-- forces script path
WHERE id = '<id>';
```

**Reset cooperative** (if you previously forced script-path and want to
go back to cooperative):

```sql
UPDATE swap_records
SET cooperative_refused = FALSE,
    claim_tx_hex        = NULL,
    claim_txid          = NULL,
    next_claim_attempt_at = NOW()
WHERE id = '<id>';
```

**Bump fee rate** (if relay-fee was the failure):

```sql
UPDATE swap_records
SET current_fee_rate    = 0.5,
    claim_tx_hex        = NULL,
    claim_txid          = NULL,
    next_claim_attempt_at = NOW(),
    status              = 'lockup_confirmed',
    claim_attempts      = 0
WHERE id = '<id>';
```

### 5. Verify recovery

After the next sweep tick, check:

```sql
SELECT status, claim_attempts, claim_txid, last_claim_error
FROM swap_records WHERE id = '<id>';
```

Expected progression: `lockup_confirmed → claiming → claimed`. If the
row is back at `claim_stuck` with the same `last_claim_error`, the
underlying problem persists — escalate.

---

## `lockup_refunded`: incident, not rescue

This means Boltz spent its own lockup output via the refund path
(timelock + Boltz signature) before we got our claim tx into the
network. The user's LN-side hold invoice was paid, the preimage was
disclosed (or expired), and there is now no on-chain output for us
to claim.

**Funds are gone from the user's perspective.** They paid LN and
received nothing back.

Treat as a P0 incident:

1. Capture: nym, amount_sat, boltz_swap_id, last_claim_error_at,
   timeoutBlockHeight (look at boltz_response_json), Liquid block height
   when refund landed.
2. Reach out to the user via npub / out-of-band contact.
3. Reconcile against support (refund out-of-band, manual adjustment,
   or write-off depending on cause).
4. Post-mortem: was this a webhook delivery failure, a Boltz API
   outage, a Liquid functionary issue, or our infra? File the
   findings against the next claim-path improvement cycle.

The row stays in `lockup_refunded` permanently — it's the audit
trail. Do not flip it to `expired` or any other status.

---

## Triggering events to monitor

Structured `tracing` events the claim path emits (filter via your log
aggregator):

| Event                                    | Meaning                                      |
|------------------------------------------|----------------------------------------------|
| `swap_claim_stuck`                       | Row hit `max_claim_attempts` → `claim_stuck` |
| `swap_lockup_refunded`                   | FUND LOSS — `transaction.refunded` observed  |
| `swap_cooperative_refused_runtime`       | Cooperative MuSig2 endpoint refused; flipped |
| `swap_expired_webhook`                   | Boltz wall-clock expiry; script-path retry   |
| `claim_broadcast_probe_recovered`        | Broadcast errored but tx is on chain — fine  |
| `reconciler_advance`                     | Reconciler caught a missed webhook           |
| `reconciler_swap_expired`                | Reconciler caught a missed `swap.expired`    |
| `reconciler_expired`                     | LN side dead — terminal `expired`            |
| `reconciler_needs_attention`             | Boltz says settled; we say not — diagnose    |

`swap_claim_stuck` and `swap_lockup_refunded` warrant pages.
`reconciler_advance` is informational unless it fires very frequently
(then webhooks are systematically being lost).
