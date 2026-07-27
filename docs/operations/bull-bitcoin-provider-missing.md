# Bull Bitcoin provider-order missing audit

Migration 080 intentionally does not infer historical `NotFound` evidence from
the generic retry counter. A retry may have represented a timeout, transport
failure, or upstream 5xx, so converting old counts into missing-order evidence
would be unsafe.

After migration and before enabling new fiat settlement admission, inspect the
historical candidate set as the schema owner or a dedicated read-only operator:

```sql
SELECT id,
       purpose,
       reconcile_attempts,
       instruction_expires_at,
       last_checked_at,
       actual_received_sat,
       funding_committed_at,
       provider_missing_since
  FROM bull_bitcoin_settlements
 WHERE provider_state = 'bound'
   AND funding_route = 'bull_bitcoin'
   AND NOT provider_final
   AND settlement_status = 'pending'
   AND bull_bitcoin_order_id IS NOT NULL
   AND instruction_expires_at < now()
 ORDER BY reconcile_attempts DESC, created_at, id;
```

This query is an audit, not a terminalization command. Do not delete a binding,
erase its credential, create a replacement, or manually label it missing based
on retry count. Once the 0.4 worker runs, it records authenticated exact-order
404s from zero, requires the configured count and time thresholds plus a
healthy authenticated provider preflight, then suppresses the instruction and
enters the explicit integrity hold.

For every escalated row, reconcile the immutable order ID against provider and
local money evidence. Any payment, claim output, invoice payment event, or
provider received-funds evidence remains a liability and requires attention.
A later authoritative observation for the same order lets the worker resolve
the hold. Replacement requires a separate explicit, audited decision and is
never performed by this runbook.

