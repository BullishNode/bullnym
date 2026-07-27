# Bull Bitcoin ambiguous-create recovery

This runbook applies only to a settlement whose provider state is
`dispatch_started`. That state means Bullnym durably crossed the provider-create
boundary but cannot yet prove whether the create succeeded. It is a financial
integrity hold: do not retry `sellToBalance`, select Bitcoin fallback, or guess
that no provider order exists.

Every create sends the local settlement UUID both as its JSON-RPC request ID
and as the HTTP `X-Request-ID`, so the provider request log and echoed response
share one durable correlation identity. A valid echoed response binds normally.
An otherwise invalid correlated response may leave a candidate provider order
UUID on the settlement; the reconciler reads that exact order with the
settlement's retained credential and binds it only after its currency, network,
Bitcoin amount, payer instruction, and any persisted mixed-claim Liquid script
shape match the committed request.

## Triage

As the privileged schema owner, inspect only the local normalized record:

```sql
SELECT id, credential_id, request_key, product, purpose, payer_rail,
       fiat_currency, requested_bitcoin_sat, provider_state,
       bull_bitcoin_order_id, order_correlation_source,
       order_correlated_at, expected_instruction_script_len,
       funding_route, settlement_status,
       funding_committed_at, actual_received_sat, provider_final, terminal_at
FROM bull_bitcoin_settlements
WHERE id = :'settlement_id';
```

If `bull_bitcoin_order_id` is present, do not attach another ID. Allow exact
reconciliation to validate it. A repeated provider `NotFound` is not proof that
the create failed and does not authorize fallback or redispatch.

If the order ID is absent, correlate the provider request through the trusted
provider-side audit record using the settlement UUID request ID. Do not search
by amount alone, copy credentials, inspect unrelated account history, or infer
absence from a timeout. Stop if there is not exactly one authoritative order
candidate.

## Guarded attachment

The attachment function is executable only by the schema owner. Supply all
four values from independently verified records:

```sql
SELECT attach_ambiguous_bull_bitcoin_order(
    :'settlement_id'::uuid,
    :'expected_credential_id'::uuid,
    :'expected_request_key'::text,
    :'candidate_order_id'::uuid
);
```

The function locks the row and rejects a wrong credential, wrong request key,
different existing order ID, non-ambiguous state, terminal state, funding,
claim-output evidence, received-funds evidence, or invoice-payment evidence.
It only records correlation evidence and wakes reconciliation. It does not
bind, fund, terminalize, expose a payer instruction, or call the provider.
Repeating the exact attachment returns `false` and makes no change.

After attachment, require the ordinary reconciler to read and validate the
exact provider order. Success changes the row to `bound`; a mismatch remains
fail-closed and must be investigated rather than overridden.

```sql
SELECT id, provider_state, bull_bitcoin_order_id,
       order_correlation_source, order_correlated_at,
       funding_route, settlement_status, last_checked_at,
       reconcile_attempts
FROM bull_bitcoin_settlements
WHERE id = :'settlement_id';
```

Record the settlement ID, operator identity, correlation evidence location,
candidate order ID, attachment result, and final reconciler result in the
private incident record. Never put API keys, provider response bodies, payer
instructions, or customer account data in logs, tickets, or public issues.
