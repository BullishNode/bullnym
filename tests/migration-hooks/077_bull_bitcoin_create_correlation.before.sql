CREATE TABLE migration_077_bound_snapshot AS
SELECT id, bull_bitcoin_order_id, provider_state, funding_route,
       settlement_status, instruction_kind, payer_instruction,
       actual_received_sat, credited_fiat_minor, provider_final,
       created_at, updated_at
  FROM bull_bitcoin_settlements
 WHERE bull_bitcoin_order_id IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM migration_077_bound_snapshot) THEN
        RAISE EXCEPTION 'migration 077 fixture requires a preexisting bound order';
    END IF;
END
$$;
