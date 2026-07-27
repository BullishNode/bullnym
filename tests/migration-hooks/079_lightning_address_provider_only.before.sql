CREATE TABLE migration_078_fiat_only_snapshot AS
SELECT id, owner_npub, invoice_id, reverse_swap_id, chain_swap_id,
       credential_id, product, purpose, payer_rail, request_key,
       fiat_percentage, fiat_currency, requested_bitcoin_sat,
       bull_bitcoin_order_id, provider_state, funding_route,
       funding_committed_at, settlement_status, instruction_kind,
       payer_instruction, actual_received_sat, credited_fiat_minor,
       provider_final, terminal_at, created_at, updated_at
  FROM bull_bitcoin_settlements
 WHERE purpose = 'fiat_only';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM migration_078_fiat_only_snapshot) THEN
        RAISE EXCEPTION 'migration 078 fixture requires a historical direct-provider row';
    END IF;
END
$$;
