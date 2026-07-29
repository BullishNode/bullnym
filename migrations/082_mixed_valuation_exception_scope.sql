-- ============================================================================
-- 082: scope mixed valuation exceptions to fiat-priced invoices
-- ============================================================================
--
-- Sat-priced invoices have no fiat face value to reconstruct. Preserve all
-- payment evidence and narrow only the operator exception projection.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE), ''
    );
    runtime_role_oid OID;
    view_owner_oid OID;
BEGIN
    SELECT oid INTO runtime_role_oid
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF runtime_role_name IS NULL OR runtime_role_oid IS NULL THEN
        RAISE EXCEPTION 'migration 082 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 082 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;

    SELECT relowner INTO view_owner_oid
      FROM pg_class
     WHERE oid = to_regclass('public.invoice_mixed_valuation_exceptions')
       AND relkind = 'v';
    IF view_owner_oid IS NULL
       OR pg_get_userbyid(view_owner_oid) <> current_user THEN
        RAISE EXCEPTION 'migration 082 must run as the exception-view owner'
            USING ERRCODE = '42501';
    END IF;
    IF runtime_role_oid = view_owner_oid
       OR pg_has_role(runtime_role_oid, view_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, view_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 082 runtime role can assume the exception-view owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE OR REPLACE VIEW invoice_mixed_valuation_exceptions
WITH (security_invoker = TRUE)
AS
SELECT event.id AS payment_event_id,
       event.invoice_id,
       event.bull_bitcoin_settlement_id,
       event.amount_sat,
       event.accounting_sequence,
       event.created_at,
       CASE
           WHEN COALESCE(reverse_swap.invoice_quote_version_id,
                         chain_swap.invoice_quote_version_id) IS NULL
             OR COALESCE(reverse_swap.invoice_quote_offer_id,
                         chain_swap.invoice_quote_offer_id) IS NULL
               THEN 'missing_parent_quote_attribution'
           WHEN COALESCE(reverse_swap.quote_payment_first_observed_at,
                         chain_swap.quote_payment_first_observed_at) IS NULL
               THEN 'missing_parent_first_observed_at'
           ELSE 'valuation_unavailable_for_observation_time'
       END AS reason
  FROM invoice_payment_events event
  JOIN invoices parent_invoice
    ON parent_invoice.id = event.invoice_id
   AND parent_invoice.pricing_mode = 'fiat_fixed'
  JOIN bull_bitcoin_settlements settlement
    ON settlement.id = event.bull_bitcoin_settlement_id
   AND settlement.purpose = 'mixed'
  LEFT JOIN swap_records reverse_swap
    ON reverse_swap.id = settlement.reverse_swap_id
  LEFT JOIN chain_swap_records chain_swap
    ON chain_swap.id = settlement.chain_swap_id
 WHERE event.source = 'bull_bitcoin_mixed_output'
   AND event.accounting_state = 'active'
   AND event.fiat_credited_minor IS NULL;

COMMENT ON VIEW invoice_mixed_valuation_exceptions IS
    'Active fiat-priced mixed invoice pay-in evidence that cannot be valued without inventing quote/rate authority; sat-priced invoices are intentionally excluded.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE invoice_mixed_valuation_exceptions FROM PUBLIC;
    EXECUTE format(
        'REVOKE ALL ON TABLE invoice_mixed_valuation_exceptions FROM %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT ON TABLE invoice_mixed_valuation_exceptions TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
