-- Prevent new mixed obligations without the exact confidential-destination
-- material required to construct and verify the eventual Liquid claim.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

CREATE FUNCTION guard_invoice_fiat_policy_mixed_blinding_key()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.fiat_percentage BETWEEN 1 AND 99
       AND NOT EXISTS (
           SELECT 1
             FROM invoices invoice
            WHERE invoice.id = NEW.invoice_id
              AND invoice.liquid_address IS NOT NULL
              AND invoice.liquid_blinding_key_hex IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'mixed fiat settlement requires complete Liquid destination material'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_fiat_policy_mixed_blinding_key_required';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoice_fiat_policy_guard_mixed_blinding_key
    BEFORE INSERT ON invoice_fiat_settlement_policies
    FOR EACH ROW
    EXECUTE FUNCTION guard_invoice_fiat_policy_mixed_blinding_key();

-- Existing rows are never rewritten by this migration. Missing material and
-- any later claim-time address/key mismatch remain inspectable as explicit
-- integrity work, while the claim scheduler excludes the latter from revival.
CREATE VIEW mixed_invoice_integrity_holds
WITH (security_invoker = TRUE)
AS
SELECT policy.invoice_id,
       NULL::UUID AS reverse_swap_id,
       NULL::UUID AS chain_swap_id,
       'legacy_invoice_missing_blinding_material'::TEXT AS reason,
       policy.captured_at AS detected_at
  FROM invoice_fiat_settlement_policies policy
  JOIN invoices invoice ON invoice.id = policy.invoice_id
 WHERE policy.fiat_percentage BETWEEN 1 AND 99
   AND (invoice.liquid_address IS NULL
        OR invoice.liquid_blinding_key_hex IS NULL)
UNION ALL
SELECT swap.invoice_id,
       swap.id AS reverse_swap_id,
       NULL::UUID AS chain_swap_id,
       swap.last_claim_error AS reason,
       swap.last_claim_error_at AS detected_at
  FROM swap_records swap
 WHERE swap.status = 'claim_stuck'
   AND swap.last_claim_error LIKE 'mixed_invoice_integrity_hold:%'
UNION ALL
SELECT swap.invoice_id,
       NULL::UUID AS reverse_swap_id,
       swap.id AS chain_swap_id,
       swap.last_claim_error AS reason,
       swap.last_claim_error_at AS detected_at
  FROM chain_swap_records swap
 WHERE swap.status = 'claim_stuck'
   AND swap.last_claim_error LIKE 'mixed_invoice_integrity_hold:%';

COMMENT ON VIEW mixed_invoice_integrity_holds IS
    'Mixed invoice destination/key defects that require operator repair and are excluded from automatic claim revival.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON FUNCTION guard_invoice_fiat_policy_mixed_blinding_key() FROM PUBLIC;
    REVOKE ALL ON TABLE mixed_invoice_integrity_holds FROM PUBLIC;
    EXECUTE format(
        'GRANT SELECT ON TABLE mixed_invoice_integrity_holds TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
