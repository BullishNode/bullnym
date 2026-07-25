DO $$
BEGIN
    IF to_regclass('public.invoice_mixed_valuation_exceptions') IS NULL THEN
        RAISE EXCEPTION 'migration 071 did not expose unresolved mixed valuation evidence';
    END IF;

    IF NOT has_table_privilege(
               'bullnym_app', 'invoice_mixed_valuation_exceptions', 'SELECT')
       OR has_table_privilege(
               'bullnym_app', 'invoice_mixed_valuation_exceptions', 'INSERT')
       OR has_table_privilege(
               'public', 'invoice_mixed_valuation_exceptions', 'SELECT') THEN
        RAISE EXCEPTION 'migration 071 exception-view ACL is unsafe';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
          JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
         WHERE trigger_info.tgrelid = 'invoice_payment_events'::regclass
           AND trigger_info.tgname = 'invoice_payment_events_guard_quote_attribution'
           AND trigger_info.tgenabled = 'O'
           AND NOT trigger_info.tgisinternal
           AND function_info.proname = 'guard_invoice_payment_quote_attribution'
           AND pg_get_triggerdef(trigger_info.oid) NOT LIKE
               '%bull_bitcoin_mixed_output%'
    ) THEN
        RAISE EXCEPTION 'migration 071 did not restore quote valuation for mixed outputs';
    END IF;

    -- Migration 069's deliberately unattributed fixture has no immutable quote
    -- authority. It must remain unchanged and visible, never receive a guessed
    -- fiat amount during upgrade.
    IF NOT EXISTS (
        SELECT 1 FROM invoice_mixed_valuation_exceptions
         WHERE bull_bitcoin_settlement_id =
               '67000000-0000-4000-8000-000000000003'
           AND reason = 'missing_parent_quote_attribution'
    ) OR EXISTS (
        SELECT 1 FROM invoice_payment_events
         WHERE bull_bitcoin_settlement_id =
               '67000000-0000-4000-8000-000000000003'
           AND fiat_credited_minor IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 071 fabricated legacy valuation evidence';
    END IF;

    -- The fully attributed fixture must be repaired without changing the
    -- number or identity of its two payment evidence rows, and its parent
    -- invoice cache must immediately reflect the complete mixed payment.
    IF (SELECT COUNT(*) FROM invoice_payment_events
         WHERE invoice_id = '71000000-0000-4000-8000-000000000001') <> 2
       OR NOT EXISTS (
           SELECT 1
             FROM invoice_payment_events
            WHERE bull_bitcoin_settlement_id =
                  '71000000-0000-4000-8000-000000000006'
              AND invoice_quote_version_id IS NOT NULL
              AND invoice_quote_offer_id =
                  '71000000-0000-4000-8000-000000000004'
              AND quote_first_observed_at IS NOT NULL
              AND fiat_credited_minor = 400
              AND fiat_credit_policy = 'quote_cumulative_saturation_v1'
              AND fiat_valuation_quote_version_id = invoice_quote_version_id
              AND fiat_rate_minor_per_btc = 30000000
       ) OR EXISTS (
           SELECT 1
             FROM invoice_mixed_valuation_exceptions
            WHERE bull_bitcoin_settlement_id =
                  '71000000-0000-4000-8000-000000000006'
       ) OR NOT EXISTS (
           SELECT 1
             FROM invoices
            WHERE id = '71000000-0000-4000-8000-000000000001'
              AND status = 'paid'
              AND presentation_status = 'payment_received'
              AND paid_via = 'mixed'
              AND paid_amount_sat = 3334
              AND paid_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 071 did not repair event and invoice projection atomically';
    END IF;
END
$$;
