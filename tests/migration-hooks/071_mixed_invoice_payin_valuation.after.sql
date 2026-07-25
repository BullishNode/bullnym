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
END
$$;
