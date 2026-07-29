DO $$
DECLARE
    view_definition TEXT := pg_get_viewdef(
        'public.invoice_mixed_valuation_exceptions'::REGCLASS,
        TRUE
    );
BEGIN
    IF POSITION(
           'parent_invoice.pricing_mode = ''fiat_fixed''::text'
           IN view_definition
       ) = 0
       OR POSITION(
           'event.accounting_state = ''active''::text'
           IN view_definition
       ) = 0
       OR NOT EXISTS (
           SELECT 1
             FROM pg_class view_info
            WHERE view_info.oid =
                  'public.invoice_mixed_valuation_exceptions'::REGCLASS
              AND view_info.relkind = 'v'
              AND 'security_invoker=true' = ANY(view_info.reloptions)
       ) THEN
        RAISE EXCEPTION 'migration 082 did not install the exact view contract';
    END IF;

    IF NOT has_table_privilege(
               'bullnym_app', 'invoice_mixed_valuation_exceptions', 'SELECT')
       OR has_table_privilege(
               'bullnym_app', 'invoice_mixed_valuation_exceptions', 'INSERT')
       OR has_table_privilege(
               'bullnym_app', 'invoice_mixed_valuation_exceptions', 'UPDATE')
       OR has_table_privilege(
               'bullnym_app', 'invoice_mixed_valuation_exceptions', 'DELETE')
       OR has_table_privilege(
               'bullnym_app', 'invoice_mixed_valuation_exceptions', 'TRUNCATE')
       OR has_table_privilege(
               'public', 'invoice_mixed_valuation_exceptions', 'SELECT') THEN
        RAISE EXCEPTION 'migration 082 exception-view ACL is incorrect';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM invoice_mixed_valuation_exceptions
         WHERE bull_bitcoin_settlement_id =
               '67000000-0000-4000-8000-000000000003'
    ) THEN
        RAISE EXCEPTION 'migration 082 retained a sat-priced false positive';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM invoice_mixed_valuation_exceptions current_exception
          JOIN migration_082_view_snapshot prior_exception
            ON prior_exception.payment_event_id =
               current_exception.payment_event_id
           AND prior_exception.reason = current_exception.reason
         WHERE current_exception.bull_bitcoin_settlement_id =
               '71000000-0000-4000-8000-000000000006'
           AND prior_exception.pricing_mode = 'fiat_fixed'
    ) THEN
        RAISE EXCEPTION 'migration 082 hid or relabeled a fiat exception';
    END IF;

    IF EXISTS (
        SELECT event.*
          FROM invoice_payment_events event
         WHERE event.bull_bitcoin_settlement_id IN (
            '67000000-0000-4000-8000-000000000003',
            '71000000-0000-4000-8000-000000000006'
         )
        EXCEPT
        SELECT * FROM migration_082_event_snapshot
    ) OR EXISTS (
        SELECT * FROM migration_082_event_snapshot
        EXCEPT
        SELECT event.*
          FROM invoice_payment_events event
         WHERE event.bull_bitcoin_settlement_id IN (
            '67000000-0000-4000-8000-000000000003',
            '71000000-0000-4000-8000-000000000006'
         )
    ) THEN
        RAISE EXCEPTION 'migration 082 modified historical payment evidence';
    END IF;
END
$$;

DROP TABLE migration_082_view_snapshot;
DROP TABLE migration_082_event_snapshot;
