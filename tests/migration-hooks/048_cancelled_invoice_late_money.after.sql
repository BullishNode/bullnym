DO $$
DECLARE
    lifecycle_status TEXT;
BEGIN
    UPDATE invoices
       SET presentation_status = 'payment_received',
           paid_via = 'liquid',
           paid_amount_sat = 1000,
           paid_at = TIMESTAMPTZ '2026-01-01 00:00:01+00',
           direct_settlement_status = 'settled',
           settlement_status = 'settled'
     WHERE id = '48000000-0000-0000-0000-000000000001';

    SELECT status INTO lifecycle_status
      FROM invoices
     WHERE id = '48000000-0000-0000-0000-000000000001';
    IF lifecycle_status <> 'cancelled' THEN
        RAISE EXCEPTION 'migration 048 rewrote the cancellation marker';
    END IF;

    BEGIN
        UPDATE invoices
           SET status = 'unpaid', paid_via = 'liquid'
         WHERE id = '48000000-0000-0000-0000-000000000001';
        RAISE EXCEPTION 'migration 048 allowed paid_via on an active unpaid invoice';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;
