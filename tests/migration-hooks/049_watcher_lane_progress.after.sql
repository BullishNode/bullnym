DO $$
DECLARE
    lifecycle_status TEXT;
BEGIN
    SELECT status INTO lifecycle_status
      FROM invoices
     WHERE id = '49000000-0000-0000-0000-000000000001';
    IF lifecycle_status <> 'cancelled' THEN
        RAISE EXCEPTION 'migration 049 rewrote the closed invoice lifecycle';
    END IF;

    INSERT INTO watcher_lane_progress (
        worker, lane, cursor_created_at, cursor_invoice_id
    ) VALUES (
        'bitcoin_direct', 'historical',
        TIMESTAMPTZ '2026-01-01 00:00:00+00',
        '49000000-0000-0000-0000-000000000001'
    );

    UPDATE watcher_lane_progress
       SET cursor_created_at = TIMESTAMPTZ '2026-01-02 00:00:00+00',
           cursor_invoice_id = '49000000-0000-0000-0000-000000000002',
           updated_at = clock_timestamp()
     WHERE worker = 'bitcoin_direct' AND lane = 'historical';

    BEGIN
        INSERT INTO watcher_lane_progress (worker, lane)
        VALUES ('unknown_worker', 'recent');
        RAISE EXCEPTION 'migration 049 allowed an unknown watcher worker';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO watcher_lane_progress (
            worker, lane, cursor_created_at, cursor_invoice_id
        ) VALUES (
            'liquid_direct', 'unknown_lane', NULL, NULL
        );
        RAISE EXCEPTION 'migration 049 allowed an unknown watcher lane';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO watcher_lane_progress (
            worker, lane, cursor_created_at, cursor_invoice_id
        ) VALUES (
            'bitcoin_direct', 'recent',
            TIMESTAMPTZ '2026-01-01 00:00:00+00', NULL
        );
        RAISE EXCEPTION 'migration 049 allowed a partial watcher cursor';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO watcher_lane_progress (worker, lane)
        VALUES ('bitcoin_direct', 'historical');
        RAISE EXCEPTION 'migration 049 allowed a duplicate worker/lane row';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;
END
$$;
