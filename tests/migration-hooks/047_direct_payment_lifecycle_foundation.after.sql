DO $$
DECLARE
    cached RECORD;
    btc_event RECORD;
    liquid_event RECORD;
    boltz_event RECORD;
    legacy_observation RECORD;
    zero_conf_cached RECORD;
    zero_conf_observation RECORD;
    row_count BIGINT;
    privilege_ok BOOLEAN;
BEGIN
    SELECT status, paid_via, paid_amount_sat,
           EXTRACT(EPOCH FROM paid_at)::BIGINT AS paid_at_unix,
           settlement_status, presentation_status,
           direct_settlement_status, swap_settlement_status,
           direct_payment_projection_version
      INTO cached
      FROM invoices
     WHERE id = '47000000-0000-0000-0000-000000000001';

    IF cached.status <> 'paid'
       OR cached.paid_via <> 'mixed'
       OR cached.paid_amount_sat <> 100000
       OR cached.paid_at_unix <> 1767225604
       OR cached.settlement_status <> 'settled'
       OR cached.presentation_status <> 'payment_received'
       OR cached.direct_settlement_status <> 'settled'
       OR cached.swap_settlement_status <> 'settled'
       OR cached.direct_payment_projection_version <> 0 THEN
        RAISE EXCEPTION 'migration 047 changed or misclassified cached invoice money state';
    END IF;

    SELECT accounting_state, accounting_sequence, verification_state,
           observation_id, last_activated_at, deactivated_at,
           deactivation_reason, superseded_by_event_id
      INTO btc_event
      FROM invoice_payment_events
     WHERE id = '47000000-0000-0000-0000-000000000003';

    SELECT accounting_state, accounting_sequence, verification_state,
           observation_id, last_activated_at, deactivated_at,
           deactivation_reason, superseded_by_event_id
      INTO liquid_event
      FROM invoice_payment_events
     WHERE id = '47000000-0000-0000-0000-000000000004';

    SELECT accounting_state, accounting_sequence, verification_state,
           observation_id, last_activated_at, deactivated_at,
           deactivation_reason, superseded_by_event_id
      INTO boltz_event
      FROM invoice_payment_events
     WHERE id = '47000000-0000-0000-0000-000000000005';

    IF btc_event.accounting_state <> 'legacy_unverified'
       OR btc_event.verification_state <> 'legacy_unverified'
       OR btc_event.observation_id <> '47000000-0000-0000-0000-000000000002'::UUID
       OR btc_event.last_activated_at IS NULL
       OR btc_event.deactivated_at IS NOT NULL
       OR btc_event.deactivation_reason IS NOT NULL
       OR btc_event.superseded_by_event_id IS NOT NULL THEN
        RAISE EXCEPTION 'migration 047 did not preserve/link legacy BTC accounting';
    END IF;

    IF liquid_event.accounting_state <> 'legacy_unverified'
       OR liquid_event.verification_state <> 'legacy_unverified'
       OR liquid_event.observation_id IS NOT NULL
       OR liquid_event.last_activated_at IS NULL
       OR liquid_event.deactivated_at IS NOT NULL
       OR liquid_event.deactivation_reason IS NOT NULL
       OR liquid_event.superseded_by_event_id IS NOT NULL THEN
        RAISE EXCEPTION 'migration 047 fabricated or deactivated legacy Liquid accounting';
    END IF;

    IF boltz_event.accounting_state <> 'active'
       OR boltz_event.verification_state <> 'not_applicable'
       OR boltz_event.observation_id IS NOT NULL
       OR boltz_event.last_activated_at IS NULL
       OR boltz_event.deactivated_at IS NOT NULL
       OR boltz_event.deactivation_reason IS NOT NULL
       OR boltz_event.superseded_by_event_id IS NOT NULL THEN
        RAISE EXCEPTION 'migration 047 changed existing Boltz accounting';
    END IF;

    IF NOT (
        btc_event.accounting_sequence < liquid_event.accounting_sequence
        AND liquid_event.accounting_sequence < boltz_event.accounting_sequence
    ) THEN
        RAISE EXCEPTION 'migration 047 accounting sequence is not deterministic';
    END IF;

    SELECT last_seen_state, verification_state, asset_id,
           lifecycle_version, last_applied_generation, absence_streak,
           invalidation_reason, invalidated_at, superseded_by_observation_id,
           superseded_by_payment_event_id
      INTO legacy_observation
      FROM invoice_payment_observations
     WHERE id = '47000000-0000-0000-0000-000000000002';

    IF legacy_observation.last_seen_state <> 'counted'
       OR legacy_observation.verification_state <> 'legacy_unverified'
       OR legacy_observation.asset_id IS NOT NULL
       OR legacy_observation.lifecycle_version <> 0
       OR legacy_observation.last_applied_generation <> 0
       OR legacy_observation.absence_streak <> 0
       OR legacy_observation.invalidation_reason IS NOT NULL
       OR legacy_observation.invalidated_at IS NOT NULL
       OR legacy_observation.superseded_by_observation_id IS NOT NULL
       OR legacy_observation.superseded_by_payment_event_id IS NOT NULL THEN
        RAISE EXCEPTION 'migration 047 invented legacy observation truth';
    END IF;

    SELECT status, settlement_status, presentation_status,
           direct_settlement_status, swap_settlement_status,
           paid_via, paid_amount_sat
      INTO zero_conf_cached
      FROM invoices
     WHERE id = '47000000-0000-0000-0000-000000000010';

    IF zero_conf_cached.status <> 'in_progress'
       OR zero_conf_cached.settlement_status <> 'pending'
       OR zero_conf_cached.presentation_status IS NOT NULL
       OR zero_conf_cached.direct_settlement_status <> 'pending'
       OR zero_conf_cached.swap_settlement_status <> 'none'
       OR zero_conf_cached.paid_via IS NOT NULL
       OR zero_conf_cached.paid_amount_sat IS NOT NULL THEN
        RAISE EXCEPTION 'migration 047 misattributed zero-conf direct settlement';
    END IF;

    SELECT last_seen_state, verification_state, lifecycle_version,
           superseded_by_observation_id, superseded_by_payment_event_id
      INTO zero_conf_observation
      FROM invoice_payment_observations
     WHERE id = '47000000-0000-0000-0000-000000000011';

    IF zero_conf_observation.last_seen_state <> 'seen_unconfirmed'
       OR zero_conf_observation.verification_state <> 'legacy_unverified'
       OR zero_conf_observation.lifecycle_version <> 0
       OR zero_conf_observation.superseded_by_observation_id IS NOT NULL
       OR zero_conf_observation.superseded_by_payment_event_id IS NOT NULL THEN
        RAISE EXCEPTION 'migration 047 changed zero-conf direct evidence';
    END IF;

    SELECT COUNT(*) INTO row_count
      FROM invoice_payment_events
     WHERE invoice_id = '47000000-0000-0000-0000-000000000010';
    IF row_count <> 0 THEN
        RAISE EXCEPTION 'migration 047 fabricated zero-conf accounting';
    END IF;

    SELECT COUNT(*) INTO row_count
      FROM invoice_payment_observations
     WHERE invoice_id = '47000000-0000-0000-0000-000000000001';
    IF row_count <> 1 THEN
        RAISE EXCEPTION 'migration 047 fabricated a missing Liquid observation';
    END IF;

    SELECT COUNT(*) INTO row_count FROM invoice_direct_scan_heads;
    IF row_count <> 0 THEN
        RAISE EXCEPTION 'migration 047 fabricated scan heads';
    END IF;

    SELECT COUNT(*) INTO row_count FROM invoice_direct_payment_transitions;
    IF row_count <> 0 THEN
        RAISE EXCEPTION 'migration 047 fabricated lifecycle transitions';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'invoice_direct_payment_transitions'
           AND t.tgname = 'invoice_direct_payment_transition_history_guard'
           AND NOT t.tgisinternal
           AND t.tgenabled IN ('O', 'A')
    ) THEN
        RAISE EXCEPTION 'migration 047 append-only DML guard is absent or disabled';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'invoice_payment_events'
           AND t.tgname = 'invoice_payment_event_compatibility_insert_classifier'
           AND NOT t.tgisinternal
           AND t.tgenabled IN ('O', 'A')
    ) THEN
        RAISE EXCEPTION 'migration 047 compatibility insert classifier is absent or disabled';
    END IF;

    BEGIN
        UPDATE invoice_payment_events
           SET amount_sat = amount_sat + 1
         WHERE id = '47000000-0000-0000-0000-000000000003';
        RAISE EXCEPTION 'migration 047 allowed payment evidence mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE invoice_payment_observations
           SET address = 'bc1q047changed000000000000000000000000000000'
         WHERE id = '47000000-0000-0000-0000-000000000002';
        RAISE EXCEPTION 'migration 047 allowed observation identity mutation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE invoice_payment_events
           SET accounting_state = 'inactive',
               deactivated_at = NOW(),
               deactivation_reason = 'not_confirmed'
         WHERE id = '47000000-0000-0000-0000-000000000003';

        UPDATE invoice_payment_events
           SET accounting_state = 'legacy_unverified',
               deactivated_at = NULL,
               deactivation_reason = NULL
         WHERE id = '47000000-0000-0000-0000-000000000003';
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'migration 047 rejected the not_confirmed inactive anchor: %', SQLERRM;
    END;

    BEGIN
        INSERT INTO invoice_direct_scan_heads (
            invoice_id, source, issued_generation, applied_generation
        ) VALUES (
            '47000000-0000-0000-0000-000000000001',
            'bitcoin_direct', 1, 2
        );
        RAISE EXCEPTION 'migration 047 allowed applied generation beyond issued';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        SELECT has_table_privilege(
            'payservice', 'invoice_direct_scan_heads', 'SELECT,INSERT,UPDATE'
        ) INTO privilege_ok;
        IF privilege_ok IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'migration 047 scan-head grants are incomplete';
        END IF;

        SELECT has_table_privilege(
            'payservice', 'invoice_direct_payment_transitions', 'SELECT,INSERT'
        ) INTO privilege_ok;
        IF privilege_ok IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'migration 047 transition read/append grants are incomplete';
        END IF;

        SELECT has_sequence_privilege(
            'payservice', 'invoice_payment_events_accounting_sequence_seq', 'USAGE'
        ) INTO privilege_ok;
        IF privilege_ok IS DISTINCT FROM TRUE THEN
            RAISE EXCEPTION 'migration 047 accounting sequence grant is missing';
        END IF;
    END IF;

    -- The production deployment applies migrations as payservice, so table
    -- ownership makes ACL-only immutability ineffective. Exercise the DML guard
    -- as the migration owner, including the intentional invoice cascade path.
    INSERT INTO invoices (
        id, nym_owner, npub_owner, origin, amount_sat, rate_locks_until,
        liquid_address, accept_btc, accept_ln, accept_liquid,
        status, settlement_status, expires_at
    ) VALUES (
        '47000000-0000-0000-0000-000000000020',
        NULL, repeat('e', 64), 'wallet', 1000,
        TIMESTAMPTZ '2027-01-01 00:00:00+00',
        'lq1q047cascadefixture0000000000000000000000000',
        FALSE, FALSE, TRUE, 'unpaid', 'none',
        TIMESTAMPTZ '2027-01-01 00:00:00+00'
    );

    INSERT INTO invoice_payment_events (
        id, invoice_id, rail, source, event_key, amount_sat,
        txid, vout, address
    ) VALUES (
        '47000000-0000-0000-0000-000000000021',
        '47000000-0000-0000-0000-000000000020',
        'liquid', 'liquid_direct',
        'liquid_direct:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee:0',
        1000, repeat('e', 64), 0,
        'lq1q047cascadefixture0000000000000000000000000'
    );

    INSERT INTO invoice_payment_events (
        id, invoice_id, rail, source, event_key, amount_sat,
        txid, boltz_swap_id
    ) VALUES (
        '47000000-0000-0000-0000-000000000022',
        '47000000-0000-0000-0000-000000000020',
        'lightning', 'lightning_boltz_reverse',
        'lightning_boltz_reverse:migration-047-cascade',
        1000, repeat('f', 64), 'migration-047-cascade'
    );

    IF EXISTS (
        SELECT 1 FROM invoice_payment_events
         WHERE id = '47000000-0000-0000-0000-000000000021'
           AND (
             accounting_state <> 'legacy_unverified'
             OR verification_state <> 'legacy_unverified'
           )
    ) THEN
        RAISE EXCEPTION 'migration 047 misclassified old-binary direct insert';
    END IF;

    IF EXISTS (
        SELECT 1 FROM invoice_payment_events
         WHERE id = '47000000-0000-0000-0000-000000000022'
           AND (
             accounting_state <> 'active'
             OR verification_state <> 'not_applicable'
           )
    ) THEN
        RAISE EXCEPTION 'migration 047 misclassified old-binary Boltz insert';
    END IF;

    INSERT INTO invoice_payment_events (
        id, invoice_id, rail, source, event_key, amount_sat,
        txid, vout, address, accounting_state, verification_state,
        last_activated_at, deactivated_at, deactivation_reason
    ) VALUES (
        '47000000-0000-0000-0000-000000000025',
        '47000000-0000-0000-0000-000000000020',
        'bitcoin', 'bitcoin_direct',
        'bitcoin_direct:abababababababababababababababababababababababababababababababab:1',
        1000, repeat('ab', 32), 1,
        'bc1q047neveractivated0000000000000000000000000',
        'inactive', 'unclassified', NULL, NOW(), 'not_confirmed'
    );

    IF (SELECT last_activated_at IS NOT NULL
               OR accounting_state <> 'inactive'
               OR verification_state <> 'unclassified'
          FROM invoice_payment_events
         WHERE id = '47000000-0000-0000-0000-000000000025') THEN
        RAISE EXCEPTION 'migration 047 fabricated activation for inactive evidence';
    END IF;

    INSERT INTO invoice_payment_observations (
        id, invoice_id, rail, source, event_key, txid, vout, address,
        amount_sat, asset_id, confirmations, last_seen_state,
        verification_state, invalidation_reason, invalidated_at,
        superseded_by_payment_event_id
    ) VALUES (
        '47000000-0000-0000-0000-000000000023',
        '47000000-0000-0000-0000-000000000020',
        'liquid', 'liquid_direct',
        'liquid_direct:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee:0',
        repeat('e', 64), 0,
        'lq1q047cascadefixture0000000000000000000000000',
        1000, repeat('a', 64), 1, 'superseded', 'verified',
        'boltz_supersession', NOW(),
        '47000000-0000-0000-0000-000000000022'
    );

    INSERT INTO invoice_direct_payment_transitions (
        id, idempotency_key, invoice_id, payment_event_id, source,
        generation, transition_kind, from_event_state, to_event_state, reason
    ) VALUES (
        '47000000-0000-0000-0000-000000000024',
        'migration-047-owner-guard',
        '47000000-0000-0000-0000-000000000020',
        '47000000-0000-0000-0000-000000000021',
        'liquid_direct', 0, 'superseded', 'legacy_unverified', 'superseded',
        'boltz_supersession'
    );

    BEGIN
        UPDATE invoice_direct_payment_transitions
           SET reason = 'replaced'
         WHERE id = '47000000-0000-0000-0000-000000000024';
        RAISE EXCEPTION 'migration 047 allowed transition history update';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        DELETE FROM invoice_direct_payment_transitions
         WHERE id = '47000000-0000-0000-0000-000000000024';
        RAISE EXCEPTION 'migration 047 allowed direct transition history delete';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO invoice_direct_payment_transitions (
            idempotency_key, invoice_id, payment_event_id, source,
            generation, transition_kind, reason
        ) VALUES (
            'migration-047-invalid-negative-generation',
            '47000000-0000-0000-0000-000000000020',
            '47000000-0000-0000-0000-000000000021',
            'liquid_direct', -1, 'superseded', 'boltz_supersession'
        );
        RAISE EXCEPTION 'migration 047 allowed a negative transition generation';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    DELETE FROM invoices
     WHERE id = '47000000-0000-0000-0000-000000000020';

    SELECT COUNT(*) INTO row_count
      FROM invoice_direct_payment_transitions
     WHERE id = '47000000-0000-0000-0000-000000000024';
    IF row_count <> 0 THEN
        RAISE EXCEPTION 'migration 047 transition guard blocked invoice cascade';
    END IF;
END
$$;
