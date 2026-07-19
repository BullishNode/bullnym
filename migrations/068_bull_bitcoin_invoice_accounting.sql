-- Crash-recoverable invoice accounting for the privacy-minimal Bull Bitcoin
-- settlement projection. No upstream response body or account identity enters
-- invoice_payment_events: the event binds only the local settlement UUID, the
-- actual Bitcoin received, and the exact fiat balance credit.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN funding_committed_at TIMESTAMPTZ;

-- A settlement may never borrow an invoice belonging to another npub.  The
-- primary key already makes the invoice-side pair unique; the explicit pair
-- constraint exists so PostgreSQL can enforce the cross-owner foreign key.
ALTER TABLE invoices
    ADD CONSTRAINT invoices_id_npub_owner_key UNIQUE (id, npub_owner);

ALTER TABLE invoice_fiat_settlement_policies
    ADD CONSTRAINT invoice_fiat_settlement_policies_invoice_owner_fkey
        FOREIGN KEY (invoice_id, owner_npub)
        REFERENCES invoices(id, npub_owner)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

ALTER TABLE bull_bitcoin_settlements
    ADD CONSTRAINT bull_bitcoin_settlements_invoice_owner_fkey
        FOREIGN KEY (invoice_id, owner_npub)
        REFERENCES invoices(id, npub_owner)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

-- Rows created by the preceding binary were all fiat-only and became payable
-- when their provider binding was exposed. Preserve that fact on upgrade.
UPDATE bull_bitcoin_settlements
   SET funding_committed_at = COALESCE(updated_at, created_at)
 WHERE provider_state = 'bound'
   AND funding_route = 'bull_bitcoin'
   AND settlement_status <> 'none';

ALTER TABLE bull_bitcoin_settlements
    DROP CONSTRAINT bull_bitcoin_settlements_rail_chk,
    DROP CONSTRAINT bull_bitcoin_settlements_status_chk,
    ADD CONSTRAINT bull_bitcoin_settlements_rail_chk CHECK (
        payer_rail IN ('bitcoin', 'lightning', 'liquid')
        AND (purpose = 'fiat_only' OR payer_rail IN ('bitcoin', 'lightning'))
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_funding_commitment_chk CHECK (
        (funding_route IS DISTINCT FROM 'bull_bitcoin'
            AND funding_committed_at IS NULL)
        OR (
            funding_route = 'bull_bitcoin'
            AND provider_state = 'bound'
            AND (
                (purpose = 'fiat_only' AND funding_committed_at IS NOT NULL)
                OR purpose = 'mixed'
            )
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_status_chk CHECK (
        settlement_status IN (
            'none', 'pending', 'settled', 'unavailable', 'integrity_error'
        )
        AND (
            (
                settlement_status = 'none'
                AND (
                    provider_state <> 'bound'
                    OR funding_route = 'bitcoin_fallback'
                    OR (purpose = 'mixed' AND funding_committed_at IS NULL)
                )
            ) OR (
                settlement_status <> 'none'
                AND provider_state = 'bound'
                AND funding_route = 'bull_bitcoin'
                AND funding_committed_at IS NOT NULL
            )
        )
    );

CREATE FUNCTION guard_bull_bitcoin_funding_commitment()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.funding_committed_at IS NOT NULL
       AND NEW.funding_committed_at IS DISTINCT FROM OLD.funding_committed_at THEN
        RAISE EXCEPTION 'Bull Bitcoin funding commitment is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_funding_commitment_immutable';
    END IF;
    IF OLD.funding_committed_at IS NULL
       AND NEW.funding_committed_at IS NOT NULL
       AND NOT (
           NEW.provider_state = 'bound'
           AND NEW.funding_route = 'bull_bitcoin'
           AND NEW.funding_committed_at >= NEW.created_at
       ) THEN
        RAISE EXCEPTION 'invalid Bull Bitcoin funding commitment'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_funding_commitment_transition';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER bull_bitcoin_settlements_guard_funding_commitment
    BEFORE UPDATE ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION guard_bull_bitcoin_funding_commitment();

ALTER TABLE invoice_payment_events
    ADD COLUMN bull_bitcoin_settlement_id UUID,
    DROP CONSTRAINT invoice_payment_events_source_chk,
    DROP CONSTRAINT invoice_payment_events_source_rail_chk,
    DROP CONSTRAINT invoice_payment_events_quote_attribution_shape_check,
    DROP CONSTRAINT invoice_payment_events_fiat_valuation_policy_check,
    ADD CONSTRAINT invoice_payment_events_source_chk CHECK (
        source IS NULL OR source IN (
            'bitcoin_direct', 'liquid_direct', 'lightning_boltz_reverse',
            'bitcoin_boltz_chain', 'bitcoin_boltz_recovery',
            'bull_bitcoin_fiat'
        )
    ),
    ADD CONSTRAINT invoice_payment_events_source_rail_chk CHECK (
        source IS NULL OR (
            (source IN ('bitcoin_direct', 'bitcoin_boltz_chain', 'bitcoin_boltz_recovery')
                AND rail = 'bitcoin')
            OR (source = 'liquid_direct' AND rail = 'liquid')
            OR (source = 'lightning_boltz_reverse' AND rail = 'lightning')
            OR (source = 'bull_bitcoin_fiat'
                AND rail IN ('bitcoin', 'lightning', 'liquid'))
        )
    ),
    ADD CONSTRAINT invoice_payment_events_bull_bitcoin_shape_chk CHECK (
        (
            source = 'bull_bitcoin_fiat'
            AND bull_bitcoin_settlement_id IS NOT NULL
            AND event_key = 'bull_bitcoin_fiat:' || bull_bitcoin_settlement_id::TEXT
            AND txid IS NULL AND vout IS NULL
            AND boltz_swap_id IS NULL AND address IS NULL
            AND accounting_state = 'active'
            AND verification_state = 'not_applicable'
        ) OR (
            source IS DISTINCT FROM 'bull_bitcoin_fiat'
            AND bull_bitcoin_settlement_id IS NULL
        )
    ),
    ADD CONSTRAINT invoice_payment_events_quote_attribution_shape_check CHECK (
        (
            source = 'bull_bitcoin_fiat'
            AND invoice_quote_version_id IS NULL
            AND invoice_quote_offer_id IS NULL
            AND quote_first_observed_at IS NULL
            AND fiat_credited_minor > 0
            AND fiat_credit_policy = 'bull_bitcoin_actual_v1'
            AND fiat_valued_at IS NOT NULL
            AND fiat_valuation_quote_version_id IS NULL
            AND fiat_rate_minor_per_btc IS NULL
            AND fiat_rate_source IS NULL
            AND fiat_rate_observed_at IS NULL
            AND fiat_rate_fetched_at IS NULL
            AND fiat_rate_fresh_until IS NULL
        ) OR (
            source IS DISTINCT FROM 'bull_bitcoin_fiat'
            AND (
                (
                    invoice_quote_version_id IS NULL
                    AND invoice_quote_offer_id IS NULL
                    AND (
                        quote_first_observed_at IS NULL
                        OR source IN ('bitcoin_direct', 'liquid_direct')
                    )
                ) OR (
                    invoice_quote_version_id IS NOT NULL
                    AND invoice_quote_offer_id IS NOT NULL
                    AND quote_first_observed_at IS NOT NULL
                )
            )
            AND (
                (
                    fiat_credited_minor IS NULL
                    AND fiat_credit_policy IS NULL
                    AND fiat_valued_at IS NULL
                    AND fiat_valuation_quote_version_id IS NULL
                    AND fiat_rate_minor_per_btc IS NULL
                    AND fiat_rate_source IS NULL
                    AND fiat_rate_observed_at IS NULL
                    AND fiat_rate_fetched_at IS NULL
                    AND fiat_rate_fresh_until IS NULL
                ) OR (
                    quote_first_observed_at IS NOT NULL
                    AND fiat_credited_minor IS NOT NULL
                    AND fiat_credited_minor >= 0
                    AND fiat_credit_policy IS NOT NULL
                    AND fiat_credit_policy ~ '^[a-z][a-z0-9_]{0,62}_v[1-9][0-9]*$'
                    AND fiat_valued_at IS NOT NULL
                    AND fiat_valuation_quote_version_id IS NOT NULL
                    AND fiat_rate_minor_per_btc > 0
                    AND fiat_rate_source IS NOT NULL
                    AND fiat_rate_source = btrim(fiat_rate_source)
                    AND fiat_rate_source ~ '^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$'
                    AND fiat_rate_observed_at IS NOT NULL
                    AND fiat_rate_fetched_at IS NOT NULL
                    AND fiat_rate_fresh_until IS NOT NULL
                    AND fiat_rate_observed_at < fiat_rate_fresh_until
                    AND fiat_rate_fetched_at < fiat_rate_fresh_until
                )
            )
        )
    ),
    ADD CONSTRAINT invoice_payment_events_fiat_valuation_policy_check CHECK (
        fiat_credit_policy IS NULL
        OR fiat_credit_policy IN (
            'quote_cumulative_saturation_v1',
            'late_observation_rate_v1',
            'bull_bitcoin_actual_v1'
        )
    ),
    ADD CONSTRAINT invoice_payment_events_bull_bitcoin_fkey
        FOREIGN KEY (bull_bitcoin_settlement_id)
        REFERENCES bull_bitcoin_settlements(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE UNIQUE INDEX invoice_payment_events_one_bull_bitcoin_settlement_idx
    ON invoice_payment_events (bull_bitcoin_settlement_id)
    WHERE bull_bitcoin_settlement_id IS NOT NULL;

-- The existing quote trigger owns all quote/rate-derived valuation. Bull
-- Bitcoin events instead carry provider-actual credit and are validated by the
-- narrow local-settlement trigger below.
DROP TRIGGER invoice_payment_events_guard_quote_attribution
    ON invoice_payment_events;
CREATE TRIGGER invoice_payment_events_guard_quote_attribution
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source IS DISTINCT FROM 'bull_bitcoin_fiat')
    EXECUTE FUNCTION guard_invoice_payment_quote_attribution();

CREATE FUNCTION guard_bull_bitcoin_invoice_payment_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    settlement_row RECORD;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.bull_bitcoin_settlement_id,
            NEW.fiat_credited_minor,
            NEW.fiat_credit_policy,
            NEW.fiat_valued_at
        ) IS DISTINCT FROM ROW(
            OLD.bull_bitcoin_settlement_id,
            OLD.fiat_credited_minor,
            OLD.fiat_credit_policy,
            OLD.fiat_valued_at
        ) THEN
            RAISE EXCEPTION 'Bull Bitcoin invoice payment evidence is immutable'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'invoice_payment_events_bull_bitcoin_immutable';
        END IF;
        RETURN NEW;
    END IF;

    SELECT invoice_id, payer_rail, actual_received_sat, credited_fiat_minor,
           provider_final, settlement_status, funding_route, funding_committed_at
      INTO settlement_row
      FROM bull_bitcoin_settlements
     WHERE id = NEW.bull_bitcoin_settlement_id;
    IF NOT FOUND
       OR settlement_row.invoice_id IS DISTINCT FROM NEW.invoice_id
       OR settlement_row.payer_rail IS DISTINCT FROM NEW.rail
       OR settlement_row.actual_received_sat IS DISTINCT FROM NEW.amount_sat
       OR settlement_row.credited_fiat_minor IS DISTINCT FROM NEW.fiat_credited_minor
       OR NOT settlement_row.provider_final
       OR settlement_row.settlement_status <> 'settled'
       OR settlement_row.funding_route <> 'bull_bitcoin'
       OR settlement_row.funding_committed_at IS NULL THEN
        RAISE EXCEPTION 'Bull Bitcoin invoice payment lacks matching provider-final authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_payment_events_bull_bitcoin_authority';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoice_payment_events_guard_bull_bitcoin
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source = 'bull_bitcoin_fiat')
    EXECUTE FUNCTION guard_bull_bitcoin_invoice_payment_event();

-- Always recompute the public aggregate from its three private components.
-- Existing writers may continue setting settlement_status as before; this
-- final alphabetically ordered trigger prevents any of them from clobbering a
-- concurrent fiat component.
CREATE FUNCTION compose_invoice_settlement_components()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.settlement_status := CASE
        WHEN NEW.swap_settlement_status = 'claim_stuck' THEN 'claim_stuck'
        WHEN NEW.swap_settlement_status = 'failed' THEN 'failed'
        WHEN NEW.swap_settlement_status = 'refunded' THEN 'refunded'
        WHEN NEW.direct_settlement_status = 'resolution_pending'
          OR NEW.fiat_settlement_status IN ('unavailable', 'integrity_error')
            THEN 'resolution_pending'
        WHEN NEW.direct_settlement_status = 'pending'
          OR NEW.swap_settlement_status = 'pending'
          OR NEW.fiat_settlement_status = 'pending' THEN 'pending'
        WHEN NEW.direct_settlement_status = 'settled'
          OR NEW.swap_settlement_status = 'settled'
          OR NEW.fiat_settlement_status = 'settled' THEN 'settled'
        ELSE 'none'
    END;
    RETURN NEW;
END
$$;

CREATE TRIGGER zz_invoices_compose_settlement_components
    BEFORE INSERT OR UPDATE OF direct_settlement_status,
        swap_settlement_status, fiat_settlement_status, settlement_status
    ON invoices
    FOR EACH ROW EXECUTE FUNCTION compose_invoice_settlement_components();

CREATE FUNCTION sync_invoice_bull_bitcoin_settlement_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_invoice_id UUID := COALESCE(NEW.invoice_id, OLD.invoice_id);
BEGIN
    IF target_invoice_id IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE invoices invoice
       SET fiat_settlement_status = projection.status
      FROM (
          SELECT CASE
              WHEN BOOL_OR(settlement_status = 'integrity_error')
                  THEN 'integrity_error'
              WHEN BOOL_OR(settlement_status = 'unavailable')
                  THEN 'unavailable'
              WHEN BOOL_OR(settlement_status = 'pending')
                  THEN 'pending'
              WHEN BOOL_OR(settlement_status = 'settled')
                  THEN 'settled'
              ELSE 'none'
          END AS status
          FROM bull_bitcoin_settlements
          WHERE invoice_id = target_invoice_id
            AND provider_state = 'bound'
            AND funding_route = 'bull_bitcoin'
            AND funding_committed_at IS NOT NULL
      ) projection
     WHERE invoice.id = target_invoice_id
       AND invoice.fiat_settlement_status IS DISTINCT FROM projection.status;
    RETURN NULL;
END
$$;

CREATE TRIGGER bull_bitcoin_settlements_sync_invoice_status
    AFTER INSERT OR UPDATE OF provider_state, funding_route,
        funding_committed_at, settlement_status
    ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION sync_invoice_bull_bitcoin_settlement_status();

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_funding_commitment() FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_invoice_payment_event() FROM PUBLIC;
    REVOKE ALL ON FUNCTION compose_invoice_settlement_components() FROM PUBLIC;
    REVOKE ALL ON FUNCTION sync_invoice_bull_bitcoin_settlement_status() FROM PUBLIC;

    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON TABLE invoice_payment_events TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
