-- ============================================================================
-- 075: fiat-only pay-in accounting and funded-instruction closure
-- ============================================================================
--
-- Bull Bitcoin's credited fiat is denominated in the merchant's payout
-- currency. It must never be compared with an invoice face in another
-- currency. Bind fiat-only invoice orders to the immutable Bullnym payer quote,
-- value received sats through that quote, and retain provider payout fiat only
-- on the settlement row.
--
-- The first received-funds observation is also an irreversible payer-admission
-- boundary. Once any Bull Bitcoin order for an invoice reports funds, no payer
-- instruction for that invoice may be created or replayed.

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
BEGIN
    IF runtime_role_name IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = runtime_role_name
    ) THEN
        RAISE EXCEPTION 'migration 075 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 075 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;
END
$$;

-- Migration 073's settlement-status projection writes a narrow invoice cache
-- from an AFTER trigger. Run that existing trigger function with its schema
-- owner's rights so the least-privilege runtime role never needs broad invoice
-- table access merely to persist a provider observation.
ALTER FUNCTION sync_invoice_bull_bitcoin_settlement_status() SECURITY DEFINER;
ALTER FUNCTION sync_invoice_bull_bitcoin_settlement_status()
    SET search_path TO pg_catalog, public;

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN invoice_quote_version_id UUID,
    ADD COLUMN quote_payment_first_observed_at TIMESTAMPTZ,
    ADD CONSTRAINT bull_bitcoin_settlements_invoice_quote_fkey FOREIGN KEY (
        invoice_quote_version_id,
        invoice_id
    ) REFERENCES invoice_quote_versions(id, invoice_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT bull_bitcoin_settlements_invoice_quote_shape_chk CHECK (
        invoice_quote_version_id IS NULL
        OR (
            purpose = 'fiat_only'
            AND invoice_id IS NOT NULL
            AND reverse_swap_id IS NULL
            AND chain_swap_id IS NULL
        )
    ),
    ADD CONSTRAINT bull_bitcoin_settlements_first_observation_shape_chk CHECK (
        quote_payment_first_observed_at IS NULL
        OR (
            purpose = 'fiat_only'
            AND actual_received_sat IS NOT NULL
        )
    );

COMMENT ON COLUMN bull_bitcoin_settlements.invoice_quote_version_id IS
    'Immutable Bullnym payer quote which denominates a fiat-fixed invoice pay-in; NULL for sat-fixed, Lightning Address, mixed, and unattributable legacy rows.';
COMMENT ON COLUMN bull_bitcoin_settlements.quote_payment_first_observed_at IS
    'First durable provider observation with actual received sats; immutable and never reconstructed for legacy rows.';

-- Recover the exact quote identity for still-unfunded pre-075 invoice orders.
-- The request key is a SHA-256 commitment to the raw quote UUID, rail, and
-- operation, so this is deterministic rather than an amount/time heuristic.
UPDATE bull_bitcoin_settlements settlement
   SET invoice_quote_version_id = quote.id
  FROM invoice_quote_versions quote
 WHERE settlement.purpose = 'fiat_only'
   AND settlement.invoice_id = quote.invoice_id
   AND settlement.actual_received_sat IS NULL
   AND quote.quote_purpose = 'payer_instruction'
   AND settlement.requested_bitcoin_sat = quote.merchant_amount_sat
   AND settlement.request_key = encode(
       digest(
           convert_to('bullnym-invoice-quote-offer-v1', 'UTF8')
           || decode('00', 'hex')
           || decode(replace(quote.id::TEXT, '-', ''), 'hex')
           || decode('00', 'hex')
           || convert_to(settlement.payer_rail, 'UTF8')
           || decode('00', 'hex')
           || convert_to('bull_bitcoin_fiat_only', 'UTF8'),
           'sha256'
       ),
       'hex'
   );

-- Existing received-funds rows must not retain a replayable instruction. Do
-- not invent their first-observed timestamp or quote attribution.
UPDATE bull_bitcoin_settlements
   SET payer_instruction = NULL,
       instruction_kind = NULL,
       instruction_expires_at = NULL,
       updated_at = clock_timestamp()
 WHERE actual_received_sat IS NOT NULL
   AND (payer_instruction IS NOT NULL OR instruction_kind IS NOT NULL);

ALTER TABLE bull_bitcoin_settlements
    ADD CONSTRAINT bull_bitcoin_settlements_funded_instruction_closed_chk CHECK (
        actual_received_sat IS NULL
        OR (payer_instruction IS NULL AND instruction_kind IS NULL)
    );

CREATE FUNCTION guard_fiat_only_quote_authority()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    quote_row RECORD;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.invoice_quote_version_id IS DISTINCT FROM OLD.invoice_quote_version_id THEN
        RAISE EXCEPTION 'Bull Bitcoin invoice quote authority is immutable'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'bull_bitcoin_settlements_invoice_quote_immutable';
    END IF;

    IF NEW.invoice_id IS NOT NULL AND NEW.purpose = 'fiat_only' THEN
        PERFORM pg_advisory_xact_lock(
            hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
        );
    END IF;

    IF TG_OP = 'INSERT'
       AND NEW.invoice_id IS NOT NULL
       AND NEW.purpose = 'fiat_only'
       AND EXISTS (
           SELECT 1 FROM bull_bitcoin_settlements funded
            WHERE funded.invoice_id = NEW.invoice_id
              AND funded.purpose = 'fiat_only'
              AND funded.actual_received_sat IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'Bull Bitcoin payment evidence closes payer admission'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'bull_bitcoin_settlements_funded_admission_closed';
    END IF;

    IF NEW.invoice_quote_version_id IS NOT NULL THEN
        SELECT quote.id, quote.invoice_id, quote.quote_purpose,
               quote.merchant_amount_sat, invoice.pricing_mode
          INTO quote_row
          FROM invoice_quote_versions quote
          JOIN invoices invoice ON invoice.id = quote.invoice_id
         WHERE quote.id = NEW.invoice_quote_version_id
           AND quote.invoice_id = NEW.invoice_id;
        IF NOT FOUND
           OR NEW.purpose <> 'fiat_only'
           OR quote_row.pricing_mode <> 'fiat_fixed'
           OR quote_row.quote_purpose <> 'payer_instruction'
           OR quote_row.merchant_amount_sat <> NEW.requested_bitcoin_sat THEN
            RAISE EXCEPTION 'fiat-only settlement does not match its payer quote'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_invoice_quote_authority';
        END IF;
    END IF;

    IF NEW.actual_received_sat IS NOT NULL
       AND (NEW.payer_instruction IS NOT NULL OR NEW.instruction_kind IS NOT NULL) THEN
        RAISE EXCEPTION 'funded Bull Bitcoin settlement retained a payer instruction'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_funded_instruction_closed_chk';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER bull_bitcoin_settlements_guard_fiat_only_quote
    BEFORE INSERT OR UPDATE OF invoice_quote_version_id, invoice_id, purpose,
        requested_bitcoin_sat, actual_received_sat, payer_instruction,
        instruction_kind
    ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION guard_fiat_only_quote_authority();

CREATE FUNCTION reject_quote_after_bull_bitcoin_payment()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.quote_purpose = 'payer_instruction' THEN
        PERFORM pg_advisory_xact_lock(
            hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
        );
        IF EXISTS (
            SELECT 1 FROM bull_bitcoin_settlements settlement
             WHERE settlement.invoice_id = NEW.invoice_id
               AND settlement.purpose = 'fiat_only'
               AND settlement.actual_received_sat IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'Bull Bitcoin payment evidence closes payer admission'
                USING ERRCODE = '55000',
                      CONSTRAINT = 'invoice_quote_versions_bull_bitcoin_admission_closed';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoice_quote_versions_reject_funded_bull_bitcoin
    BEFORE INSERT ON invoice_quote_versions
    FOR EACH ROW EXECUTE FUNCTION reject_quote_after_bull_bitcoin_payment();

-- Extend the existing late-valuation admission proof to the Bull Bitcoin
-- provider observation ledger. The rest of the quote invariant is reproduced
-- unchanged so the security-definer boundary remains explicit and auditable.
CREATE OR REPLACE FUNCTION enforce_invoice_quote_version_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    write_now TIMESTAMPTZ := clock_timestamp();
    invoice_row RECORD;
    active_fiat_credit BIGINT;
    remaining_fiat BIGINT;
    expected_merchant_amount BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
    );

    SELECT pricing_mode, fiat_amount_minor, fiat_currency, status,
           presentation_status, expires_at
      INTO invoice_row
      FROM invoices
     WHERE id = NEW.invoice_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invoice quote source invoice does not exist'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'invoice_quote_versions_invoice_fkey';
    END IF;
    IF invoice_row.pricing_mode IS DISTINCT FROM 'fiat_fixed'
       OR invoice_row.fiat_amount_minor IS NULL
       OR invoice_row.fiat_currency IS NULL THEN
        RAISE EXCEPTION 'invoice quote versions require a fiat-fixed invoice'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_versions_fiat_source_check';
    END IF;
    IF NEW.quote_purpose = 'payer_instruction' AND (
       invoice_row.status NOT IN ('unpaid', 'partially_paid', 'in_progress')
       OR invoice_row.presentation_status NOT IN ('unpaid', 'partial')
       OR invoice_row.expires_at < write_now + INTERVAL '5 minutes') THEN
        RAISE EXCEPTION 'invoice is not eligible for a new fiat quote version'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.quote_purpose = 'late_valuation' THEN
        IF NEW.rate_observed_at > NEW.late_observation_at
           OR NEW.rate_fetched_at > NEW.late_observation_at
           OR NEW.late_observation_at >= NEW.rate_fresh_until
           OR (
               NEW.late_instruction_quote_version_id IS NOT NULL
               AND (
                   NOT EXISTS (
                       SELECT 1 FROM invoice_quote_versions instruction
                        WHERE instruction.id =
                              NEW.late_instruction_quote_version_id
                          AND instruction.invoice_id = NEW.invoice_id
                          AND instruction.quote_purpose = 'payer_instruction'
                          AND NEW.late_observation_at >= instruction.expires_at
                   )
                   OR NOT (
                       EXISTS (
                           SELECT 1 FROM swap_records provider_observation
                            WHERE provider_observation.invoice_id = NEW.invoice_id
                              AND provider_observation.invoice_quote_version_id =
                                  NEW.late_instruction_quote_version_id
                              AND provider_observation.quote_payment_first_observed_at =
                                  NEW.late_observation_at
                       )
                       OR EXISTS (
                           SELECT 1 FROM chain_swap_records provider_observation
                            WHERE provider_observation.invoice_id = NEW.invoice_id
                              AND provider_observation.invoice_quote_version_id =
                                  NEW.late_instruction_quote_version_id
                              AND provider_observation.quote_payment_first_observed_at =
                                  NEW.late_observation_at
                       )
                       OR EXISTS (
                           SELECT 1
                             FROM bull_bitcoin_settlements provider_observation
                            WHERE provider_observation.invoice_id = NEW.invoice_id
                              AND provider_observation.purpose = 'fiat_only'
                              AND provider_observation.invoice_quote_version_id =
                                  NEW.late_instruction_quote_version_id
                              AND provider_observation.quote_payment_first_observed_at =
                                  NEW.late_observation_at
                              AND provider_observation.actual_received_sat IS NOT NULL
                       )
                   )
               )
           )
           OR (
               NEW.late_instruction_quote_version_id IS NULL
               AND NOT EXISTS (
                   SELECT 1
                     FROM invoice_payment_observations direct_observation
                     JOIN invoices direct_invoice
                       ON direct_invoice.id = direct_observation.invoice_id
                    WHERE direct_observation.invoice_id = NEW.invoice_id
                      AND direct_observation.first_seen_at =
                          NEW.late_observation_at
                      AND (
                          (direct_observation.rail = 'liquid'
                           AND direct_observation.address =
                               direct_invoice.liquid_address)
                          OR (direct_observation.rail = 'bitcoin'
                              AND direct_observation.address =
                                  direct_invoice.bitcoin_address)
                      )
               )
           ) THEN
            RAISE EXCEPTION 'valuation-only quote lacks exact late-observation authority'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'invoice_quote_versions_late_observation_check';
        END IF;
    END IF;
    IF NEW.quote_purpose = 'payer_instruction' AND EXISTS (
        SELECT 1 FROM invoice_payment_events e
         WHERE e.invoice_id = NEW.invoice_id
           AND (
               e.quote_first_observed_at IS NULL
               OR e.fiat_credited_minor IS NULL
               OR e.fiat_credit_policy IS NULL
               OR e.fiat_valued_at IS NULL
               OR (
                   e.source NOT IN ('bitcoin_direct', 'liquid_direct')
                   AND (
                       e.invoice_quote_version_id IS NULL
                       OR e.invoice_quote_offer_id IS NULL
                   )
               )
           )
    ) THEN
        RAISE EXCEPTION 'invoice has payment evidence awaiting fiat valuation policy'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.quote_purpose = 'payer_instruction' AND EXISTS (
        SELECT 1 FROM invoice_quote_versions q
         WHERE q.invoice_id = NEW.invoice_id
           AND q.quote_purpose = 'payer_instruction'
           AND q.expires_at > write_now
    ) THEN
        RAISE EXCEPTION 'an unexpired quote version already exists for this invoice'
            USING ERRCODE = '23505',
                  CONSTRAINT = 'invoice_quote_versions_one_current_at_insert';
    END IF;

    SELECT COALESCE(SUM(p.active_fiat_credited_minor), 0)::BIGINT
      INTO active_fiat_credit
      FROM invoice_quote_active_fiat_projection p
     WHERE p.invoice_id = NEW.invoice_id;
    remaining_fiat := invoice_row.fiat_amount_minor::BIGINT - active_fiat_credit;
    IF remaining_fiat <= 0 AND NEW.quote_purpose = 'late_valuation' THEN
        remaining_fiat := invoice_row.fiat_amount_minor::BIGINT;
    END IF;
    IF remaining_fiat <= 0 OR remaining_fiat > invoice_row.fiat_amount_minor THEN
        RAISE EXCEPTION 'invoice has no valid remaining fiat target'
            USING ERRCODE = '55000';
    END IF;

    NEW.fiat_face_amount_minor := invoice_row.fiat_amount_minor;
    NEW.fiat_target_amount_minor := remaining_fiat::INTEGER;
    NEW.fiat_currency := invoice_row.fiat_currency;
    NEW.version_number := COALESCE((
        SELECT MAX(version_number)
          FROM invoice_quote_versions
         WHERE invoice_id = NEW.invoice_id
    ), 0) + 1;
    NEW.created_at := write_now;
    NEW.expires_at := write_now + INTERVAL '5 minutes';

    expected_merchant_amount := ceil(
        remaining_fiat::NUMERIC * 100000000::NUMERIC
        / NEW.rate_minor_per_btc::NUMERIC
    )::BIGINT;
    IF expected_merchant_amount <= 0
       OR NEW.merchant_amount_sat <> expected_merchant_amount THEN
        RAISE EXCEPTION 'merchant sat target does not match the remaining fiat/rate snapshot'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_versions_merchant_target_check';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER invoice_payment_events_guard_bull_bitcoin
    ON invoice_payment_events;

CREATE FUNCTION guard_fiat_only_bull_bitcoin_invoice_payment_event()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    settlement_row RECORD;
    quote_row RECORD;
    valuation_quote_row RECORD;
    valuation_policy TEXT;
    prior_eligible_sat BIGINT;
    prior_credit BIGINT;
    next_credit BIGINT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.bull_bitcoin_settlement_id,
            NEW.invoice_quote_version_id,
            NEW.invoice_quote_offer_id,
            NEW.quote_first_observed_at,
            NEW.fiat_credited_minor,
            NEW.fiat_credit_policy,
            NEW.fiat_valued_at,
            NEW.fiat_valuation_quote_version_id,
            NEW.fiat_rate_minor_per_btc,
            NEW.fiat_rate_source,
            NEW.fiat_rate_observed_at,
            NEW.fiat_rate_fetched_at,
            NEW.fiat_rate_fresh_until
        ) IS DISTINCT FROM ROW(
            OLD.bull_bitcoin_settlement_id,
            OLD.invoice_quote_version_id,
            OLD.invoice_quote_offer_id,
            OLD.quote_first_observed_at,
            OLD.fiat_credited_minor,
            OLD.fiat_credit_policy,
            OLD.fiat_valued_at,
            OLD.fiat_valuation_quote_version_id,
            OLD.fiat_rate_minor_per_btc,
            OLD.fiat_rate_source,
            OLD.fiat_rate_observed_at,
            OLD.fiat_rate_fetched_at,
            OLD.fiat_rate_fresh_until
        ) THEN
            RAISE EXCEPTION 'Bull Bitcoin invoice payment evidence is immutable'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'invoice_payment_events_bull_bitcoin_immutable';
        END IF;
        RETURN NEW;
    END IF;

    SELECT settlement.invoice_id, settlement.payer_rail,
           settlement.actual_received_sat, settlement.credited_fiat_minor,
           settlement.provider_final, settlement.settlement_status,
           settlement.funding_route, settlement.funding_committed_at,
           settlement.purpose, settlement.invoice_quote_version_id,
           settlement.quote_payment_first_observed_at,
           invoice.pricing_mode
      INTO settlement_row
      FROM bull_bitcoin_settlements settlement
      JOIN invoices invoice ON invoice.id = settlement.invoice_id
     WHERE settlement.id = NEW.bull_bitcoin_settlement_id;
    IF NOT FOUND
       OR settlement_row.invoice_id IS DISTINCT FROM NEW.invoice_id
       OR settlement_row.payer_rail IS DISTINCT FROM NEW.rail
       OR settlement_row.actual_received_sat IS DISTINCT FROM NEW.amount_sat
       OR settlement_row.credited_fiat_minor IS NULL
       OR settlement_row.credited_fiat_minor <= 0
       OR NOT settlement_row.provider_final
       OR settlement_row.settlement_status <> 'settled'
       OR settlement_row.funding_route <> 'bull_bitcoin'
       OR settlement_row.funding_committed_at IS NULL
       OR settlement_row.purpose <> 'fiat_only' THEN
        RAISE EXCEPTION 'Bull Bitcoin invoice payment lacks matching provider-final authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_payment_events_bull_bitcoin_authority';
    END IF;

    -- Callers provide no fiat valuation. This trigger derives invoice-face
    -- credit only from persisted quote authority; provider payout fiat remains
    -- exclusively on bull_bitcoin_settlements.
    IF num_nonnulls(
        NEW.invoice_quote_version_id,
        NEW.invoice_quote_offer_id,
        NEW.quote_first_observed_at,
        NEW.fiat_credited_minor,
        NEW.fiat_credit_policy,
        NEW.fiat_valued_at,
        NEW.fiat_valuation_quote_version_id,
        NEW.fiat_rate_minor_per_btc,
        NEW.fiat_rate_source,
        NEW.fiat_rate_observed_at,
        NEW.fiat_rate_fetched_at,
        NEW.fiat_rate_fresh_until
    ) <> 0 THEN
        RAISE EXCEPTION 'caller supplied Bull Bitcoin invoice valuation'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_payment_events_bull_bitcoin_authority';
    END IF;

    IF settlement_row.invoice_quote_version_id IS NULL THEN
        -- Sat-fixed rows need no fiat valuation. A pre-075 fiat-fixed row whose
        -- quote/observation authority cannot be recovered is retained as
        -- explicit unresolved evidence instead of being assigned payout fiat.
        RETURN NEW;
    END IF;

    IF settlement_row.pricing_mode <> 'fiat_fixed'
       OR settlement_row.quote_payment_first_observed_at IS NULL THEN
        RAISE EXCEPTION 'quote-attributed Bull Bitcoin payment lacks first-observed authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_payment_events_bull_bitcoin_quote_authority';
    END IF;

    SELECT quote.id, quote.quote_purpose, quote.created_at, quote.expires_at,
           quote.fiat_target_amount_minor,
           quote.merchant_amount_sat, quote.rate_minor_per_btc,
           quote.rate_source, quote.rate_observed_at,
           quote.rate_fetched_at, quote.rate_fresh_until
      INTO quote_row
      FROM invoice_quote_versions quote
     WHERE quote.id = settlement_row.invoice_quote_version_id
       AND quote.invoice_id = NEW.invoice_id
       AND quote.quote_purpose = 'payer_instruction';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Bull Bitcoin payment quote no longer exists'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_payment_events_bull_bitcoin_quote_authority';
    END IF;

    NEW.invoice_quote_version_id := quote_row.id;
    NEW.invoice_quote_offer_id := NULL;
    NEW.quote_first_observed_at :=
        settlement_row.quote_payment_first_observed_at;
    IF settlement_row.quote_payment_first_observed_at < quote_row.expires_at THEN
        valuation_quote_row := quote_row;
        valuation_policy := 'quote_cumulative_saturation_v1';
    ELSE
        -- Equality belongs to the late side of the boundary. A late payment
        -- can use only a different Bullnym rate snapshot that already covered
        -- the exact durable provider-funds observation.
        SELECT quote.id, quote.quote_purpose, quote.created_at,
               quote.expires_at, quote.fiat_target_amount_minor,
               quote.merchant_amount_sat, quote.rate_minor_per_btc,
               quote.rate_source, quote.rate_observed_at,
               quote.rate_fetched_at, quote.rate_fresh_until
          INTO valuation_quote_row
          FROM invoice_quote_versions quote
         WHERE quote.invoice_id = NEW.invoice_id
           AND quote.id <> quote_row.id
           AND quote.rate_observed_at <=
               settlement_row.quote_payment_first_observed_at
           AND quote.rate_fetched_at <=
               settlement_row.quote_payment_first_observed_at
           AND settlement_row.quote_payment_first_observed_at <
               quote.rate_fresh_until
           AND (
               (
                   quote.quote_purpose = 'payer_instruction'
                   AND quote.created_at <=
                       settlement_row.quote_payment_first_observed_at
                   AND settlement_row.quote_payment_first_observed_at <
                       quote.expires_at
               )
               OR quote.quote_purpose = 'late_valuation'
           )
         ORDER BY (quote.quote_purpose = 'payer_instruction') DESC,
                  quote.created_at DESC, quote.version_number DESC
         LIMIT 1;
        IF NOT FOUND THEN
            -- Preserve exact payer lineage and money evidence, but never use
            -- an expired rate or provider-payout currency as invoice credit.
            RETURN NEW;
        END IF;
        valuation_policy := 'late_observation_rate_v1';
    END IF;

    SELECT COALESCE(SUM(prior.amount_sat), 0)::BIGINT
      INTO prior_eligible_sat
      FROM invoice_payment_events prior
     WHERE prior.invoice_id = NEW.invoice_id
       AND prior.fiat_valuation_quote_version_id = valuation_quote_row.id
       AND prior.accounting_sequence < NEW.accounting_sequence;
    prior_credit := invoice_quote_credit_for_sats(
        valuation_quote_row.fiat_target_amount_minor,
        valuation_quote_row.merchant_amount_sat,
        valuation_quote_row.rate_minor_per_btc,
        prior_eligible_sat
    );
    next_credit := invoice_quote_credit_for_sats(
        valuation_quote_row.fiat_target_amount_minor,
        valuation_quote_row.merchant_amount_sat,
        valuation_quote_row.rate_minor_per_btc,
        prior_eligible_sat + NEW.amount_sat
    );

    NEW.fiat_credited_minor := next_credit - prior_credit;
    NEW.fiat_credit_policy := valuation_policy;
    NEW.fiat_valued_at := clock_timestamp();
    NEW.fiat_valuation_quote_version_id := valuation_quote_row.id;
    NEW.fiat_rate_minor_per_btc := valuation_quote_row.rate_minor_per_btc;
    NEW.fiat_rate_source := valuation_quote_row.rate_source;
    NEW.fiat_rate_observed_at := valuation_quote_row.rate_observed_at;
    NEW.fiat_rate_fetched_at := valuation_quote_row.rate_fetched_at;
    NEW.fiat_rate_fresh_until := valuation_quote_row.rate_fresh_until;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoice_payment_events_guard_bull_bitcoin
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source = 'bull_bitcoin_mixed_output')
    EXECUTE FUNCTION guard_bull_bitcoin_invoice_payment_event();

CREATE TRIGGER invoice_payment_events_guard_bull_bitcoin_fiat
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source = 'bull_bitcoin_fiat')
    EXECUTE FUNCTION guard_fiat_only_bull_bitcoin_invoice_payment_event();

ALTER TABLE invoice_payment_events
    DROP CONSTRAINT invoice_payment_events_quote_attribution_shape_check,
    ADD CONSTRAINT invoice_payment_events_quote_attribution_shape_check CHECK (
        (
            source = 'bull_bitcoin_fiat'
            AND (
                (
                    invoice_quote_version_id IS NOT NULL
                    AND invoice_quote_offer_id IS NULL
                    AND quote_first_observed_at IS NOT NULL
                    AND fiat_credited_minor IS NOT NULL
                    AND fiat_credited_minor >= 0
                    AND fiat_credit_policy IN (
                        'quote_cumulative_saturation_v1',
                        'late_observation_rate_v1'
                    )
                    AND fiat_valued_at IS NOT NULL
                    AND fiat_valuation_quote_version_id IS NOT NULL
                    AND fiat_rate_minor_per_btc > 0
                    AND fiat_rate_source IS NOT NULL
                    AND fiat_rate_observed_at IS NOT NULL
                    AND fiat_rate_fetched_at IS NOT NULL
                    AND fiat_rate_fresh_until IS NOT NULL
                )
                OR (
                    -- Exact payer lineage with no Bullnym rate snapshot that
                    -- covered a late first observation. This remains visible,
                    -- unresolved evidence rather than guessed credit.
                    invoice_quote_version_id IS NOT NULL
                    AND invoice_quote_offer_id IS NULL
                    AND quote_first_observed_at IS NOT NULL
                    AND fiat_credited_minor IS NULL
                    AND fiat_credit_policy IS NULL
                    AND fiat_valued_at IS NULL
                    AND fiat_valuation_quote_version_id IS NULL
                    AND fiat_rate_minor_per_btc IS NULL
                    AND fiat_rate_source IS NULL
                    AND fiat_rate_observed_at IS NULL
                    AND fiat_rate_fetched_at IS NULL
                    AND fiat_rate_fresh_until IS NULL
                )
                OR (
                    invoice_quote_version_id IS NULL
                    AND invoice_quote_offer_id IS NULL
                    AND quote_first_observed_at IS NULL
                    AND fiat_credited_minor IS NULL
                    AND fiat_credit_policy IS NULL
                    AND fiat_valued_at IS NULL
                    AND fiat_valuation_quote_version_id IS NULL
                    AND fiat_rate_minor_per_btc IS NULL
                    AND fiat_rate_source IS NULL
                    AND fiat_rate_observed_at IS NULL
                    AND fiat_rate_fetched_at IS NULL
                    AND fiat_rate_fresh_until IS NULL
                )
                OR (
                    -- Grandfather pre-075 provider-payout events as legacy
                    -- evidence. Runtime projection no longer treats them as
                    -- invoice-face credit.
                    invoice_quote_version_id IS NULL
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
                )
            )
        )
        OR (
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
    );

REVOKE ALL ON FUNCTION guard_fiat_only_quote_authority() FROM PUBLIC;
REVOKE ALL ON FUNCTION reject_quote_after_bull_bitcoin_payment() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_fiat_only_bull_bitcoin_invoice_payment_event()
    FROM PUBLIC;

COMMIT;
