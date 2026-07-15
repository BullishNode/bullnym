-- Durable pre-network intent for quote-scoped provider mutations.
BEGIN;

SELECT set_config('bullnym.migration_runtime_role', :'runtime_role', TRUE);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(current_setting('bullnym.migration_runtime_role', TRUE), '');
    runtime_role_oid OID;
    runtime_role_is_superuser BOOLEAN;
    executor_role_oid OID;
BEGIN
    IF runtime_role_name IS NULL THEN
        RAISE EXCEPTION 'migration 062 requires a non-empty runtime_role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid, rolsuper INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 062 runtime role does not exist'
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 062 refuses a superuser runtime role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid INTO STRICT executor_role_oid FROM pg_roles WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 062 runtime role owns or can assume its schema owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

-- The invoice row owns exactly one denomination. Sat-fixed invoices retain
-- their immutable sat target. Fiat-fixed invoices retain only their immutable
-- face value; conversion authority belongs exclusively to versioned quotes.
-- This is deliberately strict and unvalidated legacy fiat rows are not
-- grandfathered or rewritten: deployment must reset/refuse an incompatible
-- database rather than fabricate monetary evidence.
ALTER TABLE invoices
    DROP CONSTRAINT invoices_amount_sat_check,
    ADD COLUMN checkout_surface_kind TEXT,
    ADD CONSTRAINT invoices_pricing_amount_authority_check CHECK (
        (
            pricing_mode = 'sat_fixed'
            AND fiat_amount_minor IS NULL
            AND fiat_currency IS NULL
            AND amount_sat > 0
            AND rate_minor_per_btc IS NULL
        )
        OR
        (
            pricing_mode = 'fiat_fixed'
            AND fiat_amount_minor IS NOT NULL
            AND fiat_currency IS NOT NULL
            AND amount_sat = 0
            AND rate_minor_per_btc IS NULL
        )
    ),
    ADD CONSTRAINT invoices_checkout_surface_kind_check CHECK (
        (origin = 'checkout' AND checkout_surface_kind IN ('payment_page', 'pos'))
        OR (origin = 'wallet' AND checkout_surface_kind IS NULL)
    );

-- `in_progress` now also represents real money whose fiat valuation is
-- deliberately unresolved (for example first observed after its quote
-- expired). Preserve the rail/amount evidence without mislabeling it paid.
ALTER TABLE invoices
    DROP CONSTRAINT invoices_paid_via_or_closed_chk,
    ADD CONSTRAINT invoices_paid_via_or_closed_chk CHECK (
        (
            status = 'unpaid'
            AND paid_via IS NULL
            AND paid_amount_sat IS NULL
        )
        OR (
            status = 'in_progress'
            AND ((paid_via IS NULL) = (paid_amount_sat IS NULL))
        )
        OR (
            status IN ('partially_paid', 'paid', 'underpaid', 'overpaid')
            AND paid_via IS NOT NULL
            AND paid_amount_sat IS NOT NULL
        )
        OR (
            status IN ('cancelled', 'expired')
            AND ((paid_via IS NULL) = (paid_amount_sat IS NULL))
        )
    );

-- Each version prices one immutable slice of the still-outstanding fiat face.
-- The original face remains separately snapshotted for audit and UI context.
-- This column is intentionally added without a default: a database containing
-- pre-cutover quote rows must be reset/refused rather than assigned invented
-- remaining-fiat evidence.
ALTER TABLE invoice_quote_versions
    ADD COLUMN quote_purpose TEXT NOT NULL DEFAULT 'payer_instruction',
    ADD COLUMN late_instruction_quote_version_id UUID,
    ADD COLUMN late_observation_at TIMESTAMPTZ,
    ADD COLUMN fiat_target_amount_minor INTEGER NOT NULL,
    ADD CONSTRAINT invoice_quote_versions_purpose_check CHECK (
        (
            quote_purpose = 'payer_instruction'
            AND late_instruction_quote_version_id IS NULL
            AND late_observation_at IS NULL
        ) OR (
            quote_purpose = 'late_valuation'
            AND late_observation_at IS NOT NULL
        )
    ),
    ADD CONSTRAINT invoice_quote_versions_late_instruction_fkey FOREIGN KEY (
        late_instruction_quote_version_id,
        invoice_id
    ) REFERENCES invoice_quote_versions(id, invoice_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT invoice_quote_versions_fiat_target_check CHECK (
        fiat_target_amount_minor > 0
        AND fiat_target_amount_minor <= fiat_face_amount_minor
    );
ALTER TABLE invoice_quote_versions ALTER COLUMN quote_purpose DROP DEFAULT;
CREATE UNIQUE INDEX invoice_quote_versions_late_valuation_snapshot_key
    ON invoice_quote_versions (
        invoice_id,
        rate_minor_per_btc,
        rate_source,
        rate_observed_at,
        rate_fetched_at,
        rate_fresh_until
    ) WHERE quote_purpose = 'late_valuation';

-- Direct Liquid instructions are the invoice's stable address and therefore
-- have no quote-offer row. Quote offers are reserved for provider obligations,
-- whose durable identity is independently observable and attributable.
ALTER TABLE invoice_quote_offers
    DROP CONSTRAINT invoice_quote_offers_rail_kind_check,
    DROP CONSTRAINT invoice_quote_offers_provider_shape_check,
    ADD CONSTRAINT invoice_quote_offers_rail_kind_check CHECK (
        (rail = 'bitcoin' AND offer_kind = 'boltz_chain')
        OR (rail = 'lightning' AND offer_kind = 'boltz_reverse')
    ),
    ADD CONSTRAINT invoice_quote_offers_provider_shape_check CHECK (
        offer_kind IN ('boltz_reverse', 'boltz_chain')
        AND provider = 'boltz'
        AND provider_offer_id IS NOT NULL
        AND provider_offer_id = btrim(provider_offer_id)
        AND octet_length(provider_offer_id) BETWEEN 1 AND 255
    );

-- Keep instruction attribution separate from valuation authority. An event
-- first observed while quote A is live is valued by A. An event first observed
-- at or after A's expiry may only be valued by a distinct quote B which was
-- already durable, live, and backed by a fresh upstream snapshot at that exact
-- observation boundary. Copy the rate evidence onto the event so no later
-- quote mutation, lookup rule, or market movement can reprice committed money.
ALTER TABLE invoice_payment_events
    ADD COLUMN fiat_valuation_quote_version_id UUID,
    ADD COLUMN fiat_rate_minor_per_btc BIGINT,
    ADD COLUMN fiat_rate_source TEXT,
    ADD COLUMN fiat_rate_observed_at TIMESTAMPTZ,
    ADD COLUMN fiat_rate_fetched_at TIMESTAMPTZ,
    ADD COLUMN fiat_rate_fresh_until TIMESTAMPTZ,
    DROP CONSTRAINT invoice_payment_events_quote_attribution_shape_check,
    ADD CONSTRAINT invoice_payment_events_quote_attribution_shape_check CHECK (
        (
            (
                invoice_quote_version_id IS NULL
                AND invoice_quote_offer_id IS NULL
                AND (
                    quote_first_observed_at IS NULL
                    OR source IN ('bitcoin_direct', 'liquid_direct')
                )
            )
            OR (
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
    ),
    ADD CONSTRAINT invoice_payment_events_fiat_valuation_quote_fkey FOREIGN KEY (
        fiat_valuation_quote_version_id,
        invoice_id
    ) REFERENCES invoice_quote_versions(id, invoice_id)
      ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE FUNCTION invoice_quote_credit_for_sats(
    fiat_target_minor INTEGER,
    merchant_target_sat BIGINT,
    rate_minor_per_btc BIGINT,
    eligible_sat BIGINT
) RETURNS BIGINT
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN eligible_sat <= 0 THEN 0
        WHEN eligible_sat >= merchant_target_sat THEN fiat_target_minor::BIGINT
        ELSE LEAST(
            fiat_target_minor::BIGINT,
            floor(
                eligible_sat::NUMERIC * rate_minor_per_btc::NUMERIC
                / 100000000::NUMERIC
            )::BIGINT
        )
    END
$$;

-- A committed event valuation is immutable audit evidence. Reorgs,
-- deactivation, reactivation, and Boltz supersession instead alter this
-- explicit active projection. `accounting_adjustment_minor` makes any
-- cumulative-rounding/supersession adjustment observable rather than silently
-- rewriting an event's committed credit.
CREATE VIEW invoice_quote_active_fiat_projection
WITH (security_invoker = TRUE)
AS
SELECT
    q.id AS quote_version_id,
    q.invoice_id,
    q.fiat_target_amount_minor,
    q.merchant_amount_sat,
    COALESCE(SUM(e.amount_sat) FILTER (
        WHERE e.accounting_state = 'active'
          AND e.fiat_credited_minor IS NOT NULL
    ), 0)::BIGINT AS active_eligible_sat,
    invoice_quote_credit_for_sats(
        q.fiat_target_amount_minor,
        q.merchant_amount_sat,
        q.rate_minor_per_btc,
        COALESCE(SUM(e.amount_sat) FILTER (
            WHERE e.accounting_state = 'active'
              AND e.fiat_credited_minor IS NOT NULL
        ), 0)::BIGINT
    ) AS active_fiat_credited_minor,
    COALESCE(SUM(e.fiat_credited_minor) FILTER (
        WHERE e.accounting_state = 'active'
          AND e.fiat_credited_minor IS NOT NULL
    ), 0)::BIGINT AS committed_active_event_credit_minor,
    invoice_quote_credit_for_sats(
        q.fiat_target_amount_minor,
        q.merchant_amount_sat,
        q.rate_minor_per_btc,
        COALESCE(SUM(e.amount_sat) FILTER (
            WHERE e.accounting_state = 'active'
              AND e.fiat_credited_minor IS NOT NULL
        ), 0)::BIGINT
    ) - COALESCE(SUM(e.fiat_credited_minor) FILTER (
        WHERE e.accounting_state = 'active'
          AND e.fiat_credited_minor IS NOT NULL
    ), 0)::BIGINT AS accounting_adjustment_minor
FROM invoice_quote_versions q
LEFT JOIN invoice_payment_events e
  ON e.fiat_valuation_quote_version_id = q.id
 AND e.invoice_id = q.invoice_id
GROUP BY q.id;

-- Quote creation derives the remaining fiat target under the shared invoice
-- lock. It permits a new version after on-time valued partial evidence, but
-- fails closed if any prior event lacks attribution or a committed valuation
-- (the deliberately unresolved late-first-observed policy).
CREATE OR REPLACE FUNCTION enforce_invoice_quote_version_insert() RETURNS trigger
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
                        WHERE instruction.id = NEW.late_instruction_quote_version_id
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
                      AND direct_observation.first_seen_at = NEW.late_observation_at
                      AND (
                          (direct_observation.rail = 'liquid'
                           AND direct_observation.address = direct_invoice.liquid_address)
                          OR (direct_observation.rail = 'bitcoin'
                              AND direct_observation.address = direct_invoice.bitcoin_address)
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
        -- A late output can arrive after earlier evidence already satisfied
        -- the face. Give its valuation bucket one full-face saturation range:
        -- the copied rate remains exact and the aggregate projection becomes
        -- visibly overpaid without rewriting any prior credit.
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

CREATE OR REPLACE FUNCTION enforce_invoice_quote_offer_insert() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    write_now TIMESTAMPTZ := clock_timestamp();
    quote_row RECORD;
    invoice_row RECORD;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
    );
    SELECT merchant_amount_sat, expires_at, quote_purpose
      INTO quote_row
      FROM invoice_quote_versions
     WHERE id = NEW.quote_version_id AND invoice_id = NEW.invoice_id
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'invoice quote offer source version does not exist'
            USING ERRCODE = '23503',
                  CONSTRAINT = 'invoice_quote_offers_quote_invoice_fkey';
    END IF;
    IF quote_row.quote_purpose <> 'payer_instruction' THEN
        RAISE EXCEPTION 'valuation-only quote versions cannot create payer offers'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_offers_payer_quote_only_check';
    END IF;
    SELECT status, presentation_status, expires_at
      INTO invoice_row
      FROM invoices
     WHERE id = NEW.invoice_id
     FOR UPDATE;
    IF invoice_row.status NOT IN ('unpaid', 'partially_paid', 'in_progress')
       OR invoice_row.presentation_status NOT IN ('unpaid', 'partial')
       OR invoice_row.expires_at <= write_now
       OR NEW.expires_at > invoice_row.expires_at
       OR quote_row.expires_at <= write_now THEN
        RAISE EXCEPTION 'invoice quote is not eligible for a new payer offer'
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (
        SELECT 1 FROM invoice_payment_events e
         WHERE e.invoice_id = NEW.invoice_id
           AND (
               e.fiat_credited_minor IS NULL
               OR e.invoice_quote_version_id = NEW.quote_version_id
           )
    ) THEN
        RAISE EXCEPTION 'payer offer cannot be created after unresolved or same-quote payment evidence'
            USING ERRCODE = '55000';
    END IF;
    NEW.created_at := write_now;
    IF NEW.expires_at > quote_row.expires_at THEN
        RAISE EXCEPTION 'payer offer cannot outlive its quote version'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_offers_quote_window_check';
    END IF;
    IF NEW.payer_amount_sat <= quote_row.merchant_amount_sat THEN
        RAISE EXCEPTION 'provider payer amount must gross up the merchant sat target'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_quote_offers_provider_amount_check';
    END IF;
    RETURN NEW;
END
$$;

-- Persist the first authoritative funding observation on the provider
-- obligation itself. Later accounting must use this durable boundary, never
-- the time a webhook/repair handler happens to insert its payment event.
ALTER TABLE swap_records
    ADD COLUMN quote_payment_first_observed_at TIMESTAMPTZ;
ALTER TABLE chain_swap_records
    ADD COLUMN quote_payment_first_observed_at TIMESTAMPTZ;

CREATE FUNCTION stamp_quote_payment_first_observed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    qualifying BOOLEAN;
BEGIN
    IF TG_TABLE_NAME = 'swap_records' THEN
        qualifying := NEW.status IN (
            'lockup_mempool', 'lockup_confirmed', 'claiming', 'claimed',
            'claim_failed', 'claim_stuck', 'lockup_refunded'
        );
    ELSE
        qualifying := NEW.status IN (
            'user_lock_mempool', 'user_lock_confirmed',
            'server_lock_mempool', 'server_lock_confirmed',
            'claiming', 'claimed', 'claim_failed', 'claim_stuck',
            'refund_due', 'refunding', 'refunded'
        );
    END IF;
    IF TG_OP = 'UPDATE'
       AND OLD.quote_payment_first_observed_at IS NOT NULL
       AND NEW.quote_payment_first_observed_at IS DISTINCT FROM
           OLD.quote_payment_first_observed_at THEN
        RAISE EXCEPTION 'provider payment first-observed time is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.invoice_quote_version_id IS NOT NULL
       AND NEW.quote_payment_first_observed_at IS NULL
       AND qualifying THEN
        NEW.quote_payment_first_observed_at := clock_timestamp();
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER swap_records_stamp_quote_payment_first_observed
BEFORE INSERT OR UPDATE OF status, quote_payment_first_observed_at
ON swap_records FOR EACH ROW
EXECUTE FUNCTION stamp_quote_payment_first_observed();
CREATE TRIGGER chain_swap_records_stamp_quote_payment_first_observed
BEFORE INSERT OR UPDATE OF status, quote_payment_first_observed_at
ON chain_swap_records FOR EACH ROW
EXECUTE FUNCTION stamp_quote_payment_first_observed();

ALTER TABLE invoice_payment_events
    DROP CONSTRAINT invoice_payment_events_fiat_valuation_deferred_check,
    ADD CONSTRAINT invoice_payment_events_fiat_valuation_policy_check CHECK (
        fiat_credit_policy IS NULL
        OR fiat_credit_policy IN (
            'quote_cumulative_saturation_v1',
            'late_observation_rate_v1'
        )
    );

CREATE OR REPLACE FUNCTION guard_invoice_payment_quote_attribution() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    quote_row RECORD;
    valuation_quote_row RECORD;
    valuation_policy TEXT;
    prior_eligible_sat BIGINT;
    prior_credit BIGINT;
    next_credit BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.invoice_quote_version_id IS NULL THEN
            IF NEW.invoice_quote_offer_id IS NOT NULL THEN
                RAISE EXCEPTION 'payment quote and offer lineage must be complete'
                    USING ERRCODE = '23514';
            END IF;
            IF NEW.source NOT IN ('bitcoin_direct', 'liquid_direct')
               OR NEW.quote_first_observed_at IS NULL THEN
                IF num_nonnulls(
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
                    RAISE EXCEPTION 'unattributed payment cannot carry fiat valuation'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END IF;

            PERFORM pg_advisory_xact_lock(
                hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
            );
            IF NEW.quote_first_observed_at > clock_timestamp() + INTERVAL '30 seconds'
               OR NOT EXISTS (
                   SELECT 1
                     FROM invoice_payment_observations direct_observation
                     JOIN invoices direct_invoice
                       ON direct_invoice.id = direct_observation.invoice_id
                    WHERE direct_observation.id = NEW.observation_id
                      AND direct_observation.invoice_id = NEW.invoice_id
                      AND direct_observation.source = NEW.source
                      AND direct_observation.first_seen_at = NEW.quote_first_observed_at
                      AND direct_invoice.pricing_mode = 'fiat_fixed'
                      AND (
                          (direct_observation.rail = 'liquid'
                           AND direct_observation.address = direct_invoice.liquid_address)
                          OR (direct_observation.rail = 'bitcoin'
                              AND direct_observation.address = direct_invoice.bitcoin_address)
                      )
               ) THEN
                RAISE EXCEPTION 'direct fiat valuation lacks its exact durable observation'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'invoice_payment_events_quote_observation_check';
            END IF;

            NEW.fiat_credited_minor := NULL;
            NEW.fiat_credit_policy := NULL;
            NEW.fiat_valued_at := NULL;
            NEW.fiat_valuation_quote_version_id := NULL;
            NEW.fiat_rate_minor_per_btc := NULL;
            NEW.fiat_rate_source := NULL;
            NEW.fiat_rate_observed_at := NULL;
            NEW.fiat_rate_fetched_at := NULL;
            NEW.fiat_rate_fresh_until := NULL;

            -- A direct output proves only its destination and observation
            -- time. It never proves which refreshed QR was scanned. Select a
            -- rate window without fabricating instruction/offer lineage.
            SELECT id, quote_purpose, created_at, expires_at,
                   fiat_target_amount_minor, merchant_amount_sat,
                   rate_minor_per_btc, rate_source, rate_observed_at,
                   rate_fetched_at, rate_fresh_until
              INTO valuation_quote_row
              FROM invoice_quote_versions
             WHERE invoice_id = NEW.invoice_id
               AND quote_purpose = 'payer_instruction'
               AND created_at <= NEW.quote_first_observed_at
               AND NEW.quote_first_observed_at < expires_at
             ORDER BY created_at DESC, version_number DESC
             LIMIT 1;
            IF NOT FOUND THEN
                SELECT id, quote_purpose, created_at, expires_at,
                       fiat_target_amount_minor, merchant_amount_sat,
                       rate_minor_per_btc, rate_source, rate_observed_at,
                       rate_fetched_at, rate_fresh_until
                  INTO valuation_quote_row
                  FROM invoice_quote_versions
                 WHERE invoice_id = NEW.invoice_id
                   AND quote_purpose = 'late_valuation'
                   AND rate_observed_at <= NEW.quote_first_observed_at
                   AND rate_fetched_at <= NEW.quote_first_observed_at
                   AND NEW.quote_first_observed_at < rate_fresh_until
                 ORDER BY created_at DESC, version_number DESC
                 LIMIT 1;
                IF NOT FOUND THEN
                    RETURN NEW;
                END IF;
            END IF;
            valuation_policy := CASE valuation_quote_row.quote_purpose
                WHEN 'payer_instruction' THEN 'quote_cumulative_saturation_v1'
                ELSE 'late_observation_rate_v1'
            END;
        ELSE
            PERFORM pg_advisory_xact_lock(
                hashtext('invoice-lightning:' || NEW.invoice_id::TEXT)
            );
            SELECT id, quote_purpose, created_at, expires_at,
                   fiat_target_amount_minor, merchant_amount_sat,
                   rate_minor_per_btc, rate_source, rate_observed_at,
                   rate_fetched_at, rate_fresh_until
              INTO quote_row
              FROM invoice_quote_versions
             WHERE id = NEW.invoice_quote_version_id
               AND invoice_id = NEW.invoice_id;
            IF NOT FOUND
               OR NEW.quote_first_observed_at < quote_row.created_at
               OR NEW.quote_first_observed_at > clock_timestamp() + INTERVAL '30 seconds' THEN
                RAISE EXCEPTION 'payment quote observation predates, postdates, or mismatches its quote'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'invoice_payment_events_quote_observation_check';
            END IF;
            NEW.fiat_credited_minor := NULL;
            NEW.fiat_credit_policy := NULL;
            NEW.fiat_valued_at := NULL;
            NEW.fiat_valuation_quote_version_id := NULL;
            NEW.fiat_rate_minor_per_btc := NULL;
            NEW.fiat_rate_source := NULL;
            NEW.fiat_rate_observed_at := NULL;
            NEW.fiat_rate_fetched_at := NULL;
            NEW.fiat_rate_fresh_until := NULL;
            IF NEW.quote_first_observed_at < quote_row.expires_at THEN
                valuation_quote_row := quote_row;
                valuation_policy := 'quote_cumulative_saturation_v1';
            ELSE
                -- Equality belongs to the late side of the boundary. Never
                -- reuse the expired instruction's rate.
                SELECT id, quote_purpose, created_at, expires_at,
                       fiat_target_amount_minor, merchant_amount_sat,
                       rate_minor_per_btc, rate_source, rate_observed_at,
                       rate_fetched_at, rate_fresh_until
                  INTO valuation_quote_row
                  FROM invoice_quote_versions
                 WHERE invoice_id = NEW.invoice_id
                   AND id <> NEW.invoice_quote_version_id
                   AND rate_observed_at <= NEW.quote_first_observed_at
                   AND rate_fetched_at <= NEW.quote_first_observed_at
                   AND NEW.quote_first_observed_at < rate_fresh_until
                   AND (
                       (
                           quote_purpose = 'payer_instruction'
                           AND created_at <= NEW.quote_first_observed_at
                           AND NEW.quote_first_observed_at < expires_at
                       )
                       OR quote_purpose = 'late_valuation'
                   )
                 ORDER BY (quote_purpose = 'payer_instruction') DESC,
                          created_at DESC, version_number DESC
                 LIMIT 1;
                IF NOT FOUND THEN
                    RETURN NEW;
                END IF;
                valuation_policy := 'late_observation_rate_v1';
            END IF;
        END IF;

        SELECT COALESCE(SUM(e.amount_sat), 0)::BIGINT
          INTO prior_eligible_sat
          FROM invoice_payment_events e
         WHERE e.fiat_valuation_quote_version_id = valuation_quote_row.id
           AND e.invoice_id = NEW.invoice_id
           AND e.accounting_sequence < NEW.accounting_sequence;
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
    END IF;

    IF ROW(
        OLD.invoice_quote_version_id,
        OLD.invoice_quote_offer_id,
        OLD.quote_first_observed_at
    ) IS DISTINCT FROM ROW(
        NEW.invoice_quote_version_id,
        NEW.invoice_quote_offer_id,
        NEW.quote_first_observed_at
    ) THEN
        RAISE EXCEPTION 'payment quote/offer attribution is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF ROW(
        OLD.fiat_credited_minor,
        OLD.fiat_credit_policy,
        OLD.fiat_valued_at,
        OLD.fiat_valuation_quote_version_id,
        OLD.fiat_rate_minor_per_btc,
        OLD.fiat_rate_source,
        OLD.fiat_rate_observed_at,
        OLD.fiat_rate_fetched_at,
        OLD.fiat_rate_fresh_until
    ) IS DISTINCT FROM ROW(
        NEW.fiat_credited_minor,
        NEW.fiat_credit_policy,
        NEW.fiat_valued_at,
        NEW.fiat_valuation_quote_version_id,
        NEW.fiat_rate_minor_per_btc,
        NEW.fiat_rate_source,
        NEW.fiat_rate_observed_at,
        NEW.fiat_rate_fetched_at,
        NEW.fiat_rate_fresh_until
    ) THEN
        RAISE EXCEPTION 'committed fiat valuation is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE invoice_quote_provider_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id UUID NOT NULL,
    quote_version_id UUID NOT NULL,
    rail TEXT NOT NULL,
    request_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    operation TEXT NOT NULL,
    merchant_amount_sat BIGINT NOT NULL,
    request_authority_json TEXT NOT NULL,
    request_authority_sha256 TEXT NOT NULL,
    claim_key_allocation_id UUID NOT NULL REFERENCES swap_key_allocations(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    refund_key_allocation_id UUID REFERENCES swap_key_allocations(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT invoice_quote_provider_attempts_quote_invoice_fkey FOREIGN KEY
        (quote_version_id, invoice_id) REFERENCES invoice_quote_versions(id, invoice_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT invoice_quote_provider_attempts_request_key_check CHECK
        (request_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT invoice_quote_provider_attempts_authority_check CHECK (
        octet_length(request_authority_json) BETWEEN 2 AND 65536
        AND request_authority_json IS JSON OBJECT
        AND request_authority_sha256 ~ '^[0-9a-f]{64}$'
        AND request_authority_sha256 = encode(
            digest(convert_to(request_authority_json, 'UTF8'), 'sha256'), 'hex'
        )
    ),
    CONSTRAINT invoice_quote_provider_attempts_identity_key UNIQUE
        (quote_version_id, rail, request_key),
    CONSTRAINT invoice_quote_provider_attempts_offer_binding_key UNIQUE
        (id, quote_version_id, invoice_id, rail, request_key),
    CONSTRAINT invoice_quote_provider_attempts_claim_key UNIQUE
        (claim_key_allocation_id),
    CONSTRAINT invoice_quote_provider_attempts_refund_key UNIQUE
        (refund_key_allocation_id),
    CONSTRAINT invoice_quote_provider_attempts_shape_check CHECK (
        provider = 'boltz' AND merchant_amount_sat > 0 AND (
            (rail = 'lightning' AND operation = 'fixed_checkout_reverse'
             AND refund_key_allocation_id IS NULL)
            OR
            (rail = 'bitcoin' AND operation = 'chain_create'
             AND refund_key_allocation_id IS NOT NULL)
        )
    )
);

-- An append-only dispatch boundary closes the dangerous ambiguity between a
-- durable request and an irreversible POST. Only an attempt with no dispatch
-- row may be sent. Once this row exists, restart must reconcile through the
-- provider's validated xpub restore contract and may never blindly resend.
CREATE TABLE invoice_quote_provider_dispatches (
    provider_attempt_id UUID PRIMARY KEY REFERENCES invoice_quote_provider_attempts(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    request_authority_sha256 TEXT NOT NULL,
    dispatched_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT invoice_quote_provider_dispatches_digest_check CHECK
        (request_authority_sha256 ~ '^[0-9a-f]{64}$')
);

-- A completion is committed in the same transaction as the exact quote offer
-- and swap lineage. The provider response digest lets audits distinguish an
-- exact replay from an unrelated provider object without retaining a second
-- mutable copy of response data.
CREATE TABLE invoice_quote_provider_completions (
    provider_attempt_id UUID PRIMARY KEY REFERENCES invoice_quote_provider_attempts(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    quote_offer_id UUID NOT NULL UNIQUE REFERENCES invoice_quote_offers(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    provider_offer_id TEXT NOT NULL,
    provider_response_sha256 TEXT NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT invoice_quote_provider_completions_provider_id_check CHECK (
        provider_offer_id = btrim(provider_offer_id)
        AND octet_length(provider_offer_id) BETWEEN 1 AND 255
    ),
    CONSTRAINT invoice_quote_provider_completions_digest_check CHECK
        (provider_response_sha256 ~ '^[0-9a-f]{64}$')
);

-- Negative restore evidence never authorizes a retry. Retain the first fixed,
-- low-cardinality reason so operators can repair the evidence boundary while
-- the possible obligation remains quarantined.
CREATE TABLE invoice_quote_provider_integrity_holds (
    provider_attempt_id UUID PRIMARY KEY REFERENCES invoice_quote_provider_attempts(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    reason TEXT NOT NULL,
    held_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT invoice_quote_provider_integrity_holds_reason_check CHECK (
        reason IN (
            'provider_outcome_unknown',
            'restore_unavailable',
            'restore_absent',
            'restore_ambiguous',
            'restored_response_incomplete',
            'restored_response_invalid'
        )
    )
);

ALTER TABLE invoice_quote_offers
    ADD COLUMN provider_attempt_id UUID,
    ADD CONSTRAINT invoice_quote_offers_provider_attempt_shape_check CHECK (
        offer_kind IN ('boltz_reverse', 'boltz_chain')
        AND provider_attempt_id IS NOT NULL
    ),
    ADD CONSTRAINT invoice_quote_offers_provider_attempt_fkey FOREIGN KEY (
        provider_attempt_id, quote_version_id, invoice_id, rail, request_key
    ) REFERENCES invoice_quote_provider_attempts (
        id, quote_version_id, invoice_id, rail, request_key
    ) ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE FUNCTION enforce_invoice_quote_offer_attempt_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.provider_attempt_id IS NULL THEN
        RAISE EXCEPTION 'provider quote offer requires its durable pre-network attempt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoice_quote_offers_enforce_attempt_binding
BEFORE INSERT ON invoice_quote_offers FOR EACH ROW
EXECUTE FUNCTION enforce_invoice_quote_offer_attempt_binding();

CREATE FUNCTION enforce_invoice_quote_provider_attempt_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    quote_amount BIGINT;
    claim_purpose TEXT;
    refund_purpose TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('invoice-lightning:' || NEW.invoice_id::TEXT));
    SELECT merchant_amount_sat INTO quote_amount
      FROM invoice_quote_versions
     WHERE id = NEW.quote_version_id AND invoice_id = NEW.invoice_id
     FOR SHARE;
    IF NOT FOUND OR quote_amount <> NEW.merchant_amount_sat THEN
        RAISE EXCEPTION 'provider attempt does not match its quote'
            USING ERRCODE = '23514';
    END IF;
    SELECT purpose INTO claim_purpose FROM swap_key_allocations
     WHERE id = NEW.claim_key_allocation_id;
    IF NEW.rail = 'lightning' AND claim_purpose IS DISTINCT FROM 'reverse_claim' THEN
        RAISE EXCEPTION 'reverse attempt has invalid claim allocation'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.rail = 'bitcoin' THEN
        SELECT purpose INTO refund_purpose FROM swap_key_allocations
         WHERE id = NEW.refund_key_allocation_id;
        IF claim_purpose IS DISTINCT FROM 'chain_claim'
           OR refund_purpose IS DISTINCT FROM 'chain_refund' THEN
            RAISE EXCEPTION 'chain attempt has invalid key allocations'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_invoice_quote_provider_attempt_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'invoice quote provider attempts are immutable'
        USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER invoice_quote_provider_attempts_enforce_insert
BEFORE INSERT ON invoice_quote_provider_attempts FOR EACH ROW
EXECUTE FUNCTION enforce_invoice_quote_provider_attempt_insert();
CREATE TRIGGER invoice_quote_provider_attempts_reject_update
BEFORE UPDATE ON invoice_quote_provider_attempts FOR EACH ROW
EXECUTE FUNCTION reject_invoice_quote_provider_attempt_mutation();
CREATE TRIGGER invoice_quote_provider_attempts_reject_delete
BEFORE DELETE ON invoice_quote_provider_attempts FOR EACH ROW
EXECUTE FUNCTION reject_invoice_quote_provider_attempt_mutation();

CREATE FUNCTION enforce_invoice_quote_provider_dispatch_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM invoice_quote_provider_attempts attempt
         WHERE attempt.id = NEW.provider_attempt_id
           AND attempt.request_authority_sha256 = NEW.request_authority_sha256
    ) THEN
        RAISE EXCEPTION 'provider dispatch does not match its canonical request authority'
            USING ERRCODE = '23514';
    END IF;
    NEW.dispatched_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION enforce_invoice_quote_provider_completion_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM invoice_quote_provider_dispatches dispatch
          JOIN invoice_quote_offers offer
            ON offer.id = NEW.quote_offer_id
           AND offer.provider_attempt_id = NEW.provider_attempt_id
           AND offer.provider_offer_id = NEW.provider_offer_id
         WHERE dispatch.provider_attempt_id = NEW.provider_attempt_id
           AND (
               (
                   offer.rail = 'lightning'
                   AND EXISTS (
                       SELECT 1 FROM swap_records swap
                        WHERE swap.boltz_swap_id = NEW.provider_offer_id
                          AND swap.invoice_quote_offer_id = NEW.quote_offer_id
                          AND NEW.provider_response_sha256 = encode(
                              digest(convert_to(swap.boltz_response_json, 'UTF8'), 'sha256'),
                              'hex'
                          )
                   )
               ) OR (
                   offer.rail = 'bitcoin'
                   AND EXISTS (
                       SELECT 1 FROM chain_swap_records chain_swap
                        WHERE chain_swap.boltz_swap_id = NEW.provider_offer_id
                          AND chain_swap.invoice_quote_offer_id = NEW.quote_offer_id
                          AND chain_swap.creation_response_sha256 =
                              NEW.provider_response_sha256
                   )
               )
           )
    ) THEN
        RAISE EXCEPTION 'provider completion lacks its dispatch and exact offer lineage'
            USING ERRCODE = '23514';
    END IF;
    NEW.completed_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION enforce_invoice_quote_provider_hold_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM invoice_quote_provider_dispatches
         WHERE provider_attempt_id = NEW.provider_attempt_id
    ) OR EXISTS (
        SELECT 1 FROM invoice_quote_provider_completions
         WHERE provider_attempt_id = NEW.provider_attempt_id
    ) THEN
        RAISE EXCEPTION 'provider integrity hold lacks an unresolved dispatch'
            USING ERRCODE = '23514';
    END IF;
    NEW.held_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION require_invoice_quote_provider_completion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.provider_attempt_id IS NULL THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM invoice_quote_provider_completions completion
         WHERE completion.provider_attempt_id = NEW.provider_attempt_id
           AND completion.quote_offer_id = NEW.id
           AND completion.provider_offer_id = NEW.provider_offer_id
    ) THEN
        RAISE EXCEPTION 'provider quote offer and completion must commit atomically'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER invoice_quote_provider_dispatches_enforce_insert
BEFORE INSERT ON invoice_quote_provider_dispatches FOR EACH ROW
EXECUTE FUNCTION enforce_invoice_quote_provider_dispatch_insert();
CREATE TRIGGER invoice_quote_provider_completions_enforce_insert
BEFORE INSERT ON invoice_quote_provider_completions FOR EACH ROW
EXECUTE FUNCTION enforce_invoice_quote_provider_completion_insert();
CREATE TRIGGER invoice_quote_provider_integrity_holds_enforce_insert
BEFORE INSERT ON invoice_quote_provider_integrity_holds FOR EACH ROW
EXECUTE FUNCTION enforce_invoice_quote_provider_hold_insert();
CREATE CONSTRAINT TRIGGER invoice_quote_offers_require_provider_completion
AFTER INSERT ON invoice_quote_offers DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_invoice_quote_provider_completion();

CREATE TRIGGER invoice_quote_provider_dispatches_reject_update
BEFORE UPDATE OR DELETE ON invoice_quote_provider_dispatches FOR EACH ROW
EXECUTE FUNCTION reject_invoice_quote_provider_attempt_mutation();
CREATE TRIGGER invoice_quote_provider_completions_reject_update
BEFORE UPDATE OR DELETE ON invoice_quote_provider_completions FOR EACH ROW
EXECUTE FUNCTION reject_invoice_quote_provider_attempt_mutation();
CREATE TRIGGER invoice_quote_provider_integrity_holds_reject_update
BEFORE UPDATE OR DELETE ON invoice_quote_provider_integrity_holds FOR EACH ROW
EXECUTE FUNCTION reject_invoice_quote_provider_attempt_mutation();

DO $$
DECLARE runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE invoice_quote_active_fiat_projection FROM PUBLIC;
    EXECUTE format(
        'GRANT SELECT ON TABLE invoice_quote_active_fiat_projection TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (checkout_surface_kind) ON TABLE invoices TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT INSERT (quote_purpose, late_instruction_quote_version_id, late_observation_at, fiat_target_amount_minor) ON TABLE invoice_quote_versions TO %I',
        runtime_role_name
    );
    REVOKE ALL ON TABLE invoice_quote_provider_attempts FROM PUBLIC;
    EXECUTE format('REVOKE ALL ON TABLE invoice_quote_provider_attempts FROM %I', runtime_role_name);
    EXECUTE format('GRANT SELECT ON TABLE invoice_quote_provider_attempts TO %I', runtime_role_name);
    EXECUTE format(
        'GRANT INSERT (invoice_id, quote_version_id, rail, request_key, provider, operation, merchant_amount_sat, request_authority_json, request_authority_sha256, claim_key_allocation_id, refund_key_allocation_id) ON TABLE invoice_quote_provider_attempts TO %I',
        runtime_role_name
    );
    REVOKE ALL ON TABLE invoice_quote_provider_dispatches FROM PUBLIC;
    REVOKE ALL ON TABLE invoice_quote_provider_completions FROM PUBLIC;
    REVOKE ALL ON TABLE invoice_quote_provider_integrity_holds FROM PUBLIC;
    EXECUTE format('REVOKE ALL ON TABLE invoice_quote_provider_dispatches FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON TABLE invoice_quote_provider_completions FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON TABLE invoice_quote_provider_integrity_holds FROM %I', runtime_role_name);
    EXECUTE format('GRANT SELECT ON TABLE invoice_quote_provider_dispatches TO %I', runtime_role_name);
    EXECUTE format('GRANT INSERT (provider_attempt_id, request_authority_sha256) ON TABLE invoice_quote_provider_dispatches TO %I', runtime_role_name);
    EXECUTE format('GRANT SELECT ON TABLE invoice_quote_provider_completions TO %I', runtime_role_name);
    EXECUTE format('GRANT INSERT (provider_attempt_id, quote_offer_id, provider_offer_id, provider_response_sha256) ON TABLE invoice_quote_provider_completions TO %I', runtime_role_name);
    EXECUTE format('GRANT SELECT ON TABLE invoice_quote_provider_integrity_holds TO %I', runtime_role_name);
    EXECUTE format('GRANT INSERT (provider_attempt_id, reason) ON TABLE invoice_quote_provider_integrity_holds TO %I', runtime_role_name);
    EXECUTE format(
        'GRANT INSERT (provider_attempt_id) ON TABLE invoice_quote_offers TO %I',
        runtime_role_name
    );
    REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_attempt_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION reject_invoice_quote_provider_attempt_mutation() FROM PUBLIC;
    REVOKE ALL ON FUNCTION enforce_invoice_quote_offer_attempt_binding() FROM PUBLIC;
    REVOKE ALL ON FUNCTION invoice_quote_credit_for_sats(INTEGER, BIGINT, BIGINT, BIGINT) FROM PUBLIC;
    REVOKE ALL ON FUNCTION stamp_quote_payment_first_observed() FROM PUBLIC;
    REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_dispatch_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_completion_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_hold_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION require_invoice_quote_provider_completion() FROM PUBLIC;
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION invoice_quote_credit_for_sats(INTEGER, BIGINT, BIGINT, BIGINT) TO %I',
        runtime_role_name
    );
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_attempt_insert() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION reject_invoice_quote_provider_attempt_mutation() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_offer_attempt_binding() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION stamp_quote_payment_first_observed() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_dispatch_insert() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_completion_insert() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION enforce_invoice_quote_provider_hold_insert() FROM %I', runtime_role_name);
    EXECUTE format('REVOKE ALL ON FUNCTION require_invoice_quote_provider_completion() FROM %I', runtime_role_name);
END
$$;

COMMIT;
