-- ============================================================================
-- 047: Durable direct-payment lifecycle foundation
-- ============================================================================
--
-- Add the durable state required to make direct Bitcoin/Liquid presentation,
-- accounting, finality, and reversal distinct.  This migration deliberately
-- does not change watcher or public API behaviour.  Existing direct events stay
-- countable as legacy-unverified evidence until the later watcher-adoption PR
-- positively revalidates them.
-- ============================================================================

BEGIN;

-- --------------------------------------------------------------------------
-- Invoice aggregate projections.  Keep the existing public settlement cache
-- while separating the direct and swap components for the dormant reducer.
-- --------------------------------------------------------------------------

ALTER TABLE invoices
  DROP CONSTRAINT IF EXISTS invoices_settlement_status_check;

ALTER TABLE invoices
  ADD CONSTRAINT invoices_settlement_status_check CHECK (
    settlement_status IN (
      'none', 'pending', 'settled', 'resolution_pending',
      'claim_stuck', 'refunded', 'failed'
    )
  ),
  ADD COLUMN presentation_status TEXT,
  ADD COLUMN direct_settlement_status TEXT NOT NULL DEFAULT 'none',
  ADD COLUMN swap_settlement_status TEXT NOT NULL DEFAULT 'none',
  ADD COLUMN direct_payment_projection_version BIGINT NOT NULL DEFAULT 0;

ALTER TABLE invoices
  ADD CONSTRAINT invoices_presentation_status_check CHECK (
    presentation_status IS NULL OR presentation_status IN (
      'unpaid', 'partial', 'payment_received', 'overpaid'
    )
  ),
  ADD CONSTRAINT invoices_direct_settlement_status_check CHECK (
    direct_settlement_status IN (
      'none', 'pending', 'settled', 'resolution_pending'
    )
  ),
  ADD CONSTRAINT invoices_swap_settlement_status_check CHECK (
    swap_settlement_status IN (
      'none', 'pending', 'settled', 'claim_stuck', 'refunded', 'failed'
    )
  ),
  ADD CONSTRAINT invoices_direct_payment_projection_version_check CHECK (
    direct_payment_projection_version >= 0
  );

-- Backfill only presentation facts already proven by the cached accounting.
-- `in_progress` remains NULL because its provisional coverage cannot be
-- reconstructed from the legacy row alone.
UPDATE invoices
SET presentation_status = CASE status
  WHEN 'unpaid' THEN 'unpaid'
  WHEN 'expired' THEN 'unpaid'
  WHEN 'cancelled' THEN 'unpaid'
  WHEN 'partially_paid' THEN 'partial'
  WHEN 'underpaid' THEN 'partial'
  WHEN 'paid' THEN 'payment_received'
  WHEN 'overpaid' THEN 'overpaid'
  ELSE NULL
END;

-- Preserve the existing aggregate byte-for-byte while attributing only what
-- can be inferred from existing evidence.  Rows with both kinds conservatively
-- retain the same component on both sides; later positive revalidation refines
-- the direct component.
UPDATE invoices i
SET direct_settlement_status = CASE
      WHEN i.settlement_status IN ('pending', 'settled')
       AND (
         EXISTS (
           SELECT 1 FROM invoice_payment_events e
            WHERE e.invoice_id = i.id
              AND e.source IN ('bitcoin_direct', 'liquid_direct')
         )
         OR (
           i.settlement_status = 'pending'
           AND EXISTS (
             SELECT 1 FROM invoice_payment_observations o
              WHERE o.invoice_id = i.id
                AND o.source = 'bitcoin_direct'
                AND o.last_seen_state IN (
                  'seen_unconfirmed', 'awaiting_confirmations'
                )
           )
         )
       ) THEN i.settlement_status
      ELSE 'none'
    END,
    swap_settlement_status = CASE
      WHEN i.settlement_status IN (
        'pending', 'settled', 'claim_stuck', 'refunded', 'failed'
      )
       AND (
         EXISTS (
           SELECT 1 FROM invoice_payment_events e
            WHERE e.invoice_id = i.id
              AND e.source IN (
                'lightning_boltz_reverse', 'bitcoin_boltz_chain'
              )
         )
         OR NOT EXISTS (
           SELECT 1 FROM invoice_payment_events e
            WHERE e.invoice_id = i.id
              AND e.source IN ('bitcoin_direct', 'liquid_direct')
         ) AND NOT EXISTS (
           SELECT 1 FROM invoice_payment_observations o
            WHERE o.invoice_id = i.id
              AND o.source = 'bitcoin_direct'
              AND o.last_seen_state IN (
                'seen_unconfirmed', 'awaiting_confirmations'
              )
         )
       ) THEN i.settlement_status
      ELSE 'none'
    END;

-- --------------------------------------------------------------------------
-- Accounting events: immutable evidence plus reversible countability.
-- --------------------------------------------------------------------------

CREATE SEQUENCE invoice_payment_events_accounting_sequence_seq;

ALTER TABLE invoice_payment_events
  ADD COLUMN accounting_sequence BIGINT,
  ADD COLUMN accounting_state TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN verification_state TEXT NOT NULL DEFAULT 'unclassified',
  ADD COLUMN state_version BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN last_activated_at TIMESTAMPTZ,
  ADD COLUMN deactivated_at TIMESTAMPTZ,
  ADD COLUMN deactivation_reason TEXT,
  ADD COLUMN observation_id UUID,
  ADD COLUMN superseded_by_event_id UUID;

WITH ordered AS (
  SELECT id, row_number() OVER (ORDER BY created_at ASC, id ASC) AS sequence
    FROM invoice_payment_events
)
UPDATE invoice_payment_events e
   SET accounting_sequence = ordered.sequence,
       last_activated_at = e.created_at
  FROM ordered
 WHERE e.id = ordered.id;

SELECT setval(
  'invoice_payment_events_accounting_sequence_seq',
  COALESCE((SELECT MAX(accounting_sequence) FROM invoice_payment_events), 0) + 1,
  false
);

ALTER TABLE invoice_payment_events
  ALTER COLUMN accounting_sequence SET DEFAULT
    nextval('invoice_payment_events_accounting_sequence_seq'),
  ALTER COLUMN accounting_sequence SET NOT NULL,
  ALTER COLUMN last_activated_at SET DEFAULT now();

ALTER SEQUENCE invoice_payment_events_accounting_sequence_seq
  OWNED BY invoice_payment_events.accounting_sequence;

UPDATE invoice_payment_events
SET accounting_state = 'legacy_unverified',
    verification_state = 'legacy_unverified'
WHERE source IN ('bitcoin_direct', 'liquid_direct');

UPDATE invoice_payment_events
SET verification_state = 'not_applicable'
WHERE source IN ('lightning_boltz_reverse', 'bitcoin_boltz_chain');

ALTER TABLE invoice_payment_events
  ADD CONSTRAINT invoice_payment_events_accounting_sequence_key
    UNIQUE (accounting_sequence),
  ADD CONSTRAINT invoice_payment_events_accounting_state_check CHECK (
    accounting_state IN (
      'active', 'inactive', 'superseded', 'legacy_unverified'
    )
  ),
  ADD CONSTRAINT invoice_payment_events_verification_state_check CHECK (
    verification_state IN (
      'unclassified', 'legacy_unverified', 'verified', 'not_applicable'
    )
  ),
  ADD CONSTRAINT invoice_payment_events_state_version_check CHECK (
    state_version >= 0
  ),
  ADD CONSTRAINT invoice_payment_events_deactivation_reason_check CHECK (
    deactivation_reason IS NULL OR deactivation_reason IN (
      'conflict', 'evicted', 'replaced', 'invalid_replacement', 'reorged',
      'authoritative_absence', 'boltz_supersession', 'not_confirmed'
    )
  ),
  ADD CONSTRAINT invoice_payment_events_accounting_shape_check CHECK (
    (
      accounting_state IN ('active', 'legacy_unverified')
      AND last_activated_at IS NOT NULL
      AND deactivated_at IS NULL
      AND deactivation_reason IS NULL
      AND superseded_by_event_id IS NULL
    ) OR (
      accounting_state = 'inactive'
      AND deactivated_at IS NOT NULL
      AND deactivation_reason IS NOT NULL
      AND superseded_by_event_id IS NULL
    ) OR (
      accounting_state = 'superseded'
      AND deactivated_at IS NOT NULL
      AND deactivation_reason IS NOT NULL
      AND superseded_by_event_id IS NOT NULL
    )
  ),
  ADD CONSTRAINT invoice_payment_events_observation_source_check CHECK (
    observation_id IS NULL OR source IN ('bitcoin_direct', 'liquid_direct')
  ),
  ADD CONSTRAINT invoice_payment_events_observation_fk FOREIGN KEY (observation_id)
    REFERENCES invoice_payment_observations(id) ON DELETE SET NULL,
  ADD CONSTRAINT invoice_payment_events_superseded_by_fk
    FOREIGN KEY (superseded_by_event_id)
    REFERENCES invoice_payment_events(id) ON DELETE RESTRICT,
  ADD CONSTRAINT invoice_payment_events_not_self_superseded_check CHECK (
    superseded_by_event_id IS NULL OR superseded_by_event_id <> id
  );

CREATE INDEX invoice_payment_events_countable_invoice_idx
  ON invoice_payment_events(invoice_id, accounting_sequence)
  INCLUDE (amount_sat, rail)
  WHERE accounting_state IN ('active', 'legacy_unverified');

CREATE INDEX invoice_payment_events_observation_idx
  ON invoice_payment_events(observation_id)
  WHERE observation_id IS NOT NULL;

CREATE FUNCTION guard_invoice_payment_event_evidence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.invoice_id IS DISTINCT FROM OLD.invoice_id
     OR NEW.rail IS DISTINCT FROM OLD.rail
     OR NEW.source IS DISTINCT FROM OLD.source
     OR NEW.event_key IS DISTINCT FROM OLD.event_key
     OR NEW.amount_sat IS DISTINCT FROM OLD.amount_sat
     OR NEW.txid IS DISTINCT FROM OLD.txid
     OR NEW.vout IS DISTINCT FROM OLD.vout
     OR NEW.boltz_swap_id IS DISTINCT FROM OLD.boltz_swap_id
     OR NEW.address IS DISTINCT FROM OLD.address
     OR NEW.accounting_sequence IS DISTINCT FROM OLD.accounting_sequence
     OR (OLD.observation_id IS NOT NULL
         AND NEW.observation_id IS DISTINCT FROM OLD.observation_id) THEN
    RAISE EXCEPTION 'invoice payment event evidence is immutable'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER invoice_payment_event_evidence_guard
BEFORE UPDATE ON invoice_payment_events
FOR EACH ROW
EXECUTE FUNCTION guard_invoice_payment_event_evidence();

-- Migration 047 is applied before the new binary starts. During that window
-- the 046 writer omits every lifecycle column, so its inserts arrive as the
-- active/unclassified defaults with no observation link. Classify only that
-- exact legacy-write shape; explicit reducer evidence (including inactive
-- unverified evidence) remains untouched.
CREATE FUNCTION classify_invoice_payment_event_compatibility_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.verification_state = 'unclassified'
     AND NEW.accounting_state = 'active'
     AND NEW.observation_id IS NULL THEN
    IF NEW.source IN ('bitcoin_direct', 'liquid_direct') THEN
      NEW.accounting_state := 'legacy_unverified';
      NEW.verification_state := 'legacy_unverified';
    ELSIF NEW.source IN ('lightning_boltz_reverse', 'bitcoin_boltz_chain') THEN
      NEW.verification_state := 'not_applicable';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER invoice_payment_event_compatibility_insert_classifier
BEFORE INSERT ON invoice_payment_events
FOR EACH ROW
EXECUTE FUNCTION classify_invoice_payment_event_compatibility_insert();

-- --------------------------------------------------------------------------
-- Observations: retain legacy writer compatibility and add the exact evidence
-- required by the dormant direct lifecycle reducer.
-- --------------------------------------------------------------------------

ALTER TABLE invoice_payment_observations
  DROP CONSTRAINT IF EXISTS invoice_payment_observations_rail_check,
  DROP CONSTRAINT IF EXISTS invoice_payment_observations_source_check,
  DROP CONSTRAINT IF EXISTS invoice_payment_observations_event_key_check,
  DROP CONSTRAINT IF EXISTS invoice_payment_observations_address_check,
  DROP CONSTRAINT IF EXISTS invoice_payment_observations_last_seen_state_check,
  DROP CONSTRAINT IF EXISTS invoice_payment_observations_check,
  DROP CONSTRAINT IF EXISTS invoice_payment_observations_check1;

ALTER TABLE invoice_payment_observations
  ADD COLUMN asset_id TEXT,
  ADD COLUMN inclusion_block_hash TEXT,
  ADD COLUMN verification_state TEXT NOT NULL DEFAULT 'legacy_unverified',
  ADD COLUMN lifecycle_version BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN latest_successful_check_at TIMESTAMPTZ,
  ADD COLUMN latest_check_authority TEXT,
  ADD COLUMN last_applied_generation BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN absence_streak INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN first_qualifying_absence_at TIMESTAMPTZ,
  ADD COLUMN last_qualifying_absence_at TIMESTAMPTZ,
  ADD COLUMN absence_authority TEXT,
  ADD COLUMN invalidation_reason TEXT,
  ADD COLUMN invalidated_at TIMESTAMPTZ,
  ADD COLUMN superseded_by_observation_id UUID,
  ADD COLUMN superseded_by_payment_event_id UUID;

ALTER TABLE invoice_payment_observations
  ADD CONSTRAINT invoice_payment_observations_source_rail_check CHECK (
    (source = 'bitcoin_direct' AND rail = 'bitcoin') OR
    (source = 'liquid_direct' AND rail = 'liquid')
  ),
  ADD CONSTRAINT invoice_payment_observations_address_length_check CHECK (
    length(address) BETWEEN 1 AND 200
  ),
  ADD CONSTRAINT invoice_payment_observations_event_identity_check CHECK (
    event_key ~ '^(bitcoin|liquid)_direct:[0-9a-fA-F]{64}:[0-9]+$'
    AND event_key = source || ':' || txid || ':' || vout::TEXT
  ),
  ADD CONSTRAINT invoice_payment_observations_asset_check CHECK (
    (source = 'bitcoin_direct' AND asset_id IS NULL) OR
    (
      source = 'liquid_direct'
      AND asset_id IS NOT NULL
      AND asset_id ~ '^[0-9a-fA-F]{64}$'
    )
  ),
  ADD CONSTRAINT invoice_payment_observations_state_check CHECK (
    last_seen_state IN (
      'seen_unconfirmed', 'awaiting_confirmations', 'counted', 'not_seen',
      'resolution_pending', 'superseded'
    )
  ),
  ADD CONSTRAINT invoice_payment_observations_verification_state_check CHECK (
    verification_state IN ('legacy_unverified', 'verified', 'unverified')
  ),
  ADD CONSTRAINT invoice_payment_observations_lifecycle_version_check CHECK (
    lifecycle_version >= 0
  ),
  ADD CONSTRAINT invoice_payment_observations_block_hash_check CHECK (
    inclusion_block_hash IS NULL OR
    inclusion_block_hash ~ '^[0-9a-fA-F]{64}$'
  ),
  ADD CONSTRAINT invoice_payment_observations_generation_check CHECK (
    last_applied_generation >= 0
  ),
  ADD CONSTRAINT invoice_payment_observations_verified_shape_check CHECK (
    verification_state <> 'verified' OR
    (
      last_seen_state = 'seen_unconfirmed'
      AND confirmations = 0
      AND block_height IS NULL
      AND inclusion_block_hash IS NULL
    ) OR (
      last_seen_state IN ('awaiting_confirmations', 'counted')
      AND confirmations > 0
      AND block_height IS NOT NULL
      AND inclusion_block_hash IS NOT NULL
    ) OR last_seen_state IN (
      'not_seen', 'resolution_pending', 'superseded'
    )
  ),
  ADD CONSTRAINT invoice_payment_observations_absence_check CHECK (
    (
      absence_streak = 0
      AND first_qualifying_absence_at IS NULL
      AND last_qualifying_absence_at IS NULL
      AND absence_authority IS NULL
    ) OR (
      absence_streak > 0
      AND first_qualifying_absence_at IS NOT NULL
      AND last_qualifying_absence_at IS NOT NULL
      AND absence_authority IS NOT NULL
    )
  ),
  ADD CONSTRAINT invoice_payment_observations_invalidation_reason_check CHECK (
    invalidation_reason IS NULL OR invalidation_reason IN (
      'conflict', 'evicted', 'replaced', 'invalid_replacement', 'reorged',
      'authoritative_absence', 'boltz_supersession'
    )
  ),
  ADD CONSTRAINT invoice_payment_observations_invalidation_shape_check CHECK (
    (
      last_seen_state IN ('resolution_pending', 'superseded')
      AND invalidation_reason IS NOT NULL
      AND invalidated_at IS NOT NULL
    ) OR (
      last_seen_state NOT IN ('resolution_pending', 'superseded')
      AND invalidation_reason IS NULL
      AND invalidated_at IS NULL
    )
  ),
  ADD CONSTRAINT invoice_payment_observations_supersession_shape_check CHECK (
    (
      last_seen_state = 'superseded'
      AND (
        (
          superseded_by_observation_id IS NOT NULL
          AND superseded_by_payment_event_id IS NULL
        ) OR (
          superseded_by_observation_id IS NULL
          AND superseded_by_payment_event_id IS NOT NULL
        )
      )
    ) OR (
      last_seen_state <> 'superseded'
      AND superseded_by_observation_id IS NULL
      AND superseded_by_payment_event_id IS NULL
    )
  ),
  ADD CONSTRAINT invoice_payment_observations_source_outpoint_key
    UNIQUE (source, txid, vout),
  ADD CONSTRAINT invoice_payment_observations_superseded_by_fk
    FOREIGN KEY (superseded_by_observation_id)
    REFERENCES invoice_payment_observations(id) ON DELETE RESTRICT,
  ADD CONSTRAINT invoice_payment_observations_superseded_by_payment_event_fk
    FOREIGN KEY (superseded_by_payment_event_id)
    REFERENCES invoice_payment_events(id) ON DELETE RESTRICT,
  ADD CONSTRAINT invoice_payment_observations_not_self_superseded_check CHECK (
    superseded_by_observation_id IS NULL OR superseded_by_observation_id <> id
  );

CREATE INDEX invoice_payment_observations_lifecycle_idx
  ON invoice_payment_observations(
    invoice_id, source, last_seen_state, last_seen_at DESC
  );

CREATE INDEX invoice_payment_observations_generation_idx
  ON invoice_payment_observations(invoice_id, source, last_applied_generation);

CREATE FUNCTION guard_invoice_payment_observation_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.invoice_id IS DISTINCT FROM OLD.invoice_id
     OR NEW.rail IS DISTINCT FROM OLD.rail
     OR NEW.source IS DISTINCT FROM OLD.source
     OR NEW.event_key IS DISTINCT FROM OLD.event_key
     OR NEW.txid IS DISTINCT FROM OLD.txid
     OR NEW.vout IS DISTINCT FROM OLD.vout
     OR NEW.address IS DISTINCT FROM OLD.address
     OR NEW.amount_sat IS DISTINCT FROM OLD.amount_sat
     OR NEW.asset_id IS DISTINCT FROM OLD.asset_id THEN
    RAISE EXCEPTION 'invoice payment observation identity is immutable'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER invoice_payment_observation_identity_guard
BEFORE UPDATE ON invoice_payment_observations
FOR EACH ROW
EXECUTE FUNCTION guard_invoice_payment_observation_identity();

-- Link exact legacy BTC observations without inventing Liquid observations.
UPDATE invoice_payment_events e
SET observation_id = o.id
FROM invoice_payment_observations o
WHERE e.invoice_id = o.invoice_id
  AND e.event_key = o.event_key
  AND e.source IN ('bitcoin_direct', 'liquid_direct');

-- --------------------------------------------------------------------------
-- Bounded per-invoice/source scan generations.  One row is updated forever;
-- transition/observation rows retain the money-relevant history.
-- --------------------------------------------------------------------------

CREATE TABLE invoice_direct_scan_heads (
  invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  source TEXT NOT NULL CHECK (
    source IN ('bitcoin_direct', 'liquid_direct')
  ),
  rail TEXT GENERATED ALWAYS AS (
    CASE source
      WHEN 'bitcoin_direct' THEN 'bitcoin'
      WHEN 'liquid_direct' THEN 'liquid'
    END
  ) STORED,
  issued_generation BIGINT NOT NULL DEFAULT 0 CHECK (issued_generation >= 0),
  applied_generation BIGINT NOT NULL DEFAULT 0 CHECK (applied_generation >= 0),
  last_started_at TIMESTAMPTZ,
  last_applied_at TIMESTAMPTZ,
  last_authority TEXT,
  last_outcome TEXT CHECK (
    last_outcome IS NULL OR last_outcome IN (
      'applied', 'already_applied', 'stale', 'failed', 'cancelled'
    )
  ),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (invoice_id, source),
  CHECK (applied_generation <= issued_generation),
  CHECK (last_authority IS NULL OR length(btrim(last_authority)) BETWEEN 1 AND 255)
);

-- --------------------------------------------------------------------------
-- Append-only lifecycle audit. Invoice deletion keeps its existing cascade
-- behaviour; a DML guard enforces immutability even when runtime owns tables.
-- --------------------------------------------------------------------------

CREATE TABLE invoice_direct_payment_transitions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key TEXT NOT NULL UNIQUE CHECK (
    length(btrim(idempotency_key)) BETWEEN 1 AND 255
  ),
  invoice_id UUID NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  observation_id UUID
    REFERENCES invoice_payment_observations(id) ON DELETE CASCADE,
  payment_event_id UUID
    REFERENCES invoice_payment_events(id) ON DELETE SET NULL,
  source TEXT NOT NULL CHECK (
    source IN ('bitcoin_direct', 'liquid_direct')
  ),
  generation BIGINT NOT NULL,
  transition_kind TEXT NOT NULL CHECK (
    transition_kind IN (
      'observed_provisional', 'accounting_activated', 'finalized',
      'resolution_pending', 'reactivated', 'superseded', 'replacement',
      'legacy_revalidated', 'evidence_unverified'
    )
  ),
  from_observation_state TEXT,
  to_observation_state TEXT,
  from_verification_state TEXT,
  to_verification_state TEXT,
  from_event_state TEXT,
  to_event_state TEXT,
  reason TEXT,
  from_presentation_status TEXT,
  to_presentation_status TEXT,
  from_settlement_status TEXT,
  to_settlement_status TEXT,
  from_invoice_status TEXT,
  to_invoice_status TEXT,
  from_paid_amount_sat BIGINT,
  to_paid_amount_sat BIGINT,
  metadata JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (
    jsonb_typeof(metadata) = 'object'
  ),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (observation_id, generation),
  CHECK (observation_id IS NOT NULL OR payment_event_id IS NOT NULL),
  CHECK (
    (
      observation_id IS NULL
      AND from_observation_state IS NULL
      AND to_observation_state IS NULL
      AND from_verification_state IS NULL
      AND to_verification_state IS NULL
    ) OR (
      observation_id IS NOT NULL
      AND to_observation_state IS NOT NULL
      AND to_verification_state IS NOT NULL
    )
  ),
  CHECK (
    generation > 0 OR (
      generation = 0
      AND transition_kind = 'superseded'
      AND reason = 'boltz_supersession'
    )
  ),
  CHECK (
    from_presentation_status IS NULL OR from_presentation_status IN (
      'unpaid', 'partial', 'payment_received', 'overpaid'
    )
  ),
  CHECK (
    to_presentation_status IS NULL OR to_presentation_status IN (
      'unpaid', 'partial', 'payment_received', 'overpaid'
    )
  ),
  CHECK (
    from_settlement_status IS NULL OR from_settlement_status IN (
      'none', 'pending', 'settled', 'resolution_pending',
      'claim_stuck', 'refunded', 'failed'
    )
  ),
  CHECK (
    to_settlement_status IS NULL OR to_settlement_status IN (
      'none', 'pending', 'settled', 'resolution_pending',
      'claim_stuck', 'refunded', 'failed'
    )
  )
);

CREATE INDEX invoice_direct_payment_transitions_invoice_idx
  ON invoice_direct_payment_transitions(invoice_id, recorded_at DESC);

CREATE INDEX invoice_direct_payment_transitions_generation_idx
  ON invoice_direct_payment_transitions(invoice_id, source, generation);

-- The deployment role owns this table, so grants/revokes cannot make its rows
-- append-only.  Reject direct mutation in DML while still allowing the
-- existing invoice ON DELETE CASCADE after the parent invoice has gone away.
CREATE FUNCTION guard_invoice_direct_payment_transition_history()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM invoices WHERE id = OLD.invoice_id) THEN
    IF TG_OP = 'DELETE' THEN
      RETURN OLD;
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'invoice direct payment transition history is append-only'
    USING ERRCODE = '23514';
END
$$;

CREATE TRIGGER invoice_direct_payment_transition_history_guard
BEFORE UPDATE OR DELETE ON invoice_direct_payment_transitions
FOR EACH ROW
EXECUTE FUNCTION guard_invoice_direct_payment_transition_history();

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
    GRANT USAGE, SELECT
      ON SEQUENCE invoice_payment_events_accounting_sequence_seq
      TO payservice;
    GRANT SELECT, INSERT, UPDATE
      ON invoice_direct_scan_heads
      TO payservice;
    GRANT SELECT, INSERT
      ON invoice_direct_payment_transitions
      TO payservice;
  END IF;
END
$$;

COMMIT;
