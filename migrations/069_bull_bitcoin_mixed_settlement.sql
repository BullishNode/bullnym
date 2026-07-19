-- Immutable swap-policy and two-output authority for mixed Bitcoin/fiat
-- settlement. The feature stores only local order/output identifiers and
-- cryptographic output evidence; it never stores Bull Bitcoin account data.

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

CREATE TABLE swap_fiat_settlement_policies (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    reverse_swap_id  UUID,
    chain_swap_id    UUID,
    owner_npub       TEXT        NOT NULL,
    credential_id    UUID        NOT NULL,
    product          TEXT        NOT NULL,
    fiat_percentage  SMALLINT    NOT NULL,
    fiat_currency    TEXT        NOT NULL,
    terms_version    TEXT        NOT NULL,
    captured_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT swap_fiat_settlement_policies_source_chk CHECK (
        (reverse_swap_id IS NOT NULL)::INTEGER
        + (chain_swap_id IS NOT NULL)::INTEGER = 1
    ),
    CONSTRAINT swap_fiat_settlement_policies_reverse_fkey
        FOREIGN KEY (reverse_swap_id) REFERENCES swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT swap_fiat_settlement_policies_chain_fkey
        FOREIGN KEY (chain_swap_id) REFERENCES chain_swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT swap_fiat_settlement_policies_credential_owner_fkey
        FOREIGN KEY (credential_id, owner_npub)
        REFERENCES bull_bitcoin_credentials(id, owner_npub)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT swap_fiat_settlement_policies_owner_shape_chk CHECK (
        owner_npub ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT swap_fiat_settlement_policies_product_chk CHECK (
        product IN ('lightning_address', 'payment_page', 'pos', 'invoice')
        AND (product <> 'lightning_address' OR reverse_swap_id IS NOT NULL)
    ),
    CONSTRAINT swap_fiat_settlement_policies_percentage_chk CHECK (
        fiat_percentage BETWEEN 1 AND 99
    ),
    CONSTRAINT swap_fiat_settlement_policies_currency_chk CHECK (
        fiat_currency IN ('ARS', 'CAD', 'COP', 'CRC', 'EUR', 'MXN', 'USD')
    ),
    CONSTRAINT swap_fiat_settlement_policies_terms_chk CHECK (
        terms_version = 'bull-bitcoin-fiat-settlement-v1'
    )
);

CREATE UNIQUE INDEX swap_fiat_settlement_policies_reverse_key
    ON swap_fiat_settlement_policies(reverse_swap_id)
    WHERE reverse_swap_id IS NOT NULL;
CREATE UNIQUE INDEX swap_fiat_settlement_policies_chain_key
    ON swap_fiat_settlement_policies(chain_swap_id)
    WHERE chain_swap_id IS NOT NULL;

CREATE FUNCTION guard_swap_fiat_policy_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    source_owner TEXT;
    source_invoice_id UUID;
BEGIN
    IF NEW.reverse_swap_id IS NOT NULL THEN
        SELECT COALESCE(invoice.npub_owner, account.npub), swap.invoice_id
          INTO source_owner, source_invoice_id
          FROM swap_records swap
          LEFT JOIN invoices invoice ON invoice.id = swap.invoice_id
          LEFT JOIN users account ON account.nym = swap.nym
         WHERE swap.id = NEW.reverse_swap_id;
    ELSE
        SELECT invoice.npub_owner, swap.invoice_id
          INTO source_owner, source_invoice_id
          FROM chain_swap_records swap
          JOIN invoices invoice ON invoice.id = swap.invoice_id
         WHERE swap.id = NEW.chain_swap_id;
    END IF;
    IF NOT FOUND
       OR source_owner IS DISTINCT FROM NEW.owner_npub
       OR (NEW.product = 'lightning_address') IS DISTINCT FROM
          (source_invoice_id IS NULL) THEN
        RAISE EXCEPTION 'swap fiat policy lacks exact owner and product authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'swap_fiat_settlement_policies_source_authority';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER swap_fiat_settlement_policies_guard_insert
    BEFORE INSERT ON swap_fiat_settlement_policies
    FOR EACH ROW EXECUTE FUNCTION guard_swap_fiat_policy_insert();

CREATE FUNCTION reject_swap_fiat_policy_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'swap fiat-settlement policy is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'swap_fiat_settlement_policies_immutable';
END
$$;

CREATE TRIGGER swap_fiat_settlement_policies_reject_mutation
    BEFORE UPDATE OR DELETE ON swap_fiat_settlement_policies
    FOR EACH ROW EXECUTE FUNCTION reject_swap_fiat_policy_mutation();

ALTER TABLE bull_bitcoin_settlements
    ADD COLUMN reverse_swap_id UUID,
    ADD COLUMN chain_swap_id UUID,
    ADD CONSTRAINT bull_bitcoin_settlements_reverse_swap_fkey
        FOREIGN KEY (reverse_swap_id) REFERENCES swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT bull_bitcoin_settlements_chain_swap_fkey
        FOREIGN KEY (chain_swap_id) REFERENCES chain_swap_records(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    ADD CONSTRAINT bull_bitcoin_settlements_swap_binding_chk CHECK (
        (
            purpose = 'fiat_only'
            AND reverse_swap_id IS NULL AND chain_swap_id IS NULL
        ) OR (
            purpose = 'mixed'
            AND (
                (reverse_swap_id IS NOT NULL)::INTEGER
                + (chain_swap_id IS NOT NULL)::INTEGER = 1
            )
            AND (
                (reverse_swap_id IS NOT NULL AND payer_rail = 'lightning')
                OR (chain_swap_id IS NOT NULL AND payer_rail = 'bitcoin')
            )
        )
    );

CREATE UNIQUE INDEX bull_bitcoin_settlements_one_reverse_mixed_key
    ON bull_bitcoin_settlements(reverse_swap_id)
    WHERE reverse_swap_id IS NOT NULL;
CREATE UNIQUE INDEX bull_bitcoin_settlements_one_chain_mixed_key
    ON bull_bitcoin_settlements(chain_swap_id)
    WHERE chain_swap_id IS NOT NULL;

ALTER TABLE bull_bitcoin_settlements
    DROP CONSTRAINT bull_bitcoin_settlements_instruction_chk,
    ADD CONSTRAINT bull_bitcoin_settlements_instruction_chk CHECK (
        (instruction_kind IS NULL AND payer_instruction IS NULL)
        OR (
            provider_state = 'bound'
            AND funding_route IS DISTINCT FROM 'bitcoin_fallback'
            AND (purpose <> 'mixed' OR funding_committed_at IS NULL)
            AND instruction_kind = CASE
                WHEN purpose = 'mixed' THEN 'liquid'
                ELSE payer_rail
            END
            AND payer_instruction IS NOT NULL
            AND length(payer_instruction) BETWEEN 1 AND 4096
            AND payer_instruction !~ '[[:cntrl:]]'
        )
    );

CREATE FUNCTION guard_bull_bitcoin_swap_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    policy_row RECORD;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.reverse_swap_id IS DISTINCT FROM OLD.reverse_swap_id
           OR NEW.chain_swap_id IS DISTINCT FROM OLD.chain_swap_id THEN
            RAISE EXCEPTION 'Bull Bitcoin swap binding is immutable'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_swap_binding_immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.purpose <> 'mixed' THEN
        RETURN NEW;
    END IF;

    SELECT policy.owner_npub, policy.credential_id, policy.product,
           policy.fiat_percentage, policy.fiat_currency, policy.terms_version,
           COALESCE(reverse_swap.invoice_id, chain_swap.invoice_id)
               AS expected_invoice_id
      INTO policy_row
      FROM swap_fiat_settlement_policies policy
      LEFT JOIN swap_records reverse_swap
        ON reverse_swap.id = policy.reverse_swap_id
      LEFT JOIN chain_swap_records chain_swap
        ON chain_swap.id = policy.chain_swap_id
     WHERE policy.reverse_swap_id IS NOT DISTINCT FROM NEW.reverse_swap_id
       AND policy.chain_swap_id IS NOT DISTINCT FROM NEW.chain_swap_id;
    IF NOT FOUND
       OR ROW(
            policy_row.owner_npub, policy_row.credential_id,
            policy_row.product, policy_row.fiat_percentage,
            policy_row.fiat_currency, policy_row.terms_version
          ) IS DISTINCT FROM ROW(
            NEW.owner_npub, NEW.credential_id, NEW.product,
            NEW.fiat_percentage, NEW.fiat_currency, NEW.terms_version
          ) THEN
        RAISE EXCEPTION 'Bull Bitcoin mixed settlement lacks its exact swap policy'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_swap_policy_authority';
    END IF;
    IF policy_row.expected_invoice_id IS DISTINCT FROM NEW.invoice_id THEN
        RAISE EXCEPTION 'Bull Bitcoin mixed settlement borrowed another invoice'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_swap_invoice_authority';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER bull_bitcoin_settlements_guard_swap_binding
    BEFORE INSERT OR UPDATE ON bull_bitcoin_settlements
    FOR EACH ROW EXECUTE FUNCTION guard_bull_bitcoin_swap_binding();

CREATE TABLE bull_bitcoin_claim_outputs (
    settlement_id               UUID        NOT NULL,
    role                        TEXT        NOT NULL,
    txid                        TEXT        NOT NULL,
    vout                        SMALLINT    NOT NULL,
    script_pubkey_hex           TEXT        NOT NULL,
    authorized_amount_sat       BIGINT      NOT NULL,
    asset_commitment_sha256     TEXT        NOT NULL,
    value_commitment_sha256     TEXT        NOT NULL,
    nonce_commitment_sha256     TEXT        NOT NULL,
    surjection_proof_sha256     TEXT        NOT NULL,
    rangeproof_sha256           TEXT        NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (settlement_id, role),
    UNIQUE (txid, vout),
    CONSTRAINT bull_bitcoin_claim_outputs_settlement_fkey
        FOREIGN KEY (settlement_id) REFERENCES bull_bitcoin_settlements(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT bull_bitcoin_claim_outputs_role_vout_chk CHECK (
        (role = 'merchant' AND vout = 0)
        OR (role = 'bull_bitcoin' AND vout = 1)
    ),
    CONSTRAINT bull_bitcoin_claim_outputs_txid_chk CHECK (
        txid ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT bull_bitcoin_claim_outputs_script_chk CHECK (
        length(script_pubkey_hex) BETWEEN 4 AND 200
        AND script_pubkey_hex ~ '^[0-9a-f]+$'
        AND length(script_pubkey_hex) % 2 = 0
    ),
    CONSTRAINT bull_bitcoin_claim_outputs_amount_chk CHECK (
        authorized_amount_sat > 0
        AND authorized_amount_sat <= 2100000000000000
    ),
    CONSTRAINT bull_bitcoin_claim_outputs_hashes_chk CHECK (
        asset_commitment_sha256 ~ '^[0-9a-f]{64}$'
        AND value_commitment_sha256 ~ '^[0-9a-f]{64}$'
        AND nonce_commitment_sha256 ~ '^[0-9a-f]{64}$'
        AND surjection_proof_sha256 ~ '^[0-9a-f]{64}$'
        AND rangeproof_sha256 ~ '^[0-9a-f]{64}$'
    )
);

CREATE FUNCTION reject_bull_bitcoin_claim_output_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Bull Bitcoin claim-output evidence is immutable'
        USING ERRCODE = '23514',
              CONSTRAINT = 'bull_bitcoin_claim_outputs_immutable';
END
$$;

CREATE FUNCTION guard_bull_bitcoin_claim_output_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    settlement_row RECORD;
BEGIN
    SELECT purpose, provider_state, funding_route, funding_committed_at,
           requested_bitcoin_sat
      INTO settlement_row
      FROM bull_bitcoin_settlements
     WHERE id = NEW.settlement_id
     FOR SHARE;
    IF NOT FOUND
       OR settlement_row.purpose <> 'mixed'
       OR settlement_row.provider_state <> 'bound'
       OR settlement_row.funding_route IS NOT NULL
       OR settlement_row.funding_committed_at IS NOT NULL
       OR (
            NEW.role = 'bull_bitcoin'
            AND NEW.authorized_amount_sat IS DISTINCT FROM
                settlement_row.requested_bitcoin_sat
       ) THEN
        RAISE EXCEPTION 'claim output lacks exact unfunded mixed-order authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_claim_outputs_settlement_authority';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER bull_bitcoin_claim_outputs_guard_insert
    BEFORE INSERT ON bull_bitcoin_claim_outputs
    FOR EACH ROW EXECUTE FUNCTION guard_bull_bitcoin_claim_output_insert();

CREATE TRIGGER bull_bitcoin_claim_outputs_reject_mutation
    BEFORE UPDATE OR DELETE ON bull_bitcoin_claim_outputs
    FOR EACH ROW EXECUTE FUNCTION reject_bull_bitcoin_claim_output_mutation();

CREATE OR REPLACE FUNCTION guard_bull_bitcoin_funding_commitment()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    output_count INTEGER;
    output_txids INTEGER;
    merchant_amount_sat BIGINT;
    bull_bitcoin_amount_sat BIGINT;
BEGIN
    IF OLD.funding_committed_at IS NOT NULL
       AND NEW.funding_committed_at IS DISTINCT FROM OLD.funding_committed_at THEN
        RAISE EXCEPTION 'Bull Bitcoin funding commitment is immutable'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'bull_bitcoin_settlements_funding_commitment_immutable';
    END IF;
    IF OLD.funding_committed_at IS NULL
       AND NEW.funding_committed_at IS NOT NULL THEN
        IF NOT (
            NEW.provider_state = 'bound'
            AND NEW.funding_route = 'bull_bitcoin'
            AND NEW.funding_committed_at >= NEW.created_at
        ) THEN
            RAISE EXCEPTION 'invalid Bull Bitcoin funding commitment'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'bull_bitcoin_settlements_funding_commitment_transition';
        END IF;
        IF NEW.purpose = 'mixed' THEN
            SELECT COUNT(*), COUNT(DISTINCT txid),
                   MAX(authorized_amount_sat) FILTER (WHERE role = 'merchant'),
                   MAX(authorized_amount_sat) FILTER (WHERE role = 'bull_bitcoin')
              INTO output_count, output_txids,
                   merchant_amount_sat, bull_bitcoin_amount_sat
              FROM bull_bitcoin_claim_outputs
             WHERE settlement_id = NEW.id;
            IF output_count <> 2
               OR output_txids <> 1
               OR bull_bitcoin_amount_sat IS DISTINCT FROM
                  ((merchant_amount_sat + bull_bitcoin_amount_sat)
                   * NEW.fiat_percentage / 100) THEN
                RAISE EXCEPTION 'mixed funding requires one exact percentage two-output journal'
                    USING ERRCODE = '23514',
                          CONSTRAINT = 'bull_bitcoin_settlements_mixed_output_authority';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END
$$;

-- A mixed reverse claim reuses the established Lightning event source for the
-- merchant leg. Bind that event to vout=0 so neither the live writer nor crash
-- repair can accidentally account the historical gross swap amount.
CREATE FUNCTION guard_mixed_reverse_merchant_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    authority RECORD;
BEGIN
    SELECT settlement.invoice_id, merchant.txid, merchant.authorized_amount_sat
      INTO authority
      FROM swap_records swap
      JOIN bull_bitcoin_settlements settlement
        ON settlement.reverse_swap_id = swap.id
       AND settlement.purpose = 'mixed'
       AND settlement.provider_state = 'bound'
       AND settlement.funding_route = 'bull_bitcoin'
       AND settlement.funding_committed_at IS NOT NULL
      LEFT JOIN bull_bitcoin_claim_outputs merchant
        ON merchant.settlement_id = settlement.id
       AND merchant.role = 'merchant'
     WHERE swap.boltz_swap_id = NEW.boltz_swap_id;
    IF FOUND AND (
        authority.invoice_id IS DISTINCT FROM NEW.invoice_id
        OR authority.txid IS DISTINCT FROM NEW.txid
        OR authority.authorized_amount_sat IS DISTINCT FROM NEW.amount_sat
        OR NEW.event_key IS DISTINCT FROM
            'lightning_boltz_reverse:' || NEW.boltz_swap_id
    ) THEN
        RAISE EXCEPTION 'mixed reverse merchant event lacks exact claim-output authority'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'invoice_payment_events_mixed_reverse_authority';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER invoice_payment_events_guard_mixed_reverse
    BEFORE INSERT ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source = 'lightning_boltz_reverse')
    EXECUTE FUNCTION guard_mixed_reverse_merchant_event();

ALTER TABLE invoice_payment_events
    DROP CONSTRAINT invoice_payment_events_source_chk,
    DROP CONSTRAINT invoice_payment_events_source_rail_chk,
    DROP CONSTRAINT invoice_payment_events_bull_bitcoin_shape_chk,
    ADD CONSTRAINT invoice_payment_events_source_chk CHECK (
        source IS NULL OR source IN (
            'bitcoin_direct', 'liquid_direct', 'lightning_boltz_reverse',
            'bitcoin_boltz_chain', 'bitcoin_boltz_recovery',
            'bull_bitcoin_fiat', 'bull_bitcoin_mixed_output'
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
            OR (source = 'bull_bitcoin_mixed_output' AND rail = 'liquid')
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
            source = 'bull_bitcoin_mixed_output'
            AND bull_bitcoin_settlement_id IS NOT NULL
            AND event_key = 'bull_bitcoin_mixed_output:' || bull_bitcoin_settlement_id::TEXT
            AND txid ~ '^[0-9a-f]{64}$' AND vout = 1
            AND boltz_swap_id IS NULL AND address IS NULL
            AND accounting_state IN ('active', 'inactive')
            AND verification_state = 'not_applicable'
            AND fiat_credited_minor IS NULL
            AND fiat_credit_policy IS NULL
            AND fiat_valued_at IS NULL
        ) OR (
            source IS DISTINCT FROM 'bull_bitcoin_fiat'
            AND source IS DISTINCT FROM 'bull_bitcoin_mixed_output'
            AND bull_bitcoin_settlement_id IS NULL
        )
    );

DROP TRIGGER invoice_payment_events_guard_quote_attribution
    ON invoice_payment_events;
CREATE TRIGGER invoice_payment_events_guard_quote_attribution
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (
        NEW.source IS DISTINCT FROM 'bull_bitcoin_fiat'
        AND NEW.source IS DISTINCT FROM 'bull_bitcoin_mixed_output'
    )
    EXECUTE FUNCTION guard_invoice_payment_quote_attribution();

CREATE OR REPLACE FUNCTION guard_bull_bitcoin_invoice_payment_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    settlement_row RECORD;
    output_row RECORD;
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

    SELECT invoice_id, purpose, payer_rail, actual_received_sat,
           credited_fiat_minor, provider_final, settlement_status,
           funding_route, funding_committed_at
      INTO settlement_row
      FROM bull_bitcoin_settlements
     WHERE id = NEW.bull_bitcoin_settlement_id;
    IF NEW.source = 'bull_bitcoin_fiat' THEN
        IF NOT FOUND
           OR settlement_row.purpose <> 'fiat_only'
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
    ELSE
        SELECT txid, vout, authorized_amount_sat
          INTO output_row
          FROM bull_bitcoin_claim_outputs
         WHERE settlement_id = NEW.bull_bitcoin_settlement_id
           AND role = 'bull_bitcoin';
        IF NOT FOUND
           OR settlement_row.purpose <> 'mixed'
           OR settlement_row.invoice_id IS DISTINCT FROM NEW.invoice_id
           OR NEW.rail <> 'liquid'
           OR settlement_row.funding_route <> 'bull_bitcoin'
           OR settlement_row.funding_committed_at IS NULL
           OR output_row.txid IS DISTINCT FROM NEW.txid
           OR output_row.vout IS DISTINCT FROM NEW.vout
           OR output_row.authorized_amount_sat IS DISTINCT FROM NEW.amount_sat THEN
            RAISE EXCEPTION 'mixed invoice payment lacks exact claim-output authority'
                USING ERRCODE = '23514',
                      CONSTRAINT = 'invoice_payment_events_bull_bitcoin_mixed_authority';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER invoice_payment_events_guard_bull_bitcoin
    ON invoice_payment_events;
CREATE TRIGGER invoice_payment_events_guard_bull_bitcoin
    BEFORE INSERT OR UPDATE ON invoice_payment_events
    FOR EACH ROW
    WHEN (NEW.source IN ('bull_bitcoin_fiat', 'bull_bitcoin_mixed_output'))
    EXECUTE FUNCTION guard_bull_bitcoin_invoice_payment_event();

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE swap_fiat_settlement_policies FROM PUBLIC;
    REVOKE ALL ON TABLE bull_bitcoin_claim_outputs FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_swap_fiat_policy_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION reject_swap_fiat_policy_mutation() FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_swap_binding() FROM PUBLIC;
    REVOKE ALL ON FUNCTION reject_bull_bitcoin_claim_output_mutation() FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_bull_bitcoin_claim_output_insert() FROM PUBLIC;
    REVOKE ALL ON FUNCTION guard_mixed_reverse_merchant_event() FROM PUBLIC;

    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE swap_fiat_settlement_policies TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT, INSERT ON TABLE bull_bitcoin_claim_outputs TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
