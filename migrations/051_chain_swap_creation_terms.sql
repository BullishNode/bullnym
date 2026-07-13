-- ============================================================================
-- 051: immutable, restorable chain-swap creation terms
-- ============================================================================
--
-- Historical chain swaps predate complete creation validation, so every new
-- column is nullable and legacy rows remain readable and lifecycle-mutable.
-- Every row inserted after this migration must, however, carry the complete
-- validated creation packet before a payer instruction can be exposed. The
-- merchant emergency Bitcoin destination remains optional until registration
-- is deployed, but it is immutable when present.

BEGIN;

ALTER TABLE chain_swap_records
    ADD COLUMN pinned_pair_hash TEXT,
    ADD COLUMN canonical_pair_quote_json TEXT,
    ADD COLUMN creation_response_sha256 TEXT,
    ADD COLUMN btc_claim_script_sha256 TEXT,
    ADD COLUMN btc_refund_script_sha256 TEXT,
    ADD COLUMN liquid_claim_script_sha256 TEXT,
    ADD COLUMN liquid_refund_script_sha256 TEXT,
    ADD COLUMN btc_timeout_height BIGINT,
    ADD COLUMN liquid_timeout_height BIGINT,
    ADD COLUMN btc_network TEXT,
    ADD COLUMN liquid_network TEXT,
    ADD COLUMN liquid_asset_id TEXT,
    ADD COLUMN merchant_liquid_destination TEXT,
    ADD COLUMN merchant_emergency_btc_address TEXT,

    ADD CONSTRAINT chain_swap_records_creation_terms_shape_check CHECK (
        (
            num_nonnulls(
                pinned_pair_hash,
                canonical_pair_quote_json,
                creation_response_sha256,
                btc_claim_script_sha256,
                btc_refund_script_sha256,
                liquid_claim_script_sha256,
                liquid_refund_script_sha256,
                btc_timeout_height,
                liquid_timeout_height,
                btc_network,
                liquid_network,
                liquid_asset_id,
                merchant_liquid_destination
            ) = 0
            AND merchant_emergency_btc_address IS NULL
        )
        OR
        num_nonnulls(
            pinned_pair_hash,
            canonical_pair_quote_json,
            creation_response_sha256,
            btc_claim_script_sha256,
            btc_refund_script_sha256,
            liquid_claim_script_sha256,
            liquid_refund_script_sha256,
            btc_timeout_height,
            liquid_timeout_height,
            btc_network,
            liquid_network,
            liquid_asset_id,
            merchant_liquid_destination
        ) = 13
    ),
    ADD CONSTRAINT chain_swap_records_pinned_pair_hash_check CHECK (
        pinned_pair_hash IS NULL OR pinned_pair_hash ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT chain_swap_records_pair_quote_json_check CHECK (
        canonical_pair_quote_json IS NULL
        OR jsonb_typeof(canonical_pair_quote_json::jsonb) = 'object'
    ),
    ADD CONSTRAINT chain_swap_records_creation_response_sha256_check CHECK (
        creation_response_sha256 IS NULL OR creation_response_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT chain_swap_records_btc_claim_script_sha256_check CHECK (
        btc_claim_script_sha256 IS NULL OR btc_claim_script_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT chain_swap_records_btc_refund_script_sha256_check CHECK (
        btc_refund_script_sha256 IS NULL OR btc_refund_script_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT chain_swap_records_liquid_claim_script_sha256_check CHECK (
        liquid_claim_script_sha256 IS NULL OR liquid_claim_script_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT chain_swap_records_liquid_refund_script_sha256_check CHECK (
        liquid_refund_script_sha256 IS NULL OR liquid_refund_script_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT chain_swap_records_btc_timeout_height_check CHECK (
        btc_timeout_height IS NULL OR btc_timeout_height > 0
    ),
    ADD CONSTRAINT chain_swap_records_liquid_timeout_height_check CHECK (
        liquid_timeout_height IS NULL OR liquid_timeout_height > 0
    ),
    ADD CONSTRAINT chain_swap_records_btc_network_check CHECK (
        btc_network IS NULL OR btc_network ~ '^[a-z0-9][a-z0-9_-]{0,31}$'
    ),
    ADD CONSTRAINT chain_swap_records_liquid_network_check CHECK (
        liquid_network IS NULL OR liquid_network ~ '^[a-z0-9][a-z0-9_-]{0,31}$'
    ),
    ADD CONSTRAINT chain_swap_records_liquid_asset_id_check CHECK (
        liquid_asset_id IS NULL OR liquid_asset_id ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT chain_swap_records_merchant_liquid_destination_check CHECK (
        merchant_liquid_destination IS NULL
        OR (
            length(merchant_liquid_destination) BETWEEN 1 AND 512
            AND merchant_liquid_destination !~ '[[:space:]]'
        )
    ),
    ADD CONSTRAINT chain_swap_records_merchant_emergency_btc_address_check CHECK (
        merchant_emergency_btc_address IS NULL
        OR (
            length(merchant_emergency_btc_address) BETWEEN 1 AND 128
            AND merchant_emergency_btc_address !~ '[[:space:]]'
        )
    );

CREATE FUNCTION require_chain_swap_creation_terms() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF num_nonnulls(
        NEW.pinned_pair_hash,
        NEW.canonical_pair_quote_json,
        NEW.creation_response_sha256,
        NEW.btc_claim_script_sha256,
        NEW.btc_refund_script_sha256,
        NEW.liquid_claim_script_sha256,
        NEW.liquid_refund_script_sha256,
        NEW.btc_timeout_height,
        NEW.liquid_timeout_height,
        NEW.btc_network,
        NEW.liquid_network,
        NEW.liquid_asset_id,
        NEW.merchant_liquid_destination
    ) <> 13 THEN
        RAISE EXCEPTION 'new chain swaps require complete immutable creation terms'
            USING ERRCODE = '23514',
                  CONSTRAINT = 'chain_swap_records_creation_terms_shape_check';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION reject_chain_swap_creation_terms_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(
        OLD.pinned_pair_hash,
        OLD.canonical_pair_quote_json,
        OLD.creation_response_sha256,
        OLD.btc_claim_script_sha256,
        OLD.btc_refund_script_sha256,
        OLD.liquid_claim_script_sha256,
        OLD.liquid_refund_script_sha256,
        OLD.btc_timeout_height,
        OLD.liquid_timeout_height,
        OLD.btc_network,
        OLD.liquid_network,
        OLD.liquid_asset_id,
        OLD.merchant_liquid_destination,
        OLD.merchant_emergency_btc_address
    ) IS DISTINCT FROM ROW(
        NEW.pinned_pair_hash,
        NEW.canonical_pair_quote_json,
        NEW.creation_response_sha256,
        NEW.btc_claim_script_sha256,
        NEW.btc_refund_script_sha256,
        NEW.liquid_claim_script_sha256,
        NEW.liquid_refund_script_sha256,
        NEW.btc_timeout_height,
        NEW.liquid_timeout_height,
        NEW.btc_network,
        NEW.liquid_network,
        NEW.liquid_asset_id,
        NEW.merchant_liquid_destination,
        NEW.merchant_emergency_btc_address
    ) THEN
        RAISE EXCEPTION 'chain swap creation terms are immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER chain_swap_records_require_creation_terms
    BEFORE INSERT ON chain_swap_records
    FOR EACH ROW EXECUTE FUNCTION require_chain_swap_creation_terms();

CREATE TRIGGER chain_swap_records_reject_creation_terms_update
    BEFORE UPDATE OF
        pinned_pair_hash,
        canonical_pair_quote_json,
        creation_response_sha256,
        btc_claim_script_sha256,
        btc_refund_script_sha256,
        liquid_claim_script_sha256,
        liquid_refund_script_sha256,
        btc_timeout_height,
        liquid_timeout_height,
        btc_network,
        liquid_network,
        liquid_asset_id,
        merchant_liquid_destination,
        merchant_emergency_btc_address
    ON chain_swap_records
    FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_creation_terms_mutation();

COMMIT;
