-- ==========================================================================
-- 065: client-encrypted presentation for wallet-origin invoices
-- ==========================================================================
--
-- Native merchant invoices are assembled and encrypted by the wallet. The
-- server stores one fixed-size opaque envelope and has no plaintext columns,
-- recovery capsule, per-field digest, or searchable presentation metadata.
-- Checkout-origin notes remain in `memo`; Donation/Page/POS behavior is not
-- part of this protocol.
--
-- There are no production wallet invoices at this cutover. Refuse rather
-- than silently deleting or pretending to encrypt any test/legacy plaintext.

BEGIN;

SELECT set_config('bullnym.migration_runtime_role', :'runtime_role', TRUE);

DO $$
DECLARE
    runtime_role_name TEXT := NULLIF(
        current_setting('bullnym.migration_runtime_role', TRUE),
        ''
    );
    runtime_role_oid OID;
    runtime_role_is_superuser BOOLEAN;
    executor_role_oid OID;
BEGIN
    IF runtime_role_name IS NULL THEN
        RAISE EXCEPTION 'migration 065 requires a non-empty runtime_role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 065 runtime role does not exist'
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 065 refuses a superuser runtime role'
            USING ERRCODE = '42501';
    END IF;
    SELECT oid INTO STRICT executor_role_oid FROM pg_roles WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 065 runtime role owns or can assume its schema owner'
            USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM invoices WHERE origin = 'wallet') THEN
        RAISE EXCEPTION
            'migration 065 refuses wallet-origin rows; reset the test database before direct cutover'
            USING ERRCODE = '55000';
    END IF;
END
$$;

ALTER TABLE invoices
    DROP CONSTRAINT invoices_checkout_no_metadata_chk,
    DROP COLUMN recipient_label,
    DROP COLUMN public_description,
    DROP COLUMN invoice_number,
    ADD COLUMN client_request_id UUID,
    ADD COLUMN client_request_digest BYTEA,
    ADD COLUMN presentation_envelope BYTEA,
    ADD CONSTRAINT invoices_private_presentation_shape_check CHECK (
        (
            origin = 'wallet'
            AND client_request_id IS NOT NULL
            AND client_request_digest IS NOT NULL
            AND octet_length(client_request_digest) = 32
            AND presentation_envelope IS NOT NULL
            AND CASE
                    WHEN octet_length(presentation_envelope) = 4125
                    THEN get_byte(presentation_envelope, 0) = 1
                    ELSE FALSE
                END
        )
        OR
        (
            origin = 'checkout'
            AND client_request_id IS NULL
            AND client_request_digest IS NULL
            AND presentation_envelope IS NULL
        )
    ),
    ADD CONSTRAINT invoices_owner_client_request_key
        UNIQUE (npub_owner, client_request_id);

COMMENT ON COLUMN invoices.client_request_id IS
    'Opaque wallet-generated idempotency identifier; not presentation data.';
COMMENT ON COLUMN invoices.client_request_digest IS
    'SHA-256 of the canonical signed create payload excluding auth timestamp/signature.';
COMMENT ON COLUMN invoices.presentation_envelope IS
    'Private-invoice-v1 fixed 4125-byte envelope: version, AES-GCM nonce, padded ciphertext and tag.';
COMMENT ON CONSTRAINT invoices_private_presentation_shape_check ON invoices IS
    'Wallet invoices require one v1 encrypted presentation; checkout invoices cannot carry one.';

CREATE FUNCTION reject_invoice_private_presentation_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.client_request_id IS DISTINCT FROM OLD.client_request_id
       OR NEW.client_request_digest IS DISTINCT FROM OLD.client_request_digest
       OR NEW.presentation_envelope IS DISTINCT FROM OLD.presentation_envelope THEN
        RAISE EXCEPTION 'private invoice create identity and presentation are immutable'
            USING ERRCODE = '55000',
                  CONSTRAINT = 'invoices_private_presentation_immutable';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION reject_invoice_private_presentation_update() FROM PUBLIC;

CREATE TRIGGER invoices_reject_private_presentation_update
BEFORE UPDATE OF client_request_id, client_request_digest, presentation_envelope
ON invoices
FOR EACH ROW
EXECUTE FUNCTION reject_invoice_private_presentation_update();

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    EXECUTE format(
        'GRANT INSERT (client_request_id, client_request_digest, presentation_envelope) ON TABLE invoices TO %I',
        runtime_role_name
    );
    EXECUTE format(
        'GRANT SELECT (client_request_id, client_request_digest, presentation_envelope) ON TABLE invoices TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
