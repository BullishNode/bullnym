-- ============================================================================
-- 064: opaque wallet-backup current objects
-- ============================================================================

BEGIN;

SELECT set_config(
    'bullnym.migration_runtime_role',
    :'runtime_role',
    TRUE
);

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
        RAISE EXCEPTION 'migration 064 requires a non-empty runtime_role'
            USING ERRCODE = '42501';
    END IF;

    SELECT oid, rolsuper
      INTO runtime_role_oid, runtime_role_is_superuser
      FROM pg_roles
     WHERE rolname = runtime_role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'migration 064 runtime role % does not exist',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42704';
    END IF;
    IF runtime_role_is_superuser THEN
        RAISE EXCEPTION 'migration 064 refuses superuser runtime role %',
            quote_ident(runtime_role_name)
            USING ERRCODE = '42501';
    END IF;

    SELECT oid INTO STRICT executor_role_oid
      FROM pg_roles
     WHERE rolname = current_user;
    IF runtime_role_oid = executor_role_oid
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, executor_role_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 064 runtime role % owns or can assume schema owner %',
            quote_ident(runtime_role_name), quote_ident(current_user)
            USING ERRCODE = '42501';
    END IF;
END
$$;

CREATE TABLE wallet_backup_blobs (
    stream              TEXT        NOT NULL,
    author_pubkey       BYTEA       NOT NULL,
    generation          BIGINT      NOT NULL CHECK (generation > 0),
    etag                 BYTEA       NOT NULL,
    ciphertext          BYTEA,
    ciphertext_sha256   BYTEA,
    ciphertext_bytes    INTEGER,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at           TIMESTAMPTZ,
    PRIMARY KEY (stream, author_pubkey),
    CONSTRAINT wallet_backup_blobs_stream_chk
        CHECK (stream IN ('keychain_manifest', 'wallet_metadata')),
    CONSTRAINT wallet_backup_blobs_author_pubkey_len_chk
        CHECK (octet_length(author_pubkey) = 32),
    CONSTRAINT wallet_backup_blobs_etag_len_chk
        CHECK (octet_length(etag) = 32),
    CONSTRAINT wallet_backup_blobs_live_tombstone_chk
        CHECK ((ciphertext IS NULL) = (deleted_at IS NOT NULL)),
    CONSTRAINT wallet_backup_blobs_payload_columns_chk CHECK (
        (ciphertext IS NULL AND ciphertext_sha256 IS NULL AND ciphertext_bytes IS NULL)
        OR
        (ciphertext IS NOT NULL AND ciphertext_sha256 IS NOT NULL AND ciphertext_bytes IS NOT NULL)
    ),
    CONSTRAINT wallet_backup_blobs_hash_len_chk
        CHECK (ciphertext_sha256 IS NULL OR octet_length(ciphertext_sha256) = 32),
    CONSTRAINT wallet_backup_blobs_size_matches_chk
        CHECK (ciphertext_bytes IS NULL OR ciphertext_bytes = octet_length(ciphertext)),
    CONSTRAINT wallet_backup_blobs_size_limit_chk
        CHECK (ciphertext_bytes IS NULL OR ciphertext_bytes <= 2097152)
);

CREATE INDEX wallet_backup_blobs_tombstone_cleanup_idx
    ON wallet_backup_blobs (deleted_at)
    WHERE deleted_at IS NOT NULL;

COMMENT ON TABLE wallet_backup_blobs IS
    'Current opaque encrypted keychain or wallet-metadata backup per stream-specific signing key.';
COMMENT ON COLUMN wallet_backup_blobs.author_pubkey IS
    'Raw 32-byte x-only BIP340 public key; distinct backup streams use distinct keys.';
COMMENT ON COLUMN wallet_backup_blobs.ciphertext IS
    'Client-encrypted opaque bytes. NULL only for a short-lived conditional-delete tombstone.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    EXECUTE format('REVOKE ALL ON TABLE wallet_backup_blobs FROM %I', runtime_role_name);
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE wallet_backup_blobs TO %I',
        runtime_role_name
    );
END
$$;

COMMIT;
