-- ============================================================================
-- 076: unified opaque wallet-backup stream
-- ============================================================================
--
-- The mobile backup coordinator writes one encrypted envelope containing its
-- versioned sections. Bullnym neither parses nor rewrites that envelope. This
-- cutover adds the single `wallet_backup` API stream while retaining existing
-- pre-release rows under their original stream identities. The Rust API no
-- longer accepts those legacy identities.

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
    runtime_role_oid OID;
    table_owner_name TEXT;
    table_owner_oid OID;
BEGIN
    SELECT oid INTO runtime_role_oid
      FROM pg_roles WHERE rolname = runtime_role_name;
    IF runtime_role_name IS NULL OR runtime_role_oid IS NULL THEN
        RAISE EXCEPTION 'migration 076 requires an existing runtime role'
            USING ERRCODE = '42501';
    END IF;
    IF current_user = runtime_role_name THEN
        RAISE EXCEPTION 'migration 076 must run as the schema owner, not the runtime role'
            USING ERRCODE = '42501';
    END IF;

    SELECT relowner, pg_get_userbyid(relowner)
      INTO table_owner_oid, table_owner_name
      FROM pg_class
     WHERE oid = to_regclass('public.wallet_backup_blobs');
    IF table_owner_name IS NULL OR table_owner_name <> current_user THEN
        RAISE EXCEPTION 'migration 076 must run as the wallet backup table owner'
            USING ERRCODE = '42501';
    END IF;
    IF runtime_role_oid = table_owner_oid
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'USAGE')
       OR pg_has_role(runtime_role_oid, table_owner_oid, 'SET') THEN
        RAISE EXCEPTION 'migration 076 runtime role can assume the wallet backup table owner'
            USING ERRCODE = '42501';
    END IF;
END
$$;

ALTER TABLE wallet_backup_blobs
    DROP CONSTRAINT wallet_backup_blobs_stream_chk,
    ADD CONSTRAINT wallet_backup_blobs_stream_chk
        CHECK (stream IN ('keychain_manifest', 'wallet_metadata', 'wallet_backup'));

COMMENT ON TABLE wallet_backup_blobs IS
    'Current opaque encrypted unified wallet backup plus preserved pre-release legacy rows.';
COMMENT ON COLUMN wallet_backup_blobs.author_pubkey IS
    'Raw 32-byte x-only BIP340 public key for the wallet-backup signing identity.';
COMMENT ON COLUMN wallet_backup_blobs.ciphertext IS
    'Client-encrypted opaque bytes. NULL only for a short-lived conditional-delete tombstone.';

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    REVOKE ALL ON TABLE wallet_backup_blobs FROM PUBLIC;
    EXECUTE format('REVOKE ALL ON TABLE wallet_backup_blobs FROM %I', runtime_role_name);
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE wallet_backup_blobs TO %I',
        runtime_role_name
    );

    IF NOT has_table_privilege(runtime_role_name, 'wallet_backup_blobs', 'SELECT')
       OR NOT has_table_privilege(runtime_role_name, 'wallet_backup_blobs', 'INSERT')
       OR NOT has_table_privilege(runtime_role_name, 'wallet_backup_blobs', 'UPDATE')
       OR NOT has_table_privilege(runtime_role_name, 'wallet_backup_blobs', 'DELETE')
       OR has_table_privilege(runtime_role_name, 'wallet_backup_blobs', 'TRUNCATE')
       OR has_table_privilege(runtime_role_name, 'wallet_backup_blobs', 'REFERENCES')
       OR has_table_privilege(runtime_role_name, 'wallet_backup_blobs', 'TRIGGER')
       OR EXISTS (
           SELECT 1
             FROM pg_class relation
             CROSS JOIN LATERAL aclexplode(COALESCE(
                 relation.relacl, acldefault('r', relation.relowner)
             )) acl
            WHERE relation.oid = 'wallet_backup_blobs'::REGCLASS
              AND acl.grantee = 0
       ) THEN
        RAISE EXCEPTION 'migration 076 could not establish exact runtime backup privileges'
            USING ERRCODE = '42501';
    END IF;
END
$$;

COMMIT;
