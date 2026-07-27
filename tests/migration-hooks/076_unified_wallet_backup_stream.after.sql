DO $$
DECLARE
    stream_constraint TEXT;
    runtime_role_oid OID;
    owner_role_oid OID;
BEGIN
    SELECT pg_get_constraintdef(oid, TRUE)
      INTO stream_constraint
      FROM pg_constraint
     WHERE conrelid = 'wallet_backup_blobs'::REGCLASS
       AND conname = 'wallet_backup_blobs_stream_chk'
       AND contype = 'c'
       AND convalidated;
    IF stream_constraint IS DISTINCT FROM
       'CHECK (stream = ANY (ARRAY[''keychain_manifest''::text, ''wallet_metadata''::text, ''wallet_backup''::text]))' THEN
        RAISE EXCEPTION 'migration 076 did not retain legacy identities and add the unified stream: %',
            stream_constraint;
    END IF;

    SELECT oid INTO STRICT runtime_role_oid
      FROM pg_roles WHERE rolname = 'bullnym_app';
    SELECT relowner INTO STRICT owner_role_oid
      FROM pg_class WHERE oid = 'wallet_backup_blobs'::REGCLASS;
    IF runtime_role_oid = owner_role_oid
       OR NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'SELECT')
       OR NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'INSERT')
       OR NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'UPDATE')
       OR NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'DELETE')
       OR has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'TRUNCATE')
       OR has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'REFERENCES')
       OR has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'TRIGGER') THEN
        RAISE EXCEPTION 'migration 076 did not preserve exact runtime backup CRUD';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_class relation
          CROSS JOIN LATERAL aclexplode(COALESCE(
              relation.relacl, acldefault('r', relation.relowner)
          )) acl
         WHERE relation.oid = 'wallet_backup_blobs'::REGCLASS
           AND acl.grantee = 0
    ) THEN
        RAISE EXCEPTION 'migration 076 exposed wallet backups through PUBLIC';
    END IF;

    IF (SELECT COUNT(*) FROM wallet_backup_blobs
         WHERE stream IN ('keychain_manifest', 'wallet_metadata')) <> 2
       OR EXISTS (
            (SELECT * FROM migration_076_legacy_backup_snapshot
             EXCEPT SELECT * FROM wallet_backup_blobs)
            UNION ALL
            (SELECT * FROM wallet_backup_blobs
              WHERE stream IN ('keychain_manifest', 'wallet_metadata')
             EXCEPT SELECT * FROM migration_076_legacy_backup_snapshot)
       ) THEN
        RAISE EXCEPTION 'migration 076 changed a legacy backup row';
    END IF;
END
$$;

-- Exercise the exact least-privilege contract as the actual runtime role and
-- prove that ciphertext bytes survive storage without interpretation.
BEGIN;
SET LOCAL ROLE bullnym_app;
INSERT INTO wallet_backup_blobs (
    stream, author_pubkey, generation, etag,
    ciphertext, ciphertext_sha256, ciphertext_bytes
) VALUES (
    'wallet_backup', decode(repeat('44', 32), 'hex'), 1,
    decode(repeat('55', 32), 'hex'), decode('00ff017f80', 'hex'),
    digest(decode('00ff017f80', 'hex'), 'sha256'), 5
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM wallet_backup_blobs
         WHERE stream = 'wallet_backup'
           AND author_pubkey = decode(repeat('44', 32), 'hex')
           AND encode(ciphertext, 'hex') = '00ff017f80'
           AND ciphertext_bytes = 5
    ) THEN
        RAISE EXCEPTION 'migration 076 did not preserve opaque ciphertext bytes';
    END IF;
END
$$;

UPDATE wallet_backup_blobs
   SET generation = 2,
       etag = decode(repeat('66', 32), 'hex')
 WHERE stream = 'wallet_backup'
   AND author_pubkey = decode(repeat('44', 32), 'hex');
DELETE FROM wallet_backup_blobs
 WHERE stream = 'wallet_backup'
   AND author_pubkey = decode(repeat('44', 32), 'hex');
COMMIT;

DROP TABLE migration_076_legacy_backup_snapshot;
