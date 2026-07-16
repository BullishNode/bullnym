DO $$
DECLARE
    object_limit_constraint TEXT;
BEGIN
    IF to_regclass('public.wallet_backup_blobs') IS NULL THEN
        RAISE EXCEPTION 'migration 064 did not create wallet_backup_blobs';
    END IF;

    IF NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'SELECT')
       OR NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'INSERT')
       OR NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'UPDATE')
       OR NOT has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'DELETE') THEN
        RAISE EXCEPTION 'migration 064 did not grant the runtime backup CRUD contract';
    END IF;
    IF has_table_privilege('bullnym_app', 'wallet_backup_blobs', 'TRUNCATE') THEN
        RAISE EXCEPTION 'migration 064 granted runtime destructive table authority';
    END IF;

    SELECT pg_get_constraintdef(oid)
      INTO object_limit_constraint
      FROM pg_constraint
     WHERE conrelid = 'wallet_backup_blobs'::regclass
       AND conname = 'wallet_backup_blobs_size_limit_chk';
    IF object_limit_constraint IS NULL
       OR object_limit_constraint NOT LIKE '%2097152%' THEN
        RAISE EXCEPTION 'migration 064 does not enforce the exact 2 MiB object limit';
    END IF;

    INSERT INTO wallet_backup_blobs (
        stream, author_pubkey, generation, etag,
        ciphertext, ciphertext_sha256, ciphertext_bytes
    ) VALUES (
        'wallet_metadata', decode(repeat('11', 32), 'hex'), 1,
        decode(repeat('22', 32), 'hex'), decode('00010203', 'hex'),
        decode(repeat('33', 32), 'hex'), 4
    );

    BEGIN
        INSERT INTO wallet_backup_blobs (
            stream, author_pubkey, generation, etag,
            ciphertext, ciphertext_sha256, ciphertext_bytes
        ) VALUES (
            'unknown', decode(repeat('44', 32), 'hex'), 1,
            decode(repeat('55', 32), 'hex'), decode('00', 'hex'),
            decode(repeat('66', 32), 'hex'), 1
        );
        RAISE EXCEPTION 'migration 064 accepted an open-ended backup stream';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    DELETE FROM wallet_backup_blobs
     WHERE author_pubkey = decode(repeat('11', 32), 'hex');
END
$$;
