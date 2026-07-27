-- Seed both pre-release streams and snapshot every persisted field. Migration
-- 076 must extend the stream constraint without relabeling, deleting, or
-- rewriting independently authenticated ciphertext.
INSERT INTO wallet_backup_blobs (
    stream, author_pubkey, generation, etag,
    ciphertext, ciphertext_sha256, ciphertext_bytes,
    created_at, updated_at, deleted_at
) VALUES
    (
        'keychain_manifest', decode(repeat('11', 32), 'hex'), 7,
        decode(repeat('21', 32), 'hex'), decode('000102ff', 'hex'),
        digest(decode('000102ff', 'hex'), 'sha256'), 4,
        TIMESTAMPTZ '2026-07-01 01:02:03+00',
        TIMESTAMPTZ '2026-07-02 04:05:06+00', NULL
    ),
    (
        'wallet_metadata', decode(repeat('12', 32), 'hex'), 9,
        decode(repeat('22', 32), 'hex'), decode('807f00aa55', 'hex'),
        digest(decode('807f00aa55', 'hex'), 'sha256'), 5,
        TIMESTAMPTZ '2026-07-03 07:08:09+00',
        TIMESTAMPTZ '2026-07-04 10:11:12+00', NULL
    );

CREATE TABLE migration_076_legacy_backup_snapshot AS
SELECT * FROM wallet_backup_blobs
 WHERE stream IN ('keychain_manifest', 'wallet_metadata');
