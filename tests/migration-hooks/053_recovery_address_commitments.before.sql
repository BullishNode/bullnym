-- Migration 053 creates a new merchant-policy ledger. Existing identities and
-- swaps must not be rewritten or assigned fabricated recovery commitments.
DO $$
BEGIN
    IF to_regclass('public.recovery_address_commitments') IS NOT NULL THEN
        RAISE EXCEPTION 'recovery-address commitment ledger unexpectedly exists before migration 053';
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'chain_swap_records'
           AND column_name = 'recovery_address_commitment_id'
    ) THEN
        RAISE EXCEPTION 'chain-swap commitment identity unexpectedly exists before migration 053';
    END IF;
    IF EXISTS (
        SELECT 1 FROM chain_swap_records
         WHERE merchant_emergency_btc_address IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'pre-053 chain swap has unexplained address-only recovery evidence';
    END IF;

    -- Production already has this runtime role. The disposable upgrade lane
    -- creates it before the migration so the migration's exact grants can be
    -- exercised rather than merely inspected syntactically.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
        EXECUTE 'CREATE ROLE payservice NOLOGIN';
    END IF;
END
$$;

-- Migration 053 accepts evidence only for a currently active merchant. Keep a
-- second historical identity to prove that mere npub presence is insufficient.
INSERT INTO users (nym, npub, ct_descriptor, is_active)
VALUES
    (
        'recovery-053-active',
        '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        'recovery-053-fixture',
        TRUE
    ),
    (
        'recovery-053-inactive',
        'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
        'recovery-053-fixture',
        FALSE
    );

-- Row-locking SELECTs require UPDATE as well as SELECT. The disposable role
-- models production's existing user lifecycle privileges so its real INSERT
-- path can exercise the trigger's active-source lookup.
GRANT SELECT, UPDATE ON users TO payservice;
