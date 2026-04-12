CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nym             TEXT NOT NULL UNIQUE,
    npub            TEXT NOT NULL UNIQUE,
    ct_descriptor   TEXT NOT NULL,
    next_addr_idx   INT NOT NULL DEFAULT 0,
    dns_record_id   TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE swap_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nym             TEXT NOT NULL REFERENCES users(nym),
    boltz_swap_id   TEXT NOT NULL,
    address         TEXT NOT NULL,
    address_index   INT NOT NULL,
    amount_sat      BIGINT NOT NULL,
    invoice         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_swap_records_nym ON swap_records(nym);
CREATE INDEX idx_swap_records_boltz_id ON swap_records(boltz_swap_id);
