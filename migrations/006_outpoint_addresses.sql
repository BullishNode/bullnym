-- Maps (nym, outpoint) -> addr_index for idempotent LNURL-pay Liquid callbacks.
-- Same UTXO always resolves to the same confidential address, preventing
-- gap-limit exhaustion attacks via repeated unauthenticated callbacks.

CREATE TABLE outpoint_addresses (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nym          TEXT NOT NULL REFERENCES users(nym) ON DELETE CASCADE,
    outpoint     TEXT NOT NULL,
    addr_index   INT NOT NULL,
    pubkey       TEXT,
    fulfilled    BOOLEAN NOT NULL DEFAULT FALSE,
    fulfilled_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (nym, outpoint)
);

CREATE INDEX idx_outpoint_addresses_nym ON outpoint_addresses(nym);
CREATE INDEX idx_outpoint_addresses_pubkey ON outpoint_addresses(pubkey);
CREATE INDEX idx_outpoint_addresses_unfulfilled
    ON outpoint_addresses(nym) WHERE fulfilled = FALSE;
