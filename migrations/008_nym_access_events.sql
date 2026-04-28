-- Per-(source, nym) access log for distinct-nym rate limiting on the
-- Liquid LUD-22 callback. source_key is "ip:<addr>" or "outpoint:<txid>:<vout>".

CREATE TABLE nym_access_events (
    id          BIGSERIAL PRIMARY KEY,
    source_key  TEXT NOT NULL,
    nym         TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nym_access_source_time
    ON nym_access_events(source_key, created_at DESC);
