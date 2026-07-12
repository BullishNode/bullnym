# Configuration

Bullnym reads non-secret policy from `config.toml` and sensitive values from the
environment. Treat the checked-in file as a development baseline, not a
production deployment manifest.

Required production inputs include `DATABASE_URL` and `SWAP_MNEMONIC`. The swap
mnemonic derives live swap-specific key material: store it in a secret manager,
restrict process access, back it up separately from the database, and test
restore procedures. The database and mnemonic are both required for complete
recovery.

Review these policy groups before deployment:

- Boltz and Electrum endpoints;
- claim retry and reconciler/slow-recovery intervals;
- Bitcoin watcher confirmations and mempool API;
- accounting tolerances and checkout expiry/grace periods;
- rate limits, trusted proxies, IP whitelist, and certification scopes;
- feature gates, especially merchant chain-swap recovery;
- PWA asset paths and public base URL.

Setting `workers.enabled = false` closes all four new-money rails, including
the direct watchers, while leaving HTTP and recovery/status paths available.
Each enabled direct rail additionally requires its own initialized watcher
backend and a successful current-process watcher cycle. Reverse and chain swap
rails separately require the retained Liquid claim-client factory, initialized
Boltz client, verified swap-key lineage, their recovery workers, and an
admitted persisted fee policy. Chain swaps further require the initialized
Bitcoin recovery-evidence client, writable transaction-attempt journal, and the
request's merchant-specific committed recovery destination. Invalid
rail-specific client configuration closes only that rail; it does not make
generic `/ready` fail or stop existing-obligation workers.

The current release deliberately keeps reverse and chain offer creation closed
until the follow-up fee-policy and recovery-commitment issues supply those
facts. Do not work around this boundary with certification, an IP whitelist, or
a temporary runtime override.

Do not enable broad IP or certification bypasses for ordinary internet traffic.
After every configuration change, call `/ready` and exercise a non-monetary
preflight before allowing payment traffic.
