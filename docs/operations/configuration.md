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

Do not enable broad IP or certification bypasses for ordinary internet traffic.
After every configuration change, call `/ready` and exercise a non-monetary
preflight before allowing payment traffic.
