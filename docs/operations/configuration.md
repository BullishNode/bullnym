# Configuration

This is the operator reference for Bullnym runtime configuration. It describes
the fields parsed by `src/config.rs`. `config.example.toml` is a complete
development-oriented example; production deployments should keep
their actual `config.toml` outside version control.

All configuration is loaded once at process startup. Bullnym does not reload
configuration dynamically. Changing any field or environment variable requires
a restart and the post-restart checks described below.

## Loading and precedence

Bullnym reads the TOML path from the first command-line argument:

```bash
pay-service /etc/bullnym/config.toml
```

With no argument it reads `./config.toml`. TOML supplies non-secret policy and
endpoint settings. A small set of environment variables is loaded afterward
and overrides the corresponding in-memory fields. There are no general
`BULLNYM_*` environment overrides for TOML keys.

Unknown TOML keys are currently ignored by Serde. A misspelled key can
therefore leave the default active without failing startup. Compare deployed
configuration against this reference and inspect startup logs after every
change.

## Environment variables

| Variable | Required/default | Purpose and implications |
|---|---|---|
| `DATABASE_URL` | Required | PostgreSQL connection string. The database is the durable state boundary for invoices, descriptors, swap secrets, retry state, and recovery evidence. Pointing at the wrong database can cause address-index rollback or loss of recovery visibility. |
| `SWAP_MNEMONIC` | Required | Seed used to derive swap-specific keys. Back it up independently but consistently with PostgreSQL. Restoring the database without the matching mnemonic can make unsettled swaps unrecoverable; restoring an old database can also rewind derivation indices, which startup guardrails attempt to detect. |
| `BOLTZ_WEBHOOK_URL_SECRET` | Optional outside production; required when `BULLNYM_RUNTIME_MODE=production` | Current secret embedded in newly registered Boltz webhook URLs. It authenticates webhook paths because Boltz does not send an HMAC header. Treat it as a credential and prevent proxy/log disclosure. |
| `BOLTZ_WEBHOOK_SECRET` | Deprecated fallback | Used only when `BOLTZ_WEBHOOK_URL_SECRET` is absent. Keep only during migration to the current name. |
| `BOLTZ_WEBHOOK_URL_SECRET_PREVIOUS` | Empty | Previous webhook URL secret accepted during rotation. Existing swaps keep their original callback URL. Remove it after the longest live-swap overlap and verify old swaps are terminal. |
| `BULLNYM_RUNTIME_MODE` | `unknown` | The exact value `production` enables production startup validation. Production deployments must set it explicitly; other values do not activate those checks. |
| `BULLNYM_ALLOW_PUBLIC_LISTEN` | False | Truthy values are `1`, `true`, `yes`, and `on`, case-insensitive. In production it permits a non-loopback `listen` address. Prefer loopback behind a reverse proxy; enabling this expands the network boundary. |
| `RUST_LOG` | `pay_service=info,tower_http=info` | Standard tracing filter. Debug logging can expose payment linkage or request details; review retention and access before increasing verbosity. |

The certification token is currently a TOML field, not an environment
override. If certification is enabled, protect the configuration file as a
secret and restrict it to the service account.

## Required root fields

| Key | Type/default | What it controls | Operational guidance |
|---|---|---|---|
| `domain` | String, required | Public host and optional port used to construct LNURL callbacks, invoice URLs, webhook URLs, and page assets. Do not include `https://` or a path. | Production validation rejects `localhost`. Changing it affects newly issued URLs and can break callbacks for existing swaps if the previous host stops routing. |
| `listen` | Socket address, required | Interface and port bound by Axum, for example `127.0.0.1:8080`. | Production mode rejects non-loopback binds unless `BULLNYM_ALLOW_PUBLIC_LISTEN` is true. Bind loopback when nginx or another local proxy terminates TLS. |
| `pool_size` | Integer, default `10` | Maximum PostgreSQL connection pool size. | Claims, reconcilers, handlers, and watchers share the pool. Too small increases contention; too large can exhaust PostgreSQL. Size against worker concurrency and database limits. |

## Boltz

The `[boltz]` section is required.

| Key | Type/default | What it controls | Operational guidance |
|---|---|---|---|
| `boltz.api_url` | String, required | Boltz v2 REST API used to create, inspect, renegotiate, claim, and refund swaps. | Use the intended network/provider endpoint with no accidental proxy rewrite. A change affects all subsequent provider calls, including recovery of existing rows. |
| `boltz.electrum_url` | String, required | Primary Liquid Electrum endpoint used by reverse- and chain-swap claim construction/broadcast. | Use an explicit `ssl://` or `tcp://` scheme. It is tried before `[electrum]` and built-in failovers. A bare host is treated as TLS but emits a warning. |

Bullnym does not expose a separate provider timeout in TOML. Claim and
reconciliation behavior is bounded by their client implementations and retry
policies.

## Feature gates

| Key | Default | Effect |
|---|---:|---|
| `features.lightning_address` | `true` | Enables LNURL-pay metadata/callback, registration, lookup, and reservation APIs. Disabling it also prevents NIP-05 routing even if `features.nip05` is true. Existing swap workers still run when workers are enabled. |
| `features.invoices` | `true` | Enables signed wallet-invoice create/list/cancel APIs and unlinked invoice pages. Public invoice status and offer routes remain enabled when either invoices or payment pages is enabled. |
| `features.payment_pages` | `true` | Enables Payment Page/POS management, rendering, aliases, anonymous checkout creation, and the public fallback renderer. Disabling it prevents new checkout chain swaps but does not disable workers for existing swaps. |
| `features.nip05` | `false` | Enables `/.well-known/nostr.json` only when Lightning Address is also enabled. Leave off unless the deployment intentionally publishes opt-in verification keys. |
| `features.chain_swap_merchant_recovery` | `false` | Enables the signed per-invoice endpoint that constructs and broadcasts real Bitcoin recovery transactions for `refund_due` checkout chain swaps. There is currently no bulk recovery-discovery endpoint. Enable only after validating the configured emergency-address flow and monitoring. Enabling it while payment pages are off creates no new recoverable swaps and logs a warning. |

Feature gates control route availability, not database migrations or worker
state. Do not use them as a substitute for draining in-flight payments.

## Workers

| Key | Default | Effect |
|---|---:|---|
| `workers.enabled` | `true` | Starts claim sweeps, reverse/chain reconcilers, settlement repair, slow recovery, Liquid and Bitcoin watchers, and GC. With `false`, HTTP routes remain active but automatic settlement and recovery do not run in that process. |

Use `false` only for an intentionally web-only/standby instance when another
healthy instance owns worker execution. A deployment with payment routes active
and no workers can detect or create obligations that it does not settle.

## Invoice accounting

| Key | Default | Effect and tradeoff |
|---|---:|---|
| `invoice_accounting.btc_shortfall_tolerance_sat` | `300` | Direct-Bitcoin and checkout chain-swap shortfalls up to this amount can satisfy an invoice. Higher values reduce underpayment friction but increase merchant loss per invoice. |
| `invoice_accounting.liquid_shortfall_tolerance_sat` | `60` | Direct-Liquid shortfall tolerance. Direct Liquid is currently credited from Electrum history before confirmation, independently of this amount tolerance. |
| `invoice_accounting.lightning_shortfall_tolerance_sat` | `1` | Reverse-swap/Lightning shortfall tolerance. Keep tight because the swap amount is server-negotiated. |
| `invoice_accounting.checkout_partial_terminal_grace_secs` | `900` | After a checkout partial payment, GC waits this long before terminalizing the remaining shortfall. Longer values leave the checkout payable longer; shorter values close it sooner. |
| `invoice_accounting.payment_grace_secs` | `3600` | Watchers continue observing and GC withholds expiry for this many seconds after `expires_at`, allowing a payment broadcast near expiry to confirm and count. Set comfortably above the expected on-chain confirmation delay. |

Tolerance values are signed integers and are not range-validated at startup.
Use non-negative values. Changing tolerances changes accounting decisions for
newly processed events; it does not rewrite existing payment events.

## Claim retry policy

| Key | Default | Effect and tradeoff |
|---|---:|---|
| `claim.max_claim_attempts` | `30` | Number of failed construction/broadcast attempts before the fast path sets `claim_stuck`. Failures use approximately 10s, 20s, 60s, 5m, 10m, 30m, then 1h capped backoff with +/-20% jitter. Slow recovery can later revive funded rows. |

Use a positive value. Very small values move transient failures into slow
recovery quickly. Very large values keep failing swaps in the fast hourly loop
longer and increase provider/Electrum load. This is an attempt budget, not a
guarantee that a swap remains claimable for that duration.

## Reconciliation and slow recovery

The same `[reconciler]` policy is shared by reverse-swap reconciliation,
chain-swap reconciliation, and settlement repair.

| Key | Default | Effect and tradeoff |
|---|---:|---|
| `reconciler.interval_secs` | `90` | Main reconciliation and settlement-repair tick. Lower values recover missed webhooks faster but increase provider and database load. Must be greater than zero; Tokio rejects a zero interval. |
| `reconciler.min_age_secs` | `60` | Excludes newer rows from normal reconciliation to avoid racing fresh webhook processing. A higher value delays dropped-webhook recovery. |
| `reconciler.max_per_tick` | `200` | Maximum rows processed per reconciler tick. Backlogs drain oldest/priority rows over multiple ticks. Zero disables useful work without disabling the task. |
| `reconciler.inter_call_delay_ms` | `50` | Delay between provider calls within a tick. Increase to reduce request rate; `0` removes the delay. |
| `reconciler.slow_recovery_interval_secs` | `1800` | How often funded `claim_stuck` rows are considered for revival. Must be greater than zero. |
| `reconciler.slow_recovery_max_per_tick` | `25` | Maximum reverse and chain rows selected per slow-recovery tick. Zero prevents revival work. |
| `reconciler.slow_recovery_backoff_base_secs` | `3600` | Base delay for successive slow-recovery revivals, with jitter. |
| `reconciler.slow_recovery_backoff_cap_secs` | `86400` | Maximum delay between slow-recovery revivals. Keep greater than or equal to the base for intuitive behavior. |

The main interval multiplied by the per-tick cap determines backlog drain
capacity. Monitor oldest unreconciled age before increasing either delay.

## Pricing

| Key | Default | Effect and tradeoff |
|---|---|---|
| `pricer.url` | `https://api.bullbitcoin.com/public/price` | JSON-RPC pricing endpoint. Fiat invoice creation and public conversion depend on it. |
| `pricer.cache_ttl_secs` | `60` | In-memory last-good rate lifetime before refresh. Larger values improve availability and reduce upstream load but allow staler quotes. `0` forces refresh on every use. |
| `pricer.request_timeout_ms` | `2000` | HTTP timeout. On error, Bullnym uses a cached last-good value when available. Very small/zero values can make pricing unusable. |
| `pricer.supported_currencies` | `USD, CAD, EUR, CRC, MXN, ARS, COP` | Currency allowlist exposed to clients and accepted before an upstream call. Codes are normalized and deduplicated at client construction; each currency must also pass a configured safety ceiling in code. |

Removing a currency prevents new invoices in that currency but does not change
the fixed sat amount stored on existing invoices.

## PWA assets

| Key | Default | Effect |
|---|---|---|
| `pwa.dist_dir` | `pwa/dist` | Directory containing built Payment Page/POS assets served at `/pwa-assets` and read for shell rendering. Relative paths resolve from the process working directory. Missing assets cause fallback or failed static requests; deploy the checked build output atomically. |

## Legacy media

| Key | Default | Effect |
|---|---|---|
| `donation.image_root_path` | `/opt/payservice/data/images` | Root for media created by older Bullnym versions. Current APIs cannot upload or replace media. The service may copy an existing nym-keyed file to a content-addressed alias path. nginx may serve the tree read-only. |

If production has no legacy hashes/files, this path is normally unused. Do not
point it at a writable or sensitive tree.

## Product limits

| Key | Default | Effect and tradeoff |
|---|---:|---|
| `limits.min_sendable_msat` | `100000` (100 sat) | LNURL minimum payment amount. Must be non-zero and no greater than the maximum. |
| `limits.max_sendable_msat` | `25000000000` (25,000,000 sat) | LNURL maximum payment amount. Also bounds payment exposure offered through Lightning Address. |
| `limits.max_descriptor_len` | `1000` | Maximum accepted descriptor string length before parsing. This is a resource/abuse bound, not descriptor-policy validation. |
| `limits.max_lifetime_nyms_per_npub` | `3` | Lifetime nym-registration quota per authentication key. Inactive nyms still count because names stay reserved. Raising it expands namespace-squatting capacity; lowering it does not remove existing rows. |

Only the min/max relationship and non-zero minimum are startup-validated.

## LUD-22 proof policy

| Key | Default | Effect and tradeoff |
|---|---|---|
| `proof.min_proof_value_sat` | `1000` | Minimum value of the confidential L-BTC UTXO used to authorize a direct-Liquid LNURL callback. Raising it increases the payer capital requirement and anti-abuse cost. |
| `proof.message_tag` | `bullpay-lnurlp-v1` | Domain-separation tag included in ownership signatures. Must be non-empty. Changing it breaks verification for clients signing the previous tag until they update. |

The broad `rate_limit.ip_whitelist` bypasses the proof requirement as well as
rate limits. Certification bypasses do not generally remove signature or money
invariants.

## Bitcoin watcher

| Key | Default | Effect and tradeoff |
|---|---|---|
| `bitcoin_watcher.enabled` | `true` | Starts direct-Bitcoin invoice observation when global workers are enabled. Turning it off stops new observations/credits; it does not disable direct-Bitcoin offers already issued. |
| `bitcoin_watcher.endpoint` | `https://mempool.bullbitcoin.com/api` | Primary mempool.space-compatible Esplora API root. Trailing slash is removed. |
| `bitcoin_watcher.endpoints` | `[]` | Additional ordered failovers after the primary. Bull Bitcoin and mempool.space built-ins are always appended and deduplicated, so this list cannot remove those built-ins. |
| `bitcoin_watcher.active_tick_secs` | `30` | Poll interval for invoices newer than `active_window_secs`. Must be greater than zero. |
| `bitcoin_watcher.idle_tick_secs` | `300` | Poll interval for older payable invoices. Must be greater than zero. |
| `bitcoin_watcher.active_window_secs` | `3600` | Age threshold separating active and idle invoices. Negative values are accepted but make normal invoices idle immediately; use a non-negative value. |
| `bitcoin_watcher.confirmations_required` | `1` | Confirmation depth before a direct-Bitcoin output creates an accounting event. Unconfirmed outputs remain observations even when this is `0`; use at least `1` for clear policy. |
| `bitcoin_watcher.rate_per_sec` | `5` | In-process token-bucket capacity/refill for Esplora calls. `0` is coerced to `1`, not disabled. This is per Bullnym process. |
| `bitcoin_watcher.request_timeout_ms` | `10000` | Timeout for each Esplora request. The watcher rotates endpoints or skips work after errors. Use a positive value below the relevant polling interval. |

One endpoint supplies the tip and address data for a given tick so confirmation
math does not mix chain views. Built-in third-party failover has privacy and
availability implications because it discloses watched addresses when used.

## Liquid Electrum and transaction cache

| Key | Default | Effect and tradeoff |
|---|---|---|
| `electrum.liquid_url` | Unset | Deprecated single endpoint. When present it is tried before `liquid_urls`. Keep only for deployed-config compatibility. |
| `electrum.liquid_urls` | `['ssl://blockstream.info:995']` | Ordered Liquid Electrum endpoints for LUD-22 proof checks and the Liquid watcher. Bare hosts are normalized to `ssl://`. |
| `electrum.cache_ttl_secs` | `3600` | Lifetime of cached raw transaction bytes used by UTXO verification. `0` makes entries immediately stale. |
| `electrum.cache_max_entries` | `10000` | Approximate in-memory transaction-cache bound. The implementation retains at least one entry even when set to `0`; use a positive value. |

Bullnym appends `ssl://les.bullbitcoin.com:995` and
`ssl://blockstream.info:995` as built-in failovers. Claim operations try
`boltz.electrum_url` first, followed by this effective pool. Operators can
choose the primary order but cannot disable the built-ins through TOML.

## Rate limits and caller identity

Most count/window limit pairs use a sliding window. Unless noted otherwise, a
limit of `0` disables that individual check. Window values are seconds. Some
hot source-IP limits are process-local; Postgres-backed identity/distinct
limits are consistent across replicas. Token buckets are also per process.

| Key | Default | Scope and implications |
|---|---:|---|
| `rate_limit.ip_whitelist` | `[]` | IP/CIDR entries that bypass every rate limit and the LUD-22 proof gate. This is substantially broader than certification; restrict it to trusted infrastructure. |
| `rate_limit.trust_forwarded_for` | `false` | Uses the rightmost `X-Forwarded-For` value for caller identity. Enable only when the immediate trusted proxy overwrites client-supplied forwarding headers. Misconfiguration permits bypass or collapses all clients into one bucket. |
| `rate_limit.per_ip_limit` | `60` | LUD-22/LNURL callback requests per source per `per_ip_window_secs`. Process-local. |
| `rate_limit.per_ip_window_secs` | `60` | Window for `per_ip_limit`. |
| `rate_limit.per_pubkey_limit` | `0` | Post-signature LUD-22 requests per proof pubkey. Disabled by default because outpoint/source limits already constrain abuse. PostgreSQL-backed when enabled. |
| `rate_limit.per_pubkey_window_secs` | `3600` | Window for `per_pubkey_limit`. |
| `rate_limit.distinct_nyms_per_ip_limit` | `5` | Distinct target nyms per IPv4 source in `distinct_nyms_window_secs`. PostgreSQL-backed. |
| `rate_limit.distinct_nyms_per_ipv6_56_limit` | `3` | Distinct targets per aggregated IPv6 /56. Tighter because a /56 normally represents one subscriber. |
| `rate_limit.distinct_nyms_per_outpoint_limit` | `3` | Distinct targets authorized by the same proof outpoint. Prevents one UTXO from exhausting many descriptor cursors. |
| `rate_limit.distinct_nyms_window_secs` | `3600` | Shared window for the three distinct-target checks. |
| `rate_limit.max_pending_reservations_per_nym` | `50000` | Hard count of unfulfilled LUD-22 reservations for one nym. Unlike most limits, `0` blocks all new reservations rather than disabling the check. |
| `rate_limit.recycle_pending_older_than_days` | `30` | **Accepted but currently unused.** Changing it has no runtime effect; pending-reservation cleanup uses other GC policy. Retained for configuration compatibility. |
| `rate_limit.lightning_rate_per_minute` | `0` | **Legacy/no active caller.** The old per-nym Lightning limiter is not invoked; source-based Lightning limits replaced it. Retained for compatibility. |
| `rate_limit.global_electrum_rate_per_sec` | `50` | Process-local token bucket for user-facing Liquid Electrum calls. `0` is coerced to `1`, not disabled. |
| `rate_limit.register_rate_limit` | `5` | Registration/lookup requests per source per `register_rate_window_secs`, before signature verification. Process-local. |
| `rate_limit.register_rate_window_secs` | `60` | Window for `register_rate_limit`. |
| `rate_limit.register_distinct_npubs_per_ip_limit` | `3` | Distinct registration identities per source. PostgreSQL-backed. |
| `rate_limit.register_distinct_npubs_per_ip_window_secs` | `3600` | Window for the distinct registration-identity cap. |
| `rate_limit.max_active_users` | `10000` | Hard global active-user ceiling checked before registration. `0` disables it. Set an alert before expected growth reaches the ceiling. |
| `rate_limit.metadata_rate_limit` | `30` | LNURL/NIP-05 metadata requests per source per `metadata_rate_window_secs`. Process-local. |
| `rate_limit.metadata_rate_window_secs` | `60` | Window for metadata request volume. |
| `rate_limit.metadata_distinct_nyms_per_ip_limit` | `10` | Distinct metadata nyms queried per source. PostgreSQL-backed. |
| `rate_limit.metadata_distinct_nyms_per_ip_window_secs` | `3600` | Window for metadata enumeration control. |
| `rate_limit.lookup_distinct_npubs_per_ip_limit` | `5` | Distinct authentication keys queried through registration lookup per source. PostgreSQL-backed. |
| `rate_limit.lookup_distinct_npubs_per_ip_window_secs` | `3600` | Window for lookup enumeration control. |
| `rate_limit.chain_watcher_electrum_rate_per_sec` | `50` | Separate process-local token bucket for the Liquid watcher so public callbacks cannot starve it. `0` becomes `1`. |
| `rate_limit.chain_watcher_active_user_tick_secs` | `30` | Liquid watcher cadence for nyms with a recent callback. Must be greater than zero. |
| `rate_limit.chain_watcher_idle_user_tick_secs` | `600` | Liquid watcher cadence for other nyms. Must be greater than zero. |
| `rate_limit.chain_watcher_active_window_secs` | `86400` | A nym is active when its last callback is within this many seconds. |
| `rate_limit.webhook_rate_limit` | `10` | Boltz webhook requests per source per `webhook_rate_window_secs`. Process-local defense if the path secret leaks. |
| `rate_limit.webhook_rate_window_secs` | `60` | Webhook window. |
| `rate_limit.lightning_per_source_limit` | `30` | Lightning operations per payer source per `lightning_per_source_window_secs`, including explicit requests and Liquid-to-Lightning fallback. Process-local. |
| `rate_limit.lightning_per_source_window_secs` | `3600` | Source-based Lightning window. |
| `rate_limit.donation_html_rate_limit` | `60` | Payment Page/POS HTML renders per source per configured window. Process-local. |
| `rate_limit.donation_html_rate_window_secs` | `60` | HTML render window. |
| `rate_limit.donation_manifest_rate_limit` | `60` | Web-manifest requests per source. Process-local and separate from HTML. |
| `rate_limit.donation_manifest_rate_window_secs` | `60` | Manifest window. |
| `rate_limit.invoice_status_per_source_per_min` | `60` | Public invoice-status polls per source per fixed 60-second window. Legacy key `donation_status_per_source_per_min` is accepted. |
| `rate_limit.invoice_create_per_source_per_min` | `5` | Anonymous checkout creations per source per fixed 60-second window. Each success writes state and may allocate a swap. |
| `rate_limit.invoice_create_per_npub_per_hour` | `100` | Signed wallet-invoice creations per authentication key per fixed one-hour window. Process-local despite being keyed by npub, so aggregate capacity grows with the number of processes. |

Rate limits are not a substitute for nginx/network controls. In-memory limits
multiply with the number of Bullnym processes, while PostgreSQL-backed limits
share a database-wide view.

## Certification bypass

Certification is a narrower, auditable test bypass. It requires all of:
enabled mode, an allowed source, the exact header token, and a configured scope.

| Key | Default | Effect |
|---|---|---|
| `certification.enabled` | `false` | Activates certification decisions and validation. When true, source, token, and scopes must all be non-empty or startup fails. |
| `certification.source_allowlist` | `[]` | IP/CIDR sources allowed to attempt certification. Caller resolution follows `rate_limit.trust_forwarded_for`. |
| `certification.token` | Empty | Exact value required in `x-bullnym-certification-token`. This is secret material currently stored in TOML. |
| `certification.scopes` | `[]` | Allowed values: `registration_setup`, `metadata_lookup`, `invoice_create`, `invoice_status`, `live_money_offer`. Unknown values fail certification parsing at startup. |

Certification bypasses selected rate limits only. It does not bypass signatures,
ownership, descriptor validation, payment accounting, or recovery invariants.
Call `/certification/preflight?scopes=...` before a test run.

## Startup validation

Startup always rejects:

- `limits.min_sendable_msat == 0`;
- `limits.min_sendable_msat > limits.max_sendable_msat`;
- an empty `proof.message_tag`;
- enabled certification with an empty token, source allowlist, or scopes;
- malformed certification IP/CIDR entries or scope names.

When `BULLNYM_RUNTIME_MODE=production`, startup additionally rejects:

- a missing current webhook URL secret;
- `domain` equal to `localhost` or beginning with `localhost:`;
- a non-loopback `listen` address unless public listening is explicitly
  allowed.

Many numeric fields have no startup range validation. In particular, zero
Tokio intervals can panic their worker after startup. Use the positive values
shown in the example unless a field explicitly documents zero semantics.

## Production procedure

1. Start from `config.example.toml`; do not copy simulator or test overrides.
2. Set `BULLNYM_RUNTIME_MODE=production`, required secrets, a public `domain`,
   and a loopback `listen` address.
3. Review all external endpoints, built-in failover disclosure, confirmation
   policy, accounting tolerances, and recovery gating.
4. Confirm the database and swap mnemonic are a matched, restorable pair.
5. Protect the TOML file if certification contains a token.
6. Restart Bullnym and require `/health`, `/ready`, and `/version` to pass.
7. Confirm startup logs show every expected worker and the intended endpoint
   order. Investigate normalization or disabled-worker warnings.
8. Run certification preflight without moving funds, then monitor at least one
   reconciler and watcher cycle.

Rollback configuration by restoring the previous reviewed file and restarting.
A configuration rollback does not reverse database migrations, address
allocations, payment events, or transactions already broadcast.
