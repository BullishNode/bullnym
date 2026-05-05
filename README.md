# bullnym

The problem that Bullnym attempts to solve is that because the BULL wallet relies on an atomic-swap server (boltz) to allow users to receive Lightning Network payments, the BULL wallet cannot offer Lightning Address (LNURL-PAY) to its users.

This is a significant UX downside of the BULL wallet compared to other custodial Lightning wallets, and other graduated wallets such as Spark-enabled wallets.

The solution is a server compatible with LNURL which has 3 main functions:

1. It receives and stores Liquid confidential descriptors for the user (recipient)
2. It generates and assigns a Lightning Network address associated to that descriptor
3. It creates a reverse submarine swap on behalf of the user (recipient) when a sender calls the LNURL endpoints and requests a bolt11 for that address.

The Lightning Address is called a "nym".

## Risks and tradeoffs. Is it custodial?

There are typically 2 risks associated with a custodial Lightning address server:

- **Risk to the user:** the server can steal funds and censor payments
- **Risk to the operator:** illegally operating a money transmission service without a license

The Bullnym system is interesting in that it is technically non-custodial: at no point in time does it actually handle user funds or facilitate a payment. All it does is calling the Boltz API and providing a Liquid network address. This eliminates the legal risk to the operator.

However, because the swap is constructed by the server and not the user, the server could maliciously create a swap with another Liquid address that doesn't actually belong to the recipient. In effect, the server could steal funds from the user. The end result is that the end user still has to trust that the server operates honestly, but as long as the server operates honestly, the swap remains non-custodial. So it's an interesting situation of non-custodial but still trusted.

## Privacy: special purpose wallet and autosweep

The other major risk to the user is that the user has to send his Liquid wallet descriptor to the server, so that the server derives a new Liquid address for every payment. The alternative is to have a single Liquid address. Having a single liquid address allows any blockchain observer to track a user's payment. Confidential transactions on the Liquid network hide amounts from on-chain observers, but address reuse is still a major privacy downside. Providing a descriptor to the server, to avoid address reuse, provides a considerable privacy improvement at the chainanalysis level but allows the server to effectively see all the transactions done to and from that wallet. The server does have the blinding key. It's part of the CT descriptor and is needed to derive confidential addresses. So it can see the amounts of every transaction received via the Lightning Address, but not other transactions on the user's main wallet.

The solution to this problem chosen by the client is to generate a single purpose Liquid wallet in the BULL application which is only used to receive payments via the Bullnym server. The "main" or "default" Liquid network wallet is therefore not compromised.

In order to provide a simple user experience, this "single purpose" liquid network wallet is derived deterministically via BIP85 so that it can be recovered from the same mnemonic backup as the default wallets. We call this the Lightning Address wallet. In addition, an auto-sweep function is added so that any payment received in the Lightning Address wallet is automatically sent to the default Liquid wallet (the Instant Payments wallet). The default user experience completely hides the existence of the Lightning Address wallet, not visible on the home page, so that the user never needs to interact with it at all. The drawback to autosweep is that it adds ~19 sats to every payment received, because of the extra Liquid network transaction. At current Bitcoin price (~80,000 USD) this is ~$0.015 and is an acceptable tradeoff.

## Nostr-based authentication

When registering a nym with the Bullnym server, the BULL app derives a nostr keypair using BIP85 and uses it to sign a registration message with the Bullnym server. This allows the user to authenticate itself with the Bullnym server to manage his nym. The main actions a user can perform are:

- **Deactivating a nym:** this prevents senders from sending payments to the Lightning address (enforced by the server).
- **Changing a descriptor associated to a nym:** in case the user migrates wallets but wants to keep the same nym.
- **Creating a new nym:** this allows the user to create a new nym for a previously registered descriptor.

Why nostr? Nostr is not required for this authentication protocol, various other protocols built on BIP85 could have been used. However, there are other features that nostr enables such as sending and receiving messages and publishing the nym on the nostr relay network for discoverability. The better question is therefore "why not nostr?" and there doesn't seem to be any downside to using nostr for authentication.

## LUD-22 and compatibility

The Bullnym server is compatible with any LNURL-enabled sender wallet. During development, we noticed: a BULL wallet user sending a Lightning network payment to a recipient that is using Bullnym for its Lightning address, there is a massive inefficiency: the sender will be creating a submarine swap from Liquid to Lightning, and paying the receiver's reverse submarine swap from Lightning to Liquid. Not only do both the sender and the receiver end up paying Boltz's swap fees, but these 2 swaps generate 4 Liquid network transactions and pay those network fees!

This is a known problem for any sender that sends funds over lightning network to a recipient where both are using the Boltz api integration. To solve this problem, Boltz created an innovative mechanism called the "magic routing hint" (MRH) where Boltz will embed the recipient's Liquid address in the bolt11 routing hint, so that a sender whose wallet is MRH-aware, when decoding the bolt11, will know to "skip" paying the bolt11 and simply extract the Liquid address from the routing hint and pay that directly. Exactly what we want to achieve. There are 4 major issues with this:

1. The magic routing hint is added by the Boltz server, at their leisure. If Boltz decides to remove this feature, there is nothing that the Bullnym server operator can do.
2. The Bullnym server can be extended to support various other forms of payment, such as Silent Payment addresses, Ark addresses, Spark addresses, etc. While there is nothing preventing Boltz from extending MRH to support these alternative methods, this is outside of the Bullnym server's control.
3. The main threat here is enumeration attacks, where any sender can repeatedly call the LNURL endpoint. More on this in the rate limiting section. The Bullnym server operator may want to implement his own rate limiting that is stricter than Boltz's.
4. MRH only works with wallets that implement the Boltz software libraries.

Bullnym introduces LUD-22, which allows the sender to specify to a LNURL server that he is able and willing to send funds over the Liquid network (or any other network). LNURL servers which implement the Bullnym model will then return a Liquid address instead of the bolt11 reverse submarine swap. This can be extended to Silent Payments, Ark addresses, Spark addresses, etc.

The result of LUD-22 is that it creates a single "nym" service which is compatible with existing LNURL-enabled wallets, but which also allows wallets to register other available payment methods that bypass the classic bolt11 response if the sender and recipient are both on a compatible alternative payment protocol. This achieves something similar to Samourai Wallet's "paynym server" system, but it is compatible with LNURL, supports Silent Payments, supports the Liquid Network, and can be extended to support practically any Bitcoin payment protocol.

## Why LUD-22, not MRH

We considered keeping MRH (Magic Routing Hint) alongside LUD-22 as an alternative on-chain shortcut and decided against it. The deciding factor is enumeration-attack resistance.

MRH has no commitment from the sender. Anyone can hit the LNURL callback over HTTP, get an address allocated and embedded in the bolt11 routing hint, and never pay. The address counter on the recipient's CT descriptor advances anyway. With enough sustained traffic, the counter ratchets past the recipient wallet's gap limit, and gap-limit-bounded scanners (BDK, LWK by default) silently stop picking up new payments until the user does a manual full rescan. Funds aren't lost, but the receive UX breaks. The only available defense for MRH is per-source-IP throttling, which is bounded by what legitimate senders tolerate rather than by what attackers tolerate. The TTL-recycle trick we use elsewhere doesn't apply, because the address stays a valid Liquid receive address indefinitely after the bolt11 expires.

LUD-22 fixes this at the protocol layer by requiring the sender to sign ownership of a Liquid UTXO worth at least 100 sats before the server hands out an address. The commitment is small but it changes everything about the attack economics. On every dimension that matters, the contrast is sharp:

| Property | MRH | LUD-22 |
|---|---|---|
| Cost per request to attacker | Zero (HTTP GET) | ≥ 100 sats committed on-chain |
| Idempotency on repeat | None — counter advances every time | Cache hit (same outpoint and nym → same address) |
| Recovery after attack | None — damage is cumulative | Automatic via TTL recycling |
| Bound on damage | Unbounded over time | 3 nyms per UTXO per hour |

The cost of deprecating MRH is borne by senders that supported MRH but not LUD-22 (mainly Aqua and other Boltz-library wallets). For those senders, payments now route through the standard reverse-swap path: roughly 580 extra sats of Boltz fees on a 100,000-sat payment, plus a few extra Liquid network transactions. The remediation is for those wallets to adopt LUD-22, at which point the on-chain shortcut is restored — with stronger privacy properties and a structurally cost-bounded defense profile.

## LUD-22 rate limiting

The threat we are mitigating is descriptor-index exhaustion. Every address handed out via LUD-22 advances the recipient's CT descriptor counter. If an attacker can advance it freely, gap-limit-bounded wallets eventually stop seeing new payments. The 100-sat UTXO ownership proof required by LUD-22 is what makes a real defense possible, because every request now costs the attacker something on-chain. That single commitment gates four cascading mechanisms:

1. **Idempotent mapping.** Each `(nym, outpoint)` pair always resolves to the same address. A repeated request with the same UTXO targeting the same nym hits cache; the descriptor counter does not advance. An attacker who simply repeats requests makes no progress.
2. **Per-outpoint fan-out cap.** A single UTXO can probe at most 3 distinct nyms per hour. To probe more, the attacker has to rotate UTXOs, which means real on-chain Liquid spends with real network fees and confirmation delays.
3. **Per-pubkey volume cap.** The signing key on the proof is rate-limited to 10 requests per hour. Spreading volume across many keys forces spreading across many UTXOs, which compounds the on-chain cost.
4. **TTL recycling.** Pending reservations release after one hour. An attacker who never pays cannot hold address allocations indefinitely; the descriptor counter is bounded by the steady-state hostage size, not by total request count over time.

Standard per-IP rate limiting applies on top of all four.

The combined effect is that the cost of a sustained enumeration attack scales with the on-chain Liquid UTXO supply the attacker controls, not with their willingness to send HTTP requests. Probing 1,000 nyms in an hour requires at least 334 distinct UTXOs of at least 100 sats each, all funded on-chain — a cost that has no analogue under MRH.

## Nostr nym registration with NIP05

The Bullnym server supports NIP05 registration. This allows users to optionally register their nym and Lightning address on the nostr relay network. This allows for discoverability (find contacts via the Nostr network) and opens up interesting possibilities such as NIP57 (zaps). Honestly, I am not sure that this adds any value because the nostr keypair generated is not associated to the user's identity and therefore doesn't let nostr users find the payment details of their contacts. It may also have downsides (discoverability introduces ddos vectors). And it does not provide redundancy because if the Bullnym server goes offline, users will not be able to obtain payment details from recipients via nostr because the NIP05 info just points to the Bullnym server. However, given that BULL plans to eventually publish Silent Payment addresses on nostr, this is a neat proof of concept and a useful place to surface issues like how to deactivate payment instructions.

## Some other considerations: nym reservations

- Users can only register up to 3 nyms per nostr identity, to prevent griefing nyms. In addition to standard rate limiting to prevent griefing. When a user deactivates his 2nd nym, he will see a message telling him that he only has 1 nym left.
- Deactivated nyms can never be taken by someone else, to prevent impersonation. They are "reserved forever" by the npub that first registered them.
- Only 1 nym available per wallet at a time. This restriction is for system and ui/ux simplicity and could be lifted later.
- Nyms that have never been used could be made to expire after a long period of time (to prevent griefing, but this is risky).

---

# Technical reference

## Architecture

bullnym is a Rust/Axum HTTP server with a Postgres backend, four background workers, and stateful integrations with a Liquid Electrum server and the Boltz API.

```
HTTP layer (Axum)
├── /.well-known/lnurlp/:nym         LUD-06 metadata
├── /.well-known/nostr.json          NIP-05 identity provider
├── /lnurlp/callback/:nym            LNURL-pay callback (Lightning + LUD-22 L-BTC)
├── /register {POST,PUT,DELETE}      Nym lifecycle, BIP-340 Schnorr-authenticated
├── /register/lookup                 Recover registration state by npub
├── /api/reservations/:nym           List the nym's pending LUD-22 reservations
├── /webhook/boltz                   Boltz reverse-swap status (HMAC-SHA256)
└── /health                          Liveness probe

Background tasks (spawned in main, joined on SIGINT)
├── claimer                          Webhook drain + MuSig2 cooperative claims
├── chain_watcher                    Liquid Electrum polling, deposit detection, TTL recycle
├── rate-limit GC                    Prunes sliding-window counter rows in Postgres
└── in-memory rate-limit sweep       Evicts idle per-IP buckets from process memory

Stateful dependencies
├── PostgreSQL                       Users, swap records, rate-limit counters
├── Boltz API v2                     Reverse-swap creation, MuSig2 cooperative claim
└── Liquid Electrum                  UTXO ownership verification, deposit polling
```

The server is stateless across processes — all durable state lives in Postgres. Restart-safety is provided by the claimer's startup scan (it re-checks every unclaimed swap on boot) and by exclusion constraints / unique indexes that make every claim and every address allocation idempotent.

## HTTP API

### Public LNURL endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/.well-known/lnurlp/:nym` | LUD-06 metadata (callback URL, min/max sendable, `payment_methods`) |
| `GET` | `/.well-known/nostr.json?name=:nym` | NIP-05 identity provider, returns the registered npub |
| `GET` | `/lnurlp/callback/:nym` | LNURL-pay callback. Returns a BOLT11 invoice (default Lightning rail) or a Liquid address (LUD-22 with `payment_method=L-BTC` plus a UTXO ownership proof) |

Wallets that support LUD-22 send `payment_method=L-BTC` along with `outpoint`, `pubkey`, and `sig` query params. The server verifies the Schnorr signature, checks the UTXO is unspent on Liquid Electrum, confirms its value is at least `proof.min_proof_value_sat` (default 1000), and returns either the cached `(nym, outpoint)` address or a freshly allocated one from the user's CT descriptor.

### Authenticated nym lifecycle

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/register` | Create a new nym |
| `PUT` | `/register` | Update CT descriptor on an existing nym |
| `DELETE` | `/register` | Deactivate a nym |
| `GET` | `/register/lookup?npub=...` | List nyms registered to an npub (rate-limited per IP, distinct-npubs cap) |
| `GET` | `/api/reservations/:nym?...` | List the nym's pending LUD-22 reservations |

All write operations require a BIP-340 Schnorr signature over a domain-tagged payload (see Authentication).

### Webhook

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/webhook/boltz` | Boltz reverse-swap status notifications, used by the claimer to drive MuSig2 cooperative claims |

Authenticated by `Boltz-HMAC-Signature: <hex(HMAC-SHA256(secret, body))>`, compared in constant time. Independent of HMAC, the route is rate-limited per source so a leaked secret does not turn into a webhook bomb.

## Authentication

### Lightning Address v1 signing

Mobile clients sign a domain-tagged byte string with the BIP-340 Schnorr key derived from BIP85 (the same Nostr keypair used for registration):

```
bullpay-la-v1\x00<action>\x00<npub_hex>\x00(<field>\x00)*<timestamp>
```

| Action | Payload fields |
|---|---|
| `register` | `nym`, `ct_descriptor` |
| `update` | `ct_descriptor` |
| `delete` | (none) |

The server verifies the Schnorr signature against `SHA-256(message)` and rejects timestamps outside `±300 s` (mobile clocks drift more than desktop). A pre-v1 format (untagged, untimestamped) is still accepted with a deprecation warning to support older mobile builds; it will be removed once warning volume drops.

### IP whitelist

`rate_limit.ip_whitelist` accepts CIDR ranges. Whitelisted callers bypass all rate limits and the LUD-22 proof-of-funds check. Used for known partners and the simulator suite. Parsing is fail-closed: a typo in a CIDR aborts startup loudly.

## Configuration

`config.toml` has the operational knobs; secrets and connection strings come from the environment.

```toml
domain    = "bullpay.ca"        # Public hostname; used in LUD-06 metadata + identifiers
listen    = "127.0.0.1:8080"    # Bind address (loopback when behind nginx)
pool_size = 10                  # Postgres connection pool

[boltz]
api_url      = "https://api.boltz.exchange/v2"
electrum_url = "blockstream.info:995"  # Boltz client's transitive Electrum dep

[limits]
min_sendable_msat          = 100_000          # 100 sats
max_sendable_msat          = 25_000_000_000   # 25 M sats
max_descriptor_len         = 1000
max_lifetime_nyms_per_npub = 3                # Hard cap per npub (incl. inactive)

[proof]
min_proof_value_sat = 1000                    # LUD-22 UTXO ownership floor
message_tag         = "bullpay-lnurlp-v1"

[electrum]
liquid_urls       = ["les.bullbitcoin.com:995"]  # First reachable wins; rotates on transport failure
cache_ttl_secs    = 3600
cache_max_entries = 10_000

[rate_limit]
trust_forwarded_for = true                    # Set true behind a known reverse proxy
ip_whitelist        = []                      # CIDRs that bypass all gates
# ...numerous tunables, organized by feature group with comments in src/config.rs...
```

The `[rate_limit]` table has many tunables, organized by feature group with comments explaining the threat each one closes (registration flood, nym-list discovery, chain-watcher starvation, webhook bomb, etc.). Defaults are conservative; production overrides live in the deployed `config.toml`.

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | Postgres DSN, e.g. `postgres://payservice:...@localhost/payservice` |
| `SWAP_MNEMONIC` | yes | 12-word BIP39 mnemonic for the Boltz `SwapMasterKey` (preimage and claim-key derivation) |
| `BOLTZ_WEBHOOK_SECRET` | recommended | Shared HMAC secret for `/webhook/boltz`. Empty disables auth (dev only); production must set it. |

`.env` at the project root is read at startup via `dotenvy`.

## Database

Postgres is the single source of truth. All migrations are plain SQL under `migrations/`, applied **manually** via `psql`; the binary does not run `sqlx::migrate!()` in-process to avoid surprise schema changes on restart.

Major tables:

- **`users`** — one row per nym. Holds `npub`, `ct_descriptor`, `next_addr_idx`, `is_active`, `last_callback_at`, `has_been_used`. `nym` is unique; deactivated rows reserve the name forever.
- **`swap_records`** — one row per Boltz reverse swap. References `users(nym)`. Includes `boltz_swap_id`, `address`, `address_index`, `amount_sat`, `invoice`, MuSig2 claim state. `address` is nullable on the Lightning path: addresses are now allocated at claim time (since the MRH deprecation), not at swap creation.
- **`outpoint_addresses`** — LUD-22 `(nym, outpoint) → address_index` cache. UNIQUE constraint enforces the idempotent-mapping defense.
- **`nym_access_events`** — sliding-window counters for the distinct-nyms-per-IP and distinct-nyms-per-outpoint caps.
- **`processed_webhook_events`** — webhook idempotency guard.
- **Rate-limit counter tables** — per-IP, per-pubkey, register and metadata sliding windows. Pruned every 10 min by the GC task.

## Background tasks

All four are spawned in `main` and shut down via a single `CancellationToken` on `SIGINT`.

- **`claimer::spawn_background_claimer`** — drains the webhook queue and Boltz events. On `transaction.mempool` it allocates a fresh address index and performs a MuSig2 cooperative claim (Taproot key-path) to the user's CT descriptor. Falls back to the script-path spend with the preimage if Boltz is unresponsive.
- **`chain_watcher::run`** — polls Liquid Electrum on a per-user tick. Active users (callback within 24 h) tick every 30 s; idle users every 10 min. Uses a dedicated Electrum token bucket so a callback storm cannot starve the watcher (and vice versa). Releases unfunded LUD-22 reservations after their TTL and detects deposits to addresses already handed out.
- **`gc::run`** — every 10 min, prunes rate-limit and access-event rows older than 24 h. Without this, sliding-window queries grow O(N).
- **In-memory rate-limit sweep** — every 5 min, evicts in-process counter buckets idle for more than 2 h. Bounds RSS under unique-IP bursts.

## Building and running locally

```bash
# Postgres
sudo -u postgres psql -c "CREATE USER payservice WITH PASSWORD 'devpass';"
sudo -u postgres psql -c "CREATE DATABASE payservice OWNER payservice;"
for m in migrations/*.sql; do
    sudo -u postgres psql -d payservice -f "$m"
done

# Env
cat > .env <<'EOF'
DATABASE_URL=postgres://payservice:devpass@localhost/payservice
SWAP_MNEMONIC=<12-word BIP39 mnemonic>
BOLTZ_WEBHOOK_SECRET=<32-byte hex>
EOF

# Build + run
cargo run --release
# → listening on 0.0.0.0:8080
curl -fsS http://localhost:8080/health   # → "ok"
```

`Cargo.toml` references `boltz-client` via a path dependency to a sibling checkout of `SatoshiPortal/boltz-rust`. Clone it as `../boltz/boltz-rust` relative to this repo, or adjust the path.

## Deployment notes

Production runs on a hardened Linux VM under systemd as user `payservice`, behind nginx with TLS via Let's Encrypt at `bullpay.ca`. The binary is built locally (`cargo build --release`) and `scp`'d to the VM — no Rust toolchain is installed on prod. Both hosts run the same glibc and arch.

- **Reverse proxy.** nginx terminates TLS and forwards to `127.0.0.1:8080`. `X-Forwarded-For` is set, so `[rate_limit] trust_forwarded_for = true` is required for per-IP gating to work.
- **Migrations.** Applied manually via `psql` against the production DB. The service does not run `sqlx::migrate!()` in-process. `_sqlx_migrations` is not present.
- **Rollback.** VM snapshots are taken before every deploy, and the prior binary is kept at `/opt/payservice/bin/pay-service.bak` for fast rollback without a snapshot restore.
- **Electrum URL scheme.** `[electrum]` URLs should be prefixed `ssl://`. The server warns and assumes `ssl://` for bare `host:port`, but explicit prefixes silence the warning and avoid a long-standing source of plain-TCP-against-TLS-port outages.

## Dependencies

| Crate | Purpose |
|---|---|
| [axum](https://github.com/tokio-rs/axum) 0.7 | HTTP server |
| [tokio](https://github.com/tokio-rs/tokio) 1 | Async runtime, signal handling |
| [sqlx](https://github.com/launchbadge/sqlx) 0.8 | Postgres with compile-time-checked queries |
| [lwk_wollet](https://github.com/Blockstream/lwk) 0.14 | Liquid CT descriptor parsing, address derivation |
| [boltz-client](https://github.com/SatoshiPortal/boltz-rust) | Boltz API v2, MuSig2 cooperative claims |
| [secp256k1](https://github.com/rust-bitcoin/rust-secp256k1) 0.29 | BIP-340 Schnorr verification |
| [electrum-client](https://github.com/bitcoindevkit/rust-electrum-client) 0.21 | Liquid Electrum (UTXO verification, mempool / chain polling) |
| [tower-http](https://github.com/tower-rs/tower-http) | TraceLayer, CORS, body-size limit |
| [rustls](https://github.com/rustls/rustls) 0.23 | TLS via `aws-lc-rs` |
| [dashmap](https://github.com/xacrimon/dashmap) 6 | Lock-free in-memory rate-limit buckets |
