# bullnym

Lightning Address pay service for Bull Bitcoin. Lets users register a nym (e.g. `francis@bullpay.ca`) and receive Lightning payments that settle on Liquid via Boltz reverse submarine swaps.

## How it works

### LNURL-pay flow

When someone pays `francis@bullpay.ca`, their wallet resolves it via [LUD-16](https://github.com/lnurl/luds/blob/luds/16.md):

1. Wallet queries `GET https://bullpay.ca/.well-known/lnurlp/francis`
2. bullnym returns LNURL-pay metadata (min/max amounts, description)
3. Wallet calls `GET /lnurlp/callback/francis?amount=<msats>`
4. bullnym creates a Boltz reverse swap (LN → L-BTC) and returns the BOLT11 invoice
5. Payer pays the invoice on Lightning

### Boltz reverse swap + cooperative claim

When the Lightning payment arrives:

1. Boltz holds the incoming LN HTLCs (can't settle — doesn't have the preimage)
2. Boltz locks L-BTC on-chain in a Taproot HTLC
3. Boltz sends a webhook to bullnym (`transaction.mempool`)
4. bullnym performs a **cooperative MuSig2 claim** with Boltz — a Taproot keypath spend that produces a CT-blinded output directly to the user's Liquid address
5. Boltz extracts the preimage from the cooperative claim and settles the Lightning HTLCs

The cooperative claim is indistinguishable from a normal Taproot transaction on-chain. The output is Confidential Transaction-blinded, preserving the user's privacy. If Boltz is unresponsive, bullnym falls back to a script-path spend using the preimage and claim key directly.

We do **not** use Boltz claim covenants. Boltz [explicitly warns](https://docs.boltz.exchange/v/api/claim-covenants) that covenants are not safe for LNURL flows where the receiving client is offline. The trust model is identical either way (service is custodial during the claim window), but cooperative claims give us CT privacy and a clean on-chain footprint.

### Failure modes

The protocol is atomic — the preimage links the Lightning payment and the on-chain lock. Most failures unwind cleanly:

- **Payer never pays**: Invoice expires, nothing happens
- **Boltz never locks L-BTC**: Lightning HTLCs time out, payer is refunded
- **bullnym goes down before claiming**: Preimage never revealed, LN HTLCs time out (payer refunded), on-chain lock times out (Boltz reclaims L-BTC). Nobody loses funds.
- **Cooperative claim fails**: Automatic fallback to script-path spend

### Trust model

The server does not hold user funds. When a payment is received, the server creates a swap and claims the resulting L-BTC directly to the user's Liquid address in a single transaction. No funds ever sit in a server-controlled address.

The server does have the theoretical capacity to steal funds by redirecting a claim to a different address. However, if the server operates honestly — which is its sole intended function — it is purely non-custodial. It acts as a technical layer that coordinates swaps on the user's behalf, not as a custodian or transmitter of funds.

Because the server never controls, holds, or transmits user funds during normal operation, it does not qualify as a virtual asset service provider or money transmitter.

A future "sovereign mode" enhancement will eliminate even the theoretical ability to redirect funds: the user pre-generates preimage hashes on-device, so the server can create swaps but cannot claim without the user's participation.

### Registration with Nostr auth

Users register by choosing a nym and signing with a Nostr keypair derived from their wallet's master seed via BIP85 (application 86, per NIP-06). The server verifies the schnorr signature and stores the user's npub alongside their nym and CT descriptor.

```
POST /register
{
  "nym": "francis",
  "ct_descriptor": "ct(slip77(...),elwpkh(...))",
  "npub": "<x-only pubkey hex>",
  "signature": "<schnorr sig over SHA256(nym + ct_descriptor)>"
}
```

The same Nostr keypair is used for all authenticated operations (update descriptor, delete registration). On registration, the mobile app also publishes a NIP-05 profile to Nostr relays with the `nip05` and `lud16` fields set, so the Lightning Address is discoverable via Nostr.

The server doubles as a NIP-05 identity provider:

```
GET /.well-known/nostr.json?name=francis
→ { "names": { "francis": "<npub hex>" } }
```

### LUD-22: Pay-to-pubkey

bullnym is designed around the idea that Lightning Addresses should be tied to Nostr identities. The nym `francis@bullpay.ca` is simultaneously:

- A Lightning Address (LUD-16) — receive Lightning payments settled to Liquid
- A NIP-05 identifier — verifiable Nostr identity
- A future LUD-22 endpoint — pay directly to a pubkey

This means any Nostr client that resolves `francis@bullpay.ca` via NIP-05 can also pay that user via Lightning, and vice versa.

### Future: BIP 353 DNS payment instructions

The plan includes BIP 353 support — DNSSEC-signed TXT records at `francis.user._bitcoin-payment.bullpay.ca` containing a `bitcoin:` URI. This gives wallets that support BIP 353 (Phoenix, Zeus, etc.) an alternative resolution path alongside LNURL:

- DNS-first wallets resolve the TXT record and get a Liquid address or BOLT12 offer
- LNURL wallets resolve via HTTPS as usual
- Both paths work from the same `user@domain` identifier

The DNS record is created at registration time and rotated when addresses are allocated during LNURL callbacks. DNSSEC validation is required by BIP 353, ensuring the payment instructions haven't been tampered with.

## Architecture

```
bullnym (Rust/Axum)
├── LNURL endpoints (LUD-06/LUD-16)
├── Registration with Nostr schnorr auth
├── Boltz reverse swap creation
├── Cooperative MuSig2 claiming (webhook-driven)
├── Crash recovery (startup scan for unclaimed swaps)
├── NIP-05 identity provider
├── CT descriptor → Liquid address derivation (lwk_wollet)
└── PostgreSQL (users, swap records, swap state)

Mobile (bullbitcoin-mobile)
├── BIP85-derived receive wallet (index 75)
├── Nostr keypair derivation (BIP85 application 86)
├── Pay service registration + deletion
├── Auto-sweep from receive wallet to main wallet
└── Nostr profile publishing (NIP-05, LUD-16)
```

## Running locally

```bash
# Create database
sudo -u postgres psql -c "CREATE USER pay_service WITH PASSWORD 'devpass';"
sudo -u postgres psql -c "CREATE DATABASE pay_service OWNER pay_service;"

# Configure
cat > .env << 'EOF'
DATABASE_URL=postgres://pay_service:devpass@localhost/pay_service
SWAP_MNEMONIC=<your 12-word BIP39 mnemonic>
EOF

# Run migrations and start
cargo run
# → listening on 0.0.0.0:8080
# → curl http://localhost:8080/health → "ok"
```

## Dependencies

- [boltz-client](https://github.com/SatoshiPortal/boltz-rust) — Boltz API V2, MuSig2 cooperative claims, Magic Routing Hints
- [lwk_wollet](https://github.com/Blockstream/lwk) — Liquid CT descriptor parsing and address derivation
- [axum](https://github.com/tokio-rs/axum) — HTTP server
- [sqlx](https://github.com/launchbadge/sqlx) — PostgreSQL with compile-time checked queries
