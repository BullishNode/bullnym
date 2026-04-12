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

### Threat model

**What the server controls:**

The server generates the preimage and holds the per-swap claim keypair. These two secrets are sufficient to claim the Boltz on-chain lockup to any address. This is the fundamental trust assumption.

**What the server can do if it acts maliciously:**

1. **Redirect funds**: Claim the L-BTC to its own address instead of the user's. The Taproot HTLC only enforces preimage + claim key — not the destination address. The payer's LN payment settles normally (Boltz extracts the preimage and completes the Lightning circuit). The user receives nothing.

2. **Withhold claiming**: Simply not claim. The LN HTLCs time out (payer refunded), the on-chain lock times out (Boltz reclaims). Nobody loses funds — the swap just fails. This is griefing, not theft.

**What the server cannot do:**

- Access the user's Liquid wallet (it only has the CT descriptor for deriving addresses — not the private keys)
- Spend funds that have already been claimed to the user's address
- Prevent the user from spending received funds
- Correlate received payments to spending (outputs are CT-blinded)

**What happens in normal operation:**

The server acts as an automated swap coordinator. The L-BTC flows directly from Boltz's on-chain lockup to the user's Liquid address in a single transaction. The server constructs and signs the claim transaction, but the output goes to the user — the server never holds a balance, never has funds in an address it controls, and never has the ability to spend the user's received L-BTC after the claim confirms.

The flow is: Boltz lockup → claim tx → user's address. There is no intermediate step where funds sit in a server-controlled address.

**Comparison to other models:**

| Model | Server holds funds? | Server can redirect? | User must trust server? |
|-------|--------------------|--------------------|----------------------|
| **Custodial LN wallet** (e.g. Wallet of Satoshi) | Yes, permanently | Yes | Yes — for all funds |
| **LSP with channels** (e.g. Phoenix) | No (funds are in channels) | Limited (force-close) | Partially — for routing |
| **bullnym (current)** | No — funds flow through | Yes, during claim window | Yes — during claim window only |
| **bullnym + sovereign mode** (future) | No | No — user pre-generates preimage hash | No |

**Sovereign mode (planned future enhancement):**

The user pre-generates preimage hashes on-device and registers them with the server. The server can create swaps using these hashes but cannot generate the preimage — only the user can reveal it (by opening the app, which triggers the claim). This eliminates the server's ability to redirect funds, making the system fully trustless. The trade-off is that the user must come online to complete the claim before the Boltz timelock expires.

**Key distinction — custodial vs. non-custodial:**

In normal operation, the server never holds user funds. It has temporary cryptographic authority over in-flight swap funds (between Boltz lockup and claim), but exercises that authority solely to route funds to the user's address. After the claim transaction confirms, the server has no further control. This is analogous to a payment router that has the technical ability to misdirect a payment but operates correctly as an automated conduit.

The server's custody window is measured in seconds (time between receiving the Boltz webhook and broadcasting the claim transaction). During this window, the funds are locked in Boltz's on-chain HTLC — not in any address controlled by the server. The server holds cryptographic keys that could unlock those funds, but does not hold the funds themselves.

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
