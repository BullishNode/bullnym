LUD-22 vs MRH: rate-limiting research and the decision to deprecate MRH support
================================================================================

`author: BullishNode`

---

## Background

Bullnym serves Lightning Address payments on three rails, picked by the server based on what the sender's wallet supports:

1. **`transaction.direct` via Magic Routing Hint (MRH).** Boltz reverse swaps allow the server to embed a Liquid address as a routing hint inside the BOLT11 invoice. Senders whose wallet uses Boltz libraries (currently Aqua, the Boltz web app, and a few others) decode the hint, skip the Lightning HTLC entirely, and pay the Liquid address on-chain. No Lightning, no claim, no extra Boltz fees.

2. **LUD-22 Liquid-direct.** Bullnym's LNURL extension (`docs/lud-22-currency-negotiation.md`). Sender requests `payment_method=L-BTC` and provides a UTXO ownership proof. Server returns a Liquid address directly. No Lightning, no Boltz at all.

3. **Cooperative MuSig2 claim.** Default Lightning rail. Sender pays the BOLT11 over Lightning. Boltz funds the lockup HTLC. Server's claimer cooperatively signs a MuSig2 keypath claim to a fresh address derived from the user's CT descriptor.

Both LUD-22 and MRH consume an `address_index` from the user's descriptor. LUD-22 has well-developed defenses against descriptor-index exhaustion attacks (see `migrations/006_outpoint_addresses.sql`, `src/rate_limit.rs`). MRH does not.

This document compares the rate-limiting properties of the two paths and concludes that MRH cannot be defended to the same standard. The recommended action is to deprecate MRH support entirely on the bullnym server: stop setting `address` and `addressSignature` at swap creation, and defer address allocation to claim time on the cooperative MuSig2 path.

## The attack model

The attack is descriptor-index exhaustion. An attacker repeatedly hits an endpoint that consumes an `address_index` from the receiver's CT descriptor. They never pay any of the resulting bolt11s. The `next_addr_idx` counter ratchets up indefinitely. Receiver wallets that perform gap-limit-bounded scanning (default in BDK and LWK) eventually stop scanning past `last_funded + gap_limit`. Future legitimate payments to high-index addresses are invisible to the wallet until a manual full descriptor rescan.

The harm is bounded (funds aren't lost, the descriptor still controls them), but the receive UX silently breaks for the targeted nym. A determined attacker can sustain the attack for as long as they care to spend on infrastructure.

## How LUD-22 defends against this

The LUD-22 path forces the sender to commit something on-chain before they can ask for an address. The commitment is a signed ownership proof of a Liquid UTXO worth at least `min_proof_value_sat` (currently 100). This commitment unlocks four cascading defenses:

**Idempotent mapping.** The `outpoint_addresses` table caches `(nym, outpoint) -> address_index` with a `UNIQUE` constraint. The same UTXO targeting the same nym always returns the same address. An attacker who repeats their request gets a cache hit; they cannot ratchet anything by repeating.

**Per-outpoint fan-out cap.** A single UTXO can be used to discover at most three different nyms per hour (`distinct_nyms_per_outpoint_limit`). To probe more nyms, the attacker must rotate UTXOs. Rotating a UTXO means spending it on-chain, which costs the spent value plus a real Liquid network fee, and takes confirmation time.

**Per-pubkey volume cap.** The script's signing key is rate-limited to 10 requests per hour on the Liquid path (`per_pubkey_limit`). Spreading across many keys means spreading across many UTXOs, which compounds with the on-chain cost.

**TTL recycling.** Unfulfilled `outpoint_addresses` rows are recycled after `pending_outpoint_ttl_secs` (3600). If the attacker doesn't pay, their address allocation eventually returns to the pool. The descriptor's `next_addr_idx` is bounded by the steady-state hostage size, not by attacker request count.

The cost of a sustained enumeration attack against bullnym via LUD-22 scales linearly with the on-chain Liquid UTXO supply the attacker controls. To probe 1000 nyms in an hour, the attacker needs at least 334 distinct UTXOs (each ≥ 100 sats), each of which represents an on-chain commitment that the attacker funded.

## How MRH "defends" against this

The MRH path has no commitment from the sender. The sender does an HTTP GET. The server allocates an address by atomically incrementing `users.next_addr_idx`, embeds it in a BOLT11 routing hint, and returns the bolt11.

The available defenses are restricted to those that don't require sender commitment:

- Per-source-bucket rate limits (currently 30/hour, proposed reduction to 10/hour).
- TTL+recycle on the address allocation, except this doesn't work cleanly because:
  - Boltz reverse-swap invoices live 12 hours, not 15 minutes (typical Lightning).
  - The MRH address remains a valid Liquid receive address indefinitely after bolt11 expiry. The sender holds the address from the routing hint and can pay it on-chain at any time. So bolt11 expiry is not a safe signal that the address can be recycled.

The result: MRH's rate-limit defense reduces to per-source-bucket throttling. The attacker's per-request cost is the cost of one HTTP GET. The defense's strength is bounded by what legitimate senders tolerate, not by what attackers tolerate.

## Why LUD-22's defense is strictly better at every defense property

Direct comparison:

| Property | LUD-22 | MRH |
|---|---|---|
| Cost per request to attacker | ≥ 100 sats committed on-chain plus spend cost of the UTXO | Zero (HTTP GET) |
| Cost per nym discovered | At minimum, one UTXO per three nyms per hour | One HTTP GET per nym |
| Idempotency on repeat request | Yes (cache hit on `(nym, outpoint)`) | No (every request advances `next_addr_idx`) |
| Recovery after attack subsides | Automatic via TTL recycling | None; damage is cumulative and persistent |
| Bound on per-resource damage | 3 nyms per UTXO per hour | Unbounded over time |

In every dimension that matters for resisting an enumeration attack, LUD-22 dominates.

## Attempting to disprove

Three counters need to be considered before committing to deprecate MRH.

**Sender-side privacy from the server.** Under MRH, the sender's interaction with the bullnym server is one request: "give me a bolt11 for this nym at this amount." The server learns nothing about the sender's wallet. Whatever the sender does next (decoding the bolt11, paying it on-chain) happens off-server.

Under LUD-22, the sender hands the server a UTXO outpoint and a signed ownership proof. The server learns that this pubkey controls this UTXO and is paying this nym. Across multiple LUD-22 requests by the same sender to different nyms, the server can graph the sender's UTXO usage.

This is a real privacy regression for the sender. It does not apply to MRH. The bullnym operator already holds the receiver's slip77 master key and sees every received payment, so the operator-trust threshold is already non-trivial. But this counter is the only real disproof of the "strictly better" defense thesis: LUD-22 is strictly better at defense properties, and MRH preserves a sender-side privacy property that LUD-22 destroys.

**Implementation cost on the sender.** MRH costs the sender nothing to implement: they decode a BOLT11 they were going to decode anyway. LUD-22 requires the sender's wallet to identify a usable UTXO, sign an ownership proof, and construct the LUD-22 callback URL. This is real work. A wallet that supports LNURL but not LUD-22 cannot use the Liquid-direct path.

This is a deployment concern, not a defense concern. It does affect the cost of deprecating MRH: wallets that haven't adopted LUD-22 lose the on-chain shortcut.

**Ecosystem compatibility.** MRH is part of the Boltz protocol. Any wallet using `boltz-rust` or `boltz-client` gets MRH automatically. LUD-22 is bullnym-specific and requires per-wallet adoption.

Same shape as the previous counter: a deployment cost, not a defense property.

## Where the disproof lands

Of the three counters, only the first (sender-side privacy from the server) is a real defense-property disproof. It does not undermine the claim that LUD-22 is strictly better at resisting enumeration attacks; it qualifies the claim to "LUD-22 is strictly better at defense properties; MRH preserves sender-server privacy in a way LUD-22 does not."

The other two counters are real but bear on the cost of deprecating MRH, not on whether MRH can be defended.

## Decision: deprecate MRH on the bullnym server

The recommendation is to stop setting `address` and `addressSignature` on Boltz reverse swaps created by bullnym. Concretely:

- `serve_lightning` no longer calls `allocate_address_index` at swap creation.
- The server creates Boltz reverse swaps without MRH metadata.
- `claimer.rs`, on receiving `transaction.mempool` for a real Lightning payment, allocates the address index then and performs the cooperative MuSig2 claim to that fresh address.
- `swap_records.address` becomes nullable and is populated only at claim time.

The descriptor's `next_addr_idx` advances exactly once per real incoming Lightning payment. Attacker callbacks that do not pay anything never advance the counter. The DoS surface on the Lightning callback is structurally eliminated, not bounded.

## Costs of the deprecation

The senders who currently rely on MRH (without supporting LUD-22) lose the on-chain shortcut. Their payments now route through the standard Boltz reverse swap and incur:

- The Boltz reverse-swap fee on the receiver side (~0.25% plus ~40 sats lockup and claim fees).
- The sender's own submarine swap fee on their side, if their wallet sends from Liquid (Aqua does).
- Four Liquid network transactions instead of one.

For a 100,000-sat payment, the additional cost is approximately 580 sats in Boltz fees plus the network fee differential.

The wallet population affected is small. Bull mobile uses LUD-22. Phoenix, Wallet of Satoshi, Zeus, and most Lightning-only wallets never used MRH. The affected set is essentially Aqua and any future Boltz-aware-but-not-LUD-22-aware wallet.

The recommended remediation for affected wallets is to adopt LUD-22 (`docs/lud-22-currency-negotiation.md`). The protocol is small and the on-chain shortcut is restored with stronger privacy and a cost-bounded defense profile.

## What this does not address

Deprecating MRH on the Lightning callback path does not address:

- Server resource consumption from callback floods. Every callback still creates a Boltz reverse swap and persists a `swap_records` row. Rate limits gate this; deprecating MRH does not change it.
- LUD-22 path attacks. LUD-22's existing defenses are unchanged.
- Metadata-endpoint enumeration. `/.well-known/lnurlp/{nym}` has its own per-IP and distinct-nyms caps; this work doesn't touch them.
- Server-side address derivation cost. Address derivation runs at claim time on real payments.

## Verification after deployment

After rolling out the deprecation:

- `next_addr_idx` should advance only on actually-funded Lightning swaps. Monitor the counter against `swap_records WHERE status IN ('LockupConfirmed', 'Claimed')` to confirm the invariant.
- Boltz reverse-swap creation requests from bullnym should no longer include `address` or `addressSignature`. Verify in Boltz API logs (operator side) or by capturing one outbound request.
- For an MRH-aware sender (Aqua) paying a bullnym recipient, observe that the BOLT11 returned has no MRH routing hint. The sender's wallet falls back to paying the BOLT11 over Lightning. Boltz processes the lockup and the server cooperatively claims to a fresh address.
- Verify gap-limit-bounded receiver wallets (LWK default) successfully receive payments after the deployment, with `next_addr_idx` growth matching real-payment volume.

## References

- `docs/lud-22-currency-negotiation.md` — the LUD-22 protocol specification.
- `src/lnurl.rs::serve_lightning` — current Lightning callback path with MRH.
- `src/lnurl.rs::serve_liquid` — current LUD-22 path.
- `src/rate_limit.rs` — rate-limit configuration and gates.
- `migrations/006_outpoint_addresses.sql` — LUD-22 idempotent-mapping schema.
- Boltz documentation on cooperative claim and `transaction.direct`: <https://docs.boltz.exchange/>
