//! UTXO ownership proof + commitment verification + Electrum backend.
//!
//! The Liquid LNURL-pay callback requires the payer to prove ownership of
//! a real, unspent UTXO worth at least `min_proof_value_sat`. This module
//! implements:
//!
//! - `verify_ownership_sig` — ECDSA over `sha256(tag || nym || outpoint)`
//! - `script_matches_pubkey` — P2WPKH match against the tx output scriptpubkey
//! - `verify_value_commitment` — Pedersen commitment reconstruction
//! - `ElectrumClient` — raw-tx fetch (cached) + unspent check (uncached)

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lwk_wollet::elements;
use lwk_wollet::elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use lwk_wollet::elements::hashes::{hash160, Hash as ElementsHash};
use lwk_wollet::elements::issuance::AssetId;
use lwk_wollet::elements::secp256k1_zkp::{self as zkp};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use crate::error::AppError;

// L-BTC asset id (display-reversed form, same as `lnurl.rs::LBTC_ASSET_ID`).
pub const LBTC_ASSET_ID_HEX: &str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

// --- Ownership signature ---

/// Build the digest `sha256(tag || nym || outpoint)`.
pub fn ownership_message_digest(tag: &[u8], nym: &str, outpoint: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(nym.as_bytes());
    h.update(outpoint.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Verify an ECDSA-DER signature over the ownership digest.
/// Returns the parsed pubkey on success.
pub fn verify_ownership_sig(
    tag: &[u8],
    nym: &str,
    outpoint: &str,
    pubkey_hex: &str,
    sig_der_hex: &str,
) -> Result<PublicKey, AppError> {
    let secp = Secp256k1::verification_only();

    let pubkey = PublicKey::from_str(pubkey_hex)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("pubkey parse: {e}")))?;

    let sig_bytes = hex::decode(sig_der_hex)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("sig hex: {e}")))?;
    let sig = Signature::from_der(&sig_bytes)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("sig der: {e}")))?;

    let digest = ownership_message_digest(tag, nym, outpoint);
    let msg = Message::from_digest(digest);

    secp.verify_ecdsa(&msg, &sig, &pubkey)
        .map_err(|_| AppError::ProofOfFundsInvalid("signature verification failed".into()))?;

    Ok(pubkey)
}

// --- Script match ---

/// Check that `script` is the P2WPKH output owned by `pubkey` (33-byte compressed).
pub fn script_matches_pubkey(script: &elements::Script, pubkey: &PublicKey) -> bool {
    let pk_bytes = pubkey.serialize();
    let hash = hash160::Hash::hash(&pk_bytes);
    let wpkh = elements::WPubkeyHash::from_raw_hash(hash);
    let expected = elements::Script::new_v0_wpkh(&wpkh);
    script == &expected
}

// --- Pedersen value commitment ---

/// Reconstruct the expected Pedersen commitment from the claimed
/// (value, value_bf, asset_bf) triple and compare to the on-chain commitment.
///
/// Blinding factors come in from the payer as hex strings. They're passed to
/// the elements crate in native byte-order (32 bytes each).
pub fn verify_value_commitment(
    asset_id: &AssetId,
    value: u64,
    value_bf_hex: &str,
    asset_bf_hex: &str,
    onchain: &zkp::PedersenCommitment,
) -> Result<bool, AppError> {
    let vbf_bytes = hex::decode(value_bf_hex)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("value_bf hex: {e}")))?;
    let abf_bytes = hex::decode(asset_bf_hex)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("asset_bf hex: {e}")))?;
    if vbf_bytes.len() != 32 || abf_bytes.len() != 32 {
        return Err(AppError::ProofOfFundsInvalid(
            "blinding factors must be 32 bytes".into(),
        ));
    }

    let vbf = ValueBlindingFactor::from_slice(&vbf_bytes)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("value_bf: {e}")))?;
    let abf = AssetBlindingFactor::from_slice(&abf_bytes)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("asset_bf: {e}")))?;

    let secp = zkp::Secp256k1::new();
    let expected = elements::confidential::Value::new_confidential_from_assetid(
        &secp, value, *asset_id, vbf, abf,
    );

    match expected {
        elements::confidential::Value::Confidential(expected_comm) => {
            Ok(expected_comm.serialize() == onchain.serialize())
        }
        _ => Err(AppError::ProofOfFundsInvalid(
            "commitment construction failed".into(),
        )),
    }
}

// --- Outpoint parsing ---

pub struct ParsedOutpoint {
    pub txid_hex: String,
    pub vout: u32,
}

impl ParsedOutpoint {
    pub fn parse(s: &str) -> Result<Self, AppError> {
        let (txid, vout) = s.split_once(':').ok_or_else(|| {
            AppError::ProofOfFundsInvalid("outpoint must be txid:vout".into())
        })?;
        if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::ProofOfFundsInvalid(
                "outpoint txid must be 64 hex chars".into(),
            ));
        }
        let vout: u32 = vout
            .parse()
            .map_err(|_| AppError::ProofOfFundsInvalid("outpoint vout must be u32".into()))?;
        Ok(Self {
            txid_hex: txid.to_string(),
            vout,
        })
    }
}

// --- Electrum backend ---

/// Minimal interface the LNURL handler needs from a blockchain backend.
#[async_trait::async_trait]
pub trait UtxoBackend: Send + Sync {
    /// Fetch the raw transaction bytes. Cache-backed — txs are immutable so
    /// long TTLs are safe.
    async fn get_raw_tx(&self, txid_hex: &str) -> Result<Vec<u8>, AppError>;

    /// Check whether `(txid:vout)` is currently unspent on chain.
    /// MUST NOT be cached — the caller depends on real-time freshness.
    async fn is_unspent(
        &self,
        script_pubkey: &elements::Script,
        txid_hex: &str,
        vout: u32,
    ) -> Result<bool, AppError>;
}

/// Cached raw-tx wrapper around a blocking electrum-client.
///
/// Resilient to two failure modes seen in production:
/// 1. The underlying TCP/TLS connection goes stale after ~10s idle and every
///    subsequent call returns a JSON-parse / EOF error. We detect any
///    transport-class error and reconnect before the next call.
/// 2. A single Electrum server may be down. Operators can configure a list
///    of URLs; we round-robin through them on connection failure.
pub struct ElectrumClient {
    urls: Vec<String>,
    state: Arc<AsyncMutex<ConnState>>,
    cache: Arc<AsyncMutex<TxCache>>,
    cache_ttl: Duration,
    cache_max: usize,
}

struct ConnState {
    /// `None` after a transport error or a failed reconnect attempt; the next
    /// caller will lazily reconnect.
    client: Option<electrum_client::Client>,
    /// Index into `urls` for the next reconnect attempt.
    url_idx: usize,
}

struct TxCache {
    entries: HashMap<String, (Instant, Vec<u8>)>,
}

impl TxCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, key: &str, ttl: Duration) -> Option<Vec<u8>> {
        if let Some((inserted, bytes)) = self.entries.get(key) {
            if inserted.elapsed() <= ttl {
                return Some(bytes.clone());
            }
        }
        self.entries.remove(key);
        None
    }

    fn insert(&mut self, key: String, bytes: Vec<u8>, max: usize) {
        if self.entries.len() >= max {
            // Evict oldest. O(n) but n is bounded (e.g. 10_000).
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (t, _))| *t)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, (Instant::now(), bytes));
    }
}

impl ElectrumClient {
    /// Construct a multi-URL Electrum client. Tries each URL in turn at
    /// startup; if one connects, uses it. If none connect, still returns
    /// `Ok(...)` so the service can come up — reconnect happens lazily on
    /// the first call. The only `Err` case is an empty URL list.
    pub fn connect(
        urls: Vec<String>,
        cache_ttl_secs: u64,
        cache_max: usize,
    ) -> Result<Self, AppError> {
        if urls.is_empty() {
            return Err(AppError::ElectrumError("liquid_urls is empty".into()));
        }

        let mut chosen: Option<(electrum_client::Client, usize)> = None;
        for (i, url) in urls.iter().enumerate() {
            match electrum_client::Client::new(url) {
                Ok(c) => {
                    tracing::info!("electrum eager-connected: {}", url);
                    chosen = Some((c, i));
                    break;
                }
                Err(e) => {
                    tracing::warn!("electrum eager-connect failed for {}: {}", url, e);
                }
            }
        }
        let (client, url_idx) = match chosen {
            Some(p) => (Some(p.0), p.1),
            None => {
                tracing::warn!(
                    "all {} electrum servers unreachable at startup; will retry lazily on first PF request",
                    urls.len()
                );
                (None, 0)
            }
        };

        Ok(Self {
            urls,
            state: Arc::new(AsyncMutex::new(ConnState { client, url_idx })),
            cache: Arc::new(AsyncMutex::new(TxCache::new())),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache_max,
        })
    }
}

/// Run an op against the current Electrum connection, reconnecting on
/// transport-class errors and rotating through `urls` on failure.
///
/// Holds the connection-state lock for the duration of the retry sequence,
/// so concurrent callers serialize through it (matches prior behavior — the
/// underlying sync client was already serialized by a single mutex).
///
/// `Protocol` errors are returned without retry: those are server-side
/// responses (e.g. "no such tx") that don't indicate a broken connection.
fn run_op_blocking<T, F>(
    state: &AsyncMutex<ConnState>,
    urls: &[String],
    op_name: &str,
    op: F,
) -> Result<T, electrum_client::Error>
where
    F: Fn(&electrum_client::Client) -> Result<T, electrum_client::Error>,
{
    let mut guard = state.blocking_lock();
    // urls.len() attempts gives every server one shot; minimum 2 so a
    // single-URL config still gets one reconnect retry on a stale TCP.
    let max_attempts = urls.len().max(2);
    let mut last_err: Option<electrum_client::Error> = None;

    for attempt in 0..max_attempts {
        if guard.client.is_none() {
            // Try to connect, walking through the URL ring once.
            for _ in 0..urls.len() {
                let url = urls[guard.url_idx].clone();
                match electrum_client::Client::new(&url) {
                    Ok(c) => {
                        tracing::info!("electrum reconnected: {}", url);
                        guard.client = Some(c);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("electrum reconnect to {} failed: {}", url, e);
                        last_err = Some(e);
                        guard.url_idx = (guard.url_idx + 1) % urls.len();
                    }
                }
            }
            if guard.client.is_none() {
                return Err(last_err.unwrap_or_else(|| {
                    electrum_client::Error::Message("no electrum urls reachable".into())
                }));
            }
        }

        let client = guard.client.as_ref().expect("client present after reconnect");
        match op(client) {
            Ok(v) => return Ok(v),
            Err(electrum_client::Error::Protocol(p)) => {
                // Server-side error (e.g. "no such mempool/blockchain tx").
                // The connection is still healthy — keep it.
                return Err(electrum_client::Error::Protocol(p));
            }
            Err(e) => {
                tracing::warn!(
                    "electrum {} attempt {}: transport error on {}: {}",
                    op_name,
                    attempt + 1,
                    urls[guard.url_idx],
                    e
                );
                guard.client = None;
                guard.url_idx = (guard.url_idx + 1) % urls.len();
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        electrum_client::Error::Message("electrum retries exhausted".into())
    }))
}

#[async_trait::async_trait]
impl UtxoBackend for ElectrumClient {
    async fn get_raw_tx(&self, txid_hex: &str) -> Result<Vec<u8>, AppError> {
        {
            let mut cache = self.cache.lock().await;
            if let Some(bytes) = cache.get(txid_hex, self.cache_ttl) {
                return Ok(bytes);
            }
        }

        let txid = electrum_client::bitcoin::Txid::from_str(txid_hex)
            .map_err(|e| AppError::ProofOfFundsInvalid(format!("txid parse: {e}")))?;

        let state = self.state.clone();
        let urls = self.urls.clone();
        let bytes = tokio::task::spawn_blocking(move || {
            run_op_blocking(&state, &urls, "transaction_get_raw", |client| {
                use electrum_client::ElectrumApi;
                client.transaction_get_raw(&txid)
            })
        })
        .await
        .map_err(|e| AppError::ElectrumError(format!("join: {e}")))?
        .map_err(|e| match e {
            electrum_client::Error::Protocol(_) => AppError::UtxoNotFound,
            other => AppError::ElectrumError(format!("transaction_get_raw: {other}")),
        })?;

        {
            let mut cache = self.cache.lock().await;
            cache.insert(txid_hex.to_string(), bytes.clone(), self.cache_max);
        }
        Ok(bytes)
    }

    async fn is_unspent(
        &self,
        script_pubkey: &elements::Script,
        txid_hex: &str,
        vout: u32,
    ) -> Result<bool, AppError> {
        // The high-level `script_list_unspent` in electrum-client is hard-coded
        // to deserialize `value` as u64 (Bitcoin shape). Liquid's electrs
        // returns a confidential value commitment (a sequence) for the same
        // field, which fails JSON deserialization with
        //   "invalid type: sequence, expected u64".
        // Use raw_call and iterate the JSON manually, ignoring `value` — we
        // only care whether the (txid, vout) pair is in the unspent list.
        let scripthash_hex = electrum_scripthash_hex(script_pubkey);
        let txid = txid_hex.to_string();

        let state = self.state.clone();
        let urls = self.urls.clone();
        let result = tokio::task::spawn_blocking(move || {
            run_op_blocking(&state, &urls, "scripthash.listunspent", |client| {
                use electrum_client::ElectrumApi;
                client.raw_call(
                    "blockchain.scripthash.listunspent",
                    vec![electrum_client::Param::String(scripthash_hex.clone())],
                )
            })
        })
        .await
        .map_err(|e| AppError::ElectrumError(format!("join: {e}")))?
        .map_err(|e| AppError::ElectrumError(format!("scripthash.listunspent: {e}")))?;

        let utxos = result.as_array().ok_or_else(|| {
            AppError::ElectrumError(
                "scripthash.listunspent: expected JSON array response".into(),
            )
        })?;

        Ok(utxos.iter().any(|u| {
            u.get("tx_hash").and_then(|v| v.as_str()) == Some(txid.as_str())
                && u.get("tx_pos").and_then(|v| v.as_u64()) == Some(vout as u64)
        }))
    }
}

/// Electrum scripthash convention: sha256 of the scriptpubkey wire bytes,
/// reversed to little-endian display order, and hex-encoded.
fn electrum_scripthash_hex(script: &elements::Script) -> String {
    let mut digest: [u8; 32] = Sha256::digest(script.as_bytes()).into();
    digest.reverse();
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    fn test_keypair() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    fn sign(tag: &[u8], nym: &str, outpoint: &str, sk: &SecretKey) -> String {
        let secp = Secp256k1::signing_only();
        let digest = ownership_message_digest(tag, nym, outpoint);
        let msg = Message::from_digest(digest);
        hex::encode(secp.sign_ecdsa(&msg, sk).serialize_der())
    }

    #[test]
    fn digest_is_deterministic() {
        let a = ownership_message_digest(b"tag", "alice", "ab:0");
        let b = ownership_message_digest(b"tag", "alice", "ab:0");
        assert_eq!(a, b);
    }

    #[test]
    fn digest_differs_per_nym() {
        let a = ownership_message_digest(b"tag", "alice", "ab:0");
        let b = ownership_message_digest(b"tag", "bob", "ab:0");
        assert_ne!(a, b);
    }

    #[test]
    fn digest_differs_per_outpoint() {
        let a = ownership_message_digest(b"tag", "alice", "ab:0");
        let b = ownership_message_digest(b"tag", "alice", "ab:1");
        assert_ne!(a, b);
    }

    #[test]
    fn valid_sig_verifies() {
        let (sk, pk) = test_keypair();
        let sig = sign(b"bullpay-lnurlp-v1", "alice", "ab:0", &sk);
        let got = verify_ownership_sig(
            b"bullpay-lnurlp-v1",
            "alice",
            "ab:0",
            &hex::encode(pk.serialize()),
            &sig,
        );
        assert!(got.is_ok());
    }

    #[test]
    fn sig_for_different_nym_fails() {
        let (sk, pk) = test_keypair();
        let sig = sign(b"tag", "alice", "ab:0", &sk);
        let got = verify_ownership_sig(
            b"tag",
            "bob",
            "ab:0",
            &hex::encode(pk.serialize()),
            &sig,
        );
        assert!(matches!(got, Err(AppError::ProofOfFundsInvalid(_))));
    }

    #[test]
    fn sig_for_different_outpoint_fails() {
        let (sk, pk) = test_keypair();
        let sig = sign(b"tag", "alice", "ab:0", &sk);
        let got = verify_ownership_sig(
            b"tag",
            "alice",
            "ab:1",
            &hex::encode(pk.serialize()),
            &sig,
        );
        assert!(matches!(got, Err(AppError::ProofOfFundsInvalid(_))));
    }

    #[test]
    fn sig_malformed_fails() {
        let (_, pk) = test_keypair();
        let got = verify_ownership_sig(
            b"tag",
            "alice",
            "ab:0",
            &hex::encode(pk.serialize()),
            "notahex",
        );
        assert!(matches!(got, Err(AppError::ProofOfFundsInvalid(_))));
    }

    #[test]
    fn script_match_p2wpkh() {
        let (_, pk) = test_keypair();
        let hash = hash160::Hash::hash(&pk.serialize());
        let wpkh = elements::WPubkeyHash::from_raw_hash(hash);
        let script = elements::Script::new_v0_wpkh(&wpkh);
        assert!(script_matches_pubkey(&script, &pk));
    }

    #[test]
    fn script_mismatch_different_pubkey() {
        let (_, pk_a) = test_keypair();
        let sk_b = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let pk_b = PublicKey::from_secret_key(&Secp256k1::new(), &sk_b);
        let hash = hash160::Hash::hash(&pk_a.serialize());
        let wpkh = elements::WPubkeyHash::from_raw_hash(hash);
        let script = elements::Script::new_v0_wpkh(&wpkh);
        assert!(!script_matches_pubkey(&script, &pk_b));
    }

    #[test]
    fn parse_outpoint_ok() {
        let o = ParsedOutpoint::parse(
            "0000000000000000000000000000000000000000000000000000000000000001:42",
        )
        .unwrap();
        assert_eq!(o.vout, 42);
    }

    #[test]
    fn parse_outpoint_missing_colon() {
        assert!(ParsedOutpoint::parse("abcdef").is_err());
    }

    #[test]
    fn parse_outpoint_bad_txid_len() {
        assert!(ParsedOutpoint::parse("ab:0").is_err());
    }
}
