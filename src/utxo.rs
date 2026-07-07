//! UTXO ownership proof + Electrum backend.
//!
//! The Liquid LNURL-pay callback requires the payer to prove ownership of
//! a real, unspent UTXO. This module implements:
//!
//! - `verify_ownership_sig` — ECDSA over `sha256(tag || nym || outpoint)`
//! - `script_matches_pubkey` — P2WPKH match against the tx output scriptpubkey
//! - `ElectrumClient` — raw-tx fetch (cached) + unspent check (uncached)

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lwk_wollet::elements;
use lwk_wollet::elements::hashes::{hash160, Hash as ElementsHash};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use crate::error::AppError;

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

// --- Confidential value/asset proof ---

/// Verify a payer-supplied confidential proof UTXO holds at least
/// `min_value_sat` of L-BTC, using **Approach B** (LUD-22): the payer supplies
/// the cleartext `value` plus the elements value/asset blinding factors, and we
/// *rebind* those against the on-chain commitments. No unblinding, no ECDH — the
/// server never needs a blinding key (which the shipped mobile client no longer
/// sends).
///
/// Two rebinds close the anti-enumeration floor (DG-7 / ISS-S-04):
///  1. Rebuild the blinded asset generator from *our own* L-BTC asset id and the
///     payer's `asset_bf`, and require it to equal `txout.asset`. This forces the
///     asset to be L-BTC *by construction* — a wrong asset, a token-masquerade
///     output, or an explicit (non-confidential) output all fail to bind.
///  2. Rebuild the Pedersen value commitment from the cleartext `value` and both
///     blinding factors, and require it to equal `txout.value`. A forged value
///     cannot bind to the committed point.
/// Then enforce the value floor.
///
/// Byte order: `value_bf`/`asset_bf` arrive as elements *display-order*
/// (byte-reversed) hex — exactly what `TxOutSecrets::to_string()` emits on the
/// client. `FromStr` reverses on ingest, so it round-trips. Do NOT swap to
/// raw-inner-byte hex or every rebind fails.
///
/// Verification-only crypto: no secret of ours is involved.
pub fn assert_proof_utxo_value(
    txout: &elements::TxOut,
    value: u64,
    value_bf_hex: &str,
    asset_bf_hex: &str,
    expected_asset_hex: &str,
    min_value_sat: u64,
) -> Result<u64, AppError> {
    use elements::confidential::{Asset, AssetBlindingFactor, Value, ValueBlindingFactor};

    let secp = elements::secp256k1_zkp::Secp256k1::new();

    let expected_asset = elements::AssetId::from_str(expected_asset_hex)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("expected asset id parse: {e}")))?;
    let asset_bf = AssetBlindingFactor::from_str(asset_bf_hex)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("asset_bf parse: {e}")))?;
    let value_bf = ValueBlindingFactor::from_str(value_bf_hex)
        .map_err(|e| AppError::ProofOfFundsInvalid(format!("value_bf parse: {e}")))?;

    // (1) Asset rebind — forces L-BTC by construction.
    let asset_commitment = Asset::new_confidential(&secp, expected_asset, asset_bf);
    if txout.asset != asset_commitment {
        return Err(AppError::ProofOfFundsInvalid(
            "proof UTXO asset commitment does not bind to L-BTC under the supplied asset_bf".into(),
        ));
    }

    // (2) Value rebind — a forged value cannot bind.
    let value_commitment =
        Value::new_confidential_from_assetid(&secp, value, expected_asset, value_bf, asset_bf);
    if txout.value != value_commitment {
        return Err(AppError::ProofOfFundsInvalid(
            "proof UTXO value commitment does not bind to the supplied value".into(),
        ));
    }

    // (3) Anti-enumeration floor.
    if value < min_value_sat {
        return Err(AppError::ProofOfFundsInvalid(format!(
            "proof UTXO value {value} sat is below the {min_value_sat} sat minimum"
        )));
    }

    Ok(value)
}

// --- Outpoint parsing ---

pub struct ParsedOutpoint {
    pub txid_hex: String,
    pub vout: u32,
}

impl ParsedOutpoint {
    pub fn parse(s: &str) -> Result<Self, AppError> {
        let (txid, vout) = s
            .split_once(':')
            .ok_or_else(|| AppError::ProofOfFundsInvalid("outpoint must be txid:vout".into()))?;
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

    /// Check whether the given script has any history (mempool + confirmed)
    /// on the Liquid network. Used by the chain watcher to detect payments
    /// landing at a nym's next-unused address.
    async fn has_history(&self, script_pubkey: &elements::Script) -> Result<bool, AppError>;

    /// Return txids touching this script (mempool + confirmed), newest/oldest
    /// ordering is backend-defined. Callers must use idempotency keys when
    /// acting on the returned txs.
    async fn history_txids(
        &self,
        script_pubkey: &elements::Script,
    ) -> Result<Vec<String>, AppError>;

    /// Find the transaction that spends `(txid:vout)` for a known Liquid
    /// script. Used by claim recovery when a rebroadcast says already-spent
    /// but our expected claim txid is absent.
    async fn find_spending_txid(
        &self,
        script_pubkey: &elements::Script,
        txid_hex: &str,
        vout: u32,
    ) -> Result<Option<String>, AppError>;

    /// Does a transaction with this txid exist on the Liquid network
    /// (in mempool or confirmed)?
    ///
    /// Used by the claim path's post-broadcast probe: when
    /// `try_broadcast_tx` returns an error that isn't "already in utxo
    /// set" (e.g. a timeout or `txn-already-known` worded slightly
    /// differently), we probe Electrum to see if our tx is actually
    /// on the network. If it is, the broadcast was effectively
    /// successful and we mark `Claimed` instead of recording a
    /// failure.
    ///
    /// Default impl: try `get_raw_tx`, treat `UtxoNotFound` as "doesn't
    /// exist". Other errors propagate so a transient Electrum hiccup
    /// doesn't cause us to incorrectly conclude the tx isn't there.
    async fn tx_exists(&self, txid_hex: &str) -> Result<bool, AppError> {
        match self.get_raw_tx(txid_hex).await {
            Ok(_) => Ok(true),
            Err(AppError::UtxoNotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }
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
            // Bounded socket timeout: a stalled-but-connected Electrum peer must
            // not hang the op indefinitely behind the ConnState mutex (which
            // would stall LUD-22 proof callbacks and the payment watcher).
            // URL failover only fires on errors, so without this a hang never
            // fails over.
            match electrum_client::Client::from_config(
                url,
                electrum_client::Config::builder().timeout(Some(10)).build(),
            ) {
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
                match electrum_client::Client::from_config(
                    &url,
                    electrum_client::Config::builder().timeout(Some(10)).build(),
                ) {
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

        let client = guard
            .client
            .as_ref()
            .expect("client present after reconnect");
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

    Err(last_err
        .unwrap_or_else(|| electrum_client::Error::Message("electrum retries exhausted".into())))
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
            AppError::ElectrumError("scripthash.listunspent: expected JSON array response".into())
        })?;

        Ok(utxos.iter().any(|u| {
            u.get("tx_hash").and_then(|v| v.as_str()) == Some(txid.as_str())
                && u.get("tx_pos").and_then(|v| v.as_u64()) == Some(vout as u64)
        }))
    }

    async fn has_history(&self, script_pubkey: &elements::Script) -> Result<bool, AppError> {
        // Use raw_call (parallel to is_unspent) so we avoid any Liquid-specific
        // deserialization quirks in the high-level electrum-client wrapper.
        // The history response shape is `[{tx_hash, height, [fee]}, ...]`; we
        // only care whether the array is non-empty.
        let scripthash_hex = electrum_scripthash_hex(script_pubkey);

        let state = self.state.clone();
        let urls = self.urls.clone();
        let result = tokio::task::spawn_blocking(move || {
            run_op_blocking(&state, &urls, "scripthash.get_history", |client| {
                use electrum_client::ElectrumApi;
                client.raw_call(
                    "blockchain.scripthash.get_history",
                    vec![electrum_client::Param::String(scripthash_hex.clone())],
                )
            })
        })
        .await
        .map_err(|e| AppError::ElectrumError(format!("join: {e}")))?
        .map_err(|e| AppError::ElectrumError(format!("scripthash.get_history: {e}")))?;

        let history = result.as_array().ok_or_else(|| {
            AppError::ElectrumError("scripthash.get_history: expected JSON array response".into())
        })?;

        Ok(!history.is_empty())
    }

    async fn history_txids(
        &self,
        script_pubkey: &elements::Script,
    ) -> Result<Vec<String>, AppError> {
        let scripthash_hex = electrum_scripthash_hex(script_pubkey);

        let state = self.state.clone();
        let urls = self.urls.clone();
        let result = tokio::task::spawn_blocking(move || {
            run_op_blocking(&state, &urls, "scripthash.get_history", |client| {
                use electrum_client::ElectrumApi;
                client.raw_call(
                    "blockchain.scripthash.get_history",
                    vec![electrum_client::Param::String(scripthash_hex.clone())],
                )
            })
        })
        .await
        .map_err(|e| AppError::ElectrumError(format!("join: {e}")))?
        .map_err(|e| AppError::ElectrumError(format!("scripthash.get_history: {e}")))?;

        history_txids(&result)
    }

    async fn find_spending_txid(
        &self,
        script_pubkey: &elements::Script,
        txid_hex: &str,
        vout: u32,
    ) -> Result<Option<String>, AppError> {
        let scripthash_hex = electrum_scripthash_hex(script_pubkey);
        let target_txid = txid_hex.to_string();

        let state = self.state.clone();
        let urls = self.urls.clone();
        let result = tokio::task::spawn_blocking(move || {
            run_op_blocking(&state, &urls, "scripthash.get_history", |client| {
                use electrum_client::ElectrumApi;
                client.raw_call(
                    "blockchain.scripthash.get_history",
                    vec![electrum_client::Param::String(scripthash_hex.clone())],
                )
            })
        })
        .await
        .map_err(|e| AppError::ElectrumError(format!("join: {e}")))?
        .map_err(|e| AppError::ElectrumError(format!("scripthash.get_history: {e}")))?;

        for history_txid in history_txids(&result)? {
            let raw = self.get_raw_tx(&history_txid).await?;
            let tx: elements::Transaction = elements::encode::deserialize(&raw)
                .map_err(|e| AppError::ElectrumError(format!("liquid tx decode: {e}")))?;
            if transaction_spends_outpoint(&tx, &target_txid, vout) {
                return Ok(Some(tx.txid().to_string()));
            }
        }

        Ok(None)
    }
}

fn history_txids(history: &serde_json::Value) -> Result<Vec<String>, AppError> {
    let history = history.as_array().ok_or_else(|| {
        AppError::ElectrumError("scripthash.get_history: expected JSON array response".into())
    })?;

    history
        .iter()
        .map(|entry| {
            entry
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    AppError::ElectrumError("scripthash.get_history: entry missing tx_hash".into())
                })
        })
        .collect()
}

fn transaction_spends_outpoint(tx: &elements::Transaction, txid_hex: &str, vout: u32) -> bool {
    tx.input.iter().any(|input| {
        input.previous_output.txid.to_string() == txid_hex && input.previous_output.vout == vout
    })
}

/// Electrum scripthash convention: sha256 of the scriptpubkey wire bytes,
/// reversed to little-endian display order, and hex-encoded.
fn electrum_scripthash_hex(script: &elements::Script) -> String {
    let mut digest: [u8; 32] = Sha256::digest(script.as_bytes()).into();
    digest.reverse();
    hex::encode(digest)
}

#[cfg(test)]
mod tests;
