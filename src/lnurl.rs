use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use lwk_wollet::elements;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::utxo::{script_matches_pubkey, verify_ownership_sig, ParsedOutpoint};
use crate::AppState;

// --- Metadata response (LUD-06 + extensions) ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlPayMetadata {
    pub callback: String,
    pub max_sendable: u64,
    pub min_sendable: u64,
    pub metadata: String,
    pub tag: String,
    pub comment_allowed: u16,
    pub currencies: Vec<Currency>,
}

#[derive(Serialize)]
pub struct Currency {
    pub code: String,
    pub name: String,
    pub network: String,
    pub symbol: String,
}

// --- Callback params ---

#[derive(Deserialize)]
pub struct CallbackParams {
    pub amount: u64,
    pub comment: Option<String>,
    pub network: Option<String>,

    // Proof-of-funds fields (required for `network=liquid` unless caller is
    // on the IP whitelist).
    pub outpoint: Option<String>,
    pub pubkey: Option<String>,
    pub sig: Option<String>,
    // Forward-compat: mobile clients still send these, but the server no
    // longer uses them. Kept in the deserialization shape so older clients
    // don't fail with "unknown field" if they were ever to be rejected.
    #[allow(dead_code)]
    pub value: Option<u64>,
    #[allow(dead_code)]
    pub value_bf: Option<String>,
    #[allow(dead_code)]
    pub asset_bf: Option<String>,
}

struct ProofFields {
    outpoint: String,
    pubkey: String,
    sig: String,
}

impl CallbackParams {
    fn take_proof(&self) -> Option<ProofFields> {
        Some(ProofFields {
            outpoint: self.outpoint.clone()?,
            pubkey: self.pubkey.clone()?,
            sig: self.sig.clone()?,
        })
    }
}

// --- Callback response variants ---

#[derive(Serialize)]
pub struct LightningResponse {
    pub pr: String,
    pub routes: Vec<()>,
    pub disposable: bool,
    #[serde(rename = "successAction")]
    pub success_action: SuccessAction,
}

#[derive(Serialize)]
pub struct SuccessAction {
    pub tag: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct LiquidResponse {
    pub onchain: OnchainPayment,
    pub disposable: bool,
}

#[derive(Serialize)]
pub struct OnchainPayment {
    pub network: String,
    pub address: String,
    pub amount_sat: u64,
    pub bip21: String,
}

// --- Metadata builder ---

fn build_metadata(nym: &str, domain: &str) -> String {
    let identifier = format!("{nym}@{domain}");
    let plain = format!("Sats for {nym}");
    serde_json::to_string(&vec![
        vec!["text/identifier", &identifier],
        vec!["text/plain", &plain],
    ])
    .expect("metadata serialization cannot fail")
}

const LBTC_ASSET_ID: &str = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

// --- Helpers ---

/// Resolve caller IP and apply the per-IP metadata rate-limit + (when a nym
/// is being queried) the distinct-nyms-per-IP cap. Whitelisted callers
/// bypass. Shared by `metadata` and `nostr::nostr_json`.
pub(crate) async fn gate_metadata_per_ip(
    state: &AppState,
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    nym: Option<&str>,
) -> Result<(), AppError> {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let ip = ip_whitelist::resolve_caller_ip(
        peer.map(|p| p.ip()),
        xff,
        state.config.rate_limit.trust_forwarded_for,
    );
    let Some(ip) = ip else { return Ok(()) };
    if state.ip_whitelist.contains(ip) {
        return Ok(());
    }
    state.rate_limiter.check_metadata_per_ip(ip).await?;
    if let Some(n) = nym {
        state
            .rate_limiter
            .check_metadata_distinct_nyms_per_ip(ip, n)
            .await?;
    }
    Ok(())
}

// --- Handlers ---

pub async fn metadata(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<LnurlPayMetadata>, AppError> {
    // P2: gate before any DB work.
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    gate_metadata_per_ip(&state, peer, &headers, Some(&nym)).await?;

    let user = db::get_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;

    if !user.is_active {
        return Err(AppError::NymNotFound(nym));
    }

    let callback = format!("https://{}/lnurlp/callback/{}", state.config.domain, nym);

    Ok(Json(LnurlPayMetadata {
        callback,
        max_sendable: state.config.limits.max_sendable_msat,
        min_sendable: state.config.limits.min_sendable_msat,
        metadata: build_metadata(&nym, &state.config.domain),
        tag: "payRequest".to_string(),
        comment_allowed: 144,
        currencies: vec![
            Currency {
                code: "BTC".to_string(),
                name: "Bitcoin".to_string(),
                network: "bitcoin".to_string(),
                symbol: "BTC".to_string(),
            },
            Currency {
                code: "BTC".to_string(),
                name: "Liquid Bitcoin".to_string(),
                network: "liquid".to_string(),
                symbol: "L-BTC".to_string(),
            },
        ],
    }))
}

// --- Soft-fallback: Liquid rate-limit → Lightning (PR C) ---

/// Internal outcome of attempting the Liquid path. Distinguishes
/// fallback-eligible rate-limit failures from hard errors that should
/// propagate to the client unchanged.
enum LiquidOutcome {
    /// One of the Liquid-specific rate-limit gates fired (per-pubkey,
    /// distinct-nyms-per-ip, distinct-nyms-per-outpoint, pending-cap,
    /// electrum-bucket). Caller may transparently fall back to Lightning.
    SoftRateLimited,
    /// Any other error: bad proof, DB failure, descriptor error, etc.
    /// Propagate to the client as-is.
    Hard(AppError),
}

impl From<AppError> for LiquidOutcome {
    fn from(e: AppError) -> Self {
        LiquidOutcome::Hard(e)
    }
}

impl From<sqlx::Error> for LiquidOutcome {
    fn from(e: sqlx::Error) -> Self {
        LiquidOutcome::Hard(AppError::from(e))
    }
}

/// Map a rate-limit gate result so `RateLimited` /
/// `TooManyPendingReservations` become the soft-fallback signal; every
/// other error stays Hard.
fn rl_gate<T>(result: Result<T, AppError>) -> Result<T, LiquidOutcome> {
    match result {
        Ok(v) => Ok(v),
        Err(AppError::RateLimited) | Err(AppError::TooManyPendingReservations) => {
            Err(LiquidOutcome::SoftRateLimited)
        }
        Err(other) => Err(LiquidOutcome::Hard(other)),
    }
}

/// Liquid LUD-22 path. On rate-limit, returns `SoftRateLimited` so the
/// caller can transparently route to Lightning (the default rail).
async fn serve_liquid(
    state: &AppState,
    nym: &str,
    user: &db::User,
    amount_sat: u64,
    params: &CallbackParams,
    caller_ip: Option<std::net::IpAddr>,
    is_whitelisted: bool,
) -> Result<axum::response::Response, LiquidOutcome> {
    if !is_whitelisted {
        let proof = params
            .take_proof()
            .ok_or(AppError::ProofOfFundsRequired(state.config.proof.min_proof_value_sat))?;

        // Sig verify (Hard — proof error if fails).
        let pubkey = verify_ownership_sig(
            state.config.proof.message_tag.as_bytes(),
            nym,
            &proof.outpoint,
            &proof.pubkey,
            &proof.sig,
        )?;

        // Per-pubkey limit (Soft).
        rl_gate(state.rate_limiter.check_per_pubkey(&proof.pubkey).await)?;

        // Idempotent cache lookup. Cache hits skip all subsequent gates.
        if db::get_outpoint_address(&state.db, nym, &proof.outpoint).await?.is_none() {
            // Distinct-nym fan-out limits (Soft on rate-limit).
            if let Some(ip) = caller_ip {
                rl_gate(state.rate_limiter.check_distinct_nyms_per_ip(ip, nym).await)?;
            }
            rl_gate(
                state.rate_limiter
                    .check_distinct_nyms_per_outpoint(&proof.outpoint, nym)
                    .await,
            )?;

            // Per-nym pending reservation cap (Soft).
            rl_gate(state.rate_limiter.check_pending_reservations(nym).await)?;

            let parsed = ParsedOutpoint::parse(&proof.outpoint)?;

            let backend = state
                .utxo_backend
                .as_ref()
                .ok_or_else(|| AppError::ElectrumError("no blockchain backend configured".into()))?;

            // Electrum bucket (Soft — backend saturation is a rate-limit signal).
            rl_gate(state.rate_limiter.check_electrum().await)?;

            let raw_tx = backend.get_raw_tx(&parsed.txid_hex).await?;
            let tx: elements::Transaction = elements::encode::deserialize(&raw_tx)
                .map_err(|e| AppError::ElectrumError(format!("tx decode: {e}")))?;

            let txout = tx
                .output
                .get(parsed.vout as usize)
                .ok_or(AppError::UtxoNotFound)?;

            if !script_matches_pubkey(&txout.script_pubkey, &pubkey) {
                return Err(AppError::PubkeyUtxoMismatch.into());
            }

            let unspent = backend
                .is_unspent(&txout.script_pubkey, &parsed.txid_hex, parsed.vout)
                .await?;
            if !unspent {
                return Err(AppError::UtxoSpent.into());
            }

            db::allocate_outpoint_address(&state.db, nym, &proof.outpoint, &proof.pubkey)
                .await?;
        }
    }

    // Last-unused address.
    let addr_index_u32 = u32::try_from(user.next_addr_idx)
        .map_err(|_| AppError::DbError("address index overflow".to_string()))?;
    let address = descriptor::derive_address(&user.ct_descriptor, addr_index_u32)?;

    let bip21 = format!(
        "liquidnetwork:{address}?amount={}&assetid={LBTC_ASSET_ID}",
        format_btc_amount(amount_sat),
    );
    let resp = LiquidResponse {
        onchain: OnchainPayment {
            network: "liquid".to_string(),
            address,
            amount_sat,
            bip21,
        },
        disposable: false,
    };
    db::touch_user_callback(&state.db, nym).await;
    Ok(Json(resp).into_response())
}

/// Lightning path. Default rail; also the destination for Liquid soft
/// fallbacks. Per-source rate-limited (loose; Boltz-quota guard).
async fn serve_lightning(
    state: &AppState,
    nym: &str,
    user: &db::User,
    amount_sat: u64,
    caller_ip: Option<std::net::IpAddr>,
    is_whitelisted: bool,
) -> Result<axum::response::Response, AppError> {
    if !is_whitelisted {
        if let Some(ip) = caller_ip {
            state.rate_limiter.check_lightning_per_source(ip).await?;
        }
    }

    let addr_index = db::allocate_address_index(&state.db, nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.to_string()))?;

    let addr_index_u32 = u32::try_from(addr_index)
        .map_err(|_| AppError::DbError("address index overflow".to_string()))?;

    let address = descriptor::derive_address(&user.ct_descriptor, addr_index_u32)?;

    let swap_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("swap key allocation failed: {e}")))?;

    let metadata_str = build_metadata(nym, &state.config.domain);
    let description_hash_hex = hex::encode(Sha256::digest(metadata_str.as_bytes()));

    let result = state
        .boltz
        .create_reverse_swap(swap_key_index, amount_sat, &address, &description_hash_hex)
        .await?;

    let preimage_hex = hex::encode(&result.preimage);
    let claim_key_hex = hex::encode(result.claim_keypair.secret_bytes());
    let boltz_response_json = serde_json::to_string(&result.boltz_response)
        .map_err(|e| AppError::BoltzError(format!("failed to serialize boltz response: {e}")))?;

    db::record_swap(
        &state.db,
        &db::NewSwapRecord {
            nym,
            boltz_swap_id: &result.swap_id,
            address: &address,
            address_index: addr_index,
            amount_sat,
            invoice: &result.invoice,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            boltz_response_json: &boltz_response_json,
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("failed to record swap {}: {e}", result.swap_id)))?;

    let resp = LightningResponse {
        pr: result.invoice,
        routes: vec![],
        disposable: false,
        success_action: SuccessAction {
            tag: "message".to_string(),
            message: format!("Payment received to {nym}@{}", state.config.domain),
        },
    };
    db::touch_user_callback(&state.db, nym).await;
    Ok(Json(resp).into_response())
}

pub async fn callback(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Result<axum::response::Response, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);

    // --- Amount validation ---
    if params.amount < state.config.limits.min_sendable_msat {
        return Err(AppError::InvalidAmount(format!(
            "minimum is {} msat",
            state.config.limits.min_sendable_msat
        )));
    }
    if params.amount > state.config.limits.max_sendable_msat {
        return Err(AppError::InvalidAmount(format!(
            "maximum is {} msat",
            state.config.limits.max_sendable_msat
        )));
    }
    if params.amount % 1000 != 0 {
        return Err(AppError::InvalidAmount(
            "amount must be a multiple of 1000 msat".to_string(),
        ));
    }
    let amount_sat = params.amount / 1000;

    let user = db::get_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;
    if !user.is_active {
        return Err(AppError::NymNotFound(nym.clone()));
    }

    // --- Caller IP + whitelist ---
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let caller_ip = ip_whitelist::resolve_caller_ip(
        peer.map(|p| p.ip()),
        xff,
        state.config.rate_limit.trust_forwarded_for,
    );
    let is_whitelisted = match caller_ip {
        Some(ip) => state.ip_whitelist.contains(ip),
        None => false,
    };

    // --- Per-IP rate (in-mem; hard fail; applies to BOTH paths) ---
    if !is_whitelisted {
        if let Some(ip) = caller_ip {
            state.rate_limiter.check_per_ip(ip).await?;
        }
    }

    // --- Liquid path is opt-in via `network=liquid` ---
    // PR C: on a Liquid-side rate-limit, transparently fall back to
    // Lightning (the default rail). Lightning doesn't leak Liquid
    // addresses, so the surveillance argument that justifies the tight
    // Liquid caps doesn't apply — serving an invoice instead of a 429
    // gives legitimate payers a working path AND raises attacker cost
    // (each fallback creates a real Boltz reverse swap, which is useless
    // for chain-analysis surveillance and costs Boltz API quota).
    if params.network.as_deref() == Some("liquid") {
        match serve_liquid(&state, &nym, &user, amount_sat, &params, caller_ip, is_whitelisted)
            .await
        {
            Ok(resp) => return Ok(resp),
            Err(LiquidOutcome::Hard(e)) => return Err(e),
            Err(LiquidOutcome::SoftRateLimited) => {
                tracing::info!(
                    event = "liquid_rate_limited_fallback_lightning",
                    nym = %nym,
                    ip = ?caller_ip,
                    "Liquid path rate-limited; falling back to Lightning"
                );
                // Fall through to Lightning below.
            }
        }
    }

    // Lightning path — default rail AND fallback destination.
    serve_lightning(&state, &nym, &user, amount_sat, caller_ip, is_whitelisted).await
}

fn format_btc_amount(sats: u64) -> String {
    let btc = sats as f64 / 100_000_000.0;
    format!("{btc:.8}")
}

use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_valid_json() {
        let meta = build_metadata("francis", "bullpay.ca");
        let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn metadata_contains_identifier() {
        let meta = build_metadata("francis", "bullpay.ca");
        assert!(meta.contains("francis@bullpay.ca"));
        assert!(meta.contains("text/identifier"));
    }

    #[test]
    fn metadata_contains_plain_text() {
        let meta = build_metadata("francis", "bullpay.ca");
        assert!(meta.contains("Sats for francis"));
        assert!(meta.contains("text/plain"));
    }

    // --- PR C: rl_gate behavior ---
    //
    // The fallback contract: rate-limit-class errors from Liquid-side
    // gates become `SoftRateLimited` (caller may fall back to Lightning).
    // Anything else stays `Hard(AppError)` and propagates unchanged.

    #[test]
    fn rl_gate_rate_limited_becomes_soft() {
        let r: Result<(), AppError> = Err(AppError::RateLimited);
        match rl_gate(r) {
            Err(LiquidOutcome::SoftRateLimited) => (),
            _ => panic!("RateLimited should map to SoftRateLimited"),
        }
    }

    #[test]
    fn rl_gate_too_many_pending_becomes_soft() {
        // Per-nym pending cap is also a fallback-eligible signal under the
        // v2 principle: the cap exists to prevent server resource pressure,
        // not to punish the user. Falling back to Lightning is the right
        // graceful response.
        let r: Result<(), AppError> = Err(AppError::TooManyPendingReservations);
        match rl_gate(r) {
            Err(LiquidOutcome::SoftRateLimited) => (),
            _ => panic!("TooManyPendingReservations should map to SoftRateLimited"),
        }
    }

    #[test]
    fn rl_gate_proof_failure_is_hard() {
        // Bad-proof errors are NOT rate-limit signals; they propagate as
        // hard errors so the client sees the actual problem.
        let r: Result<(), AppError> = Err(AppError::UtxoSpent);
        match rl_gate(r) {
            Err(LiquidOutcome::Hard(AppError::UtxoSpent)) => (),
            _ => panic!("UtxoSpent should map to Hard(UtxoSpent)"),
        }
    }

    #[test]
    fn rl_gate_db_error_is_hard() {
        let r: Result<(), AppError> = Err(AppError::DbError("test".into()));
        match rl_gate(r) {
            Err(LiquidOutcome::Hard(AppError::DbError(_))) => (),
            _ => panic!("DbError should map to Hard"),
        }
    }

    #[test]
    fn rl_gate_ok_passes_through() {
        let r: Result<u32, AppError> = Ok(42);
        assert_eq!(rl_gate(r).ok(), Some(42));
    }

    #[test]
    fn metadata_has_two_entries() {
        let meta = build_metadata("test", "example.com");
        let parsed: Vec<Vec<String>> = serde_json::from_str(&meta).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0][0], "text/identifier");
        assert_eq!(parsed[1][0], "text/plain");
    }

    #[test]
    fn description_hash_is_deterministic() {
        let meta = build_metadata("francis", "bullpay.ca");
        let hash1 = hex::encode(Sha256::digest(meta.as_bytes()));
        let hash2 = hex::encode(Sha256::digest(build_metadata("francis", "bullpay.ca").as_bytes()));
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn description_hash_differs_per_nym() {
        let h1 = hex::encode(Sha256::digest(build_metadata("alice", "bullpay.ca").as_bytes()));
        let h2 = hex::encode(Sha256::digest(build_metadata("bob", "bullpay.ca").as_bytes()));
        assert_ne!(h1, h2);
    }

    #[test]
    fn format_btc_amount_works() {
        assert_eq!(format_btc_amount(307), "0.00000307");
        assert_eq!(format_btc_amount(100_000_000), "1.00000000");
        assert_eq!(format_btc_amount(1), "0.00000001");
    }
}
