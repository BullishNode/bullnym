use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use lwk_wollet::elements;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::admission::Rail;
use crate::certification::{self, CertificationScope};
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
    #[serde(rename = "payment_methods", skip_serializing_if = "Vec::is_empty")]
    pub payment_methods: Vec<&'static str>,
}

// --- Callback params ---

#[derive(Deserialize)]
pub struct CallbackParams {
    pub amount: u64,
    pub comment: Option<String>,
    pub payment_method: Option<String>,
    pub outpoint: Option<String>,
    pub pubkey: Option<String>,
    pub sig: Option<String>,
    /// LUD-22 Approach B proof-of-funds (the shipped mobile-client contract):
    /// the payer supplies the cleartext output `value` (sat) plus the elements
    /// value/asset blinding factors (display-order hex, i.e. `TxOutSecrets`
    /// `to_string()`). The server rebinds them against the on-chain commitments
    /// to enforce asset == L-BTC AND value >= `proof.min_proof_value_sat`
    /// (DG-7 / ISS-S-04) — without unblinding.
    pub value: Option<u64>,
    pub value_bf: Option<String>,
    pub asset_bf: Option<String>,
    /// Approach A (legacy) fields. Accepted-but-ignored for forward/backward
    /// compat: a client still sending a `blinding_key`/`asset` must not 422.
    #[allow(dead_code)]
    pub blinding_key: Option<String>,
    #[allow(dead_code)]
    pub asset: Option<String>,
}

struct ProofFields {
    outpoint: String,
    pubkey: String,
    sig: String,
    value: u64,
    value_bf: String,
    asset_bf: String,
}

impl CallbackParams {
    fn take_proof(&self) -> Option<ProofFields> {
        Some(ProofFields {
            outpoint: self.outpoint.clone()?,
            pubkey: self.pubkey.clone()?,
            sig: self.sig.clone()?,
            value: self.value?,
            value_bf: self.value_bf.clone()?,
            asset_bf: self.asset_bf.clone()?,
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

// --- Helpers ---

fn requests_method(payment_method: Option<&str>, target: &str) -> bool {
    payment_method
        .map(|s| s.split(',').any(|m| m.trim() == target))
        .unwrap_or(false)
}

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
    if certification::allows_scope(
        state,
        CertificationScope::MetadataLookup,
        peer,
        headers,
        "metadata",
        nym,
    ) {
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
    // Gate before any DB work.
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    gate_metadata_per_ip(&state, peer, &headers, Some(&nym)).await?;

    let _user = db::get_active_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;

    let callback = format!("https://{}/lnurlp/callback/{}", state.config.domain, nym);

    Ok(Json(LnurlPayMetadata {
        callback,
        max_sendable: state.config.limits.max_sendable_msat,
        min_sendable: state.config.limits.min_sendable_msat,
        metadata: build_metadata(&nym, &state.config.domain),
        tag: "payRequest".to_string(),
        comment_allowed: 144,
        payment_methods: vec!["L-BTC"],
    }))
}

// --- Soft fallback: Liquid rate-limit to Lightning ---

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

/// Map a rate-limit gate result so any rate-limit-class error becomes the
/// soft-fallback signal; every other error stays Hard. The rate-limit
/// classification is owned by `AppError::is_rate_limit` so adding a new
/// rate-limit code in `error.rs` automatically routes through the soft
/// path here.
fn rl_gate<T>(result: Result<T, AppError>) -> Result<T, LiquidOutcome> {
    match result {
        Ok(v) => Ok(v),
        Err(e) if e.is_rate_limit() => Err(LiquidOutcome::SoftRateLimited),
        Err(other) => Err(LiquidOutcome::Hard(other)),
    }
}

fn liquid_response_addr_index(
    current_next_addr_idx: i32,
    reserved_addr_index: Option<i32>,
) -> Result<u32, AppError> {
    let addr_index = reserved_addr_index.unwrap_or(current_next_addr_idx);
    u32::try_from(addr_index).map_err(|_| AppError::DbError("address index overflow".to_string()))
}

/// Liquid LUD-22 path. On rate-limit, returns `SoftRateLimited` so the
/// caller can transparently route to Lightning (the default rail).
async fn serve_liquid(
    state: &AppState,
    nym: &str,
    user: &db::User,
    _amount_sat: u64,
    params: &CallbackParams,
    caller_ip: Option<std::net::IpAddr>,
    is_whitelisted: bool,
) -> Result<axum::response::Response, LiquidOutcome> {
    let reserved_addr_index = if !is_whitelisted {
        let proof = params.take_proof().ok_or(AppError::ProofOfFundsRequired {
            min_sat: state.config.proof.min_proof_value_sat,
        })?;

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
        let addr_index = match db::get_outpoint_address(&state.db, nym, &proof.outpoint).await? {
            Some(cached) => cached.addr_index,
            None => {
                state
                    .admission
                    .enforce(Rail::DirectLiquid)
                    .map_err(|_| LiquidOutcome::Hard(AppError::MoneyAdmissionUnavailable))?;

                // Distinct-nym fan-out limits (Soft on rate-limit).
                if let Some(ip) = caller_ip {
                    rl_gate(state.rate_limiter.check_distinct_nyms_per_ip(ip, nym).await)?;
                }
                rl_gate(
                    state
                        .rate_limiter
                        .check_distinct_nyms_per_outpoint(&proof.outpoint, nym)
                        .await,
                )?;

                // Per-nym pending reservation cap (Soft).
                rl_gate(state.rate_limiter.check_pending_reservations(nym).await)?;

                let parsed = ParsedOutpoint::parse(&proof.outpoint)?;

                let backend = state.utxo_backend.as_ref().ok_or_else(|| {
                    AppError::ElectrumError("no blockchain backend configured".into())
                })?;

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

                // Rebind the payer-supplied cleartext value + blinding factors
                // against the on-chain commitments (LUD-22 Approach B) and
                // enforce the L-BTC value floor. Makes the anti-enumeration cost
                // real: a dust UTXO no longer satisfies the proof (DG-7 / ISS-S-04).
                crate::utxo::assert_proof_utxo_value(
                    txout,
                    proof.value,
                    &proof.value_bf,
                    &proof.asset_bf,
                    crate::invoice::LIQUID_BTC_ASSET_ID,
                    state.config.proof.min_proof_value_sat,
                )?;

                db::allocate_outpoint_address(&state.db, nym, &proof.outpoint, &proof.pubkey)
                    .await?
            }
        };
        Some(addr_index)
    } else {
        state
            .admission
            .enforce(Rail::DirectLiquid)
            .map_err(|_| LiquidOutcome::Hard(AppError::MoneyAdmissionUnavailable))?;
        None
    };

    let addr_index_u32 = liquid_response_addr_index(user.next_addr_idx, reserved_addr_index)?;
    let address = descriptor::derive_address(&user.ct_descriptor, addr_index_u32)?;

    let resp = serde_json::json!({ "L-BTC": { "address": address } });
    db::touch_user_callback(&state.db, nym).await;
    Ok(Json(resp).into_response())
}

/// Lightning path. Default rail; also the destination for Liquid soft
/// fallbacks. Per-source rate-limited (loose; Boltz-quota guard).
async fn serve_lightning(
    state: &AppState,
    nym: &str,
    amount_sat: u64,
    caller_ip: Option<std::net::IpAddr>,
    is_whitelisted: bool,
) -> Result<axum::response::Response, AppError> {
    if !is_whitelisted {
        if let Some(ip) = caller_ip {
            state.rate_limiter.check_lightning_per_source(ip).await?;
        }
    }

    let (resp, _swap_id) = create_lightning_swap(state, nym, amount_sat).await?;
    Ok(Json(resp).into_response())
}

/// Reusable Lightning-swap creation. Allocates a swap key, asks Boltz for
/// a reverse swap, records the swap, returns the LNURL-pay response shape
/// (with the BOLT11) plus the Boltz swap id.
///
/// Rate-limit is the caller's responsibility — different callers gate on
/// different buckets.
pub(crate) async fn create_lightning_swap(
    state: &AppState,
    nym: &str,
    amount_sat: u64,
) -> Result<(LightningResponse, String), AppError> {
    state
        .admission
        .enforce(Rail::LightningReverse)
        .map_err(|_| AppError::MoneyAdmissionUnavailable)?;

    let swap_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("swap key allocation failed: {e}")))?;
    let derived_key = state.boltz.derive_swap_key(swap_key_index)?;
    let claim_public_key_hex = derived_key.public_key_hex();
    let preimage_hash_hex = derived_key.preimage_hash_hex();
    let key_allocation_id = db::reserve_swap_key_allocation(
        &state.db,
        &db::NewSwapKeyAllocation {
            root_fingerprint: state.swap_key_root_fingerprint.as_str(),
            key_epoch: state.config.boltz.key_epoch,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            child_index: swap_key_index as i64,
            purpose: db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: Some(&preimage_hash_hex),
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("swap key reservation failed: {e}")))?;

    let metadata_str = build_metadata(nym, &state.config.domain);
    let description_hash_hex = hex::encode(Sha256::digest(metadata_str.as_bytes()));

    // No address pre-allocated: the cooperative MuSig2 claim path allocates
    // the descriptor index at claim time. See docs/lud-22-vs-mrh-research.md.
    let result = state
        .boltz
        .create_reverse_swap(derived_key, amount_sat, None, Some(&description_hash_hex))
        .await?;

    let preimage_hex = hex::encode(&result.preimage);
    let claim_key_hex = hex::encode(result.claim_keypair.secret_bytes());
    let boltz_response_json = serde_json::to_string(&result.boltz_response)
        .map_err(|e| AppError::BoltzError(format!("failed to serialize boltz response: {e}")))?;

    db::record_swap_with_lineage(
        &state.db,
        &db::NewSwapRecord {
            nym: Some(nym),
            boltz_swap_id: &result.swap_id,
            address: None,
            address_index: None,
            amount_sat,
            invoice: &result.invoice,
            preimage_hex: &preimage_hex,
            claim_key_hex: &claim_key_hex,
            boltz_response_json: &boltz_response_json,
            // LNURL Lightning Address path is invoice-less by design.
            invoice_id: None,
            key_index: Some(swap_key_index as i64),
            root_fingerprint: Some(state.swap_key_root_fingerprint.as_str()),
        },
        &db::ReverseSwapLineage {
            allocation_id: key_allocation_id,
            key_epoch: state.config.boltz.key_epoch,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: &preimage_hash_hex,
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
    Ok((resp, result.swap_id))
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

    let user = db::get_active_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::NymNotFound(nym.clone()))?;

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

    if requests_method(params.payment_method.as_deref(), "L-BTC") {
        match serve_liquid(
            &state,
            &nym,
            &user,
            amount_sat,
            &params,
            caller_ip,
            is_whitelisted,
        )
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
    serve_lightning(&state, &nym, amount_sat, caller_ip, is_whitelisted).await
}

use axum::response::IntoResponse;

#[cfg(test)]
mod tests;
