use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use lwk_wollet::elements;

use boltz_client::elements as boltz_elements;
use boltz_client::network::electrum::ElectrumLiquidClient;
use boltz_client::network::{BitcoinChain, Chain, LiquidChain, LiquidClient};
use boltz_client::swaps::boltz::{
    BoltzApiClientV2, ChainPair, CreateChainResponse, CreateReverseResponse, Side,
};
use boltz_client::swaps::{
    BtcLikeTransaction, ChainClient, SwapScript, SwapTransactionParams, TransactionOptions,
};
use boltz_client::util::fees::Fee;
use boltz_client::util::secrets::Preimage;
use boltz_client::Keypair;

use crate::admission::WorkerReporter;
use crate::boltz::{ChainSwapQuote, ChainSwapQuoteProviderError, ChainSwapQuoteProviderErrorKind};
use crate::builder_fee::LiquidBuilderFeeDecision;
use crate::chain_swap_runtime::{
    apply_chain_swap_provider_effect, apply_chain_swap_provider_effect_with_evidence,
    ChainSwapProviderApplyOutcome, ChainSwapProviderEvidence,
};
use crate::chain_swap_renegotiation::{
    ChainSwapRenegotiationOperation, ChangedQuoteRedrive, RenegotiationErrorClass,
    RenegotiationIdentity, RenegotiationState, TransitionDisposition,
    VerifiedRenegotiationAcceptance,
};
use crate::config::Config;
use crate::db::{self, ChainSwapStatus, SwapStatus};
use crate::descriptor;
use crate::error::AppError;
use crate::fee_decision_record::{FeeConstructionPurpose, FeeDecisionRecord};
use crate::fee_policy::{FeeFreshness, LiquidFeeDecision, LiquidFeePolicy};
use crate::fee_runtime::FeeRuntime;
use crate::invoice;
use crate::ip_whitelist;
use crate::merchant_output_verifier::{
    prepare_liquid_claim_journal, MerchantSourcePrevout, PersistableMerchantTransactionJournal,
    MAX_MERCHANT_OUTPUT_RAW_TRANSACTION_BYTES, MAX_MERCHANT_OUTPUT_SOURCE_PREVOUTS,
};
use crate::utxo::UtxoBackend;
use crate::validators;
use crate::AppState;

const CLAIM_SWEEP_INTERVAL_SECS: u64 = 10;
const REVERSE_TEST_GUARD_REJECTED: &str =
    "claim integration seam requires a malformed reverse response without persisted claim bytes";
const CHAIN_TEST_GUARD_REJECTED: &str =
    "claim integration seam requires a malformed chain response without persisted claim bytes";
const RENEGOTIATION_POLICY_VERSION: &str = "issue38-primary-mismatch-v1";
// Boltz requires more than 60 minutes before the Bitcoin timeout. Bitcoin's
// target interval is ten minutes, so a strict `remaining > 6` check is the
// conservative block-height form of that provider boundary.
const RENEGOTIATION_MIN_REMAINING_BTC_BLOCKS: i64 = 6;
const RENEGOTIATION_MAX_PRIMARY_OBSERVATION_AGE_SECS: i64 = 120;
const RENEGOTIATION_MAX_SERVER_LOCK_OBSERVATION_AGE_SECS: i64 = 120;
const RENEGOTIATION_ACCEPT_REQUEST_STALE_AFTER_SECS: i64 = 30;
/// Stable, non-secret explanation for a claim that remains pending until fee
/// policy supplies accepted live or recent same-rail evidence.
#[doc(hidden)]
pub const LIQUID_FEE_DECISION_PENDING_REASON: &str =
    "Liquid fee decision unavailable; retry after accepted live or recent same-rail evidence";

fn liquid_claim_fee(decision: &LiquidBuilderFeeDecision, _cooperative_or_script_path: bool) -> Fee {
    // Both paths use the same sat/vByte decision. `boltz-client` applies it
    // to each path's actual virtual size, so their absolute fees may differ.
    Fee::Relative(decision.rate().as_f64())
}

/// A persisted claim owns its original construction authority and must remain
/// replayable without a current quote. Fresh bytes, however, may be committed
/// only while the process-local monotonic deadline captured in the decision
/// record is still live.
fn liquid_claim_journal_authorized(
    had_persisted_claim: bool,
    fee_record: Option<&FeeDecisionRecord>,
) -> bool {
    had_persisted_claim || fee_record.is_some_and(FeeDecisionRecord::authorizes_construction_now)
}

fn validated_chain_creation_destination(
    terms: &db::ChainSwapCreationTerms,
) -> Result<String, AppError> {
    if terms.btc_network != "bitcoin" || terms.liquid_network != "liquid" {
        return Err(AppError::ClaimError(format!(
            "chain swap creation packet has unsupported networks: {}/{}",
            terms.btc_network, terms.liquid_network
        )));
    }
    let expected_asset = elements::AssetId::LIQUID_BTC.to_string();
    if terms.liquid_asset_id != expected_asset {
        return Err(AppError::ClaimError(format!(
            "chain swap creation packet has unexpected Liquid asset {}",
            terms.liquid_asset_id
        )));
    }
    let canonical = validators::canonical_liquid_mainnet_address(
        &terms.merchant_liquid_destination,
    )
    .map_err(|error| {
        AppError::ClaimError(format!(
            "invalid immutable chain-swap Liquid destination: {error}"
        ))
    })?;
    if canonical != terms.merchant_liquid_destination {
        return Err(AppError::ClaimError(
            "immutable chain-swap Liquid destination is not canonical".into(),
        ));
    }
    Ok(canonical)
}

/// Source quality required before a wrong-amount provider mutation is even
/// considered. There is deliberately no incomplete or single-backend variant:
/// those observations remain read-only and must be reconciled by #82/#139.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrimaryFundingEvidenceQuality {
    CompleteAndAgreed,
}

/// Independently verified value of the primary Bitcoin funding transaction.
///
/// The webhook's `transaction.lockupFailed` string and the swap's expected
/// amount are not evidence of what was actually funded. The later #139
/// projection integration must construct this value only from a complete,
/// agreeing primary-source observation with stable identity and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPrimaryFundingAmountMismatch {
    quality: PrimaryFundingEvidenceQuality,
    chain_swap_id: Uuid,
    observed_amount_sat: u64,
    expected_amount_sat: u64,
    authoritative_bitcoin_tip: u32,
    observed_at_unix: i64,
    primary_identity: String,
    primary_evidence_sha256: String,
}

impl VerifiedPrimaryFundingAmountMismatch {
    pub(crate) fn new_complete_and_agreed(
        chain_swap_id: Uuid,
        observed_amount_sat: u64,
        expected_amount_sat: u64,
        authoritative_bitcoin_tip: u32,
        observed_at_unix: i64,
        primary_identity: impl Into<String>,
        primary_evidence_sha256: impl Into<String>,
    ) -> Result<Self, AppError> {
        let evidence = Self {
            quality: PrimaryFundingEvidenceQuality::CompleteAndAgreed,
            chain_swap_id,
            observed_amount_sat,
            expected_amount_sat,
            authoritative_bitcoin_tip,
            observed_at_unix,
            primary_identity: primary_identity.into(),
            primary_evidence_sha256: primary_evidence_sha256.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), AppError> {
        self.validate_common()?;
        if self.observed_amount_sat == self.expected_amount_sat {
            return Err(AppError::ClaimError(
                "renegotiation is forbidden for a correctly funded primary transaction".into(),
            ));
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), AppError> {
        if self.quality != PrimaryFundingEvidenceQuality::CompleteAndAgreed {
            return Err(AppError::ClaimError(
                "renegotiation requires complete, agreeing primary funding evidence".into(),
            ));
        }
        if self.chain_swap_id.is_nil() {
            return Err(AppError::ClaimError(
                "renegotiation primary funding observation has no swap identity".into(),
            ));
        }
        if self.observed_amount_sat == 0 || self.expected_amount_sat == 0 {
            return Err(AppError::ClaimError(
                "renegotiation requires positive primary funding amounts".into(),
            ));
        }
        let now = current_unix_time()?;
        if self.authoritative_bitcoin_tip == 0
            || self.observed_at_unix <= 0
            || self.observed_at_unix > now
            || now.saturating_sub(self.observed_at_unix)
                > RENEGOTIATION_MAX_PRIMARY_OBSERVATION_AGE_SECS
        {
            return Err(AppError::ClaimError(
                "renegotiation primary funding observation height or time is invalid".into(),
            ));
        }
        if self.primary_identity.is_empty()
            || self.primary_identity.len() > 256
            || self.primary_identity.chars().any(char::is_whitespace)
        {
            return Err(AppError::ClaimError(
                "renegotiation primary funding identity is invalid".into(),
            ));
        }
        if !is_lower_sha256(&self.primary_evidence_sha256) {
            return Err(AppError::ClaimError(
                "renegotiation primary funding evidence digest is invalid".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPrimaryFundingObservation(VerifiedPrimaryFundingAmountMismatch);

impl VerifiedPrimaryFundingObservation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_complete_and_agreed(
        chain_swap_id: Uuid,
        observed_amount_sat: u64,
        expected_amount_sat: u64,
        authoritative_bitcoin_tip: u32,
        observed_at_unix: i64,
        primary_identity: impl Into<String>,
        primary_evidence_sha256: impl Into<String>,
    ) -> Result<Self, AppError> {
        let observation = VerifiedPrimaryFundingAmountMismatch {
            quality: PrimaryFundingEvidenceQuality::CompleteAndAgreed,
            chain_swap_id,
            observed_amount_sat,
            expected_amount_sat,
            authoritative_bitcoin_tip,
            observed_at_unix,
            primary_identity: primary_identity.into(),
            primary_evidence_sha256: primary_evidence_sha256.into(),
        };
        observation.validate_common()?;
        Ok(Self(observation))
    }

    fn mismatch(&self) -> Option<&VerifiedPrimaryFundingAmountMismatch> {
        (self.0.observed_amount_sat != self.0.expected_amount_sat).then_some(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedLiquidServerLockProgression {
    chain_swap_id: Uuid,
    observed_amount_sat: u64,
    output_identity: String,
    output_evidence_sha256: String,
    observed_at_unix: i64,
}

impl VerifiedLiquidServerLockProgression {
    pub(crate) fn new(
        chain_swap_id: Uuid,
        observed_amount_sat: u64,
        output_identity: impl Into<String>,
        output_evidence_sha256: impl Into<String>,
        observed_at_unix: i64,
    ) -> Result<Self, AppError> {
        let evidence = Self {
            chain_swap_id,
            observed_amount_sat,
            output_identity: output_identity.into(),
            output_evidence_sha256: output_evidence_sha256.into(),
            observed_at_unix,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), AppError> {
        let now = current_unix_time()?;
        if self.chain_swap_id.is_nil()
            || self.observed_amount_sat == 0
            || self.observed_at_unix <= 0
            || self.observed_at_unix > now
            || now.saturating_sub(self.observed_at_unix)
                > RENEGOTIATION_MAX_SERVER_LOCK_OBSERVATION_AGE_SECS
            || self.output_identity.is_empty()
            || self.output_identity.len() > 256
            || self.output_identity.chars().any(char::is_whitespace)
            || !is_lower_sha256(&self.output_evidence_sha256)
        {
            return Err(AppError::ClaimError(
                "verified Liquid server-lock progression is invalid".into(),
            ));
        }
        Ok(())
    }

    fn terminal_digest(&self) -> Result<String, AppError> {
        let value = serde_json::json!({
            "chainSwapId": self.chain_swap_id,
            "observedAmountSat": self.observed_amount_sat,
            "outputIdentitySha256": hex::encode(Sha256::digest(self.output_identity.as_bytes())),
            "outputEvidenceSha256": self.output_evidence_sha256,
            "observedAtUnix": self.observed_at_unix,
        });
        crate::canonical_json::canonical_json_and_sha256(&value)
            .map(|(_, digest)| digest)
            .map_err(|error| {
                AppError::ClaimError(format!(
                    "Liquid server-lock evidence is not canonical: {error}"
                ))
            })
    }
}

fn current_unix_time() -> Result<i64, AppError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::ClaimError("system clock is before the Unix epoch".into()))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| AppError::ClaimError("system clock exceeds supported range".into()))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Deserialize)]
struct WebhookEnvelope {
    data: WebhookData,
}

#[derive(Deserialize)]
struct WebhookData {
    id: String,
    status: String,
}

/// Constant-time match of a presented URL-path secret against a
/// (current, previous) pair of configured secrets.
///
/// - Returns `true` only when `presented` matches one of the configured
///   secrets exactly.
/// - Empty configured secrets never validate, even against an empty
///   presented value — otherwise a misconfigured deploy would silently
///   accept any request.
/// - Length differences fail before the constant-time compare. This
///   leaks "wrong length" via timing but the configured secret is a
///   fixed long random string; the worst case is the attacker learns
///   "you didn't pick this length", which is uninteresting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlSecretMatch {
    Current,
    Previous,
    None,
}

fn match_url_secret_pair(presented: &str, current: &str, previous: &str) -> UrlSecretMatch {
    fn ct_eq(a: &str, b: &str) -> bool {
        if b.is_empty() || a.len() != b.len() {
            return false;
        }
        a.as_bytes().ct_eq(b.as_bytes()).into()
    }
    if ct_eq(presented, current) {
        UrlSecretMatch::Current
    } else if ct_eq(presented, previous) {
        UrlSecretMatch::Previous
    } else {
        UrlSecretMatch::None
    }
}

#[cfg(test)]
fn url_secret_matches_pair(presented: &str, current: &str, previous: &str) -> bool {
    match_url_secret_pair(presented, current, previous) != UrlSecretMatch::None
}

fn match_webhook_url_secret(presented: &str, config: &Config) -> UrlSecretMatch {
    match_url_secret_pair(
        presented,
        &config.boltz_webhook_url_secret,
        &config.boltz_webhook_url_secret_previous,
    )
}

/// Preserve the standard structured [`AppError`] response body and logging,
/// but make dispatcher failures visible to Boltz at the HTTP layer so it
/// retries the same delivery. Some public endpoints intentionally encode
/// errors in HTTP 200 responses; that convention is not valid for webhooks.
fn webhook_dispatch_response(result: Result<&'static str, AppError>) -> Response {
    match result {
        Ok(body) => body.into_response(),
        Err(error) => {
            let mut response = error.into_response();
            if response.status().is_success() {
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            }
            response
        }
    }
}

/// Authenticated webhook entrypoint: `/webhook/boltz/:secret`.
/// Routes the request to the shared dispatcher only after the URL
/// segment matches a configured secret in constant time.
pub async fn webhook_with_secret(
    State(state): State<AppState>,
    Path(secret): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    match match_webhook_url_secret(&secret, &state.config) {
        UrlSecretMatch::Current => {
            tracing::debug!("boltz webhook: URL secret matched current secret");
        }
        UrlSecretMatch::Previous => {
            tracing::warn!("boltz webhook: URL secret matched previous rotation secret");
        }
        UrlSecretMatch::None => {
            // Same shape as a route miss — don't leak whether the path
            // existed but the secret was wrong vs. the route doesn't exist.
            // Webhook-bomb rate-limit is still applied below.
            let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
            let caller_ip = ip_whitelist::resolve_caller_ip(
                peer_opt.map(|ConnectInfo(addr)| addr.ip()),
                xff,
                state.config.rate_limit.trust_forwarded_for,
            );
            tracing::warn!("boltz webhook: URL secret mismatch from {:?}", caller_ip);
            return Ok((StatusCode::NOT_FOUND, "").into_response());
        }
    }
    Ok(webhook_dispatch_response(
        dispatch_webhook(state, peer_opt, headers, body).await,
    ))
}

/// Compatibility webhook entrypoint: `/webhook/boltz`.
/// See docs/compatibility-ledger.md for removal policy.
///
/// **First-time secret rollout (operational note).** The webhook URL is
/// captured Boltz-side at swap-creation time. Setting the secret on a
/// running deployment that previously created swaps without one will
/// reject all in-flight swaps' webhook deliveries (Boltz retries 5×60s
/// then abandons). Mitigation: deploy this code with the secret unset
/// first, drain in-flight swaps (~24h max via reconciler / on-chain
/// timeouts), then flip the secret on.
pub async fn webhook_unauthenticated(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    if !state.config.boltz_webhook_url_secret.is_empty() {
        let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
        let caller_ip = ip_whitelist::resolve_caller_ip(
            peer_opt.map(|ConnectInfo(addr)| addr.ip()),
            xff,
            state.config.rate_limit.trust_forwarded_for,
        );
        tracing::warn!(
            "boltz webhook: hit on unauthenticated path while secret is configured (caller={:?})",
            caller_ip,
        );
        return Ok((StatusCode::NOT_FOUND, "").into_response());
    }
    tracing::warn!(
        "boltz webhook: BOLTZ_WEBHOOK_URL_SECRET unset — accepting unauthenticated payload (DEV ONLY)"
    );
    Ok(webhook_dispatch_response(
        dispatch_webhook(state, peer_opt, headers, body).await,
    ))
}

/// Shared post-auth webhook handler.
///
/// Returns `Ok("ok")` (200) for every payload we successfully decode and
/// route — including unknown swap IDs and unhandled statuses — so Boltz's
/// webhook caller treats the delivery as successful and stops retrying.
/// We only return errors for malformed payloads or DB failures, which
/// Boltz should retry.
async fn dispatch_webhook(
    state: AppState,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> Result<&'static str, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);

    // Per-source rate-limit gate. Survives even with a leaked URL secret.
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let caller_ip = ip_whitelist::resolve_caller_ip(
        peer.map(|p| p.ip()),
        xff,
        state.config.rate_limit.trust_forwarded_for,
    );
    if let Some(ip) = caller_ip {
        if !state.ip_whitelist.contains(ip) {
            state.rate_limiter.check_webhook_per_ip(ip).await?;
        }
    }

    tracing::debug!("boltz webhook raw: {}", body);

    let envelope: WebhookEnvelope = serde_json::from_str(&body).map_err(|e| {
        tracing::error!("failed to parse webhook: {e}");
        AppError::ClaimError(format!("invalid webhook payload: {e}"))
    })?;
    let data = envelope.data;

    tracing::info!("boltz webhook: swap={} status={}", data.id, data.status);

    let swap = db::get_swap_by_boltz_id(&state.db, &data.id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if swap.is_none() {
        if let Some(chain_swap) = db::get_chain_swap_by_boltz_id(&state.db, &data.id)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?
        {
            // Chain swaps deliberately do not use permanent
            // `{swap_id}:{status}` delivery dedup as a correctness gate. The
            // shared row-locked transition below makes duplicates/reordering
            // safe, and every delivery can redrive an executor that failed
            // after the prior state commit. The reconciler calls the same path.
            handle_chain_swap_webhook(&state, &chain_swap, &data.status).await?;
            return Ok("ok");
        }
    }

    // Legacy reverse-swap delivery dedup remains scoped to that path. It is
    // intentionally checked only after ruling out a chain swap, so a chain
    // delivery cannot be permanently consumed before its transition succeeds.
    let event_id = format!("{}:{}", data.id, data.status);
    let is_first = db::try_record_webhook_event(&state.db, &event_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if !is_first {
        tracing::debug!("boltz webhook: duplicate reverse/unknown event {event_id}");
        return Ok("ok");
    }

    let Some(swap) = swap else {
        // Unknown swap_id is not an error condition for Boltz to retry —
        // either we never created the swap here, or the row was purged.
        // Returning 200 stops the Boltz retry storm.
        tracing::warn!("boltz webhook for unknown swap: {}", data.id);
        return Ok("ok");
    };

    let status = swap
        .parsed_status()
        .map_err(|e| AppError::ClaimError(format!("invalid persisted swap status: {e}")))?;
    if status.is_terminal() {
        tracing::debug!("ignoring webhook for {} swap {}", swap.status, data.id);
        return Ok("ok");
    }

    match data.status.as_str() {
        "transaction.mempool" | "transaction.confirmed" => {
            let is_mempool = data.status == "transaction.mempool";
            let new_status = if is_mempool {
                SwapStatus::LockupMempool
            } else {
                SwapStatus::LockupConfirmed
            };
            db::update_swap_status(&state.db, swap.id, new_status, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

            // Lockup sightings are only payment evidence. They may show
            // the public page as "payment detected", but accounting is
            // recorded only after our claim succeeds below.
            invoice::flip_invoice_on_lightning_in_progress(
                &state.db,
                swap.invoice_id,
                &swap.boltz_swap_id,
            )
            .await;

            try_claim_with_retry(&swap, ClaimAttemptContext::from_state(&state)).await;
        }
        "invoice.settled" => {
            // Preimage was disclosed and Boltz settled the LN HTLC. This
            // arrives downstream of our successful cooperative claim. We
            // don't transition status here — the claim path itself sets
            // `Claimed` with the on-chain txid.
            tracing::info!("invoice settled for swap {}", data.id);
        }
        "swap.expired" => {
            // `swap.expired` is the wall-clock hold-invoice timer (~50% of
            // swap timeout per Boltz docs). It does NOT mean the on-chain
            // HTLC is dead — the lockup output stays claimable until
            // `timeoutBlockHeight`. After this status, however, the
            // cooperative claim endpoint refuses (per `MusigSigner.ts`),
            // so the only path is script-path with the preimage.
            //
            // Action: set `cooperative_refused = TRUE` so the next sweep
            // tick takes the script path.
            // Do NOT transition to a terminal state — that would abandon
            // potentially-claimable funds.
            tracing::warn!(
                event = "swap_expired_webhook",
                swap_id = %data.id,
                "swap.expired received; flipping cooperative_refused for script-path retry"
            );
            db::mark_cooperative_refused(&state.db, swap.id)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        "transaction.failed" => {
            // Boltz tried to lock up on-chain but failed (e.g. their fee
            // estimation was rejected). The user's LN HTLC auto-cancels
            // — they don't pay, we have nothing to claim. Terminal.
            tracing::info!(
                event = "swap_transaction_failed",
                swap_id = %data.id,
                "boltz lockup failed; LN HTLC will cancel back to sender"
            );
            db::update_swap_status(&state.db, swap.id, SwapStatus::Expired, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        "invoice.expired" => {
            // The user never paid the LN invoice within its TTL. Boltz
            // never funded a lockup. Terminal Expired (same shape as
            // `transaction.failed`).
            tracing::info!(
                event = "swap_invoice_expired",
                swap_id = %data.id,
                "invoice expired before payment"
            );
            db::update_swap_status(&state.db, swap.id, SwapStatus::Expired, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
        }
        "transaction.refunded" => {
            // Boltz refunded its own lockup before we claimed it. The
            // user paid the LN invoice and is not made whole — this is
            // the fund-loss terminal state. P0 alert.
            //
            // This status should be rare; if it arrives, preserve a loud
            // terminal signal for operator rescue.
            tracing::error!(
                event = "swap_lockup_refunded",
                swap_id = %data.id,
                nym = %swap.nym.as_deref().unwrap_or("<invoice-only>"),
                amount_sat = swap.amount_sat,
                "FUND LOSS: boltz refunded lockup; user paid LN side, no on-chain claim"
            );
            db::update_swap_status(&state.db, swap.id, SwapStatus::LockupRefunded, None)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;
            db::mark_invoice_settlement_status(&state.db, swap.invoice_id, "refunded")
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

            // Do not record an invoice payment event here. A refunded
            // lockup means the merchant-side claim did not settle.
        }
        _ => {
            // Other Boltz statuses (`swap.created`, `minerfee.paid`, etc.)
            // are informational; we don't act on them. Logged at debug
            // so a new status appearing in the wild is visible in -v
            // logs without spamming production at info level.
            tracing::debug!("ignoring webhook status: {}", data.status);
        }
    }

    Ok("ok")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenegotiationCheckpoint {
    QuoteObservedBeforePersistence,
    QuotePersisted,
    AcceptRequested,
    ProviderAcceptedResponse,
    BeforeAcceptanceCommit,
    AcceptanceCommitted,
}

pub(crate) trait RenegotiationCheckpointObserver: Send + Sync {
    fn reached(&self, checkpoint: RenegotiationCheckpoint) -> Result<(), AppError>;
}

struct NoopRenegotiationCheckpointObserver;

impl RenegotiationCheckpointObserver for NoopRenegotiationCheckpointObserver {
    fn reached(&self, _checkpoint: RenegotiationCheckpoint) -> Result<(), AppError> {
        Ok(())
    }
}

#[async_trait]
pub(crate) trait ChainSwapRenegotiationProvider: Send + Sync {
    async fn get_quote(&self, swap_id: &str)
        -> Result<ChainSwapQuote, ChainSwapQuoteProviderError>;

    async fn accept_quote(
        &self,
        swap_id: &str,
        amount_sat: u64,
    ) -> Result<String, ChainSwapQuoteProviderError>;
}

#[async_trait]
impl ChainSwapRenegotiationProvider for crate::boltz::BoltzService {
    async fn get_quote(
        &self,
        swap_id: &str,
    ) -> Result<ChainSwapQuote, ChainSwapQuoteProviderError> {
        self.get_chain_swap_quote(swap_id).await
    }

    async fn accept_quote(
        &self,
        swap_id: &str,
        amount_sat: u64,
    ) -> Result<String, ChainSwapQuoteProviderError> {
        self.accept_chain_swap_quote(swap_id, amount_sat).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AcceptedRenegotiationFinalization {
    Committed(ChainSwapRenegotiationOperation),
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DefiniteDeclineFinalization {
    Declined(ChainSwapRenegotiationOperation),
    Busy,
    LiquidPathActive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RenegotiationStoreTransition {
    Applied(ChainSwapRenegotiationOperation),
    ExactRetry(ChainSwapRenegotiationOperation),
}

impl RenegotiationStoreTransition {
    fn into_parts(self) -> (ChainSwapRenegotiationOperation, bool) {
        match self {
            Self::Applied(operation) => (operation, true),
            Self::ExactRetry(operation) => (operation, false),
        }
    }
}

/// Narrow store seam for the one #38 operation. The production implementation
/// delegates to the typed PostgreSQL adapter; deterministic tests use an
/// in-memory CAS fake to prove crash/restart ordering without a database.
#[async_trait]
pub(crate) trait ChainSwapRenegotiationStore: Send + Sync {
    async fn get(
        &self,
        chain_swap_id: Uuid,
    ) -> Result<Option<ChainSwapRenegotiationOperation>, AppError>;

    async fn persist_quoted(
        &self,
        identity: &RenegotiationIdentity,
    ) -> Result<ChainSwapRenegotiationOperation, AppError>;

    async fn request_accept(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
    ) -> Result<RenegotiationStoreTransition, AppError>;

    async fn request_changed_accept(
        &self,
        current: &ChainSwapRenegotiationOperation,
        replacement: &RenegotiationIdentity,
    ) -> Result<RenegotiationStoreTransition, AppError>;

    async fn mark_ambiguous(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
        error_class: RenegotiationErrorClass,
    ) -> Result<RenegotiationStoreTransition, AppError>;

    async fn mark_declined(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
        terminal_response_digest: &str,
    ) -> Result<DefiniteDeclineFinalization, AppError>;

    /// Reacquire the shared per-swap serialization and atomically commit both
    /// the Accepted journal transition and the legacy operational amount.
    async fn record_accepted(
        &self,
        evidence: &VerifiedRenegotiationAcceptance,
        expected_version: u64,
    ) -> Result<AcceptedRenegotiationFinalization, AppError>;
}

struct PostgresChainSwapRenegotiationStore<'a> {
    pool: &'a sqlx::PgPool,
}

#[async_trait]
impl ChainSwapRenegotiationStore for PostgresChainSwapRenegotiationStore<'_> {
    async fn get(
        &self,
        chain_swap_id: Uuid,
    ) -> Result<Option<ChainSwapRenegotiationOperation>, AppError> {
        db::get_chain_swap_renegotiation(self.pool, chain_swap_id)
            .await
            .map_err(|error| AppError::DbError(error.to_string()))
    }

    async fn persist_quoted(
        &self,
        identity: &RenegotiationIdentity,
    ) -> Result<ChainSwapRenegotiationOperation, AppError> {
        db::persist_quoted_chain_swap_renegotiation(self.pool, identity)
            .await
            .map_err(|error| AppError::DbError(error.to_string()))
    }

    async fn request_accept(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
    ) -> Result<RenegotiationStoreTransition, AppError> {
        db::request_chain_swap_renegotiation_accept(self.pool, identity, expected_version)
            .await
            .map(|outcome| match outcome.disposition {
                TransitionDisposition::Apply => {
                    RenegotiationStoreTransition::Applied(outcome.operation)
                }
                TransitionDisposition::ExactRetry => {
                    RenegotiationStoreTransition::ExactRetry(outcome.operation)
                }
            })
            .map_err(|error| AppError::DbError(error.to_string()))
    }

    async fn request_changed_accept(
        &self,
        current: &ChainSwapRenegotiationOperation,
        replacement: &RenegotiationIdentity,
    ) -> Result<RenegotiationStoreTransition, AppError> {
        let redrive = ChangedQuoteRedrive::new(
            current.identity.clone(),
            replacement.clone(),
            current.version,
        )
        .map_err(|error| AppError::ClaimError(error.to_string()))?;
        db::request_changed_chain_swap_renegotiation_accept(self.pool, &redrive)
            .await
            .map(|outcome| match outcome.disposition {
                TransitionDisposition::Apply => {
                    RenegotiationStoreTransition::Applied(outcome.operation)
                }
                TransitionDisposition::ExactRetry => {
                    RenegotiationStoreTransition::ExactRetry(outcome.operation)
                }
            })
            .map_err(|error| AppError::DbError(error.to_string()))
    }

    async fn mark_ambiguous(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
        error_class: RenegotiationErrorClass,
    ) -> Result<RenegotiationStoreTransition, AppError> {
        db::mark_chain_swap_renegotiation_ambiguous(
            self.pool,
            identity,
            expected_version,
            error_class,
        )
        .await
        .map(|outcome| match outcome.disposition {
            TransitionDisposition::Apply => {
                RenegotiationStoreTransition::Applied(outcome.operation)
            }
            TransitionDisposition::ExactRetry => {
                RenegotiationStoreTransition::ExactRetry(outcome.operation)
            }
        })
        .map_err(|error| AppError::DbError(error.to_string()))
    }

    async fn mark_declined(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
        terminal_response_digest: &str,
    ) -> Result<DefiniteDeclineFinalization, AppError> {
        use db::RecordDeclinedRenegotiationOutcome as DbOutcome;

        db::record_definite_declined_chain_swap_renegotiation(
            self.pool,
            identity,
            expected_version,
            terminal_response_digest,
        )
        .await
        .map(|outcome| match outcome {
            DbOutcome::Applied(operation) | DbOutcome::ExactRetry(operation) => {
                DefiniteDeclineFinalization::Declined(operation)
            }
            DbOutcome::Busy => DefiniteDeclineFinalization::Busy,
            DbOutcome::LiquidPathActive => DefiniteDeclineFinalization::LiquidPathActive,
        })
        .map_err(|error| AppError::DbError(error.to_string()))
    }

    async fn record_accepted(
        &self,
        evidence: &VerifiedRenegotiationAcceptance,
        expected_version: u64,
    ) -> Result<AcceptedRenegotiationFinalization, AppError> {
        use db::RecordAcceptedRenegotiationOutcome as DbOutcome;

        db::record_accepted_chain_swap_renegotiation(self.pool, evidence, expected_version)
            .await
            .map(|outcome| match outcome {
                DbOutcome::Applied(operation)
                | DbOutcome::ExactRetry(operation)
                | DbOutcome::RepairedParent(operation) => {
                    AcceptedRenegotiationFinalization::Committed(operation)
                }
                DbOutcome::Busy => AcceptedRenegotiationFinalization::Busy,
            })
            .map_err(|error| AppError::DbError(error.to_string()))
    }
}

fn renegotiation_error_class(error: ChainSwapQuoteProviderErrorKind) -> RenegotiationErrorClass {
    match error {
        ChainSwapQuoteProviderErrorKind::Timeout => RenegotiationErrorClass::Timeout,
        ChainSwapQuoteProviderErrorKind::Transport => RenegotiationErrorClass::Transport,
        ChainSwapQuoteProviderErrorKind::ProviderServerError => {
            RenegotiationErrorClass::ProviderServerError
        }
        ChainSwapQuoteProviderErrorKind::MalformedResponse => {
            RenegotiationErrorClass::MalformedResponse
        }
        ChainSwapQuoteProviderErrorKind::InvalidOrStaleQuote => {
            RenegotiationErrorClass::BackendDisagreement
        }
        ChainSwapQuoteProviderErrorKind::RefundAlreadySigned
        | ChainSwapQuoteProviderErrorKind::FundingNotAmountRejected
        | ChainSwapQuoteProviderErrorKind::ExpiryMarginTooShort
        | ChainSwapQuoteProviderErrorKind::AboveMaximum
        | ChainSwapQuoteProviderErrorKind::BelowMinimum
        | ChainSwapQuoteProviderErrorKind::UnknownProviderOutcome => {
            RenegotiationErrorClass::UnknownProviderOutcome
        }
    }
}

fn policy_evidence_digest(
    swap: &db::ChainSwapRecord,
    evidence: &VerifiedPrimaryFundingAmountMismatch,
    quote_amount_sat: u64,
    quote_response_sha256: &str,
    pair: &ChainPair,
    canonical_pair_sha256: &str,
) -> Result<String, AppError> {
    let primary_identity_sha256 = hex::encode(Sha256::digest(evidence.primary_identity.as_bytes()));
    let value = serde_json::json!({
        "policyVersion": RENEGOTIATION_POLICY_VERSION,
        "chainSwapId": swap.id,
        "boltzSwapIdSha256": hex::encode(Sha256::digest(swap.boltz_swap_id.as_bytes())),
        "primaryFunding": {
            "quality": "complete_and_agreed",
            "chainSwapId": evidence.chain_swap_id,
            "identitySha256": primary_identity_sha256,
            "evidenceSha256": evidence.primary_evidence_sha256,
            "observedAmountSat": evidence.observed_amount_sat,
            "expectedAmountSat": evidence.expected_amount_sat,
            "authoritativeBitcoinTip": evidence.authoritative_bitcoin_tip,
            "observedAtUnix": evidence.observed_at_unix,
        },
        "quote": {
            "amountSat": quote_amount_sat,
            "responseSha256": quote_response_sha256,
        },
        "pinnedPair": {
            "hash": pair.hash,
            "canonicalSha256": canonical_pair_sha256,
            "minimal": pair.limits.minimal,
            "maximal": pair.limits.maximal,
            "maximalZeroConf": pair.limits.maximal_zero_conf,
            "percentageFee": pair.fees.percentage,
            "serverMinerFee": pair.fees.miner_fees.server,
            "userClaimMinerFee": pair.fees.miner_fees.user.claim,
            "userLockupMinerFee": pair.fees.miner_fees.user.lockup,
        },
        "bitcoinTimeoutHeight": swap.creation_terms.as_ref().map(|terms| terms.btc_timeout_height),
        "minimumRemainingBitcoinBlocks": RENEGOTIATION_MIN_REMAINING_BTC_BLOCKS,
        "maximumPrimaryObservationAgeSeconds": RENEGOTIATION_MAX_PRIMARY_OBSERVATION_AGE_SECS,
    });
    crate::canonical_json::canonical_json_and_sha256(&value)
        .map(|(_, digest)| digest)
        .map_err(|error| {
            AppError::ClaimError(format!(
                "renegotiation policy evidence is not canonical: {error}"
            ))
        })
}

fn validate_renegotiation_preconditions(
    swap: &db::ChainSwapRecord,
    evidence: &VerifiedPrimaryFundingAmountMismatch,
) -> Result<(ChainPair, String), AppError> {
    evidence.validate()?;
    if evidence.chain_swap_id != swap.id {
        return Err(AppError::ClaimError(
            "primary funding evidence belongs to a different chain swap".into(),
        ));
    }
    let expected_amount_sat = u64::try_from(swap.user_lock_amount_sat).map_err(|_| {
        AppError::ClaimError("chain swap expected primary funding amount is invalid".into())
    })?;
    if evidence.expected_amount_sat != expected_amount_sat {
        return Err(AppError::ClaimError(
            "primary funding evidence disagrees with immutable swap terms".into(),
        ));
    }
    let creation = swap.creation_terms.as_ref().ok_or_else(|| {
        AppError::ClaimError("renegotiation requires immutable chain-swap creation terms".into())
    })?;
    let pair: ChainPair = serde_json::from_str(&creation.canonical_pair_quote_json)
        .map_err(|_| AppError::ClaimError("immutable chain-swap pair quote is malformed".into()))?;
    let (canonical_pair_json, canonical_pair_sha256) =
        crate::canonical_json::canonical_json_and_sha256(&pair).map_err(|error| {
            AppError::ClaimError(format!(
                "immutable chain-swap pair quote is invalid: {error}"
            ))
        })?;
    if canonical_pair_json != creation.canonical_pair_quote_json
        || pair.hash != creation.pinned_pair_hash
        || pair.limits.minimal == 0
        || pair.limits.maximal < pair.limits.minimal
        || evidence.observed_amount_sat < pair.limits.minimal
        || evidence.observed_amount_sat > pair.limits.maximal
    {
        return Err(AppError::ClaimError(
            "renegotiation evidence violates immutable provider pair limits".into(),
        ));
    }
    let remaining_blocks = creation
        .btc_timeout_height
        .checked_sub(i64::from(evidence.authoritative_bitcoin_tip))
        .ok_or_else(|| {
            AppError::ClaimError("renegotiation Bitcoin timeout has already passed".into())
        })?;
    if remaining_blocks <= RENEGOTIATION_MIN_REMAINING_BTC_BLOCKS {
        return Err(AppError::ClaimError(
            "renegotiation is inside the conservative Bitcoin timeout margin".into(),
        ));
    }
    Ok((pair, canonical_pair_sha256))
}

fn validate_renegotiation_policy(
    swap: &db::ChainSwapRecord,
    evidence: &VerifiedPrimaryFundingAmountMismatch,
    quote: &ChainSwapQuote,
) -> Result<RenegotiationIdentity, AppError> {
    let (pair, canonical_pair_sha256) = validate_renegotiation_preconditions(swap, evidence)?;
    if quote.amount_sat == 0
        || quote.amount_sat > i64::MAX as u64
        || quote.amount_sat > evidence.observed_amount_sat
        || !is_lower_sha256(&quote.response_sha256)
    {
        return Err(AppError::ClaimError(
            "renegotiation quote violates the verified funding value boundary".into(),
        ));
    }

    let policy_digest = policy_evidence_digest(
        swap,
        evidence,
        quote.amount_sat,
        &quote.response_sha256,
        &pair,
        &canonical_pair_sha256,
    )?;
    let observed_at_unix = current_unix_time()?;
    RenegotiationIdentity::new(
        swap.id,
        quote.amount_sat,
        quote.response_sha256.clone(),
        observed_at_unix,
        RENEGOTIATION_POLICY_VERSION,
        policy_digest,
        observed_at_unix,
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))
}

fn same_validated_quote(
    current: &RenegotiationIdentity,
    candidate: &RenegotiationIdentity,
) -> bool {
    current.chain_swap_id == candidate.chain_swap_id
        && current.quoted_actual_amount_sat == candidate.quoted_actual_amount_sat
        && current.quote_response_digest() == candidate.quote_response_digest()
        && current.policy_version() == candidate.policy_version()
}

fn provider_error(error: &ChainSwapQuoteProviderError) -> AppError {
    AppError::BoltzError(error.to_string())
}

async fn load_or_observe_renegotiation<S, P, O>(
    store: &S,
    provider: &P,
    observer: &O,
    swap: &db::ChainSwapRecord,
    evidence: &VerifiedPrimaryFundingAmountMismatch,
) -> Result<Option<ChainSwapRenegotiationOperation>, AppError>
where
    S: ChainSwapRenegotiationStore,
    P: ChainSwapRenegotiationProvider,
    O: RenegotiationCheckpointObserver,
{
    if let Some(current) = store.get(swap.id).await? {
        if current.state.is_terminal() {
            return Ok(Some(current));
        }
        let persisted_quote = ChainSwapQuote {
            amount_sat: current.identity.quoted_actual_amount_sat,
            response_sha256: current.identity.quote_response_digest().to_owned(),
        };
        let current_policy = validate_renegotiation_policy(swap, evidence, &persisted_quote)?;
        if current.identity.quoted_actual_amount_sat != current_policy.quoted_actual_amount_sat
            || current.identity.quote_response_digest() != current_policy.quote_response_digest()
            || current.identity.policy_version() != current_policy.policy_version()
        {
            return Err(AppError::ClaimError(
                "persisted renegotiation quote disagrees with current verified policy evidence"
                    .into(),
            ));
        }
        return Ok(Some(current));
    }

    let quote = match provider.get_quote(&swap.boltz_swap_id).await {
        Ok(quote) => quote,
        Err(error) if error.kind.is_explicit_non_eligibility() => {
            tracing::info!(
                event = "chain_swap_renegotiation_explicitly_unavailable",
                swap_id = %swap.boltz_swap_id,
                reason = %error,
                "verified wrong-amount swap is not eligible for provider renegotiation"
            );
            return Ok(None);
        }
        Err(error) => return Err(provider_error(&error)),
    };
    let identity = validate_renegotiation_policy(swap, evidence, &quote)?;
    observer.reached(RenegotiationCheckpoint::QuoteObservedBeforePersistence)?;
    let operation = store.persist_quoted(&identity).await?;
    observer.reached(RenegotiationCheckpoint::QuotePersisted)?;
    Ok(Some(operation))
}

async fn repair_or_confirm_accepted<S: ChainSwapRenegotiationStore>(
    store: &S,
    operation: &ChainSwapRenegotiationOperation,
) -> Result<AcceptedRenegotiationFinalization, AppError> {
    let terminal_response_digest = operation.terminal_response_digest().ok_or_else(|| {
        AppError::ClaimError("accepted renegotiation is missing terminal evidence".into())
    })?;
    let evidence = VerifiedRenegotiationAcceptance::new(
        operation.identity.clone(),
        operation.identity.quoted_actual_amount_sat,
        operation.identity.quote_response_digest(),
        terminal_response_digest,
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))?;
    let expected_version = operation.version.checked_sub(1).ok_or_else(|| {
        AppError::ClaimError("accepted renegotiation has an invalid persisted version".into())
    })?;
    store.record_accepted(&evidence, expected_version).await
}

/// Execute the one #38 quote mutation from independently verified primary
/// funding evidence. Every store call completes before provider I/O begins;
/// accepted finalization reacquires `chain-claim:<id>` inside the production
/// store and atomically writes both journal and parent operational amount.
async fn try_renegotiate_chain_swap_with_verified_mismatch_using<S, P, O>(
    store: &S,
    provider: &P,
    observer: &O,
    swap: &db::ChainSwapRecord,
    boltz_status: &str,
    evidence: &VerifiedPrimaryFundingAmountMismatch,
) -> Result<bool, AppError>
where
    S: ChainSwapRenegotiationStore,
    P: ChainSwapRenegotiationProvider,
    O: RenegotiationCheckpointObserver,
{
    if boltz_status != "transaction.lockupFailed" {
        // Unrelated provider failures never reach a quote API and cannot be
        // transformed into recovery eligibility by this executor.
        return Ok(true);
    }
    if let Some(persisted) = store.get(swap.id).await? {
        if persisted.state == RenegotiationState::Accepted {
            return match repair_or_confirm_accepted(store, &persisted).await? {
                AcceptedRenegotiationFinalization::Committed(_)
                | AcceptedRenegotiationFinalization::Busy => Ok(true),
            };
        }
        if persisted.state == RenegotiationState::Declined {
            return Ok(false);
        }
    }
    evidence.validate()?;
    if evidence.chain_swap_id != swap.id {
        return Err(AppError::ClaimError(
            "primary funding evidence belongs to a different chain swap".into(),
        ));
    }
    // Reject stale tips, unsafe expiry margin, replayed evidence, and pinned
    // pair/limit disagreement before the first provider request.
    validate_renegotiation_preconditions(swap, evidence)?;

    let Some(mut operation) =
        load_or_observe_renegotiation(store, provider, observer, swap, evidence).await?
    else {
        return Ok(false);
    };
    let mut changed_quote_redriven = false;
    let mut accept_prepared_in_process = false;

    loop {
        match operation.state {
            RenegotiationState::Accepted => {
                return match repair_or_confirm_accepted(store, &operation).await? {
                    AcceptedRenegotiationFinalization::Committed(_) => Ok(true),
                    AcceptedRenegotiationFinalization::Busy => Ok(true),
                };
            }
            RenegotiationState::Declined => return Ok(false),
            RenegotiationState::Quoted => {
                let (requested, applied) = store
                    .request_accept(&operation.identity, operation.version)
                    .await?
                    .into_parts();
                if !applied {
                    return Ok(true);
                }
                operation = requested;
                accept_prepared_in_process = true;
            }
            RenegotiationState::Ambiguous => {
                let quote = match provider.get_quote(&swap.boltz_swap_id).await {
                    Ok(quote) => quote,
                    Err(error) if error.kind.is_explicit_non_eligibility() => {
                        return Err(provider_error(&error));
                    }
                    Err(error) => return Err(provider_error(&error)),
                };
                let replacement = validate_renegotiation_policy(swap, evidence, &quote)?;
                let requested = if same_validated_quote(&operation.identity, &replacement) {
                    store
                        .request_accept(&operation.identity, operation.version)
                        .await?
                } else {
                    store
                        .request_changed_accept(&operation, &replacement)
                        .await?
                };
                let (requested, applied) = requested.into_parts();
                if !applied {
                    return Ok(true);
                }
                operation = requested;
                accept_prepared_in_process = true;
            }
            RenegotiationState::AcceptRequested => {
                if !accept_prepared_in_process {
                    let requested_at = operation.accept_requested_at_unix.ok_or_else(|| {
                        AppError::ClaimError(
                            "accept-requested renegotiation has no request timestamp".into(),
                        )
                    })?;
                    if current_unix_time()?.saturating_sub(requested_at)
                        <= RENEGOTIATION_ACCEPT_REQUEST_STALE_AFTER_SECS
                    {
                        // Another worker may still be inside the bounded 10s
                        // POST. Fresh intent owns progress and must not be
                        // redriven concurrently.
                        return Ok(true);
                    }
                    let (ambiguous, applied) = store
                        .mark_ambiguous(
                            &operation.identity,
                            operation.version,
                            RenegotiationErrorClass::UnknownProviderOutcome,
                        )
                        .await?
                        .into_parts();
                    if !applied {
                        return Ok(true);
                    }
                    operation = ambiguous;
                    continue;
                }
            }
        }
        debug_assert!(accept_prepared_in_process);
        accept_prepared_in_process = false;
        observer.reached(RenegotiationCheckpoint::AcceptRequested)?;

        match provider
            .accept_quote(
                &swap.boltz_swap_id,
                operation.identity.quoted_actual_amount_sat,
            )
            .await
        {
            Ok(terminal_response_digest) => {
                observer.reached(RenegotiationCheckpoint::ProviderAcceptedResponse)?;
                let accepted = VerifiedRenegotiationAcceptance::new(
                    operation.identity.clone(),
                    operation.identity.quoted_actual_amount_sat,
                    operation.identity.quote_response_digest(),
                    terminal_response_digest,
                )
                .map_err(|error| AppError::ClaimError(error.to_string()))?;
                observer.reached(RenegotiationCheckpoint::BeforeAcceptanceCommit)?;
                return match store.record_accepted(&accepted, operation.version).await {
                    Ok(AcceptedRenegotiationFinalization::Committed(_)) => {
                        observer.reached(RenegotiationCheckpoint::AcceptanceCommitted)?;
                        Ok(true)
                    }
                    Ok(AcceptedRenegotiationFinalization::Busy) => Ok(true),
                    Err(commit_error) => {
                        // The provider response is definite but the local
                        // transaction result is not. Re-read before deciding;
                        // never repeat accept directly from this branch.
                        match store.get(swap.id).await {
                            Ok(Some(current)) if current.state == RenegotiationState::Accepted => {
                                observer.reached(RenegotiationCheckpoint::AcceptanceCommitted)?;
                                Ok(true)
                            }
                            Ok(Some(current))
                                if current.state == RenegotiationState::AcceptRequested =>
                            {
                                let _ = store
                                    .mark_ambiguous(
                                        &current.identity,
                                        current.version,
                                        RenegotiationErrorClass::LocalCommitUncertainty,
                                    )
                                    .await;
                                Err(commit_error)
                            }
                            Ok(Some(_)) | Ok(None) | Err(_) => Err(commit_error),
                        }
                    }
                };
            }
            Err(error) if error.kind.is_explicit_non_eligibility() => {
                let terminal_digest =
                    error.terminal_evidence_sha256.as_deref().ok_or_else(|| {
                        AppError::ClaimError(
                            "explicit provider decline is missing canonical evidence".into(),
                        )
                    })?;
                return match store
                    .mark_declined(&operation.identity, operation.version, terminal_digest)
                    .await?
                {
                    DefiniteDeclineFinalization::Declined(operation) => {
                        debug_assert_eq!(operation.state, RenegotiationState::Declined);
                        Ok(false)
                    }
                    DefiniteDeclineFinalization::Busy
                    | DefiniteDeclineFinalization::LiquidPathActive => Ok(true),
                };
            }
            Err(error) => {
                let invalid_or_stale =
                    error.kind == ChainSwapQuoteProviderErrorKind::InvalidOrStaleQuote;
                let (ambiguous, applied) = store
                    .mark_ambiguous(
                        &operation.identity,
                        operation.version,
                        renegotiation_error_class(error.kind),
                    )
                    .await?
                    .into_parts();
                if !applied {
                    return Ok(true);
                }
                operation = ambiguous;
                if !invalid_or_stale || changed_quote_redriven {
                    return Err(provider_error(&error));
                }
                changed_quote_redriven = true;
                let replacement_quote = provider
                    .get_quote(&swap.boltz_swap_id)
                    .await
                    .map_err(|replacement_error| provider_error(&replacement_error))?;
                let replacement =
                    validate_renegotiation_policy(swap, evidence, &replacement_quote)?;
                let requested = if same_validated_quote(&operation.identity, &replacement) {
                    store
                        .request_accept(&operation.identity, operation.version)
                        .await?
                } else {
                    store
                        .request_changed_accept(&operation, &replacement)
                        .await?
                };
                let (requested, applied) = requested.into_parts();
                if !applied {
                    return Ok(true);
                }
                operation = requested;
                accept_prepared_in_process = true;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenegotiationAdoptionOutcome {
    NotApplicable,
    OwnsProgress,
    ExplicitlyUnavailable,
}

async fn adopt_verified_primary_funding_for_renegotiation_using<S, P, O>(
    store: &S,
    provider: &P,
    observer: &O,
    swap: &db::ChainSwapRecord,
    boltz_status: &str,
    observation: &VerifiedPrimaryFundingObservation,
) -> Result<RenegotiationAdoptionOutcome, AppError>
where
    S: ChainSwapRenegotiationStore,
    P: ChainSwapRenegotiationProvider,
    O: RenegotiationCheckpointObserver,
{
    if boltz_status != "transaction.lockupFailed" {
        return Ok(RenegotiationAdoptionOutcome::NotApplicable);
    }
    let Some(mismatch) = observation.mismatch() else {
        // Executable correct-amount boundary: complete/agreed evidence is
        // accepted, but neither GET nor POST is reachable.
        return Ok(RenegotiationAdoptionOutcome::NotApplicable);
    };
    if try_renegotiate_chain_swap_with_verified_mismatch_using(
        store,
        provider,
        observer,
        swap,
        boltz_status,
        mismatch,
    )
    .await?
    {
        Ok(RenegotiationAdoptionOutcome::OwnsProgress)
    } else {
        Ok(RenegotiationAdoptionOutcome::ExplicitlyUnavailable)
    }
}

/// Narrow #139 adoption seam. It accepts only a verified primary observation;
/// exact funding is NotApplicable without provider I/O, while a mismatch is
/// routed through the crash-safe journal executor.
pub(crate) async fn adopt_verified_primary_funding_for_renegotiation(
    state: &AppState,
    swap: &db::ChainSwapRecord,
    boltz_status: &str,
    observation: &VerifiedPrimaryFundingObservation,
) -> Result<RenegotiationAdoptionOutcome, AppError> {
    let store = PostgresChainSwapRenegotiationStore { pool: &state.db };
    adopt_verified_primary_funding_for_renegotiation_using(
        &store,
        state.boltz.as_ref(),
        &NoopRenegotiationCheckpointObserver,
        swap,
        boltz_status,
        observation,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerLockRenegotiationOutcome {
    LiquidPathWon,
    Observe,
}

async fn reconcile_renegotiation_from_verified_server_lock_using<S: ChainSwapRenegotiationStore>(
    store: &S,
    swap: &db::ChainSwapRecord,
    evidence: &VerifiedLiquidServerLockProgression,
) -> Result<ServerLockRenegotiationOutcome, AppError> {
    evidence.validate()?;
    if evidence.chain_swap_id != swap.id {
        return Err(AppError::ClaimError(
            "Liquid server-lock evidence belongs to a different chain swap".into(),
        ));
    }
    let Some(operation) = store.get(swap.id).await? else {
        return Ok(ServerLockRenegotiationOutcome::Observe);
    };
    if evidence.observed_amount_sat != operation.identity.quoted_actual_amount_sat {
        return Err(AppError::ClaimError(
            "Liquid server-lock amount disagrees with the active renegotiation quote".into(),
        ));
    }
    if operation.state == RenegotiationState::Declined
        || operation.state == RenegotiationState::Quoted
    {
        tracing::error!(
            event = "chain_swap_server_lock_contradicts_renegotiation_journal",
            swap_id = %swap.boltz_swap_id,
            journal_state = %operation.state,
            "verified Liquid server-lock progression wins; retaining immutable journal contradiction for operator evidence"
        );
        return Ok(ServerLockRenegotiationOutcome::LiquidPathWon);
    }
    let terminal_digest = if operation.state == RenegotiationState::Accepted {
        operation
            .terminal_response_digest()
            .ok_or_else(|| {
                AppError::ClaimError("accepted renegotiation lacks terminal evidence".into())
            })?
            .to_owned()
    } else {
        evidence.terminal_digest()?
    };
    let acceptance = VerifiedRenegotiationAcceptance::new(
        operation.identity.clone(),
        evidence.observed_amount_sat,
        operation.identity.quote_response_digest(),
        terminal_digest,
    )
    .map_err(|error| AppError::ClaimError(error.to_string()))?;
    let expected_version = if operation.state == RenegotiationState::Accepted {
        operation.version.checked_sub(1).ok_or_else(|| {
            AppError::ClaimError("accepted renegotiation has an invalid version".into())
        })?
    } else {
        operation.version
    };
    match store.record_accepted(&acceptance, expected_version).await? {
        AcceptedRenegotiationFinalization::Committed(_) => {
            Ok(ServerLockRenegotiationOutcome::LiquidPathWon)
        }
        AcceptedRenegotiationFinalization::Busy => Ok(ServerLockRenegotiationOutcome::Observe),
    }
}

/// Reconcile a requested/ambiguous accept from independently verified Liquid
/// chain progression. This performs no quote or accept provider call.
pub(crate) async fn reconcile_renegotiation_from_verified_server_lock(
    state: &AppState,
    swap: &db::ChainSwapRecord,
    evidence: &VerifiedLiquidServerLockProgression,
) -> Result<ServerLockRenegotiationOutcome, AppError> {
    let store = PostgresChainSwapRenegotiationStore { pool: &state.db };
    reconcile_renegotiation_from_verified_server_lock_using(&store, swap, evidence).await
}

pub(crate) async fn try_renegotiate_chain_swap_with_verified_mismatch(
    state: &AppState,
    swap: &db::ChainSwapRecord,
    boltz_status: &str,
    evidence: &VerifiedPrimaryFundingAmountMismatch,
) -> Result<bool, AppError> {
    let store = PostgresChainSwapRenegotiationStore { pool: &state.db };
    try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        state.boltz.as_ref(),
        &NoopRenegotiationCheckpointObserver,
        swap,
        boltz_status,
        evidence,
    )
    .await
}

pub(crate) async fn handle_chain_swap_webhook(
    state: &AppState,
    swap: &db::ChainSwapRecord,
    boltz_status: &str,
) -> Result<(), AppError> {
    handle_chain_swap_webhook_with_provider_evidence(state, swap, boltz_status, None).await
}

/// Shared chain-swap provider-observation path with an explicit independently
/// assembled evidence handoff. Ordinary webhook/reconciler callers pass no
/// snapshot and therefore observe fail-closed until the runtime evidence
/// collector supplies one.
#[doc(hidden)]
pub async fn handle_chain_swap_webhook_with_provider_evidence(
    state: &AppState,
    swap: &db::ChainSwapRecord,
    boltz_status: &str,
    provider_evidence: Option<ChainSwapProviderEvidence<'_>>,
) -> Result<(), AppError> {
    let observed_local_status = swap
        .parsed_status()
        .map_err(|error| AppError::DbError(format!("invalid persisted chain status: {error}")))?;
    if boltz_status == "swap.expired" && observed_local_status == ChainSwapStatus::Pending {
        let outcome = match provider_evidence {
            Some(evidence) => {
                apply_chain_swap_provider_effect_with_evidence(
                    &state.db,
                    swap.id,
                    boltz_status,
                    evidence,
                )
                .await?
            }
            None => apply_chain_swap_provider_effect(state, swap.id, boltz_status).await?,
        };
        match outcome {
            ChainSwapProviderApplyOutcome::Finalized => {
                tracing::info!(
                    event = "chain_swap_unfunded_expiry_finalized",
                    swap_id = %swap.boltz_swap_id,
                    "complete independent evidence proved the pending chain swap unfunded"
                );
            }
            ChainSwapProviderApplyOutcome::AlreadyFinalized => {
                tracing::debug!(
                    swap_id = %swap.boltz_swap_id,
                    "duplicate unfunded expiry evidence left the chain swap finalized"
                );
            }
            ChainSwapProviderApplyOutcome::IntegrityHold => {
                tracing::error!(
                    event = "chain_swap_provider_evidence_integrity_hold",
                    swap_id = %swap.boltz_swap_id,
                    "independent chain evidence conflicts with provider expiry; automation stopped"
                );
            }
            ChainSwapProviderApplyOutcome::Reconcile(action) => {
                tracing::info!(
                    event = "chain_swap_provider_evidence_reconcile",
                    swap_id = %swap.boltz_swap_id,
                    ?action,
                    "provider expiry reduced to an action owned by a later evidence executor"
                );
            }
            ChainSwapProviderApplyOutcome::Busy => {
                tracing::debug!(
                    swap_id = %swap.boltz_swap_id,
                    "chain swap execution lock is busy; later reconciliation will retry expiry evidence"
                );
            }
            ChainSwapProviderApplyOutcome::Missing => {
                tracing::debug!(
                    swap_id = %swap.boltz_swap_id,
                    "chain swap disappeared before expiry evidence could be applied"
                );
            }
            ChainSwapProviderApplyOutcome::StateChanged(status) => {
                tracing::debug!(
                    swap_id = %swap.boltz_swap_id,
                    %status,
                    "unfunded expiry evidence arrived after the pending branch changed"
                );
            }
            ChainSwapProviderApplyOutcome::Observed => {
                tracing::debug!(
                    event = "chain_swap_provider_expiry_observed",
                    swap_id = %swap.boltz_swap_id,
                    "provider expiry lacks complete independent chain evidence; observing without mutation or claim redrive"
                );
            }
        }
        return Ok(());
    }

    let Some(input) = chain_swap_provider_input(boltz_status) else {
        tracing::debug!(
            "ignoring chain-swap webhook status: {} for {}",
            boltz_status,
            swap.boltz_swap_id
        );
        return Ok(());
    };
    let transition = db::apply_chain_swap_provider_status(&state.db, swap.id, input)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| {
            AppError::DbError(format!(
                "chain swap disappeared while applying provider status: {}",
                swap.id
            ))
        })?;
    let status = transition.current_status;

    if status.is_terminal() {
        tracing::debug!(
            "ignoring webhook for terminal chain swap {} ({})",
            swap.boltz_swap_id,
            status
        );
        return Ok(());
    }

    if status == ChainSwapStatus::Refunding {
        // A customer self-claim refund is in flight (Phase 4). The refund
        // executor owns this row under the advisory lock; the webhook/reconciler
        // path must NOT touch it — regressing it to a lifecycle state or marking
        // refund_due mid-broadcast would break the double-payout guard (G12). A
        // `transaction.claimed` here is a genuine anomaly (Boltz settled a swap
        // we are refunding) — surface it loudly for operator investigation.
        if boltz_status == "transaction.claimed" {
            tracing::error!(
                event = "chain_swap_claimed_while_refunding",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "boltz reports claimed while a refund is in flight — potential double payout, investigate immediately (operator P1)"
            );
        } else {
            tracing::debug!(
                "ignoring {} for refunding chain swap {}",
                boltz_status,
                swap.boltz_swap_id
            );
        }
        return Ok(());
    }

    if status == ChainSwapStatus::RefundDue {
        if matches!(
            input,
            db::ChainSwapProviderStatusInput::UserLockMempool
                | db::ChainSwapProviderStatusInput::UserLockConfirmed
        ) {
            // A RefundDue row may have been selected by the shared evidence
            // reducer or may predate this fail-closed fold. Re-drive the invoice
            // projection for an independently delivered user-lock hint, but do
            // not let the hint create or strengthen recovery eligibility.
            invoice::flip_invoice_on_bitcoin_boltz_in_progress(
                &state.db,
                swap.id,
                Some(swap.invoice_id),
                &swap.boltz_swap_id,
            )
            .await;
        }
        // A late server-lock observation has already moved `refund_due` back to
        // the normal Liquid branch atomically. Remaining evidence cannot prove
        // that recovery is ineligible, so keep the provisional recovery state.
        if boltz_status == "transaction.claimed" {
            tracing::warn!(
                event = "chain_swap_refund_due_but_claimed",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "chain swap is refund_due but Boltz now reports claimed; refund must be gated on Boltz not-claimed before broadcast (Phase 4)"
            );
        } else {
            tracing::debug!(
                "ignoring {} for refund_due chain swap {}",
                boltz_status,
                swap.boltz_swap_id
            );
        }
        return Ok(());
    }

    if boltz_status == "transaction.claimed" {
        tracing::info!(
            event = "chain_swap_boltz_claimed_observed",
            swap_id = %swap.boltz_swap_id,
            local_status = %status,
            "boltz reports chain swap claimed; local claim path remains authoritative for invoice accounting"
        );
        try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
        return Ok(());
    }

    if boltz_status == "swap.expired" {
        // Preserve the existing funded Liquid path in this narrow slice. The
        // new reducer intercept above only retires or observes locally pending
        // offers; a server lock already seen by the runtime remains claimable.
        tracing::warn!(
            event = "chain_swap_expired_webhook",
            swap_id = %swap.boltz_swap_id,
            local_status = %status,
            cooperative_refused = transition.cooperative_refused,
            "chain swap.expired received; retaining the forward-most funded branch"
        );
        try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
        return Ok(());
    }

    if boltz_status == "transaction.lockupFailed"
        && matches!(
            status,
            ChainSwapStatus::Pending
                | ChainSwapStatus::UserLockMempool
                | ChainSwapStatus::UserLockConfirmed
        )
    {
        // This webhook is only a provider hint. Exact base 72d76ea has no
        // independently verified primary-funding value, so it must make zero
        // quote calls and cannot authorize FundingFailed/refund_due. #139 will
        // map its complete/agreed projection into the guarded entrypoint above.
        tracing::warn!(
            event = "chain_swap_renegotiation_waiting_for_verified_funding",
            swap_id = %swap.boltz_swap_id,
            invoice_id = %swap.invoice_id,
            "lockupFailed observed without complete/agreed primary funding evidence; retaining Observe and blocking fallback"
        );
        return Ok(());
    }

    if matches!(
        boltz_status,
        "transaction.lockupFailed" | "transaction.failed" | "transaction.refunded"
    ) {
        // Pending plus a provider failure is not proof of payer funding. A
        // server-lock/claim branch is stronger local evidence and remains
        // authoritative; re-drive it instead of guessing recovery success.
        if matches!(
            status,
            ChainSwapStatus::ServerLockMempool
                | ChainSwapStatus::ServerLockConfirmed
                | ChainSwapStatus::Claiming
                | ChainSwapStatus::ClaimFailed
        ) {
            tracing::warn!(
                event = "chain_swap_provider_failure_after_server_lock",
                swap_id = %swap.boltz_swap_id,
                local_status = %status,
                boltz_status,
                "provider failure disagrees with the local Liquid branch; preserving and redriving claim"
            );
            try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
        } else {
            tracing::debug!(
                swap_id = %swap.boltz_swap_id,
                local_status = %status,
                boltz_status,
                "provider failure did not add local funding evidence; observing without authorizing recovery"
            );
        }
        return Ok(());
    }

    let next = match input {
        db::ChainSwapProviderStatusInput::UserLockMempool => ChainSwapStatus::UserLockMempool,
        db::ChainSwapProviderStatusInput::UserLockConfirmed => ChainSwapStatus::UserLockConfirmed,
        db::ChainSwapProviderStatusInput::ServerLockMempool => ChainSwapStatus::ServerLockMempool,
        db::ChainSwapProviderStatusInput::ServerLockConfirmed => {
            ChainSwapStatus::ServerLockConfirmed
        }
        db::ChainSwapProviderStatusInput::Observe
        | db::ChainSwapProviderStatusInput::SwapExpired
        | db::ChainSwapProviderStatusInput::FundingFailed => return Ok(()),
    };

    if transition.changed {
        tracing::info!(
            event = "chain_swap_webhook",
            swap_id = %swap.boltz_swap_id,
            from = %transition.previous_status,
            to = %transition.current_status,
            boltz_status,
            "chain swap provider status advanced atomically"
        );
    } else {
        tracing::debug!(
            swap_id = %swap.boltz_swap_id,
            local_status = %transition.current_status,
            boltz_status,
            "duplicate/reordered chain swap evidence left state unchanged"
        );
    }

    if matches!(
        next,
        ChainSwapStatus::UserLockMempool
            | ChainSwapStatus::UserLockConfirmed
            | ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
    ) {
        invoice::flip_invoice_on_bitcoin_boltz_in_progress(
            &state.db,
            swap.id,
            Some(swap.invoice_id),
            &swap.boltz_swap_id,
        )
        .await;
    }

    if matches!(
        transition.current_status,
        ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::Claiming
            | ChainSwapStatus::ClaimFailed
    ) {
        try_claim_chain_swap_with_retry(swap, ClaimAttemptContext::from_state(state)).await;
    }
    Ok(())
}

fn chain_swap_provider_input(boltz_status: &str) -> Option<db::ChainSwapProviderStatusInput> {
    match boltz_status {
        "swap.created" => None,
        "transaction.mempool" => Some(db::ChainSwapProviderStatusInput::UserLockMempool),
        "transaction.confirmed" => Some(db::ChainSwapProviderStatusInput::UserLockConfirmed),
        "transaction.server.mempool" => Some(db::ChainSwapProviderStatusInput::ServerLockMempool),
        "transaction.server.confirmed" => {
            Some(db::ChainSwapProviderStatusInput::ServerLockConfirmed)
        }
        // Locally pending `swap.expired` observations are intercepted before
        // this mapper and reduced from independently assembled evidence. Every
        // other raw expiry remains an observation-only trigger.
        // 0-conf rejection is NOT a failure: Boltz just wants a confirmation
        // before proceeding, then the swap continues normally. Treat it as a
        // (re)sighting of the user lockup in the mempool — previously this was
        // terminalized as `lockup_failed`, killing a payment that would settle.
        "transaction.zeroconf.rejected" => Some(db::ChainSwapProviderStatusInput::UserLockMempool),
        "swap.expired" => Some(db::ChainSwapProviderStatusInput::Observe),
        // The durable migration-056 renegotiation journal owns quote/accept
        // execution. Bare provider status cannot start that network workflow.
        "transaction.lockupFailed" | "transaction.claimed" => {
            Some(db::ChainSwapProviderStatusInput::Observe)
        }
        "transaction.failed" | "transaction.refunded" => {
            Some(db::ChainSwapProviderStatusInput::Observe)
        }
        _ => None,
    }
}

struct ClaimAttemptContext<'a> {
    pool: &'a sqlx::PgPool,
    claim_clients: Option<&'a LiquidClaimClientFactory>,
    boltz_url: &'a str,
    max_claim_attempts: i32,
    utxo_backend: Option<&'a Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_runtime: &'a FeeRuntime,
}

impl<'a> ClaimAttemptContext<'a> {
    fn from_state(state: &'a AppState) -> Self {
        Self {
            pool: &state.db,
            claim_clients: state.liquid_claim_client_factory.as_deref(),
            boltz_url: &state.config.boltz.api_url,
            max_claim_attempts: state.config.claim.max_claim_attempts,
            utxo_backend: state.utxo_backend.as_ref(),
            tolerances: db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
            fee_runtime: state.fee_runtime.as_ref(),
        }
    }
}

async fn try_claim_chain_swap_with_retry(
    swap: &db::ChainSwapRecord,
    context: ClaimAttemptContext<'_>,
) {
    let fee_decision = context
        .fee_runtime
        .liquid_construction_decision_now(FeeConstructionPurpose::ChainLiquidClaim)
        .ok();
    match claim_chain_swap(
        context.pool,
        swap.id,
        context.claim_clients,
        context.boltz_url,
        context.max_claim_attempts,
        context.utxo_backend,
        context.tolerances,
        fee_decision.as_ref().map(|(decision, _)| decision),
        fee_decision.as_ref().map(|(_, record)| record),
    )
    .await
    {
        Ok(ClaimOutcome::Broadcast) => {}
        Ok(ClaimOutcome::AlreadyTerminal) => {}
        Ok(ClaimOutcome::SkippedLockHeld) => {
            tracing::debug!(
                "webhook chain-swap claim skipped (lock held) for swap {}",
                swap.boltz_swap_id
            );
        }
        Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
            tracing::info!(
                swap_id = %swap.boltz_swap_id,
                reason,
                "webhook chain-swap claim remains pending"
            );
        }
        Err(e) => {
            tracing::warn!(
                "webhook chain-swap claim attempt failed for {}: {e}",
                swap.boltz_swap_id
            );
        }
    }
}

/// Outcome of a single `claim_swap` invocation.
#[derive(Debug, Clone, Copy)]
pub enum ClaimOutcome {
    /// Constructed (or re-broadcast) a claim tx and the backend accepted it
    /// (or independently recovered the exact journaled txid). For chain swaps,
    /// this means in-flight `claiming`; observation owns accounting/finality.
    Broadcast,
    /// Another process owns or just superseded this claim invocation; the
    /// next scheduled sweep (or webhook delivery) will retry live state.
    SkippedLockHeld,
    /// Row reached a terminal state (`Claimed`, `Expired`, `ClaimStuck`,
    /// `LockupRefunded`) — nothing to do.
    AlreadyTerminal,
    /// No accepted live or recent same-rail Liquid fee decision exists. No
    /// bytes or retry-failure state were written; a later sweep may retry.
    PendingFeeUnavailable { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimFailureScope {
    Local,
    Systemic,
}

/// Health of one rail-specific claimer sweep. A malformed persisted
/// obligation must remain isolated, while database and provider-wide failures
/// make the worker cycle unhealthy for admission hysteresis.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ClaimCycleHealth {
    systemic_failure: bool,
}

impl ClaimCycleHealth {
    fn observe_error(&mut self, error: &AppError) {
        if classify_claim_failure(error) == ClaimFailureScope::Systemic {
            self.systemic_failure = true;
        }
    }

    fn report(self, reporter: &WorkerReporter) {
        if self.systemic_failure {
            reporter.cycle_failed();
        } else {
            reporter.cycle_succeeded();
        }
    }
}

fn classify_claim_failure(error: &AppError) -> ClaimFailureScope {
    match error {
        AppError::DbError(_) | AppError::ElectrumError(_) | AppError::BoltzError(_) => {
            ClaimFailureScope::Systemic
        }
        AppError::ClaimError(message) => {
            if is_cooperative_refusal(error) || is_local_claim_error(message) {
                ClaimFailureScope::Local
            } else {
                // Unknown claim-path errors fail closed. Known malformed-data and
                // business-local shapes are enumerated below; the remaining
                // errors are connection, provider, construction, or broadcast
                // failures shared by the worker's operating environment.
                ClaimFailureScope::Systemic
            }
        }
        _ => ClaimFailureScope::Local,
    }
}

fn is_local_claim_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "swap_records row gone:",
        "swap not found:",
        "chain swap not found:",
        "invoice not found:",
        "user not found:",
        "address allocation failed:",
        "address index overflow",
        "decode persisted",
        "missing ",
        "invalid ",
        "swap script build failed:",
        "chain claim script build failed:",
        "chain lockup script build failed:",
    ]
    .iter()
    .any(|prefix| message.starts_with(prefix))
        || message.contains(" has no ")
        || message.contains(" no nym and no invoice ")
}

/// Webhook-path single-shot claim attempt. Errors are recorded by
/// `claim_swap` itself (which calls `db::record_claim_failure` to
/// schedule the next retry on the documented backoff). The background
/// sweep is the retry mechanism — the webhook handler does not loop.
///
/// The previous implementation looped 3 times with 2s delays inside the
/// webhook handler. That blocked the response to Boltz for up to ~10
/// seconds (Boltz's webhook timeout is 15s) and overlapped poorly with
/// the background sweep's retry tick — every webhook produced 4 claim
/// attempts before the sweep even started.
async fn try_claim_with_retry(swap: &db::SwapRecord, context: ClaimAttemptContext<'_>) {
    let fee_decision = context
        .fee_runtime
        .liquid_construction_decision_now(FeeConstructionPurpose::ReverseLiquidClaim)
        .ok();
    match claim_swap(
        context.pool,
        swap.id,
        context.claim_clients,
        context.boltz_url,
        context.max_claim_attempts,
        context.utxo_backend,
        context.tolerances,
        fee_decision.as_ref().map(|(decision, _)| decision),
        fee_decision.as_ref().map(|(_, record)| record),
    )
    .await
    {
        Ok(ClaimOutcome::Broadcast) => {}
        Ok(ClaimOutcome::AlreadyTerminal) => {}
        Ok(ClaimOutcome::SkippedLockHeld) => {
            tracing::debug!(
                "webhook claim skipped (lock held) for swap {}",
                swap.boltz_swap_id
            );
        }
        Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
            tracing::info!(
                swap_id = %swap.boltz_swap_id,
                reason,
                "webhook reverse-swap claim remains pending"
            );
        }
        Err(e) => {
            tracing::warn!(
                "webhook claim attempt failed for swap {}: {e}",
                swap.boltz_swap_id
            );
        }
    }
}

/// Returns the claim destination for this swap. Three branches in order:
///
///   (A) **Cached**: a previous attempt already wrote `swap_records.address`.
///       Return it as-is. This makes claim retries fully idempotent — the
///       same destination is used across attempts whether the address came
///       from the descriptor allocator or a wallet-supplied invoice.
///
///   (B) **Invoice-bound**: the swap was created for a Get-paid invoice.
///       Read `invoices.liquid_address` (wallet-supplied at create time);
///       persist it into `swap_records.address` (with `address_index = NULL`,
///       since there is no descriptor index for wallet-supplied addresses).
///
///   (C) **Lightning Address**: the swap is for the LNURL flow. Bump
///       `users.next_addr_idx` and derive a fresh CT address from the
///       user's descriptor.
///
/// Runs inside the caller's locked claim-preparation transaction. The
/// `SELECT ... FOR UPDATE` serializes concurrent webhook deliveries (e.g.
/// transaction.mempool followed by transaction.confirmed) so they cannot
/// double-allocate or split addresses, without checking out another pool
/// connection while the advisory-lock connection is already held.
async fn resolve_claim_address(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    swap: &db::SwapRecord,
) -> Result<String, AppError> {
    // Re-read the swap row under FOR UPDATE — `swap` may be stale (the
    // caller loaded it before this call, possibly on a previous attempt).
    let row: Option<(Option<String>, Option<i32>, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT address, address_index, invoice_id FROM swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(swap.id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let (cached_addr, _cached_idx, invoice_id) =
        row.ok_or_else(|| AppError::ClaimError(format!("swap_records row gone: {}", swap.id)))?;

    // (A) Cached destination — return as-is. Idempotent retries land on
    //     the same address regardless of how it was first resolved.
    if let Some(addr) = cached_addr {
        return Ok(addr);
    }

    // (B) Invoice-bound — wallet supplied the destination at create time.
    //     `liquid_address_index` stays NULL: there's no descriptor cursor
    //     to bump for wallet addresses. Persist into swap_records.address
    //     so the cache branch wins on the next retry.
    if let Some(inv_id) = invoice_id {
        let inv_row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT liquid_address FROM invoices WHERE id = $1")
                .bind(inv_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| AppError::DbError(e.to_string()))?;

        let addr = inv_row.and_then(|(a,)| a).ok_or_else(|| {
            AppError::ClaimError(format!("invoice {inv_id} has no liquid_address"))
        })?;

        sqlx::query("UPDATE swap_records SET address = $1, address_index = NULL WHERE id = $2")
            .bind(&addr)
            .bind(swap.id)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;

        tracing::info!(
            event = "lightning_swap_address_from_invoice_prepared",
            swap_id = %swap.id,
            invoice_id = %inv_id,
            "claim destination prepared from invoice.liquid_address; pending claim transaction commit"
        );
        return Ok(addr);
    }

    // (C) Lightning Address descriptor allocator. Funds locked up against
    //     a swap we created belong to the receiver even if they deactivate
    //     the nym before funding. `purge_user` refuses to run while swaps
    //     are in flight; if a purged row ever reaches this path, the empty
    //     descriptor fails loudly instead of silently stranding funds.
    let nym = swap.nym.as_deref().ok_or_else(|| {
        AppError::ClaimError(format!(
            "swap {} has no nym and no invoice claim destination",
            swap.id
        ))
    })?;

    let user = db::get_user_by_nym(&mut **tx, nym)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("user not found: {nym}")))?;

    let addr_index_row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET next_addr_idx = next_addr_idx + 1 \
         WHERE nym = $1 \
         RETURNING next_addr_idx - 1",
    )
    .bind(nym)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;

    let addr_index = addr_index_row
        .map(|(idx,)| idx)
        .ok_or_else(|| AppError::ClaimError(format!("address allocation failed: {nym}")))?;

    let addr_index_u32 = u32::try_from(addr_index)
        .map_err(|_| AppError::ClaimError("address index overflow".to_string()))?;
    let derived = descriptor::derive_address(&user.ct_descriptor, addr_index_u32)?;

    sqlx::query("UPDATE swap_records SET address = $2, address_index = $3 WHERE id = $1")
        .bind(swap.id)
        .bind(&derived)
        .bind(addr_index)
        .execute(&mut **tx)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    tracing::info!(
        event = "lightning_swap_address_allocation_prepared",
        nym = %nym,
        swap_id = %swap.id,
        address_index = addr_index,
        "claim-time descriptor allocation prepared; pending claim transaction commit"
    );

    Ok(derived)
}

/// Single-flight, idempotent claim.
///
/// `construct_claim` is non-deterministic on Liquid — random MuSig2
/// session nonces (`liquid.rs:703-714`) plus random asset/value
/// blinding factors (`liquid.rs:833`) yield a different valid-but-
/// conflicting tx every call. The previous implementation called
/// `construct_claim` from scratch on every retry; if a previous
/// broadcast had landed but our response was lost, the next attempt
/// produced a different tx that Electrum rejected as a double-spend
/// and we marked the row `claim_failed` even though the swap had
/// actually succeeded.
///
/// This version persists the constructed tx hex into `swap_records`
/// BEFORE the first broadcast, so subsequent attempts re-broadcast
/// the SAME tx instead of constructing a new one. Re-broadcasting
/// is idempotent at the Electrum boundary: `try_broadcast_tx`
/// (boltz-rust `wrappers.rs:199-212`) treats `"already in block
/// chain"` and `"already in utxo set"` as success.
///
/// The shape:
///
///   1. Open a transaction; try to acquire `pg_try_advisory_xact_lock`
///      keyed on `claim:<swap_id>`. Concurrent attempts return
///      `SkippedLockHeld` and try on the next tick.
///   2. Reload the row inside the lock. If terminal, return
///      `AlreadyTerminal`.
///   3. If no transaction is journaled and no accepted fee decision is
///      available, return `PendingFeeUnavailable` without allocating a
///      destination or consuming an attempt.
///   4. Resolve the claim destination address (allocates a fresh
///      descriptor index if none was set at swap creation).
///   5. If `claim_tx_hex` is set, deserialize it. Otherwise
///      `construct_claim` and persist `(claim_tx_hex, claim_txid,
///      claim_path)` in the same transaction. Mark status `claiming`.
///      Set a short in-flight lease in `next_claim_attempt_at`.
///   6. Commit (releases the advisory lock).
///   7. Broadcast the tx OUTSIDE the lock — broadcast is the slow,
///      I/O-bound step and we don't want to hold a DB connection.
///      Idempotent on Electrum.
///   8. Mark status `claimed` with the on-chain txid.
#[allow(clippy::too_many_arguments)]
async fn claim_swap(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
) -> Result<ClaimOutcome, AppError> {
    claim_swap_with_guard(
        pool,
        swap_id,
        claim_clients,
        boltz_url,
        max_claim_attempts,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        false,
    )
    .await
}

/// Constrained-pool integration seam. It executes the exact production path,
/// but only while the persisted provider response is malformed and no claim
/// bytes exist, guaranteeing a local construction error before any
/// Electrum/Boltz call or broadcast.
/// Normal application code calls the private [`claim_swap`] entry point.
#[doc(hidden)]
pub async fn exercise_reverse_claim_with_malformed_response(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    fee_decision: &LiquidFeeDecision,
) -> Result<ClaimOutcome, AppError> {
    let factory = LiquidClaimClientFactory::try_new(vec!["tcp://127.0.0.1:1".to_string()])?;
    let fee_record = liquid_fee_record_for_compatibility_seam(
        FeeConstructionPurpose::ReverseLiquidClaim,
        fee_decision,
    )?;
    claim_swap_with_guard(
        pool,
        swap_id,
        Some(&factory),
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        Some(fee_decision),
        Some(&fee_record),
        true,
    )
    .await
}

/// Exercise production claim preparation without a usable fee quote. This
/// seam performs no network I/O: unjournaled bytes remain pending before any
/// claim client is required.
#[doc(hidden)]
pub async fn exercise_reverse_claim_without_fee(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
) -> Result<ClaimOutcome, AppError> {
    claim_swap_with_guard(
        pool,
        swap_id,
        None,
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        None,
        None,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn claim_swap_with_guard(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
) -> Result<ClaimOutcome, AppError> {
    // Outer wrapper: records every Err uniformly via
    // `db::record_claim_failure`. Pending/skip outcomes are Ok variants and do
    // not count as failures because no construction attempt was made.
    let result = claim_swap_inner(
        pool,
        swap_id,
        claim_clients,
        boltz_url,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        require_malformed_response,
    )
    .await;
    if require_malformed_response
        && matches!(
            &result,
            Err(AppError::ClaimError(message)) if message == REVERSE_TEST_GUARD_REJECTED
        )
    {
        return result;
    }
    if let Err(ref e) = result {
        let err_str = e.to_string();
        match db::record_claim_failure(pool, swap_id, &err_str, max_claim_attempts).await {
            Ok(db::ClaimFailureOutcome::Stuck) => {
                tracing::error!(
                    event = "swap_claim_stuck",
                    swap_id = %swap_id,
                    attempts = max_claim_attempts,
                    last_error = %err_str,
                    "swap reached max_claim_attempts; transitioned to claim_stuck"
                );
                // Do not record invoice payment here. `claim_stuck`
                // requires operator recovery; the customer-facing
                // invoice can remain payment-detected until recovered.
                if let Err(e) =
                    db::mark_invoice_settlement_status_for_swap(pool, swap_id, "claim_stuck").await
                {
                    tracing::error!(
                        event = "invoice_claim_stuck_mark_failed",
                        swap_id = %swap_id,
                        "failed to mark invoice settlement_status=claim_stuck: {e}"
                    );
                    return Err(AppError::DbError(e.to_string()));
                }
            }
            Ok(db::ClaimFailureOutcome::Scheduled) => {
                tracing::warn!(
                    event = "swap_claim_failure_scheduled",
                    swap_id = %swap_id,
                    last_error = %err_str,
                    "claim failed; scheduled for retry"
                );
            }
            Ok(db::ClaimFailureOutcome::NoOp) => {
                tracing::debug!(
                    "claim failure for {} arrived after row reached terminal state",
                    swap_id
                );
            }
            Err(db_err) => {
                tracing::error!(
                    "failed to record claim failure for swap {}: {db_err}",
                    swap_id
                );
                return Err(AppError::DbError(db_err.to_string()));
            }
        }
    }
    result
}

/// Preserve preparation writes that were already durable before claim
/// construction in the old two-transaction flow (notably the resolved reverse
/// destination and descriptor cursor), then return the original local/provider
/// error. Cooperative-refusal callers also set their one-way flag on this
/// transaction before committing here.
async fn commit_claim_preparation_error<T>(
    tx: sqlx::Transaction<'_, sqlx::Postgres>,
    error: AppError,
) -> Result<T, AppError> {
    if let Err(commit_error) = tx.commit().await {
        tracing::error!(
            event = "claim_preparation_error_commit_failed",
            original_error = %error,
            error = %commit_error,
            "failed to commit handled claim-preparation state"
        );
        return Err(AppError::DbError(format!(
            "commit handled claim-preparation state after {error}: {commit_error}"
        )));
    }
    Err(error)
}

/// Persist the one-way chain cooperative-refusal fact in the same locked
/// preparation transaction, then return the original provider/local error.
/// Both the live construction arm and its guarded no-network test seam use
/// this boundary so retry bookkeeping can never run before the flag commits.
async fn commit_chain_cooperative_refusal<T>(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    chain_swap_id: Uuid,
    boltz_swap_id: &str,
    error: AppError,
) -> Result<T, AppError> {
    tracing::warn!(
        event = "chain_swap_cooperative_refused_runtime",
        swap_id = %boltz_swap_id,
        error = %error,
        "boltz refused cooperative chain claim; flipping cooperative_refused for next sweep"
    );
    let updated = db::mark_chain_swap_cooperative_refused(&mut *tx, chain_swap_id)
        .await
        .map_err(|db_error| AppError::DbError(db_error.to_string()))?;
    if updated != 1 {
        return Err(AppError::DbError(
            "chain cooperative-refusal transition did not update one active swap".into(),
        ));
    }
    commit_claim_preparation_error(tx, error).await
}

#[allow(clippy::too_many_arguments)]
async fn claim_swap_inner(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
) -> Result<ClaimOutcome, AppError> {
    // Acquire single-flight and prepare the claim tx.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // Advisory locks live on `pg_try_advisory_xact_lock` for the duration
    // of the transaction. `claim:<uuid>` lives in a disjoint string space
    // from the existing `register:` / `donation:` / raw-npub-hex usages
    // (db.rs:201, 1088), so no AB/BA deadlock is possible with those.
    let lock_key = format!("claim:{swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
    if !got_lock {
        tracing::debug!("claim_swap: lock held for {swap_id}, skipping");
        return Ok(ClaimOutcome::SkippedLockHeld);
    }

    let swap = db::get_swap_by_id(&mut *tx, swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("swap not found: {swap_id}")))?;

    let status = swap
        .parsed_status()
        .map_err(|e| AppError::ClaimError(format!("invalid persisted swap status: {e}")))?;
    if !status.is_claimable() {
        tracing::debug!("claim_swap: {} is not claimable ({})", swap_id, swap.status);
        return Ok(ClaimOutcome::AlreadyTerminal);
    }
    if require_malformed_response
        && (swap.claim_tx_hex.is_some()
            || swap.boltz_response_json.as_deref().is_some_and(|response| {
                serde_json::from_str::<CreateReverseResponse>(response).is_ok()
            }))
    {
        return Err(AppError::ClaimError(
            REVERSE_TEST_GUARD_REJECTED.to_string(),
        ));
    }

    let had_persisted_claim = swap.claim_tx_hex.is_some();
    if !had_persisted_claim
        && (fee_decision.is_none()
            || !liquid_claim_journal_authorized(had_persisted_claim, fee_record))
    {
        return Ok(ClaimOutcome::PendingFeeUnavailable {
            reason: LIQUID_FEE_DECISION_PENDING_REASON,
        });
    }
    let claim_clients = claim_clients.ok_or_else(|| {
        AppError::ClaimError("Liquid claim client factory is unavailable".to_string())
    })?;

    // Destination resolution uses this same transaction/connection. Returning
    // to the pool here would self-starve at max_connections=1 and can deadlock
    // a saturated pool when multiple claim preparations each hold one slot.
    let output_address = resolve_claim_address(&mut tx, &swap).await?;

    let chain = Chain::Liquid(LiquidChain::Liquid);
    let claim_tx = if let Some(hex) = swap.claim_tx_hex.as_deref() {
        // Idempotent path: a previous attempt persisted the constructed
        // tx but failed somewhere between persistence and "Claimed"
        // status. Re-broadcast THAT tx, not a fresh one.
        match BtcLikeTransaction::from_hex(chain, hex)
            .map_err(|e| AppError::ClaimError(format!("decode persisted claim_tx: {e}")))
        {
            Ok(claim_tx) => {
                if let Err(error) = validate_replayed_liquid_claim_fee_authority(
                    &swap.claim_fee_authority,
                    FeeConstructionPurpose::ReverseLiquidClaim,
                    &claim_tx,
                ) {
                    return commit_claim_preparation_error(tx, error).await;
                }
                claim_tx
            }
            Err(error) => return commit_claim_preparation_error(tx, error).await,
        }
    } else {
        let fee_record = fee_record.expect("unjournaled claims require fee decision metadata");
        let fee_decision = LiquidBuilderFeeDecision::from(
            fee_decision.expect("unjournaled claims require a policy decision"),
        );
        // Choose the claim path. `cooperative_refused` is set by either:
        //   - the webhook handler on `swap.expired`, OR
        //   - this function on a previous attempt where Boltz returned
        //     a known cooperative-refusal error (below).
        // Once it flips, the row stays on script-path forever — no
        // ping-pong. `cooperative_refused` is a one-way flag.
        let use_cooperative = !swap.cooperative_refused;
        let constructed = match construct_claim_tx(
            &swap,
            &output_address,
            claim_clients,
            boltz_url,
            &fee_decision,
            use_cooperative,
        )
        .await
        {
            Ok(tx) => tx,
            Err(e) if use_cooperative && is_cooperative_refusal(&e) => {
                // Boltz refused cooperative MuSig2 (status mismatch,
                // bad preimage, or operator-disabled). Flip the flag
                // so the next sweep tick takes the script path. The flag and
                // any newly resolved destination must commit before this
                // attempt returns the refusal to the retry wrapper.
                tracing::warn!(
                    event = "swap_cooperative_refused_runtime",
                    swap_id = %swap.boltz_swap_id,
                    error = %e,
                    "boltz refused cooperative claim; flipping cooperative_refused for next attempt"
                );
                db::mark_cooperative_refused(&mut *tx, swap.id)
                    .await
                    .map_err(|db_error| AppError::DbError(db_error.to_string()))?;
                return commit_claim_preparation_error(tx, e).await;
            }
            Err(e) => return commit_claim_preparation_error(tx, e).await,
        };
        let (actual_fee_sat, actual_fee_rate_sat_vb, actual_vbytes) =
            liquid_actual_fee(&constructed)?;
        ensure_actual_fee_authorized(
            "Liquid reverse claim",
            actual_fee_sat,
            actual_vbytes,
            fee_record,
        )?;
        let quoted_at = checked_fee_i64(
            "claim_fee_decision_quoted_at_unix",
            fee_record.quoted_at_unix(),
        )?;
        let evaluated_at = checked_fee_i64(
            "claim_fee_decision_evaluated_at_unix",
            fee_record.evaluated_at_unix(),
        )?;
        let freshness_age = checked_fee_i64(
            "claim_fee_decision_freshness_age_secs",
            fee_record.freshness_age_secs(),
        )?;
        let freshness_max_age = checked_fee_i64(
            "claim_fee_decision_freshness_max_age_secs",
            fee_record.freshness_max_age_secs(),
        )?;
        let hex = match serialize_claim_tx_hex(&constructed) {
            Ok(hex) => hex,
            Err(error) => return commit_claim_preparation_error(tx, error).await,
        };
        let txid = btc_like_txid(&constructed);
        let claim_path = if use_cooperative {
            "cooperative"
        } else {
            "script"
        };
        if !fee_record.authorizes_construction_now() {
            return Ok(ClaimOutcome::PendingFeeUnavailable {
                reason: LIQUID_FEE_DECISION_PENDING_REASON,
            });
        }
        // `WHERE claim_tx_hex IS NULL` makes this a no-op if a concurrent
        // attempt persisted first (defensive — the advisory lock should
        // have prevented this; the guard is there to fail closed).
        let persisted = sqlx::query(
            "UPDATE swap_records \
             SET claim_tx_hex = $2, claim_txid = $3, claim_path = $4, \
                 claim_actual_fee_sat = $5, claim_actual_fee_rate_sat_vb = $6, \
                 claim_fee_decision_purpose = $7, claim_fee_decision_rail = $8, \
                 claim_fee_decision_target = $9, claim_fee_decision_source = $10, \
                 claim_fee_decision_rate_sat_vb = $11, \
                 claim_fee_decision_quoted_at_unix = $12, \
                 claim_fee_decision_evaluated_at_unix = $13, \
                 claim_fee_decision_freshness_age_secs = $14, \
                 claim_fee_decision_freshness_max_age_secs = $15, \
                 claim_fee_decision_provenance = $16, \
                 claim_fee_decision_policy_floor_sat_vb = $17, \
                 claim_fee_decision_policy_cap_sat_vb = $18, \
                 claim_fee_decision_policy_version = $19 \
             WHERE id = $1 AND claim_tx_hex IS NULL",
        )
        .bind(swap.id)
        .bind(&hex)
        .bind(&txid)
        .bind(claim_path)
        .bind(actual_fee_sat)
        .bind(actual_fee_rate_sat_vb)
        .bind(fee_record.purpose().as_str())
        .bind(fee_record.rail().as_str())
        .bind(fee_record.target().as_str())
        .bind(fee_record.source().as_str())
        .bind(fee_record.rate().as_f64())
        .bind(quoted_at)
        .bind(evaluated_at)
        .bind(freshness_age)
        .bind(freshness_max_age)
        .bind(fee_record.provenance_for_persistence())
        .bind(fee_record.policy_floor().as_f64())
        .bind(fee_record.policy_cap().as_f64())
        .bind(fee_record.policy_version())
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
        if persisted.rows_affected() != 1 {
            return Err(AppError::DbError(format!(
                "reverse claim preparation lost its locked row: {}",
                swap.id
            )));
        }
        constructed
    };

    // Status -> Claiming. The retry timestamp doubles as an in-flight
    // lease: webhook/reconciler/background races must wait for this
    // deadline before rebroadcasting the persisted transaction.
    let marked_claiming = sqlx::query(
        "UPDATE swap_records \
         SET status = 'claiming', \
             next_claim_attempt_at = NOW() + $2::interval, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'claim_stuck', 'lockup_refunded')",
    )
    .bind(swap.id)
    .bind(db::CLAIM_IN_FLIGHT_LEASE)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;
    if marked_claiming.rows_affected() != 1 {
        return Err(AppError::DbError(format!(
            "reverse claim preparation could not publish claiming state: {}",
            swap.id
        )));
    }

    // Construction and the two journal writes can outlive the authority that
    // was valid at entry. Recheck at the last synchronous boundary before
    // COMMIT so an expired fresh decision rolls back bytes, metadata, status,
    // and destination allocation atomically. Existing bytes deliberately do
    // not consult current fee state during replay.
    if !liquid_claim_journal_authorized(had_persisted_claim, fee_record) {
        return Ok(ClaimOutcome::PendingFeeUnavailable {
            reason: LIQUID_FEE_DECISION_PENDING_REASON,
        });
    }

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // Cross the commit boundary before selecting bytes for broadcast. The
    // transaction built above is only an expectation now; reload the durable
    // journal and compare the full canonical serialization, including witness
    // bytes that the Liquid txid does not commit to. This makes a successful
    // commit (rather than process memory) the broadcast authority, while
    // retaining the same bytes across retries.
    let expected_hex = serialize_claim_tx_hex(&claim_tx)?;
    let claim_tx = reload_reverse_claim_for_broadcast(pool, swap.id, &expected_hex).await?;

    // Broadcast outside the lock.
    //
    // Broadcast is pure I/O against Electrum and may take seconds. We
    // hold no DB connection or lock during the call. If the process
    // dies between here and the final update, the next sweep tick re-acquires
    // the advisory lock, sees `claim_tx_hex` is set, and re-broadcasts
    // THIS exact tx (idempotent).
    let liquid_client = claim_clients.connect().await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);

    let mut txid = btc_like_txid(&claim_tx);

    if let Err(broadcast_err) = chain_client.try_broadcast_tx(&claim_tx).await {
        // `try_broadcast_tx` only swallows `"already in block chain"` /
        // `"already in utxo set"` (boltz-rust wrappers.rs:199-212). Other
        // mempool-acceptance phrasings vary by node implementation
        // (`"txn-already-known"`, `"transaction already in block chain"`,
        // timeouts after a successful write, etc.) and bubble as Err.
        //
        // Probe the multi-URL utxo backend for the txid before we
        // declare failure — if the tx is on the network, the broadcast
        // was effectively successful and we should mark Claimed instead
        // of feeding the failure to the backoff schedule.
        if let Some(backend) = utxo_backend {
            match backend.tx_exists(&txid).await {
                Ok(true) => {
                    tracing::info!(
                        event = "claim_broadcast_probe_recovered",
                        swap_id = %swap.boltz_swap_id,
                        txid = %txid,
                        broadcast_error = %broadcast_err,
                        "broadcast errored but tx is on chain; treating as success"
                    );
                    // fall through to the final status update
                }
                Ok(false) => match recover_claim_from_lockup_spend(&claim_tx, backend).await {
                    Ok(Some(spending_txid)) => {
                        tracing::info!(
                            event = "claim_outspend_recovered",
                            swap_id = %swap.boltz_swap_id,
                            expected_txid = %txid,
                            recovered_txid = %spending_txid,
                            broadcast_error = %broadcast_err,
                            "claim broadcast errored and expected txid was absent, but lockup outspend was found"
                        );
                        txid = spending_txid;
                    }
                    Ok(None) => {
                        return Err(AppError::ClaimError(format!(
                            "broadcast failed: {broadcast_err}"
                        )));
                    }
                    Err(recovery_err) => {
                        tracing::warn!(
                            "claim outspend recovery failed for {}: {recovery_err}; \
                                 treating broadcast as failed",
                            swap.boltz_swap_id
                        );
                        return Err(AppError::ClaimError(format!(
                            "broadcast failed: {broadcast_err}"
                        )));
                    }
                },
                Err(probe_err) => {
                    // Probe itself failed (Electrum hiccup). Conservatively
                    // assume the tx isn't on chain and propagate the
                    // original broadcast error so the wrapper records a
                    // failure and we retry on backoff. Log the probe error
                    // for diagnosis.
                    tracing::warn!(
                        "tx_exists probe failed for {}: {probe_err}; \
                         treating broadcast as failed",
                        swap.boltz_swap_id
                    );
                    return Err(AppError::ClaimError(format!(
                        "broadcast failed: {broadcast_err}"
                    )));
                }
            }
        } else {
            // No utxo backend configured (dev/test). Honor the broadcast
            // error verbatim.
            return Err(AppError::ClaimError(format!(
                "broadcast failed: {broadcast_err}"
            )));
        }
    }

    tracing::info!("swap {} claimed: txid={}", swap.boltz_swap_id, txid);

    // Mark Claimed and clear retry bookkeeping.
    db::update_swap_status(pool, swap.id, SwapStatus::Claimed, Some(&txid))
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if let Err(e) = db::mark_invoice_settlement_status(pool, swap.invoice_id, "settled").await {
        tracing::warn!(
            event = "invoice_settlement_status_mark_failed",
            swap_id = %swap.boltz_swap_id,
            "failed to mark invoice settlement_status=settled: {e}"
        );
    }
    if let Err(e) = db::clear_claim_failure_state(pool, swap.id).await {
        // Non-fatal: row is Claimed; stale last-error fields are an
        // observability nuisance only.
        tracing::warn!("clear_claim_failure_state for {}: {e}", swap.boltz_swap_id);
    }

    // Merchant-side claim succeeded. This is the Lightning accounting
    // boundary; lockup confirmation, refund, and claim-stuck states do
    // not record invoice payment events.
    invoice::flip_invoice_on_lightning_settlement(
        pool,
        swap.invoice_id,
        swap.amount_sat,
        &swap.boltz_swap_id,
        &txid,
        tolerances,
    )
    .await;

    Ok(ClaimOutcome::Broadcast)
}

#[allow(clippy::too_many_arguments)]
async fn claim_chain_swap(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
) -> Result<ClaimOutcome, AppError> {
    claim_chain_swap_with_guard(
        pool,
        chain_swap_id,
        claim_clients,
        boltz_url,
        max_claim_attempts,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        false,
    )
    .await
}

/// Replay the exact journaled Liquid claim after a durable settlement
/// demotion. The claim path reloads the row by ID under its advisory lock, so
/// callers cannot accidentally redrive from a stale pre-demotion record.
pub(crate) async fn redrive_journaled_chain_claim(
    state: &AppState,
    chain_swap_id: Uuid,
) -> Result<ClaimOutcome, AppError> {
    claim_chain_swap(
        &state.db,
        chain_swap_id,
        state.liquid_claim_client_factory.as_deref(),
        &state.config.boltz.api_url,
        state.config.claim.max_claim_attempts,
        state.utxo_backend.as_ref(),
        db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
        None,
        None,
    )
    .await
}

/// Constrained-pool integration seam for chain claims. The persisted provider
/// response must be malformed and no claim bytes may exist, guaranteeing that
/// the exact production path fails locally before Electrum/Boltz I/O or
/// broadcast.
#[doc(hidden)]
pub async fn exercise_chain_claim_with_malformed_response(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    fee_decision: &LiquidFeeDecision,
) -> Result<ClaimOutcome, AppError> {
    let factory = LiquidClaimClientFactory::try_new(vec!["tcp://127.0.0.1:1".to_string()])?;
    let fee_record = liquid_fee_record_for_compatibility_seam(
        FeeConstructionPurpose::ChainLiquidClaim,
        fee_decision,
    )?;
    claim_chain_swap_with_guard(
        pool,
        chain_swap_id,
        Some(&factory),
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        Some(fee_decision),
        Some(&fee_record),
        true,
    )
    .await
}

/// Exercise production chain-claim preparation without a usable fee quote.
/// Unjournaled bytes remain pending before any network client is required.
#[doc(hidden)]
pub async fn exercise_chain_claim_without_fee(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
) -> Result<ClaimOutcome, AppError> {
    claim_chain_swap_with_guard(
        pool,
        chain_swap_id,
        None,
        "http://127.0.0.1:1",
        20,
        None,
        db::InvoiceAccountingTolerances::default(),
        None,
        None,
        false,
    )
    .await
}

/// Integration seam for an already-constructed Liquid claim retry. This calls
/// the production preparation path directly, without the outer retry-bookkeeping
/// wrapper, so a test can prove that a missing immutable journal rolls the
/// advisory transaction back before the Electrum broadcaster is reached.
#[doc(hidden)]
pub async fn exercise_journaled_chain_claim_retry(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    claim_clients: &LiquidClaimClientFactory,
    utxo_backend: &Arc<dyn UtxoBackend>,
) -> Result<ClaimOutcome, AppError> {
    claim_chain_swap_inner(
        pool,
        chain_swap_id,
        Some(claim_clients),
        "http://127.0.0.1:1",
        Some(utxo_backend),
        db::InvoiceAccountingTolerances::default(),
        None,
        None,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn claim_chain_swap_with_guard(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    max_claim_attempts: i32,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
) -> Result<ClaimOutcome, AppError> {
    let result = claim_chain_swap_inner(
        pool,
        chain_swap_id,
        claim_clients,
        boltz_url,
        utxo_backend,
        tolerances,
        fee_decision,
        fee_record,
        require_malformed_response,
    )
    .await;
    if require_malformed_response
        && matches!(
            &result,
            Err(AppError::ClaimError(message)) if message == CHAIN_TEST_GUARD_REJECTED
        )
    {
        return result;
    }
    if let Err(ref e) = result {
        let err_str = e.to_string();
        match db::record_chain_swap_claim_failure(pool, chain_swap_id, &err_str, max_claim_attempts)
            .await
        {
            Ok(db::ClaimFailureOutcome::Stuck) => {
                tracing::error!(
                    event = "chain_swap_claim_stuck",
                    swap_id = %chain_swap_id,
                    attempts = max_claim_attempts,
                    last_error = %err_str,
                    "chain swap reached max_claim_attempts; transitioned to claim_stuck"
                );
                db::mark_chain_swap_invoice_claim_stuck_if_current(pool, chain_swap_id)
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            event = "invoice_chain_swap_claim_stuck_mark_failed",
                            swap_id = %chain_swap_id,
                            "failed to publish guarded invoice claim_stuck state: {e}"
                        );
                        AppError::DbError(e.to_string())
                    })?;
            }
            Ok(db::ClaimFailureOutcome::Scheduled) => {
                tracing::warn!(
                    event = "chain_swap_claim_failure_scheduled",
                    swap_id = %chain_swap_id,
                    last_error = %err_str,
                    "chain swap claim failed; scheduled for retry"
                );
            }
            Ok(db::ClaimFailureOutcome::NoOp) => {
                tracing::debug!(
                    "chain-swap claim failure for {} arrived after terminal state",
                    chain_swap_id
                );
            }
            Err(db_err) => {
                tracing::error!(
                    "failed to record chain-swap claim failure for {}: {db_err}",
                    chain_swap_id
                );
                return Err(AppError::DbError(db_err.to_string()));
            }
        }
    }
    result
}

#[derive(Debug)]
struct PreparedChainClaimJournal {
    journal: PersistableMerchantTransactionJournal,
    fee_amount_sat: u64,
    fee_rate_sat_vb: f64,
}

fn ensure_chain_claim_journal_fee_matches_actual(
    journal_fee_amount_sat: u64,
    journal_fee_rate_sat_vb: f64,
    actual_fee_sat: i64,
    actual_fee_rate_sat_vb: f64,
) -> Result<(), AppError> {
    let actual_fee_amount_sat = u64::try_from(actual_fee_sat).map_err(|_| {
        AppError::ClaimError("Liquid chain claim fee is negative or unrepresentable".into())
    })?;
    if journal_fee_amount_sat != actual_fee_amount_sat
        || journal_fee_rate_sat_vb.to_bits() != actual_fee_rate_sat_vb.to_bits()
    {
        return Err(AppError::ClaimError(format!(
            "Liquid chain claim settlement fee {journal_fee_amount_sat} sat at {journal_fee_rate_sat_vb} sat/vB does not match exact signed transaction fee {actual_fee_amount_sat} sat at {actual_fee_rate_sat_vb} sat/vB"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistedChainClaimJournalMode {
    ConstructAndInsert,
    DecodeAndLoadExact,
}

fn persisted_chain_claim_journal_mode(
    claim_tx_hex: Option<&str>,
    claim_txid: Option<&str>,
) -> Result<PersistedChainClaimJournalMode, AppError> {
    match (claim_tx_hex, claim_txid) {
        (None, None) => Ok(PersistedChainClaimJournalMode::ConstructAndInsert),
        (Some(_), Some(_)) => Ok(PersistedChainClaimJournalMode::DecodeAndLoadExact),
        _ => Err(AppError::ClaimError(
            "persisted chain claim has orphan bytes or txid; integrity review required".into(),
        )),
    }
}

fn require_terminal_chain_claim_journal(
    status: ChainSwapStatus,
    journal_mode: PersistedChainClaimJournalMode,
) -> Result<(), AppError> {
    if status == ChainSwapStatus::Claimed
        && journal_mode != PersistedChainClaimJournalMode::DecodeAndLoadExact
    {
        return Err(AppError::ClaimError(
            "claimed chain swap lacks committed claim bytes and txid; integrity review required"
                .into(),
        ));
    }
    Ok(())
}

fn require_exact_persisted_chain_claim_journal<T>(
    loaded: Result<T, db::MerchantSettlementRepositoryError>,
) -> Result<T, AppError> {
    loaded.map_err(|error| {
        AppError::DbError(format!(
            "load exact Liquid merchant settlement journal: {error}"
        ))
    })
}

/// Rebuild the complete immutable Liquid claim journal from locally decoded
/// transaction bytes and the independently fetched source transactions. This
/// runs while the per-swap advisory transaction is still open and before any
/// broadcaster can observe the claim.
async fn prepare_chain_claim_settlement_journal(
    claim_tx: &BtcLikeTransaction,
    approved_destination_address: &str,
    liquid_asset_id: &str,
    merchant_blinding_key_hex: &str,
    source_lockup_address: &str,
    source_blinding_key_hex: &str,
    backend: &Arc<dyn UtxoBackend>,
) -> Result<PreparedChainClaimJournal, AppError> {
    let BtcLikeTransaction::Liquid(transaction) = claim_tx else {
        return Err(AppError::ClaimError(
            "chain claim construction returned a non-Liquid transaction".into(),
        ));
    };
    if transaction.input.is_empty() || transaction.input.len() > MAX_MERCHANT_OUTPUT_SOURCE_PREVOUTS
    {
        return Err(AppError::ClaimError(
            "chain claim transaction has an invalid source count".into(),
        ));
    }

    let expected_asset = boltz_elements::AssetId::from_str(liquid_asset_id)
        .map_err(|error| AppError::ClaimError(format!("invalid Liquid asset id: {error}")))?;
    let source_address =
        boltz_elements::Address::from_str(source_lockup_address).map_err(|error| {
            AppError::ClaimError(format!("invalid committed Liquid lockup address: {error}"))
        })?;
    if source_address.params != &boltz_elements::AddressParams::LIQUID
        || source_address.blinding_pubkey.is_none()
    {
        return Err(AppError::ClaimError(
            "committed Liquid lockup address is not confidential mainnet".into(),
        ));
    }
    let source_blinding_key = boltz_elements::secp256k1_zkp::SecretKey::from_str(
        source_blinding_key_hex,
    )
    .map_err(|error| {
        AppError::ClaimError(format!(
            "invalid committed Liquid lockup blinding key: {error}"
        ))
    })?;
    let secp = boltz_elements::secp256k1_zkp::Secp256k1::new();
    let source_blinding_pubkey =
        boltz_elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &source_blinding_key);
    if source_address.blinding_pubkey != Some(source_blinding_pubkey) {
        return Err(AppError::ClaimError(
            "committed Liquid lockup blinding key does not match its address".into(),
        ));
    }
    let source_script = source_address.script_pubkey();

    let mut source_prevouts = Vec::with_capacity(transaction.input.len());
    let mut total_source_sat = 0u64;
    for input in &transaction.input {
        if input.is_pegin || !input.asset_issuance.is_null() {
            return Err(AppError::ClaimError(
                "chain claim transaction contains an unsupported source input".into(),
            ));
        }
        let source_txid = input.previous_output.txid.to_string();
        let source_vout = input.previous_output.vout;
        if source_prevouts
            .iter()
            .any(|source: &db::MerchantSettlementSourcePrevout| {
                source.txid == source_txid && source.vout == source_vout
            })
        {
            return Err(AppError::ClaimError(
                "chain claim transaction repeats a source outpoint".into(),
            ));
        }

        let raw_source = backend.get_raw_tx(&source_txid).await?;
        if raw_source.is_empty() || raw_source.len() > MAX_MERCHANT_OUTPUT_RAW_TRANSACTION_BYTES {
            return Err(AppError::ClaimError(format!(
                "Liquid claim source transaction {source_txid} exceeds the journal bounds"
            )));
        }
        let source_transaction: boltz_elements::Transaction =
            boltz_elements::encode::deserialize(&raw_source).map_err(|error| {
                AppError::ClaimError(format!(
                    "decode Liquid claim source transaction {source_txid}: {error}"
                ))
            })?;
        if source_transaction.txid() != input.previous_output.txid {
            return Err(AppError::ClaimError(format!(
                "Liquid claim source bytes do not match txid {source_txid}"
            )));
        }
        let source_output = source_transaction
            .output
            .get(source_vout as usize)
            .ok_or_else(|| {
                AppError::ClaimError(format!(
                    "Liquid claim source {source_txid}:{source_vout} has no such output"
                ))
            })?;
        if source_output.script_pubkey != source_script {
            return Err(AppError::ClaimError(format!(
                "Liquid claim source {source_txid}:{source_vout} is not the committed lockup script"
            )));
        }
        let opened = source_output
            .unblind(&secp, source_blinding_key)
            .map_err(|error| {
                AppError::ClaimError(format!(
                    "unblind Liquid claim source {source_txid}:{source_vout}: {error}"
                ))
            })?;
        if opened.asset != expected_asset || opened.value == 0 {
            return Err(AppError::ClaimError(format!(
                "Liquid claim source {source_txid}:{source_vout} has the wrong asset or amount"
            )));
        }
        total_source_sat = total_source_sat
            .checked_add(opened.value)
            .ok_or_else(|| AppError::ClaimError("Liquid claim source amount overflow".into()))?;
        source_prevouts.push(db::MerchantSettlementSourcePrevout {
            txid: source_txid,
            vout: source_vout,
            amount_sat: opened.value,
            script_pubkey_hex: hex::encode(source_output.script_pubkey.as_bytes()),
        });
    }

    let destination =
        elements::Address::from_str(approved_destination_address).map_err(|error| {
            AppError::ClaimError(format!("invalid approved Liquid destination: {error}"))
        })?;
    if destination.params != &elements::AddressParams::LIQUID
        || destination.blinding_pubkey.is_none()
    {
        return Err(AppError::ClaimError(
            "approved Liquid destination is not confidential mainnet".into(),
        ));
    }
    let raw_transaction = boltz_elements::encode::serialize(transaction);
    let source_views = source_prevouts
        .iter()
        .map(|source| MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat,
            script_pubkey_hex: &source.script_pubkey_hex,
        })
        .collect::<Vec<_>>();
    let journal = prepare_liquid_claim_journal(
        &raw_transaction,
        &source_views,
        approved_destination_address,
        &hex::encode(destination.script_pubkey().as_bytes()),
        liquid_asset_id,
        merchant_blinding_key_hex,
    )
    .map_err(|error| {
        AppError::ClaimError(format!(
            "prepare Liquid merchant settlement journal: {error}"
        ))
    })?;

    let fee_amount_sat = transaction.fee_in(expected_asset);
    let fee_vsize = transaction.discount_vsize();
    if fee_amount_sat == 0
        || fee_vsize == 0
        || transaction.all_fees().len() != 1
        || transaction
            .output
            .iter()
            .filter(|output| !output.is_fee())
            .count()
            != 1
        || total_source_sat.checked_sub(fee_amount_sat) != Some(journal.amount_sat)
    {
        return Err(AppError::ClaimError(
            "Liquid claim transaction has an invalid exact output/fee balance".into(),
        ));
    }

    Ok(PreparedChainClaimJournal {
        journal,
        fee_amount_sat,
        fee_rate_sat_vb: fee_amount_sat as f64 / fee_vsize as f64,
    })
}

#[allow(clippy::too_many_arguments)]
async fn claim_chain_swap_inner(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    claim_clients: Option<&LiquidClaimClientFactory>,
    boltz_url: &str,
    utxo_backend: Option<&Arc<dyn UtxoBackend>>,
    _tolerances: db::InvoiceAccountingTolerances,
    fee_decision: Option<&LiquidFeeDecision>,
    fee_record: Option<&FeeDecisionRecord>,
    require_malformed_response: bool,
) -> Result<ClaimOutcome, AppError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    let lock_key = format!("chain-claim:{chain_swap_id}");
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
    if !got_lock {
        return Ok(ClaimOutcome::SkippedLockHeld);
    }

    let swap = db::get_chain_swap_by_id_for_update(&mut *tx, chain_swap_id)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("chain swap not found: {chain_swap_id}")))?;
    swap.verify_creation_response_integrity()
        .map_err(AppError::ClaimError)?;

    let status = swap
        .parsed_status()
        .map_err(|e| AppError::ClaimError(format!("invalid persisted chain status: {e}")))?;
    // A `claimed` parent must still prove its complete independently
    // reconstructed journal packet below. Other terminal branches do not own
    // a successful Liquid merchant settlement and remain no-op outcomes.
    if status.is_terminal() && status != ChainSwapStatus::Claimed {
        return Ok(ClaimOutcome::AlreadyTerminal);
    }
    if !matches!(
        status,
        ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::Claiming
            | ChainSwapStatus::Claimed
            | ChainSwapStatus::ClaimFailed
    ) {
        return Ok(ClaimOutcome::AlreadyTerminal);
    }
    if require_malformed_response
        && (swap.claim_tx_hex.is_some()
            || serde_json::from_str::<CreateChainResponse>(&swap.boltz_response_json).is_ok())
    {
        return Err(AppError::ClaimError(CHAIN_TEST_GUARD_REJECTED.to_string()));
    }

    let journal_mode = persisted_chain_claim_journal_mode(
        swap.claim_tx_hex.as_deref(),
        swap.claim_txid.as_deref(),
    )?;
    let had_persisted_claim = journal_mode == PersistedChainClaimJournalMode::DecodeAndLoadExact;
    require_terminal_chain_claim_journal(status, journal_mode)?;
    if journal_mode == PersistedChainClaimJournalMode::ConstructAndInsert
        && (fee_decision.is_none()
            || !liquid_claim_journal_authorized(had_persisted_claim, fee_record))
    {
        return Ok(ClaimOutcome::PendingFeeUnavailable {
            reason: LIQUID_FEE_DECISION_PENDING_REASON,
        });
    }
    let persisted_claim_tx = if journal_mode == PersistedChainClaimJournalMode::DecodeAndLoadExact {
        let claim_tx_hex = swap
            .claim_tx_hex
            .as_deref()
            .expect("validated persisted chain claim bytes");
        let claim_tx =
            match BtcLikeTransaction::from_hex(Chain::Liquid(LiquidChain::Liquid), claim_tx_hex)
                .map_err(|error| {
                    AppError::ClaimError(format!("decode persisted chain claim_tx: {error}"))
                }) {
                Ok(transaction) => transaction,
                Err(error) => return commit_claim_preparation_error(tx, error).await,
            };
        let claim_txid = btc_like_txid(&claim_tx);
        if swap.claim_txid.as_deref() != Some(claim_txid.as_str()) {
            return commit_claim_preparation_error(
                tx,
                AppError::ClaimError(
                    "persisted chain claim bytes/txid do not match their decoded journal".into(),
                ),
            )
            .await;
        }
        if let Err(error) = validate_replayed_liquid_claim_fee_authority(
            &swap.claim_fee_authority,
            FeeConstructionPurpose::ChainLiquidClaim,
            &claim_tx,
        ) {
            return commit_claim_preparation_error(tx, error).await;
        }
        Some(claim_tx)
    } else {
        None
    };
    let boltz_response: CreateChainResponse = match serde_json::from_str(&swap.boltz_response_json)
    {
        Ok(response) => response,
        Err(parse_error) => {
            let error =
                AppError::ClaimError(format!("invalid chain boltz response json: {parse_error}"));
            // The guarded seam accepts only malformed persisted evidence
            // and performs no provider or chain I/O. A known refusal phrase
            // lets it exercise the exact durable transition used by the
            // live construction arm. Production never classifies corrupt
            // persisted JSON as provider authority.
            if require_malformed_response && is_cooperative_refusal(&error) {
                return commit_chain_cooperative_refusal(tx, swap.id, &swap.boltz_swap_id, error)
                    .await;
            }
            return Err(error);
        }
    };
    // Malformed persisted provider evidence remains diagnosable without a
    // chain backend, but every valid claim path must have authoritative source
    // evidence before invoice loading, transaction construction, or a provider
    // interaction can occur.
    let backend = utxo_backend.ok_or_else(|| {
        AppError::ClaimError(
            "Liquid source-evidence backend is unavailable for pre-broadcast journaling".into(),
        )
    })?;
    let invoice = db::get_invoice_by_id(&mut *tx, swap.invoice_id)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?
        .ok_or_else(|| AppError::ClaimError(format!("invoice not found: {}", swap.invoice_id)))?;

    // Post-051 swaps claim only to the immutable destination committed before
    // the payer saw the Bitcoin address. Never re-resolve it through the
    // mutable invoice relationship. Historical rows have no creation packet,
    // so they retain the explicit legacy fallback.
    let output_address = if let Some(terms) = swap.creation_terms.as_ref() {
        validated_chain_creation_destination(terms)?
    } else {
        invoice.liquid_address.clone().ok_or_else(|| {
            AppError::ClaimError(format!(
                "legacy invoice {} has no liquid_address for chain-swap claim",
                swap.invoice_id
            ))
        })?
    };
    let merchant_blinding_key_hex =
        invoice.liquid_blinding_key_hex.as_deref().ok_or_else(|| {
            AppError::ClaimError(format!(
                "invoice {} has no Liquid blinding key for chain-swap settlement",
                swap.invoice_id
            ))
        })?;
    validators::validate_liquid_blinding_key_matches_address(
        &output_address,
        merchant_blinding_key_hex,
    )
    .map_err(|error| {
        AppError::ClaimError(format!(
            "chain-swap settlement destination/blinding key mismatch: {error}"
        ))
    })?;
    let default_liquid_asset_id = elements::AssetId::LIQUID_BTC.to_string();
    let liquid_asset_id = swap
        .creation_terms
        .as_ref()
        .map(|terms| terms.liquid_asset_id.as_str())
        .unwrap_or(&default_liquid_asset_id);

    let claim_tx = if let Some(claim_tx) = persisted_claim_tx {
        claim_tx
    } else {
        let claim_clients = claim_clients.ok_or_else(|| {
            AppError::ClaimError("Liquid claim client factory is unavailable".to_string())
        })?;
        let fee_decision = LiquidBuilderFeeDecision::from(
            fee_decision.expect("unjournaled chain claims require a policy decision"),
        );
        // Cooperative MuSig2 claim by default; script-path (preimage) claim once
        // a concrete runtime refusal below sets `cooperative_refused`. Provider
        // expiry is interpreted by the shared evidence reducer and cannot flip
        // this execution selector by itself. One-way flag, so no
        // cooperative/script ping-pong. Mirrors claim_swap_inner (reverse path).
        let use_cooperative = !swap.cooperative_refused;
        let constructed = match construct_chain_claim_tx(
            &swap,
            &output_address,
            claim_clients,
            boltz_url,
            &fee_decision,
            use_cooperative,
        )
        .await
        {
            Ok(t) => t,
            Err(e) if use_cooperative && is_cooperative_refusal(&e) => {
                return commit_chain_cooperative_refusal(tx, swap.id, &swap.boltz_swap_id, e).await;
            }
            Err(e) => return commit_claim_preparation_error(tx, e).await,
        };
        constructed
    };

    let prepared = prepare_chain_claim_settlement_journal(
        &claim_tx,
        &output_address,
        liquid_asset_id,
        merchant_blinding_key_hex,
        &boltz_response.claim_details.lockup_address,
        boltz_response
            .claim_details
            .blinding_key
            .as_deref()
            .ok_or_else(|| {
                AppError::ClaimError("committed Liquid lockup blinding key is missing".into())
            })?,
        backend,
    )
    .await?;
    let new_journal = db::NewLiquidMerchantSettlementJournal {
        chain_swap_id: swap.id,
        replaces_txid: None,
        prepared: &prepared.journal,
        fee_amount_sat: prepared.fee_amount_sat,
        fee_rate_sat_vb: prepared.fee_rate_sat_vb,
        liquid_blinding_key_hex: merchant_blinding_key_hex,
        fee_authority: match journal_mode {
            PersistedChainClaimJournalMode::ConstructAndInsert => fee_record,
            PersistedChainClaimJournalMode::DecodeAndLoadExact => None,
        },
    };
    let journal_disposition = if journal_mode == PersistedChainClaimJournalMode::ConstructAndInsert
    {
        let fee_record = new_journal.fee_authority.ok_or_else(|| {
            AppError::ClaimError("unjournaled chain claim is missing fee authority".into())
        })?;
        let (actual_fee_sat, actual_fee_rate_sat_vb, actual_vbytes) = liquid_actual_fee(&claim_tx)?;
        ensure_actual_fee_authorized(
            "Liquid chain claim",
            actual_fee_sat,
            actual_vbytes,
            fee_record,
        )?;
        ensure_chain_claim_journal_fee_matches_actual(
            prepared.fee_amount_sat,
            prepared.fee_rate_sat_vb,
            actual_fee_sat,
            actual_fee_rate_sat_vb,
        )?;
        let quoted_at = checked_fee_i64(
            "claim_fee_decision_quoted_at_unix",
            fee_record.quoted_at_unix(),
        )?;
        let evaluated_at = checked_fee_i64(
            "claim_fee_decision_evaluated_at_unix",
            fee_record.evaluated_at_unix(),
        )?;
        let freshness_age = checked_fee_i64(
            "claim_fee_decision_freshness_age_secs",
            fee_record.freshness_age_secs(),
        )?;
        let freshness_max_age = checked_fee_i64(
            "claim_fee_decision_freshness_max_age_secs",
            fee_record.freshness_max_age_secs(),
        )?;
        if !fee_record.authorizes_construction_now() {
            return Ok(ClaimOutcome::PendingFeeUnavailable {
                reason: LIQUID_FEE_DECISION_PENDING_REASON,
            });
        }
        let persisted = sqlx::query(
            "UPDATE chain_swap_records \
             SET claim_tx_hex = $2, claim_txid = $3, \
                 claim_actual_fee_sat = $4, claim_actual_fee_rate_sat_vb = $5, \
                 claim_fee_decision_purpose = $6, claim_fee_decision_rail = $7, \
                 claim_fee_decision_target = $8, claim_fee_decision_source = $9, \
                 claim_fee_decision_rate_sat_vb = $10, \
                 claim_fee_decision_quoted_at_unix = $11, \
                 claim_fee_decision_evaluated_at_unix = $12, \
                 claim_fee_decision_freshness_age_secs = $13, \
                 claim_fee_decision_freshness_max_age_secs = $14, \
                 claim_fee_decision_provenance = $15, \
                 claim_fee_decision_policy_floor_sat_vb = $16, \
                 claim_fee_decision_policy_cap_sat_vb = $17, \
                 claim_fee_decision_policy_version = $18 \
             WHERE id = $1 AND claim_tx_hex IS NULL",
        )
        .bind(swap.id)
        .bind(&prepared.journal.raw_transaction_hex)
        .bind(&prepared.journal.txid)
        .bind(actual_fee_sat)
        .bind(actual_fee_rate_sat_vb)
        .bind(fee_record.purpose().as_str())
        .bind(fee_record.rail().as_str())
        .bind(fee_record.target().as_str())
        .bind(fee_record.source().as_str())
        .bind(fee_record.rate().as_f64())
        .bind(quoted_at)
        .bind(evaluated_at)
        .bind(freshness_age)
        .bind(freshness_max_age)
        .bind(fee_record.provenance_for_persistence())
        .bind(fee_record.policy_floor().as_f64())
        .bind(fee_record.policy_cap().as_f64())
        .bind(fee_record.policy_version())
        .execute(&mut *tx)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
        if persisted.rows_affected() != 1 {
            return Err(AppError::DbError(format!(
                "chain claim preparation lost its locked row: {}",
                swap.id
            )));
        }
        db::insert_liquid_merchant_settlement_journal(&mut tx, &new_journal)
            .await
            .map_err(|error| {
                AppError::DbError(format!(
                    "insert Liquid merchant settlement journal: {error}"
                ))
            })?;
        db::ExactLiquidMerchantSettlementJournalDisposition::Broadcastable
    } else {
        if swap.claim_tx_hex.as_deref() != Some(prepared.journal.raw_transaction_hex.as_str())
            || swap.claim_txid.as_deref() != Some(prepared.journal.txid.as_str())
        {
            return Err(AppError::ClaimError(
                "persisted chain claim bytes/txid do not match their decoded journal".into(),
            ));
        }
        require_exact_persisted_chain_claim_journal(
            db::load_exact_liquid_merchant_settlement_journal(&mut tx, &new_journal).await,
        )?
    };

    match journal_disposition {
        db::ExactLiquidMerchantSettlementJournalDisposition::AlreadySettled => {
            tx.commit()
                .await
                .map_err(|error| AppError::DbError(error.to_string()))?;
            return Ok(ClaimOutcome::AlreadyTerminal);
        }
        db::ExactLiquidMerchantSettlementJournalDisposition::Broadcastable
            if status == ChainSwapStatus::Claimed =>
        {
            return Err(AppError::ClaimError(
                "claimed chain swap has no confirmed or finalized exact journal".into(),
            ));
        }
        db::ExactLiquidMerchantSettlementJournalDisposition::Broadcastable => {}
    }

    let claim_clients = claim_clients.ok_or_else(|| {
        AppError::ClaimError("Liquid claim client factory is unavailable".to_string())
    })?;

    let marked_claiming = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'claiming', \
             next_claim_attempt_at = NOW() + $2::interval, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck')",
    )
    .bind(swap.id)
    .bind(db::CLAIM_IN_FLIGHT_LEASE)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::DbError(e.to_string()))?;
    if marked_claiming.rows_affected() != 1 {
        return Err(AppError::DbError(format!(
            "chain claim preparation could not publish claiming state: {}",
            swap.id
        )));
    }

    // Mirror the reverse path's last-moment construction-authority check. A
    // slow journal/status write must not turn an expired observation into new
    // durable claim bytes; replay of an existing journal remains independent
    // of a fresh quote.
    if !liquid_claim_journal_authorized(had_persisted_claim, fee_record) {
        return Ok(ClaimOutcome::PendingFeeUnavailable {
            reason: LIQUID_FEE_DECISION_PENDING_REASON,
        });
    }

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    // As on the reverse path, only bytes reloaded from the committed journal
    // may reach the broadcaster. The expected serialization detects any
    // disagreement between the locked preparation and the post-commit row,
    // including witness-only changes that do not alter the txid.
    let expected_hex = serialize_claim_tx_hex(&claim_tx)?;
    let claim_tx = reload_chain_claim_for_broadcast(pool, swap.id, &expected_hex).await?;

    let txid = btc_like_txid(&claim_tx);
    match db::mark_liquid_merchant_settlement_broadcast_started(
        pool,
        swap.id,
        &txid,
        "liquid_claim",
    )
    .await
    .map_err(|error| {
        AppError::DbError(format!(
            "start Liquid merchant settlement broadcast: {error}"
        ))
    })? {
        db::LiquidMerchantSettlementBroadcastStartDisposition::Started => {}
        db::LiquidMerchantSettlementBroadcastStartDisposition::AlreadySettled => {
            tracing::info!(
                event = "chain_claim_broadcast_start_already_settled",
                swap_id = %swap.boltz_swap_id,
                txid = %txid,
                "exact Liquid claim settled before broadcast start; skipping network call"
            );
            return Ok(ClaimOutcome::AlreadyTerminal);
        }
        db::LiquidMerchantSettlementBroadcastStartDisposition::Superseded => {
            tracing::info!(
                event = "chain_claim_broadcast_start_superseded",
                swap_id = %swap.boltz_swap_id,
                txid = %txid,
                "another worker superseded the prepared Liquid claim; skipping network call"
            );
            return Ok(ClaimOutcome::SkippedLockHeld);
        }
    }
    let liquid_client = claim_clients.connect().await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    let broadcast_result = match chain_client.try_broadcast_tx(&claim_tx).await {
        Ok(_) => "broadcast accepted or exact transaction already known",
        Err(broadcast_err) => match backend.tx_exists(&txid).await {
            Ok(true) => {
                tracing::info!(
                    event = "chain_claim_broadcast_probe_recovered",
                    swap_id = %swap.boltz_swap_id,
                    txid = %txid,
                    broadcast_error = %broadcast_err,
                    "chain claim broadcast errored but tx is on chain; treating as success"
                );
                "broadcast errored; exact transaction observed"
            }
            Ok(false) => match recover_claim_from_lockup_spend(&claim_tx, backend).await {
                Ok(Some(spending_txid)) if spending_txid.eq_ignore_ascii_case(&txid) => {
                    tracing::info!(
                        event = "chain_claim_outspend_recovered",
                        swap_id = %swap.boltz_swap_id,
                        expected_txid = %txid,
                        recovered_txid = %spending_txid,
                        broadcast_error = %broadcast_err,
                        "chain claim broadcast errored and expected txid was absent, but its exact lockup outspend was found"
                    );
                    "broadcast errored; exact journal outspend observed"
                }
                Ok(Some(spending_txid)) => {
                    return Err(AppError::ClaimError(format!(
                            "chain claim lockup was spent by unlinked transaction {spending_txid}; expected journaled {txid}; settlement integrity review required"
                        )));
                }
                Ok(None) => {
                    return Err(AppError::ClaimError(format!(
                        "broadcast chain claim failed: {broadcast_err}"
                    )));
                }
                Err(recovery_err) => {
                    tracing::warn!(
                            "chain claim outspend recovery failed for {}: {recovery_err}; treating broadcast as failed",
                            swap.boltz_swap_id
                        );
                    return Err(AppError::ClaimError(format!(
                        "broadcast chain claim failed: {broadcast_err}"
                    )));
                }
            },
            Err(probe_err) => {
                tracing::warn!(
                        "chain claim tx_exists probe failed for {}: {probe_err}; treating broadcast as failed",
                        swap.boltz_swap_id
                    );
                return Err(AppError::ClaimError(format!(
                    "broadcast chain claim failed: {broadcast_err}"
                )));
            }
        },
    };

    db::mark_liquid_merchant_settlement_broadcast(
        pool,
        swap.id,
        &txid,
        "liquid_claim",
        broadcast_result,
    )
    .await
    .map_err(|error| {
        AppError::DbError(format!(
            "mark Liquid merchant settlement broadcast: {error}"
        ))
    })?;

    // Broadcast is retained as an in-flight `claiming` transaction. Exact
    // merchant-output observation owns one-confirmation accounting and the
    // later Liquid-finality transition; provider/broadcast success cannot
    // terminalize the obligation or supply an invoice amount.
    tracing::info!(
        event = "chain_swap_claim_broadcast_pending_settlement",
        swap_id = %swap.boltz_swap_id,
        claim_txid = %txid,
        "chain claim broadcast; awaiting exact merchant-output confirmation"
    );

    Ok(ClaimOutcome::Broadcast)
}

/// Build a claim tx for a freshly-funded reverse swap.
///
/// `cooperative` selects the spending path:
///
///   - `true`: MuSig2 keypath — fastest, smallest tx (~107 vB on Liquid),
///     requires Boltz to cosign via `POST /swap/reverse/{id}/claim`.
///     Default for swaps in good standing.
///   - `false`: script-path with preimage reveal — ~85 vB larger
///     (~9 sats more on Liquid), works without Boltz, and is the only
///     option once `swap.expired` has fired (Boltz refuses cooperative
///     post-expiry per `MusigSigner.ts`).
///
/// Pure I/O — called under the per-swap advisory lock so at most one
/// `construct_claim` runs per swap at a time, regardless of webhook /
/// sweep / reconciler concurrency.
async fn construct_claim_tx(
    swap: &db::SwapRecord,
    output_address: &str,
    claim_clients: &LiquidClaimClientFactory,
    boltz_url: &str,
    fee_decision: &LiquidBuilderFeeDecision,
    cooperative: bool,
) -> Result<BtcLikeTransaction, AppError> {
    let preimage_hex = swap
        .preimage_hex
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("missing preimage".to_string()))?;
    let claim_key_hex = swap
        .claim_key_hex
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("missing claim key".to_string()))?;
    let response_json = swap
        .boltz_response_json
        .as_deref()
        .ok_or_else(|| AppError::ClaimError("missing boltz response".to_string()))?;

    let preimage_bytes = hex::decode(preimage_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid preimage hex: {e}")))?;
    let preimage = Preimage::from_vec(preimage_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid preimage: {e}")))?;

    let key_bytes = hex::decode(claim_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid claim key hex: {e}")))?;
    let secp = boltz_client::Secp256k1::new();
    let secret_key = boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&key_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid secret key: {e}")))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    let boltz_response: CreateReverseResponse = serde_json::from_str(response_json)
        .map_err(|e| AppError::ClaimError(format!("invalid boltz response json: {e}")))?;

    let claim_public_key = boltz_client::PublicKey::new(keypair.public_key());
    let chain = Chain::Liquid(LiquidChain::Liquid);
    let swap_script = SwapScript::reverse_from_swap_resp(chain, &boltz_response, claim_public_key)
        .map_err(|e| AppError::ClaimError(format!("swap script build failed: {e}")))?;

    // New connection per construct call: ElectrumLiquidClient wraps a TCP
    // socket and isn't Send+Sync, so it can't be shared across tasks.
    let liquid_client = claim_clients.connect().await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    // Bound the claim-path Boltz client. With no timeout a hung Boltz (as seen
    // during a degradation/DDoS) blocks the cooperative-claim round-trip
    // indefinitely, which wedges the whole sweep loop and lets funded lockups
    // drift to their timeout height — Boltz then refunds itself and the payer's
    // money is lost. 15s covers the MuSig2 round-trip while still failing fast.
    let boltz_api = BoltzApiClientV2::new(boltz_url.to_string(), Some(Duration::from_secs(15)));

    let params = SwapTransactionParams {
        keys: keypair,
        output_address: output_address.to_string(),
        fee: liquid_claim_fee(fee_decision, cooperative),
        swap_id: swap.boltz_swap_id.clone(),
        chain_client: &chain_client,
        boltz_client: &boltz_api,
        options: Some(TransactionOptions::default().with_cooperative(cooperative)),
    };

    swap_script
        .construct_claim(&preimage, params)
        .await
        .map_err(|e| AppError::ClaimError(format!("construct_claim failed: {e}")))
}

async fn construct_chain_claim_tx(
    swap: &db::ChainSwapRecord,
    output_address: &str,
    claim_clients: &LiquidClaimClientFactory,
    boltz_url: &str,
    fee_decision: &LiquidBuilderFeeDecision,
    use_cooperative: bool,
) -> Result<BtcLikeTransaction, AppError> {
    let preimage_bytes = hex::decode(&swap.preimage_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain preimage hex: {e}")))?;
    let preimage = Preimage::from_vec(preimage_bytes)
        .map_err(|e| AppError::ClaimError(format!("invalid chain preimage: {e}")))?;

    let claim_key_bytes = hex::decode(&swap.claim_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain claim key hex: {e}")))?;
    let refund_key_bytes = hex::decode(&swap.refund_key_hex)
        .map_err(|e| AppError::ClaimError(format!("invalid chain refund key hex: {e}")))?;
    let secp = boltz_client::Secp256k1::new();
    let claim_secret_key =
        boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&claim_key_bytes)
            .map_err(|e| AppError::ClaimError(format!("invalid chain claim secret key: {e}")))?;
    let refund_secret_key =
        boltz_client::bitcoin::secp256k1::SecretKey::from_slice(&refund_key_bytes)
            .map_err(|e| AppError::ClaimError(format!("invalid chain refund secret key: {e}")))?;
    let claim_keypair = Keypair::from_secret_key(&secp, &claim_secret_key);
    let refund_keypair = Keypair::from_secret_key(&secp, &refund_secret_key);

    let boltz_response: CreateChainResponse = serde_json::from_str(&swap.boltz_response_json)
        .map_err(|e| AppError::ClaimError(format!("invalid chain boltz response json: {e}")))?;

    let claim_public_key = boltz_client::PublicKey::new(claim_keypair.public_key());
    let refund_public_key = boltz_client::PublicKey::new(refund_keypair.public_key());
    let claim_script = SwapScript::chain_from_swap_resp(
        Chain::Liquid(LiquidChain::Liquid),
        Side::Claim,
        boltz_response.claim_details.clone(),
        claim_public_key,
    )
    .map_err(|e| AppError::ClaimError(format!("chain claim script build failed: {e}")))?;
    let lockup_script = SwapScript::chain_from_swap_resp(
        Chain::Bitcoin(BitcoinChain::Bitcoin),
        Side::Lockup,
        boltz_response.lockup_details.clone(),
        refund_public_key,
    )
    .map_err(|e| AppError::ClaimError(format!("chain lockup script build failed: {e}")))?;

    let liquid_client = claim_clients.connect().await?;
    let chain_client = ChainClient::new().with_liquid(liquid_client);
    // Bound the claim-path Boltz client. With no timeout a hung Boltz (as seen
    // during a degradation/DDoS) blocks the cooperative-claim round-trip
    // indefinitely, which wedges the whole sweep loop and lets funded lockups
    // drift to their timeout height — Boltz then refunds itself and the payer's
    // money is lost. 15s covers the MuSig2 round-trip while still failing fast.
    let boltz_api = BoltzApiClientV2::new(boltz_url.to_string(), Some(Duration::from_secs(15)));

    let params = SwapTransactionParams {
        keys: claim_keypair,
        output_address: output_address.to_string(),
        fee: liquid_claim_fee(fee_decision, use_cooperative),
        swap_id: swap.boltz_swap_id.clone(),
        chain_client: &chain_client,
        boltz_client: &boltz_api,
        options: Some(
            TransactionOptions::default()
                .with_chain_claim(refund_keypair, lockup_script)
                .with_cooperative(use_cooperative),
        ),
    };

    claim_script
        .construct_claim(&preimage, params)
        .await
        .map_err(|e| AppError::ClaimError(format!("construct_chain_claim failed: {e}")))
}

/// Phase 4 merchant-recovery executor (#44). Drains a `refund_due` chain swap
/// by refunding the payer's BTC lockup to the destination address committed on
/// the swap (supplied by the merchant via the signed `/recover` endpoint).
/// Returns the broadcast refund txid on success.
///
/// Money-safety design:
///   * **G12 (double-payout):** we first verify Boltz has NOT claimed the swap
///     (merchant unpaid), then atomically flip `refund_due` -> `refunding` under
///     the shared `chain-claim:<id>` advisory lock. `refunding` is excluded from
///     every claim path, so the L-BTC claim and the BTC refund — which spend
///     different UTXOs on different chains — can never both fire. A claim only
///     ever starts from a claimable lifecycle state, never from
///     `refunding`/`refund_due`.
///   * **G14 (idempotency):** the refund address is persisted (first-write-wins)
///     before this runs. Exact signed bytes and intent commit in the same
///     transaction as the single-winner `refunding` flip. A failed or ambiguous
///     broadcast remains there and only those committed bytes may be replayed.
///
/// Construction and journaling happen under the advisory transaction lock;
/// broadcast happens after commit without holding a database connection.
/// Returns true if the chain-swap USER lockup transaction is CONFIRMED on-chain.
///
/// The confirmation is checked by TXID, not by address: the deployment's esplora
/// runs without an address/script-hash index (address endpoints error), but
/// txid + block endpoints work. So we ask Boltz for the lockup funding txid
/// (`/swap/chain/{id}/transactions` -> userLock.transaction.id) and then query
/// the esplora `/tx/{txid}/status`. An observed unconfirmed transaction is
/// `Ok(false)`; an unavailable provider is a typed backend error so worker
/// health cannot mistake an outage for a healthy deferral.
async fn chain_lockup_confirmed(
    boltz_url: &str,
    esploras: &[String],
    swap_id: &str,
) -> Result<bool, AppError> {
    // 1) lockup funding txid from Boltz
    #[derive(serde::Deserialize)]
    struct LockTx {
        id: String,
    }
    #[derive(serde::Deserialize)]
    struct UserLock {
        transaction: LockTx,
    }
    #[derive(serde::Deserialize)]
    struct ChainTxs {
        #[serde(rename = "userLock")]
        user_lock: UserLock,
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(error) => {
            return Err(AppError::BoltzError(format!(
                "build recovery confirmation client: {error}"
            )))
        }
    };
    let txs_url = format!(
        "{}/swap/chain/{}/transactions",
        boltz_url.trim_end_matches('/'),
        swap_id
    );
    let response = client.get(&txs_url).send().await.map_err(|error| {
        AppError::BoltzError(format!("fetch recovery lockup transaction: {error}"))
    })?;
    if !response.status().is_success() {
        return Err(AppError::BoltzError(format!(
            "fetch recovery lockup transaction returned HTTP {}",
            response.status()
        )));
    }
    let txid = match response.json::<ChainTxs>().await {
        Ok(c) => c.user_lock.transaction.id,
        Err(error) => {
            return Err(AppError::BoltzError(format!(
                "decode recovery lockup transaction: {error}"
            )))
        }
    };

    // 2) confirmation from the esplora, txid-based (no address index needed),
    // failing over across all configured endpoints.
    #[derive(serde::Deserialize)]
    struct TxStatus {
        confirmed: bool,
    }
    crate::esplora::get_json::<TxStatus>(esploras, &format!("tx/{txid}/status"))
        .await
        .map(|s| s.confirmed)
        .ok_or_else(|| {
            AppError::ElectrumError(format!(
                "Bitcoin lockup confirmation is unavailable for {txid}"
            ))
        })
}

pub(crate) async fn execute_chain_swap_refund(
    state: &AppState,
    swap: &db::ChainSwapRecord,
) -> Result<String, AppError> {
    let refund_address = swap.refund_address.clone().ok_or_else(|| {
        AppError::ClaimError("chain swap refund requested without a refund address".to_string())
    })?;

    // G12 (belt-and-suspenders): never refund a swap Boltz has already claimed
    // (the merchant was paid). Read-only Boltz truth, before we take the lock.
    let boltz_api = BoltzApiClientV2::new(
        state.config.boltz.api_url.clone(),
        Some(Duration::from_secs(15)),
    );
    match boltz_api.get_swap(&swap.boltz_swap_id).await {
        Ok(remote) if remote.status == "transaction.claimed" => {
            tracing::error!(
                event = "chain_swap_refund_blocked_boltz_claimed",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                "refund blocked: Boltz reports the swap claimed (merchant paid); refusing to refund (operator P1)"
            );
            return Err(AppError::ClaimError(
                "refund blocked: swap already claimed".to_string(),
            ));
        }
        Ok(_) => {}
        Err(e) => {
            // Cannot confirm Boltz state → do NOT broadcast a refund we can't
            // prove is safe. Leave the swap `refund_due` for a later retry.
            return Err(AppError::BoltzError(format!(
                "refund pre-check get_swap failed: {e}"
            )));
        }
    }

    // Lockup-confirmation gate: never attempt a refund on an UNCONFIRMED lockup.
    // Boltz emits `transaction.lockupFailed` on 0-conf detection of an underpaid
    // lockup, so `refund_due` is reached before the lockup mines. Refunding then
    // fails: Boltz won't co-sign a cooperative refund of an unconfirmed lockup,
    // and the script-path fallback is non-final pre-timeout — either way
    // `sendrawtransaction` rejects it. Defer until the lockup has >=1 conf; the
    // caller (endpoint poll / reconciler) retries and it self-heals. This avoids
    // the wasted `refunding`->revert churn and the confusing broadcast errors.
    let bitcoin_recovery_backend = state.bitcoin_recovery_backend.as_deref().ok_or_else(|| {
        AppError::ElectrumError("Bitcoin recovery evidence client is unavailable".into())
    })?;
    match chain_lockup_confirmed(
        &state.config.boltz.api_url,
        bitcoin_recovery_backend.endpoints(),
        &swap.boltz_swap_id,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(
                event = "chain_swap_recover_deferred_unconfirmed_lockup",
                swap_id = %swap.boltz_swap_id,
                invoice_id = %swap.invoice_id,
                lockup_address = %swap.lockup_address,
                "recovery deferred: BTC lockup not yet confirmed; retry after confirmation"
            );
            return Err(AppError::RecoveryNotAvailable(
                "recovery deferred: BTC lockup not yet confirmed".to_string(),
            ));
        }
        Err(error) => return Err(error),
    }

    tracing::warn!(
        event = "chain_swap_refunding",
        swap_id = %swap.boltz_swap_id,
        invoice_id = %swap.invoice_id,
        refund_address = %refund_address,
        "journaled Bitcoin recovery starting (operator P2)"
    );

    crate::chain_recovery::execute_journaled_recovery(state, swap.id).await
}

/// Heuristic classifier for cooperative-claim refusals from Boltz.
///
/// `boltz-rust`'s `get_reverse_partial_sig` surfaces an HTTP 4xx as
/// `Error::Serde` (the response body isn't a `PartialSig`, so JSON
/// parse fails). The status code is not preserved on the wire — we
/// have to inspect the message body for known refusal phrases.
///
/// Per the plan's risk register: misclassification toward "transient"
/// is safer than toward "refused". Premature cooperative abandonment
/// costs an extra ~9 sats of fee on a recoverable swap; the reverse
/// silently disables the optimal claim path. Only the substrings below
/// are treated as definite refusal; everything else falls through to
/// the wrapper's normal retry-with-backoff handling.
fn is_cooperative_refusal(err: &AppError) -> bool {
    let s = err.to_string().to_lowercase();
    // Phrasing taken from `boltz-backend` `lib/service/cooperative/MusigSigner.ts`
    // and the public Boltz API errors documented at
    // https://api.docs.boltz.exchange/. Update this list if Boltz's
    // error wording shifts — symptom would be cooperative attempts
    // looping at backoff cap until ClaimStuck.
    s.contains("swap expired")
        || s.contains("invalid preimage")
        || s.contains("cooperative claim disabled")
        || s.contains("cooperative signing disabled")
        || s.contains("not eligible for a cooperative claim")
        || s.contains("not eligible for cooperative")
}

/// Strip the URL scheme from an electrum endpoint for boltz-client's
/// `ElectrumLiquidClient`, which expects a bare `host:port` and re-adds the
/// scheme itself (`build_client` does `format!("ssl://{url}")`). Our config
/// carries the scheme (the electrum-client backend in utxo.rs wants it), so
/// passing it through unmodified yields a doubled `ssl://ssl://host:port` that
/// fails DNS resolution ("Name or service not known") — meaning claims never
/// broadcast. Strip `ssl://`/`tcp://` here so both electrum clients get the
/// form they expect.
fn electrum_host_port(url: &str) -> &str {
    url.strip_prefix("ssl://")
        .or_else(|| url.strip_prefix("tcp://"))
        .unwrap_or(url)
}

/// Retained, process-local witness for the exact Liquid claim client path.
///
/// The underlying Boltz Electrum client owns a socket and is intentionally
/// created per operation, so it cannot live in [`AppState`]. This factory is
/// the initialized hard fact instead: it validates and retains the immutable
/// failover configuration used by every claim construction and broadcast.
/// Reachability remains transient worker evidence and is checked by
/// [`connect`](Self::connect), never promoted to a permanent hard failure.
#[derive(Debug)]
pub struct LiquidClaimClientFactory {
    urls: Vec<String>,
}

impl LiquidClaimClientFactory {
    pub fn try_new(urls: Vec<String>) -> Result<Self, AppError> {
        let urls: Vec<String> = urls
            .into_iter()
            .filter(|url| crate::config::valid_electrum_endpoint(url))
            .collect();
        if urls.is_empty() {
            return Err(AppError::ClaimError(
                "no valid Liquid claim client endpoint is configured".to_string(),
            ));
        }
        Ok(Self { urls })
    }

    #[cfg(test)]
    fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Connect a Liquid Electrum client for the claim/broadcast path, trying
    /// each validated URL until one connects and answers a cheap probe — the
    /// same provider failover the UtxoBackend pool already has (#47).
    async fn connect(&self) -> Result<ElectrumLiquidClient, AppError> {
        connect_liquid_electrum(&self.urls).await
    }
}

async fn connect_liquid_electrum(urls: &[String]) -> Result<ElectrumLiquidClient, AppError> {
    let mut errors: Vec<String> = Vec::new();
    for (i, url) in urls.iter().enumerate() {
        let tls = url.starts_with("ssl://");
        let client = match ElectrumLiquidClient::new(
            LiquidChain::Liquid,
            electrum_host_port(url),
            tls,
            tls,
            30,
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    event = "liquid_electrum_failover",
                    endpoint = %url,
                    err = %e,
                    "Liquid electrum connect failed; trying next endpoint"
                );
                errors.push(format!("{url}: connect: {e}"));
                continue;
            }
        };
        // Post-connect validation: a genesis-header fetch is cheap and
        // deterministic; an up-but-broken node errors here and we rotate.
        if let Err(e) = client.get_genesis_hash().await {
            tracing::warn!(
                event = "liquid_electrum_failover",
                endpoint = %url,
                err = %e,
                "Liquid electrum connected but failed validation probe; trying next endpoint"
            );
            errors.push(format!("{url}: probe: {e}"));
            continue;
        }
        if i > 0 {
            tracing::warn!(
                event = "liquid_electrum_failover",
                endpoint = %url,
                "connected to failover Liquid electrum after earlier endpoint(s) failed"
            );
        }
        return Ok(client);
    }
    tracing::error!(
        event = "liquid_electrum_all_endpoints_failed",
        endpoints = urls.len(),
        "all Liquid electrum endpoints failed to connect"
    );
    Err(AppError::ClaimError(format!(
        "electrum connection failed on all {} url(s): {}",
        urls.len(),
        errors.join(" | ")
    )))
}

/// Hex-encode a fully-signed claim tx for storage in
/// `swap_records.claim_tx_hex`. Mirrors the deserialize path in
/// `BtcLikeTransaction::from_hex` so a round-trip is well-defined for
/// both Liquid (elements consensus) and Bitcoin (consensus crate).
fn serialize_claim_tx_hex(tx: &BtcLikeTransaction) -> Result<String, AppError> {
    Ok(match tx {
        BtcLikeTransaction::Liquid(t) => hex::encode(boltz_client::elements::encode::serialize(t)),
        BtcLikeTransaction::Bitcoin(t) => {
            hex::encode(boltz_client::bitcoin::consensus::serialize(t))
        }
    })
}

fn btc_like_txid(tx: &BtcLikeTransaction) -> String {
    match tx {
        BtcLikeTransaction::Liquid(t) => t.txid().to_string(),
        BtcLikeTransaction::Bitcoin(t) => t.compute_txid().to_string(),
    }
}

fn validate_reloaded_liquid_claim(
    context: &str,
    expected_hex: &str,
    persisted_txid: Option<&str>,
    persisted_hex: Option<&str>,
) -> Result<BtcLikeTransaction, AppError> {
    let persisted_hex = persisted_hex.ok_or_else(|| {
        AppError::ClaimError(format!(
            "committed {context} claim bytes disappeared before broadcast"
        ))
    })?;
    let persisted_txid = persisted_txid.ok_or_else(|| {
        AppError::ClaimError(format!(
            "committed {context} claim txid disappeared before broadcast"
        ))
    })?;
    if !persisted_hex.eq_ignore_ascii_case(expected_hex) {
        return Err(AppError::ClaimError(format!(
            "committed {context} claim bytes changed across the commit boundary"
        )));
    }
    let transaction =
        BtcLikeTransaction::from_hex(Chain::Liquid(LiquidChain::Liquid), persisted_hex).map_err(
            |error| {
                AppError::ClaimError(format!(
                    "decode committed {context} claim transaction: {error}"
                ))
            },
        )?;
    let decoded_txid = btc_like_txid(&transaction);
    if !decoded_txid.eq_ignore_ascii_case(persisted_txid) {
        return Err(AppError::ClaimError(format!(
            "committed {context} claim bytes do not match the committed txid"
        )));
    }
    let canonical_hex = serialize_claim_tx_hex(&transaction)?;
    if !canonical_hex.eq_ignore_ascii_case(persisted_hex) {
        return Err(AppError::ClaimError(format!(
            "committed {context} claim bytes are not a canonical transaction encoding"
        )));
    }
    Ok(transaction)
}

async fn reload_reverse_claim_for_broadcast(
    pool: &sqlx::PgPool,
    swap_id: Uuid,
    expected_hex: &str,
) -> Result<BtcLikeTransaction, AppError> {
    let persisted = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT claim_txid, claim_tx_hex FROM swap_records WHERE id = $1",
    )
    .bind(swap_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| AppError::DbError(error.to_string()))?
    .ok_or_else(|| {
        AppError::ClaimError(format!(
            "reverse swap {swap_id} disappeared before claim broadcast"
        ))
    })?;
    validate_reloaded_liquid_claim(
        "reverse",
        expected_hex,
        persisted.0.as_deref(),
        persisted.1.as_deref(),
    )
}

async fn reload_chain_claim_for_broadcast(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    expected_hex: &str,
) -> Result<BtcLikeTransaction, AppError> {
    let persisted = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT claim_txid, claim_tx_hex FROM chain_swap_records WHERE id = $1",
    )
    .bind(chain_swap_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| AppError::DbError(error.to_string()))?
    .ok_or_else(|| {
        AppError::ClaimError(format!(
            "chain swap {chain_swap_id} disappeared before claim broadcast"
        ))
    })?;
    validate_reloaded_liquid_claim(
        "chain",
        expected_hex,
        persisted.0.as_deref(),
        persisted.1.as_deref(),
    )
}

fn liquid_actual_fee(tx: &BtcLikeTransaction) -> Result<(i64, f64, u64), AppError> {
    let BtcLikeTransaction::Liquid(transaction) = tx else {
        return Err(AppError::ClaimError(
            "Liquid claim builder returned a non-Liquid transaction".into(),
        ));
    };
    let mut fee_outputs = transaction.output.iter().filter(|output| output.is_fee());
    let fee_output = fee_outputs.next().ok_or_else(|| {
        AppError::ClaimError("constructed Liquid claim has no explicit fee output".into())
    })?;
    if fee_outputs.next().is_some() {
        return Err(AppError::ClaimError(
            "constructed Liquid claim has multiple fee outputs".into(),
        ));
    }
    match fee_output.asset {
        boltz_elements::confidential::Asset::Explicit(asset)
            if asset == boltz_elements::AssetId::LIQUID_BTC => {}
        _ => {
            return Err(AppError::ClaimError(
                "constructed Liquid claim fee is not explicit L-BTC".into(),
            ))
        }
    }
    let fee_sat = match fee_output.value {
        boltz_elements::confidential::Value::Explicit(value) if value > 0 => value,
        _ => {
            return Err(AppError::ClaimError(
                "constructed Liquid claim fee is not a positive explicit value".into(),
            ))
        }
    };
    // Liquid claims are constructed through boltz-client with
    // `is_discount_ct = true`, so the relative fee is applied to Elements'
    // discounted confidential-transaction virtual size. Record the actual
    // effective rate on that same basis.
    let vsize = transaction.discount_vsize();
    if vsize == 0 {
        return Err(AppError::ClaimError(
            "constructed Liquid claim has zero discounted virtual size".into(),
        ));
    }
    let discounted_vbytes = u64::try_from(vsize).map_err(|_| {
        AppError::ClaimError("Liquid claim discounted virtual size exceeds u64".into())
    })?;
    let fee_sat_i64 = i64::try_from(fee_sat)
        .map_err(|_| AppError::ClaimError("Liquid claim fee exceeds BIGINT storage".into()))?;
    Ok((
        fee_sat_i64,
        fee_sat as f64 / vsize as f64,
        discounted_vbytes,
    ))
}

fn ensure_actual_fee_authorized(
    context: &str,
    actual_fee_sat: i64,
    actual_vbytes: u64,
    fee_record: &FeeDecisionRecord,
) -> Result<(), AppError> {
    let actual_fee_sat = u64::try_from(actual_fee_sat)
        .map_err(|_| AppError::ClaimError(format!("{context} fee is negative")))?;
    let exact_fee_sat = fee_record
        .exact_authorized_fee_sat(actual_vbytes)
        .map_err(|error| {
            AppError::ClaimError(format!(
                "{context} fee bound cannot be represented for {actual_vbytes} vbytes: {error}"
            ))
        })?;
    if actual_fee_sat != exact_fee_sat {
        return Err(AppError::ClaimError(format!(
            "{context} fee {actual_fee_sat} sat does not match exact accepted decision fee {exact_fee_sat} sat for {actual_vbytes} vbytes"
        )));
    }
    Ok(())
}

fn validate_replayed_liquid_claim_fee_authority(
    authority: &db::LiquidClaimFeeAuthority,
    expected_purpose: FeeConstructionPurpose,
    claim_tx: &BtcLikeTransaction,
) -> Result<(), AppError> {
    // Pre-054 bytes are intentionally replayable without inventing authority
    // that did not exist at construction time. Every complete post-054 packet
    // is instead checked against values rederived from the exact stored bytes.
    if authority.is_legacy() {
        return Ok(());
    }
    let (actual_fee_sat, actual_fee_rate_sat_vb, discounted_vbytes) = liquid_actual_fee(claim_tx)?;
    authority
        .validate_replayed_claim(
            expected_purpose,
            actual_fee_sat,
            actual_fee_rate_sat_vb,
            discounted_vbytes,
        )
        .map_err(|error| {
            AppError::ClaimError(format!(
                "invalid persisted Liquid claim fee authority: {error}"
            ))
        })
}

fn checked_fee_i64(field: &'static str, value: u64) -> Result<i64, AppError> {
    i64::try_from(value)
        .map_err(|_| AppError::ClaimError(format!("{field} exceeds BIGINT storage")))
}

fn liquid_fee_record_for_compatibility_seam(
    purpose: FeeConstructionPurpose,
    decision: &LiquidFeeDecision,
) -> Result<FeeDecisionRecord, AppError> {
    let evaluated_at_unix =
        match decision.freshness() {
            FeeFreshness::Fresh { age_secs, .. } => decision
                .observed_at_unix()
                .checked_add(age_secs)
                .ok_or_else(|| AppError::ClaimError("fee decision clock overflow".into()))?,
            _ => {
                return Err(AppError::ClaimError(
                    LIQUID_FEE_DECISION_PENDING_REASON.into(),
                ))
            }
        };
    FeeDecisionRecord::from_liquid(
        purpose,
        decision,
        &LiquidFeePolicy::default(),
        evaluated_at_unix,
    )
    .map_err(|error| AppError::ClaimError(format!("invalid Liquid fee decision record: {error}")))
}

async fn recover_claim_from_lockup_spend(
    claim_tx: &BtcLikeTransaction,
    backend: &Arc<dyn UtxoBackend>,
) -> Result<Option<String>, AppError> {
    let BtcLikeTransaction::Liquid(tx) = claim_tx else {
        return Ok(None);
    };

    let Some(input) = tx.input.first() else {
        return Err(AppError::ClaimError(
            "claim tx has no input for outspend recovery".into(),
        ));
    };

    let lockup_txid = input.previous_output.txid.to_string();
    let lockup_vout = input.previous_output.vout;
    let raw_lockup = backend.get_raw_tx(&lockup_txid).await?;
    let lockup_tx: elements::Transaction = elements::encode::deserialize(&raw_lockup)
        .map_err(|e| AppError::ClaimError(format!("decode lockup tx: {e}")))?;
    let lockup_output = lockup_tx
        .output
        .get(lockup_vout as usize)
        .ok_or_else(|| AppError::ClaimError(format!("lockup vout {lockup_vout} missing")))?;

    let Some(spending_txid) = backend
        .find_spending_txid(&lockup_output.script_pubkey, &lockup_txid, lockup_vout)
        .await?
    else {
        return Ok(None);
    };

    let raw_spending = backend.get_raw_tx(&spending_txid).await?;
    let spending_tx: boltz_elements::Transaction =
        boltz_elements::encode::deserialize(&raw_spending)
            .map_err(|e| AppError::ClaimError(format!("decode spending tx: {e}")))?;
    if !spending_tx_matches_claim_destination(&spending_tx, tx) {
        return Err(AppError::ClaimError(format!(
            "lockup spent by {spending_txid}, but spender does not pay the claim destination"
        )));
    }

    Ok(Some(spending_txid))
}

fn spending_tx_matches_claim_destination(
    spending_tx: &boltz_elements::Transaction,
    claim_tx: &boltz_elements::Transaction,
) -> bool {
    claim_tx.output.iter().any(|claim_output| {
        !claim_output.script_pubkey.is_empty()
            && spending_tx
                .output
                .iter()
                .any(|out| out.script_pubkey == claim_output.script_pubkey)
    })
}

#[derive(Debug, Default)]
struct ClaimClientStartup {
    initialized: bool,
}

impl ClaimClientStartup {
    /// Returns `true` only for the call that first proves initialization.
    /// Once latched, the probe closure is never invoked again.
    async fn ensure_initialized<F, Fut>(&mut self, probe: F) -> Result<bool, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), AppError>>,
    {
        if self.initialized {
            return Ok(false);
        }
        probe().await?;
        self.initialized = true;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;

/// Owned runtime dependencies for the long-lived reverse and chain claim
/// sweeps. Worker health reporters are grouped separately because they are
/// mutable rail-local state, not claim-construction capabilities.
pub struct BackgroundClaimerDependencies {
    pool: sqlx::PgPool,
    config: Arc<Config>,
    claim_clients: Option<Arc<LiquidClaimClientFactory>>,
    utxo_backend: Option<Arc<dyn UtxoBackend>>,
    fee_runtime: Arc<FeeRuntime>,
    cancel: CancellationToken,
}

impl BackgroundClaimerDependencies {
    pub fn new(
        pool: sqlx::PgPool,
        config: Arc<Config>,
        claim_clients: Option<Arc<LiquidClaimClientFactory>>,
        utxo_backend: Option<Arc<dyn UtxoBackend>>,
        fee_runtime: Arc<FeeRuntime>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            pool,
            config,
            claim_clients,
            utxo_backend,
            fee_runtime,
            cancel,
        }
    }
}

/// Rail-local admission reporters consumed by the background claimer task.
pub struct BackgroundClaimerReporters {
    reverse: WorkerReporter,
    chain: WorkerReporter,
}

impl BackgroundClaimerReporters {
    pub fn new(reverse: WorkerReporter, chain: WorkerReporter) -> Self {
        Self { reverse, chain }
    }
}

pub fn spawn_background_claimer(
    dependencies: BackgroundClaimerDependencies,
    reporters: BackgroundClaimerReporters,
) -> tokio::task::JoinHandle<()> {
    let BackgroundClaimerDependencies {
        pool,
        config,
        claim_clients,
        utxo_backend,
        fee_runtime,
        cancel,
    } = dependencies;
    let BackgroundClaimerReporters {
        reverse: mut reverse_reporter,
        chain: mut chain_reporter,
    } = reporters;
    tokio::spawn(async move {
        let mut first_reverse_run = true;
        let mut claim_client_startup = ClaimClientStartup::default();
        // Heartbeat counter. Log liveness every N ticks so "is the
        // background claimer running?" is a grep-able question, not a
        // process-tree archaeology one. At 10s/tick x 30 ticks, that's
        // every 5 minutes — same cadence as the rate-limit GC.
        const HEARTBEAT_EVERY_N_TICKS: u32 = 30;
        let mut tick_count: u32 = 0;
        loop {
            // The factory is the immutable hard capability, but #68 also
            // requires this process to prove the exact socket/client path
            // before an empty DB scan may open swap admission. Probe once;
            // transient startup failures stay under worker hysteresis and are
            // retried, while later operation failures are observed by the
            // ordinary claim cycles.
            if let Some(factory) = claim_clients.as_deref() {
                match claim_client_startup
                    .ensure_initialized(|| async {
                        let client = factory.connect().await?;
                        drop(client);
                        Ok(())
                    })
                    .await
                {
                    Ok(initialized_now) => {
                        if initialized_now {
                            tracing::info!(
                                event = "liquid_claim_client_initialized",
                                "Liquid claim client path initialized for this process"
                            );
                        }
                    }
                    Err(error) => {
                        reverse_reporter.cycle_failed();
                        chain_reporter.cycle_failed();
                        tracing::warn!(
                            event = "liquid_claim_client_startup_failed",
                            error = %error,
                            "Liquid claim client initialization failed; retrying"
                        );
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                reverse_reporter.intentional_shutdown();
                                chain_reporter.intentional_shutdown();
                                return;
                            }
                            _ = tokio::time::sleep(Duration::from_secs(CLAIM_SWEEP_INTERVAL_SECS)) => {}
                        }
                        continue;
                    }
                }
            }

            tick_count = tick_count.wrapping_add(1);
            let mut ready_count = 0;
            match db::get_ready_to_claim_swaps(&pool).await {
                Ok(ready) => {
                    ready_count = ready.len();
                    let mut health = ClaimCycleHealth::default();
                    if !ready.is_empty() {
                        if first_reverse_run {
                            tracing::info!(
                                "background claimer: found {} unclaimed swaps on startup",
                                ready.len()
                            );
                        }
                        for swap in &ready {
                            reverse_reporter.progress();
                            let fee_decision = fee_runtime
                                .liquid_construction_decision_now(
                                    FeeConstructionPurpose::ReverseLiquidClaim,
                                )
                                .ok();
                            match claim_swap(
                                &pool,
                                swap.id,
                                claim_clients.as_deref(),
                                &config.boltz.api_url,
                                config.claim.max_claim_attempts,
                                utxo_backend.as_ref(),
                                db::InvoiceAccountingTolerances::from(&config.invoice_accounting),
                                fee_decision.as_ref().map(|(decision, _)| decision),
                                fee_decision.as_ref().map(|(_, record)| record),
                            )
                            .await
                            {
                                Ok(ClaimOutcome::Broadcast) => {
                                    tracing::info!(
                                        "background claimer: claimed swap {}",
                                        swap.boltz_swap_id
                                    );
                                }
                                Ok(ClaimOutcome::SkippedLockHeld) => {
                                    tracing::debug!(
                                        "background claimer: skipped {} (lock held)",
                                        swap.boltz_swap_id
                                    );
                                }
                                Ok(ClaimOutcome::AlreadyTerminal) => {
                                    tracing::debug!(
                                        "background claimer: skipped {} (already terminal)",
                                        swap.boltz_swap_id
                                    );
                                }
                                Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
                                    tracing::info!(
                                        swap_id = %swap.boltz_swap_id,
                                        reason,
                                        "background claimer: reverse swap remains pending"
                                    );
                                }
                                Err(e) => {
                                    health.observe_error(&e);
                                    tracing::warn!(
                                        "background claimer: swap {}: {e}",
                                        swap.boltz_swap_id
                                    );
                                }
                            }
                        }
                    } else if first_reverse_run {
                        tracing::info!("background claimer: no unclaimed swaps found");
                    }
                    health.report(&reverse_reporter);
                    first_reverse_run = false;
                }
                Err(e) => {
                    tracing::error!("background claimer: db query failed: {e}");
                    reverse_reporter.cycle_failed();
                }
            }

            let mut ready_chain_count = 0;
            match db::get_ready_to_claim_chain_swaps(&pool).await {
                Ok(ready_chain) => {
                    ready_chain_count = ready_chain.len();
                    let mut health = ClaimCycleHealth::default();
                    if !ready_chain.is_empty() {
                        tracing::info!(
                            "background claimer: found {} chain swap(s) ready to claim",
                            ready_chain.len()
                        );
                        for swap in &ready_chain {
                            chain_reporter.progress();
                            let fee_decision = fee_runtime
                                .liquid_construction_decision_now(
                                    FeeConstructionPurpose::ChainLiquidClaim,
                                )
                                .ok();
                            match claim_chain_swap(
                                &pool,
                                swap.id,
                                claim_clients.as_deref(),
                                &config.boltz.api_url,
                                config.claim.max_claim_attempts,
                                utxo_backend.as_ref(),
                                db::InvoiceAccountingTolerances::from(&config.invoice_accounting),
                                fee_decision.as_ref().map(|(decision, _)| decision),
                                fee_decision.as_ref().map(|(_, record)| record),
                            )
                            .await
                            {
                                Ok(ClaimOutcome::Broadcast) => {
                                    tracing::info!(
                                        "background claimer: claimed chain swap {}",
                                        swap.boltz_swap_id
                                    );
                                }
                                Ok(ClaimOutcome::SkippedLockHeld) => {
                                    tracing::debug!(
                                        "background claimer: skipped chain swap {} (lock held)",
                                        swap.boltz_swap_id
                                    );
                                }
                                Ok(ClaimOutcome::AlreadyTerminal) => {
                                    tracing::debug!(
                                        "background claimer: skipped chain swap {} (already terminal)",
                                        swap.boltz_swap_id
                                    );
                                }
                                Ok(ClaimOutcome::PendingFeeUnavailable { reason }) => {
                                    tracing::info!(
                                        swap_id = %swap.boltz_swap_id,
                                        reason,
                                        "background claimer: chain swap remains pending"
                                    );
                                }
                                Err(e) => {
                                    health.observe_error(&e);
                                    tracing::warn!(
                                        "background claimer: chain swap {}: {e}",
                                        swap.boltz_swap_id
                                    );
                                }
                            }
                        }
                    }
                    health.report(&chain_reporter);
                }
                Err(e) => {
                    tracing::error!("background claimer: chain-swap db query failed: {e}");
                    chain_reporter.cycle_failed();
                }
            }

            if tick_count.is_multiple_of(HEARTBEAT_EVERY_N_TICKS) {
                tracing::info!(
                    target: "claimer",
                    event = "claimer_heartbeat",
                    tick = tick_count,
                    ready_count = ready_count,
                    ready_chain_count = ready_chain_count,
                    "background claimer heartbeat"
                );
            }

            tokio::select! {
                _ = cancel.cancelled() => {
                    reverse_reporter.intentional_shutdown();
                    chain_reporter.intentional_shutdown();
                    tracing::info!("background claimer: shutting down");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(CLAIM_SWEEP_INTERVAL_SECS)) => {}
            }
        }
    })
}
