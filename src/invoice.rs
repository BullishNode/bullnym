//! Invoices: unified payment-intent abstraction.
//!
//! Three entry families share this module:
//!
//! 1. **Anonymous (sender-side) checkout** — payment-page-driven:
//!    - `POST /<nym>/invoice` body `{ amount_sat | (fiat_amount_minor + fiat_currency) }`
//!    - `GET /<nym>/i/<id>` HTML render
//!
//! 2. **Public unlinked render** — wallet-only invoices that aren't shared via
//!    a payment page:
//!    - `GET /invoice/<id>` HTML render
//!    - `GET /robots.txt` for the indexing posture
//!
//! 3. **Schnorr-signed (recipient-side, wallet)** endpoints:
//!    - `POST   /api/v1/<nym>/invoices`     — linked invoice-create
//!    - `POST   /api/v1/invoices`           — unlinked invoice-create
//!    - `DELETE /api/v1/<nym>/invoices/<id>`— linked invoice-cancel
//!    - `DELETE /api/v1/invoices/<id>`      — unlinked invoice-cancel
//!    - `GET    /api/v1/invoices?npub=...`  — npub-keyed list (linked + unlinked)
//!
//! Both create paths verify a v2 Schnorr signature BEFORE any DB write, with
//! the `nym_or_empty` slot driving the linked vs unlinked branch.
//!
//! Status-poll and Lightning lazy-fetch helpers remain shared across linked
//! and unlinked invoices via `id`-only paths:
//!    - `GET  /api/v1/invoices/<id>/status`
//!    - `GET  /api/v1/invoices/<id>/presentation` (opaque ciphertext only)
//!    - `POST /api/v1/invoices/<id>/lightning`

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use askama::Template;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Acquire;
use uuid::Uuid;

use crate::admission::Rail;
use crate::auth;
use crate::certification::{self, CertificationScope};
use crate::chain_swap_creation_permit::{ChainSwapCreationPermit, ChainSwapCreationPermitError};
use crate::db;
use crate::descriptor;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::pricer;
use crate::validators;
use crate::AppState;

// Integration tests need to stop the real handler at exact transaction
// boundaries; database-only tests cannot prove that handlers keep every read
// on the same connection. This one-shot seam is inert unless a test installs
// it and adds only one atomic read to each covered boundary.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceIntegrationTestHookPoint {
    StatusAfterInvoiceRead,
    ListAfterInvoiceRead,
    OfferBeforeCommit,
    ChainOfferBeforeRecoveryGate,
    ProviderAttemptBeforeDispatch,
    ProviderResponseBeforeCommit,
    ProviderOfferAfterCommit,
}

#[derive(Debug)]
struct InvoiceIntegrationTestHookState {
    point: InvoiceIntegrationTestHookPoint,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

static INVOICE_INTEGRATION_TEST_HOOK_ACTIVE: AtomicBool = AtomicBool::new(false);
static INVOICE_INTEGRATION_TEST_HOOK: OnceLock<
    Mutex<Option<Arc<InvoiceIntegrationTestHookState>>>,
> = OnceLock::new();

fn invoice_integration_test_hook_slot(
) -> &'static Mutex<Option<Arc<InvoiceIntegrationTestHookState>>> {
    INVOICE_INTEGRATION_TEST_HOOK.get_or_init(|| Mutex::new(None))
}

/// One-shot synchronization guard for DB-backed integration tests. Dropping
/// the guard releases a paused request so a failed test cannot strand it.
#[doc(hidden)]
pub struct InvoiceIntegrationTestHook {
    state: Arc<InvoiceIntegrationTestHookState>,
}

impl InvoiceIntegrationTestHook {
    pub async fn wait_until_reached(&self) {
        self.state.reached.notified().await;
    }

    pub fn release(&self) {
        self.state.release.notify_one();
    }
}

impl Drop for InvoiceIntegrationTestHook {
    fn drop(&mut self) {
        self.state.release.notify_one();
        let mut slot = invoice_integration_test_hook_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.state))
        {
            slot.take();
            INVOICE_INTEGRATION_TEST_HOOK_ACTIVE.store(false, Ordering::Release);
        }
    }
}

#[doc(hidden)]
pub fn install_invoice_integration_test_hook(
    point: InvoiceIntegrationTestHookPoint,
) -> InvoiceIntegrationTestHook {
    let state = Arc::new(InvoiceIntegrationTestHookState {
        point,
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let mut slot = invoice_integration_test_hook_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        slot.is_none(),
        "an invoice integration-test hook is already installed"
    );
    *slot = Some(state.clone());
    INVOICE_INTEGRATION_TEST_HOOK_ACTIVE.store(true, Ordering::Release);
    InvoiceIntegrationTestHook { state }
}

async fn pause_at_invoice_integration_test_hook(point: InvoiceIntegrationTestHookPoint) {
    if !INVOICE_INTEGRATION_TEST_HOOK_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let state = {
        let mut slot = invoice_integration_test_hook_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|installed| installed.point == point)
        {
            INVOICE_INTEGRATION_TEST_HOOK_ACTIVE.store(false, Ordering::Release);
            slot.take()
        } else {
            None
        }
    };
    if let Some(state) = state {
        state.reached.notify_one();
        state.release.notified().await;
    }
}

// =====================================================================
// Action constants (v2 Schnorr signing)
//
// Wire-protocol identifiers — must match mobile's
// `core/nostr/bullpay_la_v2_signing.dart`. Renaming any of these is a
// wire-breaking change requiring lockstep mobile-server deploy.
// =====================================================================

pub const ACTION_CREATE: &str = "invoice-create";
pub const ACTION_CANCEL: &str = "invoice-cancel";
pub const ACTION_LIST: &str = "invoice-list";
pub const ACTION_RECOVERY_LIST: &str = "invoice-recovery-list";

/// Exact outer lifetime shared by wallet-origin and checkout invoices.
/// Short-lived payer quotes and provider instructions keep their independent
/// expiry windows and must never extend this deadline.
pub(crate) const INVOICE_LIFETIME_SECS: i64 = 30 * 24 * 60 * 60;

/// Hard upper bound and default for wallet-origin invoice expiry (30 days).
/// Clients may omit `expires_at_unix`; the server then uses this default.
/// When a client does request an expiry, the server still caps it here so
/// a runaway or malicious client cannot pin a row indefinitely or refresh
/// Boltz offers forever.
const MAX_WALLET_EXPIRES_SECS: i64 = INVOICE_LIFETIME_SECS;

/// Default cap on `list_invoices.pageSize`. Mobile can request a smaller
/// page size; never larger.
const LIST_LIMIT_MAX: i64 = 100;

/// Exact outer expiry for checkout-origin invoices. Individual Boltz
/// BOLT11s may expire sooner and are refreshed while the invoice is live;
/// this cap prevents abandoned checkout invoices from refreshing forever.
const CHECKOUT_DEFAULT_EXPIRES_SECS: i64 = INVOICE_LIFETIME_SECS;

const FIAT_QUOTE_WINDOW_SECS: i64 = 5 * 60;

/// private-invoice-v1 envelope: one version byte, 12-byte AES-GCM nonce,
/// 4096-byte padded ciphertext, and 16-byte authentication tag.
pub const PRIVATE_INVOICE_PRESENTATION_VERSION: u8 = 1;
pub const PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BYTES: usize = 1 + 12 + 4096 + 16;
const PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BASE64_LEN: usize =
    PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BYTES / 3 * 4;
const PRIVATE_INVOICE_CREATE_DIGEST_DOMAIN: &[u8] = b"bullnym-private-invoice-create-v1";
pub(crate) const LIQUID_BTC_ASSET_ID: &str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

// =====================================================================
// Settlement hook (called by claimer/reconciler on Lightning settlement)
// =====================================================================

/// Flip an invoice to `in_progress` on the FIRST Boltz mempool sighting
/// of the lockup tx for an invoice-bound swap. Called by the claimer
/// (`transaction.mempool` webhook) and the reconciler (sync path that
/// observes the same status without a webhook delivery) AFTER the
/// forward-only CAS state-update succeeds.
///
/// Contract mirrors `flip_invoice_on_lightning_settlement`:
/// - `invoice_id == None` → no-op (LNURL-only swaps without an invoice).
/// - `mark_invoice_in_progress` is idempotent: a 0-rows-affected return
///   means the invoice was already past `unpaid` (already in_progress,
///   already paid/under/over, expired, cancelled). Logged at debug.
/// - On error: LOG and RETURN. Never propagate. Settlement (paid) flows
///   through `flip_invoice_on_lightning_settlement` later and self-heals.
pub async fn flip_invoice_on_lightning_in_progress(
    pool: &sqlx::PgPool,
    invoice_id: Option<Uuid>,
    boltz_swap_id: &str,
) {
    let Some(id) = invoice_id else {
        return;
    };
    match db::mark_invoice_in_progress_for_component(pool, id, db::InvoiceInProgressComponent::Swap)
        .await
    {
        Ok(true) => {
            tracing::info!(
                event = "invoice_in_progress_via_lightning",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "lightning mempool flipped invoice to in_progress"
            );
        }
        Ok(false) => {
            tracing::debug!(
                event = "invoice_in_progress_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice already past unpaid; in_progress flip is a no-op"
            );
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_in_progress_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "mark_invoice_in_progress failed (swap CAS already committed): {e}"
            );
        }
    }
}

/// Flip an invoice to `in_progress` on the FIRST payer-side BTC lockup
/// sighting for an invoice-bound Boltz BTC-to-LBTC chain swap. Accounting
/// is still recorded only after the server claims the LBTC output.
pub async fn flip_invoice_on_bitcoin_boltz_in_progress(
    pool: &sqlx::PgPool,
    chain_swap_id: Uuid,
    invoice_id: Option<Uuid>,
    boltz_swap_id: &str,
) {
    let Some(id) = invoice_id else {
        return;
    };
    match db::mark_chain_swap_invoice_in_progress_if_current(pool, chain_swap_id, id).await {
        Ok(true) => {
            tracing::info!(
                event = "invoice_in_progress_via_bitcoin_boltz_chain",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "bitcoin chain-swap lockup flipped invoice to in_progress"
            );
        }
        Ok(false) => {
            tracing::debug!(
                event = "invoice_bitcoin_boltz_in_progress_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice already past unpaid; bitcoin chain-swap in_progress flip is a no-op"
            );
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_bitcoin_boltz_in_progress_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "mark_invoice_in_progress failed (chain-swap CAS already committed): {e}"
            );
        }
    }
}

/// Record an invoice payment event after the corresponding Lightning
/// reverse swap is claimed by the merchant wallet. Lockup mempool,
/// lockup confirmation, refund, and claim-stuck states are not enough:
/// they prove only payer-side progress, not merchant-side settlement.
///
/// Contract:
/// - `invoice_id == None` → no-op for non-invoice swaps.
/// - `record_invoice_payment` is idempotent on
///   `lightning_boltz_reverse:<boltz_swap_id>`.
/// - On error: LOG and return `false`. Callers that supervise settlement
///   repair can then mark that worker cycle unhealthy without changing the
///   idempotent payment-recording contract.
pub async fn flip_invoice_on_lightning_settlement(
    pool: &sqlx::PgPool,
    invoice_id: Option<Uuid>,
    amount_sat: i64,
    boltz_swap_id: &str,
    claim_txid: &str,
    tolerances: db::InvoiceAccountingTolerances,
) -> bool {
    let Some(id) = invoice_id else {
        return true;
    };
    let event_key = format!("lightning_boltz_reverse:{boltz_swap_id}");
    match db::record_invoice_payment(
        pool,
        id,
        db::InvoicePaymentEvidence {
            rail: "lightning",
            source: "lightning_boltz_reverse",
            event_key: &event_key,
            amount_sat,
            txid: Some(claim_txid),
            vout: None,
            boltz_swap_id: Some(boltz_swap_id),
            address: None,
        },
        tolerances,
    )
    .await
    {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                event = "invoice_payment_event_lightning",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "lightning settlement recorded invoice payment"
            );
            true
        }
        Ok(_) => {
            tracing::debug!(
                event = "invoice_flip_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice payment event already recorded; no-op"
            );
            true
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_flip_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "record_invoice_payment failed (swap CAS already committed): {e}"
            );
            false
        }
    }
}

/// Record an invoice payment event after a BTC-to-LBTC Boltz chain swap
/// has been claimed to the merchant's Liquid address. This is the
/// Donation Page Bitcoin-rail settlement boundary: user BTC lockup and
/// Boltz server lockup are only progress signals; the merchant is paid
/// after our Liquid claim broadcasts successfully.
pub async fn flip_invoice_on_bitcoin_boltz_settlement(
    pool: &sqlx::PgPool,
    invoice_id: Option<Uuid>,
    amount_sat: i64,
    boltz_swap_id: &str,
    claim_txid: &str,
    tolerances: db::InvoiceAccountingTolerances,
) -> bool {
    let Some(id) = invoice_id else {
        return true;
    };
    let event_key = format!("bitcoin_boltz_chain:{boltz_swap_id}");
    match db::record_invoice_payment(
        pool,
        id,
        db::InvoicePaymentEvidence {
            rail: "bitcoin",
            source: "bitcoin_boltz_chain",
            event_key: &event_key,
            amount_sat,
            txid: Some(claim_txid),
            vout: None,
            boltz_swap_id: Some(boltz_swap_id),
            address: None,
        },
        tolerances,
    )
    .await
    {
        Ok(rows) if rows > 0 => {
            tracing::info!(
                event = "invoice_payment_event_bitcoin_boltz",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "bitcoin chain-swap settlement recorded invoice payment"
            );
            true
        }
        Ok(_) => {
            tracing::debug!(
                event = "invoice_bitcoin_boltz_flip_noop",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                "invoice payment event already recorded; no-op"
            );
            true
        }
        Err(e) => {
            tracing::error!(
                event = "invoice_bitcoin_boltz_flip_failed",
                invoice_id = %id,
                boltz_swap_id = %boltz_swap_id,
                amount_sat = amount_sat,
                "record_invoice_payment failed (chain-swap CAS already committed): {e}"
            );
            false
        }
    }
}

pub(crate) async fn prefetch_provider_observation_rate(
    state: &crate::AppState,
    invoice_id: Uuid,
    quote_version_id: Option<Uuid>,
) -> Option<pricer::RateView> {
    let quote_version_id = quote_version_id?;
    let currency = match db::invoice_quote_currency(&state.db, invoice_id, quote_version_id).await {
        Ok(Some(currency)) => currency,
        Ok(None) => return None,
        Err(error) => {
            tracing::error!(
                event = "invoice_provider_observation_currency_failed",
                invoice_id = %invoice_id,
                quote_version_id = %quote_version_id,
                error = %error,
                "failed to load quote currency before provider observation"
            );
            return None;
        }
    };
    match state.pricer.get_rate(&currency).await {
        Ok(rate) => Some(rate),
        Err(error) => {
            tracing::warn!(
                event = "invoice_provider_observation_rate_unavailable",
                invoice_id = %invoice_id,
                quote_version_id = %quote_version_id,
                currency,
                error = %error,
                "provider status will persist without an invented fiat valuation"
            );
            None
        }
    }
}

pub(crate) fn quote_candidate_from_rate(
    rate: &pricer::RateView,
) -> Option<db::NewInvoiceQuoteVersion<'_>> {
    Some(db::NewInvoiceQuoteVersion {
        rate_minor_per_btc: rate.minor_per_btc,
        rate_source: &rate.source,
        rate_observed_at_unix: i64::try_from(rate.observed_at_unix).ok()?,
        rate_fetched_at_unix: i64::try_from(rate.fetched_at_unix).ok()?,
        rate_fresh_until_unix: i64::try_from(rate.expires_at_unix).ok()?,
        minimum_merchant_amount_sat: 1,
        maximum_merchant_amount_sat: i64::MAX,
    })
}

pub(crate) async fn capture_late_quote_valuation_snapshot(
    pool: &sqlx::PgPool,
    pricer: &pricer::PricerClient,
    observation: Option<db::PersistedInvoiceQuoteObservation>,
) -> bool {
    let Some(observation) = observation else {
        return true;
    };
    let currency = match db::late_observation_valuation_status(
        pool,
        observation.invoice_id,
        observation.instruction_quote_version_id,
        observation.first_observed_at_unix_micros,
    )
    .await
    {
        Ok(db::LateObservationValuationStatus::OnTime)
        | Ok(db::LateObservationValuationStatus::Ready(_)) => return true,
        Ok(db::LateObservationValuationStatus::NeedsRate { fiat_currency }) => fiat_currency,
        Err(error) => {
            tracing::error!(
                event = "invoice_late_valuation_context_failed",
                invoice_id = %observation.invoice_id,
                error = %error,
                "failed to inspect durable provider first-observation evidence"
            );
            return false;
        }
    };
    let rate = match pricer.get_rate(&currency).await {
        Ok(rate) => rate,
        Err(error) => {
            tracing::warn!(
                event = "invoice_late_valuation_rate_unavailable",
                invoice_id = %observation.invoice_id,
                currency,
                error = %error,
                "provider payment observation remains durably unvalued"
            );
            return false;
        }
    };
    let timestamp = |value: u64, field: &'static str| match i64::try_from(value) {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::error!(
                event = "invoice_late_valuation_rate_timestamp_invalid",
                invoice_id = %observation.invoice_id,
                field,
                "pricer timestamp exceeds durable storage range"
            );
            None
        }
    };
    let Some(rate_observed_at_unix) = timestamp(rate.observed_at_unix, "observed_at") else {
        return false;
    };
    let Some(rate_fetched_at_unix) = timestamp(rate.fetched_at_unix, "fetched_at") else {
        return false;
    };
    let Some(rate_fresh_until_unix) = timestamp(rate.expires_at_unix, "fresh_until") else {
        return false;
    };
    let candidate = db::NewInvoiceQuoteVersion {
        rate_minor_per_btc: rate.minor_per_btc,
        rate_source: &rate.source,
        rate_observed_at_unix,
        rate_fetched_at_unix,
        rate_fresh_until_unix,
        minimum_merchant_amount_sat: 1,
        maximum_merchant_amount_sat: i64::MAX,
    };
    match db::create_or_reuse_late_observation_valuation_quote(
        pool,
        observation.invoice_id,
        observation.instruction_quote_version_id,
        observation.first_observed_at_unix_micros,
        &candidate,
    )
    .await
    {
        Ok(resolution) => {
            tracing::info!(
                event = "invoice_late_valuation_snapshot_ready",
                invoice_id = %observation.invoice_id,
                valuation_quote_version_id = %resolution.quote.id,
                created = resolution.created,
                "durable fresh rate now covers provider payment first observation"
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                event = "invoice_late_valuation_snapshot_failed",
                invoice_id = %observation.invoice_id,
                error = %error,
                "provider payment observation remains durably unvalued"
            );
            false
        }
    }
}

// =====================================================================
// Helpers
// =====================================================================

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Last 8 chars of an npub for log correlation. Full npub stays out of
/// logs to honor the discipline outlined in the get-paid plan (F2).
fn npub_log_tag(npub: &str) -> &str {
    let len = npub.len();
    if len > 8 {
        &npub[len - 8..]
    } else {
        npub
    }
}

/// Parse the Uuid path parameter, returning `InvoiceNotFound` (NOT
/// `InvalidAmount` or 400) on parse failure. Reason: a malformed id is
/// information-equivalent to an unknown id from the caller's perspective,
/// and we don't want to leak the existence/non-existence boundary.
fn parse_invoice_id(s: &str) -> Result<Uuid, AppError> {
    Uuid::from_str(s).map_err(|_| AppError::InvoiceNotFound(s.to_string()))
}

/// Defensive HTML response headers for invoice-render handlers. Adds
/// indexing + caching posture beyond `donation_render`'s baseline so the
/// invoice page (which is reachable at a guessable URL) cannot be
/// indexed by crawlers and cannot be served from intermediate caches.
fn html_response(html: String) -> Response {
    let mut resp = (StatusCode::OK, html).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    h.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
    resp
}

// =====================================================================
// GET /robots.txt
// =====================================================================

/// Permit crawlers to fetch public Payment Pages so they can read Open Graph
/// metadata. Page responses independently send `X-Robots-Tag: noindex`, which
/// prevents search indexing without blocking link-preview crawlers from the
/// content they need.
pub async fn robots_txt() -> Response {
    let body = "User-agent: *\nDisallow: /.well-known/\nDisallow: /api/\nDisallow: /register\nDisallow: /webhook/\nAllow: /\n";
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

// =====================================================================
// POST /<nym>/invoice — anonymous, sender-side
// =====================================================================

/// Body for anonymous invoice creation. Caller specifies EITHER
/// `amount_sat` (sat-denominated) OR `(fiat_amount_minor, fiat_currency)`
/// (fiat-denominated). Server rejects payloads that supply both or
/// neither.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAnonymousRequest {
    pub amount_sat: Option<i64>,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    /// Optional free-text note attached to the invoice as its private `memo`:
    /// the PoS merchant's own description, or a donor's "leave a message".
    /// Stored server-side and returned ONLY on the signed invoice list
    /// (`GET /api/v1/invoices` verified by the owning nym's key) — never on the
    /// public status/render paths.
    #[serde(default)]
    pub note: Option<String>,
}

/// `memo` column cap (migration 019: `length(memo) <= 280`). PostgreSQL counts
/// characters rather than UTF-8 bytes, so request validation must do the same.
/// Validating here returns a clean error instead of a DB constraint failure.
const MAX_INVOICE_NOTE_LEN: usize = 280;

#[derive(Serialize)]
#[serde(tag = "pricing_mode", rename_all = "snake_case")]
pub enum CreateInvoiceResponse {
    /// Fiat checkout creation returns identity only. Payment instructions are
    /// exclusively returned by the explicit selected-rail quote mutation.
    FiatFixed {
        invoice_id: Uuid,
        expires_at_unix: i64,
    },
    /// Sat-fixed remains the current product behavior: Liquid is immediately
    /// payable and provider-backed rails are independently best effort.
    SatFixed {
        invoice_id: Uuid,
        lightning_pr: String,
        lightning_amount_sat: Option<i64>,
        liquid_address: String,
        liquid_amount_sat: i64,
        bitcoin_chain_address: Option<String>,
        bitcoin_chain_bip21: Option<String>,
        bitcoin_chain_amount_sat: Option<i64>,
        expires_at_unix: i64,
    },
}

/// POST /:nym/invoice — keyless Payment Page checkout (anonymous, unsigned).
pub async fn create_anonymous(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateAnonymousRequest>,
) -> Result<Json<CreateInvoiceResponse>, AppError> {
    create_anonymous_for_kind(
        state,
        nym,
        db::KIND_PAYMENT_PAGE,
        None,
        peer_opt,
        headers,
        req,
    )
    .await
}

/// POST /:nym/pos/invoice — keyless POS terminal checkout. Same anonymous
/// flow as the Payment Page, but scoped to the nym's POS surface (idx 103):
/// the settlement address derives from the POS descriptor, and there is NO
/// Lightning-Address cursor fallback (KR-1) so POS receipts never leak into
/// the Lightning Address wallet.
pub async fn create_anonymous_pos(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateAnonymousRequest>,
) -> Result<Json<CreateInvoiceResponse>, AppError> {
    create_anonymous_for_kind(state, nym, db::KIND_POS, None, peer_opt, headers, req).await
}

/// POST /a/:slug/invoice — keyless Payment Page checkout under an alias.
pub async fn create_anonymous_alias(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateAnonymousRequest>,
) -> Result<Json<CreateInvoiceResponse>, AppError> {
    create_anonymous_alias_for_kind(state, slug, db::KIND_PAYMENT_PAGE, peer_opt, headers, req)
        .await
}

/// POST /a/:slug/pos/invoice — keyless POS checkout selected through the same
/// permanent owner-level alias.
pub async fn create_anonymous_alias_pos(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateAnonymousRequest>,
) -> Result<Json<CreateInvoiceResponse>, AppError> {
    create_anonymous_alias_for_kind(state, slug, db::KIND_POS, peer_opt, headers, req).await
}

async fn create_anonymous_alias_for_kind(
    state: AppState,
    slug: String,
    kind: &'static str,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    req: CreateAnonymousRequest,
) -> Result<Json<CreateInvoiceResponse>, AppError> {
    let page = db::get_donation_page_by_alias(&state.db, &slug, kind)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(slug.clone()))?;
    if !page.enabled || page.is_archived {
        return Err(AppError::DonationPageNotFound(slug));
    }
    create_anonymous_for_kind(state, page.nym, kind, Some(slug), peer_opt, headers, req).await
}

/// Shared anonymous-checkout implementation for the donation-page surfaces.
/// `kind` selects the (nym, kind) donation_pages row whose descriptor and
/// address cursor settle the checkout.
async fn create_anonymous_for_kind(
    state: AppState,
    nym: String,
    kind: &'static str,
    // When the checkout came in via `/a/<slug>/invoice`, the slug is recorded
    // on the invoice so its public URL (bolt11 description, BIP21 message)
    // stays nym-free. `None` for the nym-path routes.
    public_slug: Option<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    req: CreateAnonymousRequest,
) -> Result<Json<CreateInvoiceResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::InvoiceCreate,
        peer,
        &headers,
        "anonymous_invoice_create",
        Some(&nym),
    );

    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_invoice_create_per_source(ip)
                .await?;
        }
    }

    let (amount_sat, fiat) = parse_create_request(&req, &state)?;

    // Optional note → invoice `memo` (private; merchant-only via the signed
    // list). Trim to treat whitespace-only as absent, and reject over-long
    // notes before the insert hits the column CHECK.
    let note = req.note.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(note) = note {
        if note.chars().count() > MAX_INVOICE_NOTE_LEN {
            return Err(AppError::InvalidAmount(format!(
                "note too long (max {MAX_INVOICE_NOTE_LEN} chars)"
            )));
        }
    }

    // Verify the store is live AND resolve the page owner's npub for the
    // canonical invoice identity. The page→user join is required because
    // donation_pages doesn't store npub directly.
    let page = db::get_donation_page_by_nym(&state.db, &nym, kind)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;
    if !page.enabled || page.is_archived {
        return Err(AppError::DonationPageNotFound(nym.clone()));
    }
    let owner = db::get_user_by_nym(&state.db, &nym)
        .await?
        .ok_or_else(|| AppError::DonationPageNotFound(nym.clone()))?;

    // Direct Liquid is the independently payable baseline for anonymous
    // checkout. Provider-backed rails remain best-effort below, but no new
    // descriptor address or invoice may be exposed while its own watcher is
    // unavailable.
    state
        .admission
        .enforce(Rail::DirectLiquid)
        .map_err(|_| AppError::MoneyAdmissionUnavailable)?;

    // Eagerly allocate a Liquid address from the donation page owner's
    // CT descriptor. Donation Page checkout never uses customer- or
    // merchant-supplied payout addresses; every customer-facing settlement
    // rail resolves back to this descriptor-derived Liquid address:
    //   - Lightning: `claimer::resolve_claim_address` branch (B) routes
    //     the Boltz claim to `invoice.liquid_address` once
    //     `create_lightning_offer` (below) binds the swap to this invoice.
    //   - Direct Liquid: customer pays this address directly; the
    //     chain_watcher's address-keyed scan detects the inbound tx.
    //   - BTC via Boltz chain swap: customer pays Boltz's Bitcoin lockup
    //     address; the chain-swap claimer spends the resulting LBTC to
    //     this same `invoice.liquid_address`.
    // The `invoices_ln_or_liquid_addr_chk` constraint requires
    // `liquid_address` to be present at insert time when either LN or
    // Liquid is accepted, so allocation must run BEFORE insert.
    let (liquid_address, _liquid_index, payment_descriptor) =
        match db::allocate_next_liquid_for_donation_page(
            &state.db,
            &nym,
            kind,
            |ct_descriptor, idx| {
                descriptor::derive_address(ct_descriptor, idx)
                    .map_err(|e| sqlx::Error::Protocol(format!("derive_address: {e}")))
            },
        )
        .await?
        {
            Some((address, index, descriptor)) => (address, index, descriptor),
            // Every Page/POS surface owns its descriptor and cursor. Missing or
            // unavailable surface allocation is never redirected through the
            // owner's independently configured Lightning Address wallet.
            None => return Err(AppError::DonationPageNotFound(nym.clone())),
        };
    let liquid_blinding_key_hex =
        descriptor::derive_blinding_key_hex(&payment_descriptor, &liquid_address)?;

    let new_invoice = db::NewInvoice {
        nym_owner: Some(&nym),
        public_slug: public_slug.as_deref(),
        npub_owner: &owner.npub,
        origin: "checkout",
        checkout_surface_kind: Some(kind),
        fiat_amount_minor: fiat.as_ref().map(|(amt, _)| *amt),
        fiat_currency: fiat.as_ref().map(|(_, cur)| cur.as_str()),
        amount_sat,
        rate_minor_per_btc: None,
        rate_lock_secs: CHECKOUT_DEFAULT_EXPIRES_SECS,
        memo: note,
        // Checkout-origin: direct BTC stays disabled on the invoice row.
        // Donation Page BTC, when available, is represented separately as a
        // Boltz chain-swap lockup so bitcoin_watcher never mistakes the
        // Boltz deposit address for merchant-settled direct BTC.
        accept_btc: false,
        accept_ln: true,
        accept_liquid: true,
        bitcoin_address: None,
        liquid_address: Some(&liquid_address),
        liquid_blinding_key_hex: Some(&liquid_blinding_key_hex),
        expires_in_secs: CHECKOUT_DEFAULT_EXPIRES_SECS,
    };
    let invoice = db::insert_invoice(&state.db, &new_invoice).await?;

    // Fiat-fixed provider obligations are created only by the explicit
    // selected-rail quote endpoint after its durable five-minute version
    // exists. Sat-fixed checkout retains its current eager behavior.
    let lightning_offer = if fiat.is_some() {
        None
    } else {
        match create_lightning_offer(&state, Some(&nym), amount_sat as u64, &invoice).await {
            Ok(offer) => Some(offer),
            Err(e) => {
                // Boltz's reverse-swap service can be transiently unavailable
                // (e.g. 502 / timeout while Boltz is under load). Do NOT fail the
                // whole checkout: a payable Liquid address is already allocated on
                // this invoice, and the BTC chain offer below is likewise treated
                // as best-effort. Keep the invoice and return an empty
                // `lightning_pr`; the client requests the Lightning offer lazily
                // via `POST /api/v1/invoices/:id/lightning` (fetch_lightning_offer)
                // once Boltz recovers — the same path used for deep-link
                // reconstruction. This keeps checkout working (Liquid + BTC rails)
                // through a Boltz degradation instead of taking it down entirely.
                tracing::warn!(
                    invoice_id = %invoice.id,
                    "eager Lightning offer unavailable; returning checkout invoice with Liquid rail, client will fetch the LN offer lazily: {e}",
                );
                None
            }
        }
    };
    let bitcoin_chain_offer = if fiat.is_some() {
        None
    } else {
        match create_bitcoin_chain_offer(&state, Some(&nym), amount_sat as u64, &invoice).await {
            Ok(offer) => offer,
            Err(e) => {
                tracing::warn!(
                    invoice_id = %invoice.id,
                    "BTC-to-LBTC chain-swap offer unavailable for checkout invoice: {e}",
                );
                None
            }
        }
    };

    let response = if fiat.is_some() {
        CreateInvoiceResponse::FiatFixed {
            invoice_id: invoice.id,
            expires_at_unix: invoice.expires_at_unix,
        }
    } else {
        CreateInvoiceResponse::SatFixed {
            invoice_id: invoice.id,
            lightning_pr: lightning_offer
                .as_ref()
                .map(|offer| offer.pr.clone())
                .unwrap_or_default(),
            lightning_amount_sat: lightning_offer.as_ref().map(|offer| offer.payer_amount_sat),
            liquid_address,
            liquid_amount_sat: amount_sat,
            bitcoin_chain_address: bitcoin_chain_offer
                .as_ref()
                .map(|offer| offer.lockup_address.clone()),
            bitcoin_chain_bip21: bitcoin_chain_offer
                .as_ref()
                .and_then(|offer| offer.lockup_bip21.clone()),
            bitcoin_chain_amount_sat: bitcoin_chain_offer
                .as_ref()
                .map(|offer| offer.payer_amount_sat),
            expires_at_unix: invoice.expires_at_unix,
        }
    };
    Ok(Json(response))
}

/// Validate the create-anonymous body and preserve the requested denomination.
///
/// Fiat creation is intentionally independent of the live pricer. A fiat row
/// persists only its immutable face value; the first explicit payer quote owns
/// conversion and records the exact rate, freshness, and sat target in an
/// immutable quote version.
///
/// Returns `(amount_sat, Option<(fiat_amount_minor, fiat_currency)>)`.
fn parse_create_request(
    req: &CreateAnonymousRequest,
    state: &AppState,
) -> Result<(i64, Option<(i32, String)>), AppError> {
    let has_sat = req.amount_sat.is_some();
    let has_fiat = req.fiat_amount_minor.is_some() || req.fiat_currency.is_some();

    if has_sat && has_fiat {
        return Err(AppError::InvalidAmount(
            "specify amount_sat OR (fiat_amount_minor + fiat_currency), not both".into(),
        ));
    }
    if !has_sat && !has_fiat {
        return Err(AppError::InvalidAmount(
            "missing amount_sat or (fiat_amount_minor + fiat_currency)".into(),
        ));
    }

    if let Some(sat) = req.amount_sat {
        if sat <= 0 {
            return Err(AppError::InvalidAmount("amount_sat must be > 0".into()));
        }
        let min_sat = (state.config.limits.min_sendable_msat / 1000) as i64;
        let max_sat = (state.config.limits.max_sendable_msat / 1000) as i64;
        if sat < min_sat {
            return Err(AppError::InvalidAmount(format!("minimum is {min_sat} sat")));
        }
        if sat > max_sat {
            return Err(AppError::InvalidAmount(format!("maximum is {max_sat} sat")));
        }
        return Ok((sat, None));
    }

    let minor = req
        .fiat_amount_minor
        .ok_or_else(|| AppError::InvalidAmount("missing fiat_amount_minor".into()))?;
    let currency = req
        .fiat_currency
        .as_deref()
        .ok_or_else(|| AppError::InvalidAmount("missing fiat_currency".into()))?;
    let currency = pricer::normalize_currency_code(currency);
    if !state.pricer.is_supported_currency(&currency) {
        return Err(AppError::InvalidAmount(format!(
            "unsupported fiat_currency {currency}; fetch /api/v1/supported-currencies"
        )));
    }
    if minor <= 0 {
        return Err(AppError::InvalidAmount(
            "fiat_amount_minor must be > 0".into(),
        ));
    }
    const MAX_FIAT_MINOR: i32 = 1_000_000_000;
    if minor > MAX_FIAT_MINOR {
        return Err(AppError::InvalidAmount(format!(
            "fiat_amount_minor exceeds {MAX_FIAT_MINOR}"
        )));
    }

    Ok((0, Some((minor, currency))))
}

// =====================================================================
// GET /<nym>/i/<id> — render the linked payment view
// =====================================================================

#[derive(Template)]
#[template(path = "invoice_payment.html")]
struct InvoicePaymentTpl<'a> {
    /// Nym for the linked render path; empty string for unlinked. Templates
    /// gate URL construction on `is_unlinked` rather than this field.
    nym: &'a str,
    /// True when nym_owner is None — page is reached via /invoice/<id>
    /// rather than /<nym>/i/<id>. Drives header copy and URL templating.
    is_unlinked: bool,
    /// True when the invoice is rendered under a nym-free alias path
    /// (`/a/<slug>/i/<id>`). The invoice is still nym-linked internally, but
    /// the served page must not reveal the nym, so the header renders the same
    /// generic branch as `is_unlinked`. Distinct concept from `is_unlinked`
    /// (which means "no owner at all").
    hide_owner: bool,
    /// True only for wallet-origin native merchant invoices. Anonymous
    /// checkout pages never attempt private-presentation decryption.
    private_presentation: bool,
    invoice_id: String,
    domain: &'a str,
    status: &'a str,
    /// Server-computed money presentation. Empty means the projection is
    /// unknown (for example, an unresolved row from the migration rollout).
    presentation_status: &'a str,
    presentation_known: bool,
    settlement_status: &'a str,
    rails_payable: bool,
    amount_sat: i64,
    remaining_amount_sat: i64,
    fiat_display: Option<String>,
    accept_btc: bool,
    accept_ln: bool,
    accept_liquid: bool,
    bitcoin_chain_address: Option<&'a str>,
    bitcoin_chain_amount_sat: Option<i64>,
    lightning_pr_js: String,
    lightning_amount_sat: Option<i64>,
    liquid_amount_sat: Option<i64>,
    bitcoin_address_js: String,
    bitcoin_chain_address_js: String,
    bitcoin_chain_bip21_js: String,
    liquid_address_js: String,
    liquid_btc_asset_id: &'a str,
}

fn format_fiat_major(minor: i32, currency: &str) -> String {
    let p = pricer::currency_precision(currency);
    if p == 0 {
        format!("{minor} {currency}")
    } else {
        let divisor = 10i64.pow(p as u32);
        let major = minor as i64 / divisor;
        let frac = (minor as i64 % divisor).unsigned_abs();
        format!("{major}.{frac:0>width$} {currency}", width = p as usize)
    }
}

fn js_string_literal(value: Option<&str>) -> Result<String, AppError> {
    let json = serde_json::to_string(value.unwrap_or(""))
        .map_err(|e| AppError::DbError(format!("js string encode: {e}")))?;
    Ok(json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026"))
}

fn invoice_payment_rails_are_payable(inv: &db::Invoice) -> bool {
    if !matches!(
        inv.status.as_str(),
        "unpaid" | "in_progress" | "partially_paid"
    ) {
        return false;
    }

    match (
        inv.presentation_status.as_deref(),
        inv.settlement_status.as_str(),
    ) {
        // No accepted evidence: the normal fresh-invoice state.
        (Some("unpaid"), "none") => true,
        // A partial direct payment remains payable while it confirms and even
        // after that contribution reaches finality. The server projection is
        // authoritative; clients must not reproduce amount/tolerance rules.
        (Some("partial"), "none" | "pending" | "settled") => true,
        // Sufficient/overpaid evidence, incidents, and unknown projections all
        // suppress new instructions and provider-side offer creation.
        _ => false,
    }
}

struct PublicDirectPaymentAddresses<'a> {
    bitcoin: Option<&'a str>,
    liquid: Option<&'a str>,
}

/// Direct addresses are payment instructions on public invoice surfaces, not
/// reconciliation data. Only publish an address when that direct rail was
/// explicitly accepted and the invoice remains payable. In particular, an
/// LN-only invoice may store a Liquid claim destination internally without
/// accepting direct Liquid. Authenticated merchant history keeps the raw
/// stored values for reconciliation.
fn public_direct_payment_addresses(inv: &db::Invoice) -> PublicDirectPaymentAddresses<'_> {
    if sat_fixed_payment_instructions_are_payable(inv) {
        PublicDirectPaymentAddresses {
            bitcoin: inv
                .accept_btc
                .then_some(inv.bitcoin_address.as_deref())
                .flatten(),
            liquid: inv
                .accept_liquid
                .then_some(inv.liquid_address.as_deref())
                .flatten(),
        }
    } else {
        PublicDirectPaymentAddresses {
            bitcoin: None,
            liquid: None,
        }
    }
}

/// Public status/render instruction fields are the current sat-fixed contract.
/// Fiat-fixed callers must use the complete selected-rail quote response so an
/// address or amount can never escape without its immutable version identity.
fn sat_fixed_payment_instructions_are_payable(inv: &db::Invoice) -> bool {
    inv.pricing_mode == "sat_fixed" && invoice_payment_rails_are_payable(inv)
}

/// Owns the PostgreSQL session that carries the lazy-offer advisory lock.
/// Normal paths explicitly unlock and return the physical connection to the
/// pool. If the request future is cancelled or errors while still locked,
/// `Drop` closes that one backend session so the lock cannot leak into the
/// pool. `close_on_drop` is intentionally armed only on that exceptional path.
struct InvoiceOfferAdvisoryLock {
    connection: sqlx::pool::PoolConnection<sqlx::Postgres>,
    lock_key: String,
    locked: bool,
}

impl InvoiceOfferAdvisoryLock {
    fn new(connection: sqlx::pool::PoolConnection<sqlx::Postgres>, lock_key: String) -> Self {
        Self {
            connection,
            lock_key,
            locked: true,
        }
    }

    async fn unlock(&mut self) -> Result<(), AppError> {
        let lock_key = self.lock_key.clone();
        let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(hashtext($1))")
            .bind(lock_key)
            .fetch_one(&mut **self)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        if !unlocked {
            return Err(AppError::DbError(
                "invoice Lightning advisory lock was not held by its connection".into(),
            ));
        }
        self.locked = false;
        Ok(())
    }
}

impl std::ops::Deref for InvoiceOfferAdvisoryLock {
    type Target = sqlx::PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl std::ops::DerefMut for InvoiceOfferAdvisoryLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

impl Drop for InvoiceOfferAdvisoryLock {
    fn drop(&mut self) {
        if self.locked {
            self.connection.close_on_drop();
        }
    }
}

/// Public invoice projections combine several tables. Keep every field in one
/// PostgreSQL snapshot so a reducer commit cannot mix an old invoice row with
/// new event sums or payment offers in the same response/render/list item.
async fn begin_invoice_read_snapshot(
    pool: &sqlx::PgPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, AppError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

pub async fn render_payment(
    State(state): State<AppState>,
    Path((nym, id_str)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // Linked render path requires nym_owner == path nym. Cross-nym lookup
    // (or unlinked invoice accessed via a /<nym>/i/<id> URL) returns 404
    // with the same wire copy as missing-id.
    if inv.nym_owner.as_deref() != Some(nym.as_str()) {
        return Err(AppError::InvoiceNotFound(id_str));
    }

    Ok(html_response(
        render_invoice_template(&state, &inv, false).await?,
    ))
}

// =====================================================================
// GET /invoice/<id> — render the unlinked (wallet-only) payment view
// =====================================================================

pub async fn render_unlinked_payment(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
) -> Result<Response, AppError> {
    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // The unlinked render path serves both nym-linked AND nym-NULL invoices
    // (the wallet may always share via /invoice/<id> regardless of linkage).
    // Distinct handlers for the two paths only affect URL parsing.
    Ok(html_response(
        render_invoice_template(&state, &inv, false).await?,
    ))
}

// =====================================================================
// GET /a/<slug>/i/<id> — render a checkout invoice under its alias path
// =====================================================================

/// Render an invoice created via an alias surface. Resolves the slug to its
/// owning nym, confirms the invoice belongs to that nym (same anti-enumeration
/// posture as `render_payment`), and renders with the nym scrubbed from the
/// page (`hide_owner = true`).
pub async fn render_payment_alias(
    State(state): State<AppState>,
    Path((slug, id_str)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // The invoice must belong to the nym that owns this alias. Mismatch (or a
    // cross-alias lookup) returns the same wire copy as a missing id — never
    // reveal existence, and never leak the nym.
    let Some(nym_owner) = inv.nym_owner.as_deref() else {
        return Err(AppError::InvoiceNotFound(id_str));
    };
    if !db::alias_owns_nym(&state.db, &slug, nym_owner).await? {
        return Err(AppError::InvoiceNotFound(id_str));
    }

    Ok(html_response(
        render_invoice_template(&state, &inv, true).await?,
    ))
}

async fn render_invoice_template(
    state: &AppState,
    inv: &db::Invoice,
    hide_owner: bool,
) -> Result<String, AppError> {
    let mut snapshot = begin_invoice_read_snapshot(&state.db).await?;
    let inv = db::get_invoice_by_id(&mut *snapshot, inv.id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(inv.id.to_string()))?;
    let fiat_display = match (inv.fiat_amount_minor, inv.fiat_currency.as_deref()) {
        (Some(minor), Some(cur)) => Some(format_fiat_major(minor, cur)),
        _ => None,
    };
    let received_sat = db::invoice_presentation_received_sat(&mut *snapshot, inv.id)
        .await?
        .unwrap_or_else(|| inv.paid_amount_sat.unwrap_or(0));
    let remaining_sat = remaining_amount_from_received(&inv, received_sat);
    let sat_fixed_instructions_payable = sat_fixed_payment_instructions_are_payable(&inv);
    let lightning_offer = if sat_fixed_instructions_payable {
        latest_reusable_lightning_offer(&mut *snapshot, &inv, remaining_sat).await?
    } else {
        None
    };
    let bitcoin_chain_offer = if sat_fixed_instructions_payable {
        db::latest_payer_exposable_chain_swap_for_invoice(&mut *snapshot, inv.id, remaining_sat)
            .await?
    } else {
        None
    };
    snapshot.commit().await?;
    // Suppress the nym in the served page when rendering under an alias path,
    // even though the invoice is nym-linked internally.
    let nym = if hide_owner {
        ""
    } else {
        inv.nym_owner.as_deref().unwrap_or("")
    };
    let is_unlinked = inv.nym_owner.is_none();
    let bitcoin_chain_offer = bitcoin_chain_offer
        .as_ref()
        .and_then(payer_exposable_bitcoin_chain_offer);
    let bitcoin_chain_address = bitcoin_chain_offer.map(|offer| offer.lockup_address);
    let bitcoin_chain_bip21 = bitcoin_chain_offer
        .and_then(|offer| public_bitcoin_chain_bip21(offer.lockup_address, offer.payer_amount_sat));
    let bitcoin_chain_amount_sat = bitcoin_chain_offer.map(|offer| offer.payer_amount_sat);
    let direct_addresses = public_direct_payment_addresses(&inv);
    let liquid_amount_sat = direct_addresses
        .liquid
        .filter(|_| sat_fixed_instructions_payable && remaining_sat > 0)
        .map(|_| remaining_sat);
    let tpl = InvoicePaymentTpl {
        nym,
        is_unlinked,
        hide_owner,
        private_presentation: inv.origin == "wallet",
        invoice_id: inv.id.to_string(),
        domain: &state.config.domain,
        status: &inv.status,
        presentation_status: inv.presentation_status.as_deref().unwrap_or(""),
        presentation_known: matches!(
            inv.presentation_status.as_deref(),
            Some("unpaid" | "partial" | "payment_received" | "overpaid")
        ),
        settlement_status: &inv.settlement_status,
        rails_payable: sat_fixed_instructions_payable,
        amount_sat: inv.amount_sat,
        remaining_amount_sat: remaining_sat,
        fiat_display,
        accept_btc: inv.accept_btc,
        accept_ln: inv.accept_ln,
        accept_liquid: inv.accept_liquid,
        bitcoin_chain_address,
        bitcoin_chain_amount_sat,
        lightning_pr_js: js_string_literal(
            lightning_offer.as_ref().map(|offer| offer.pr.as_str()),
        )?,
        lightning_amount_sat: lightning_offer.as_ref().map(|offer| offer.payer_amount_sat),
        liquid_amount_sat,
        bitcoin_address_js: js_string_literal(direct_addresses.bitcoin)?,
        bitcoin_chain_address_js: js_string_literal(bitcoin_chain_address)?,
        bitcoin_chain_bip21_js: js_string_literal(bitcoin_chain_bip21.as_deref())?,
        liquid_address_js: js_string_literal(direct_addresses.liquid)?,
        liquid_btc_asset_id: LIQUID_BTC_ASSET_ID,
    };
    tpl.render()
        .map_err(|e| AppError::DbError(format!("template render: {e}")))
}

// =====================================================================
// GET /api/v1/invoices/:id/presentation
// =====================================================================

#[derive(Serialize)]
pub struct PrivateInvoicePresentationResponse {
    /// Canonical unpadded base64url private-invoice-v1 envelope. The AES key
    /// exists only in the payer's URL fragment and is never sent here.
    pub presentation_envelope: String,
}

pub async fn private_presentation(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<PrivateInvoicePresentationResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::InvoiceStatus,
        peer,
        &headers,
        "invoice_private_presentation",
        Some(&id_str),
    );
    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_invoice_status_per_source(ip)
                .await?;
        }
    }

    let id = parse_invoice_id(&id_str)?;
    let envelope = db::get_private_invoice_presentation(&state.db, id)
        .await?
        .ok_or(AppError::InvoiceNotFound(id_str))?;
    if envelope.len() != PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BYTES
        || envelope.first().copied() != Some(PRIVATE_INVOICE_PRESENTATION_VERSION)
    {
        return Err(AppError::DbError(format!(
            "invoice {id} has an invalid private presentation envelope"
        )));
    }
    Ok(Json(PrivateInvoicePresentationResponse {
        presentation_envelope: URL_SAFE_NO_PAD.encode(envelope),
    }))
}

// =====================================================================
// GET /api/v1/invoices/:id/status
// =====================================================================

#[derive(Serialize)]
pub struct BitcoinDirectObservationResponse {
    pub source: String,
    pub rail: String,
    pub txid: String,
    pub vout: i32,
    pub address: String,
    pub amount_sat: i64,
    pub confirmations: i32,
    pub block_height: Option<i32>,
    pub state: String,
    pub first_seen_at_unix: i64,
    pub last_seen_at_unix: i64,
}

#[derive(Serialize)]
pub struct InvoiceStatusResponse {
    pub status: String,
    pub presentation_status: Option<String>,
    pub pricing_mode: String,
    pub settlement_status: String,
    pub amount_sat: i64,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub remaining_amount_sat: i64,
    pub payment_tolerance_sat: i64,
    pub rate_minor_per_btc: Option<i64>,
    pub rate_locks_until_unix: i64,
    pub expires_at_unix: i64,
    pub paid_via: Option<String>,
    pub paid_at_unix: Option<i64>,
    pub paid_amount_sat: Option<i64>,
    pub lightning_pr: Option<String>,
    /// Exact BOLT11 principal paired with `lightning_pr`.
    pub lightning_amount_sat: Option<i64>,
    pub liquid_address: Option<String>,
    /// Exact direct-Liquid amount paired with `liquid_address`.
    pub liquid_amount_sat: Option<i64>,
    pub bitcoin_address: Option<String>,
    pub bitcoin_direct_observations: Vec<BitcoinDirectObservationResponse>,
    pub bitcoin_chain_address: Option<String>,
    pub bitcoin_chain_bip21: Option<String>,
    /// Exact payer-side Bitcoin lock amount for `bitcoin_chain_address`.
    /// Null whenever the chain offer is absent or internally inconsistent.
    pub bitcoin_chain_amount_sat: Option<i64>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    /// Required object for fiat-fixed invoices and null for sat-fixed invoices.
    /// This pure projection is the only browser authority for quote tabs.
    pub quote_rail_availability: Option<PayerQuoteRailAvailability>,
}

pub async fn status(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<InvoiceStatusResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::InvoiceStatus,
        peer,
        &headers,
        "invoice_status",
        Some(&id_str),
    );

    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state
                .rate_limiter
                .check_invoice_status_per_source(ip)
                .await?;
        }
    }

    let id = parse_invoice_id(&id_str)?;
    db::terminalize_stale_checkout_partial_invoice(
        &state.db,
        id,
        state
            .config
            .invoice_accounting
            .checkout_partial_terminal_grace_secs,
    )
    .await?;
    let mut snapshot = begin_invoice_read_snapshot(&state.db).await?;
    let inv = db::get_invoice_by_id(&mut *snapshot, id)
        .await?
        .ok_or(AppError::InvoiceNotFound(id_str))?;
    pause_at_invoice_integration_test_hook(InvoiceIntegrationTestHookPoint::StatusAfterInvoiceRead)
        .await;

    let received_sat = db::invoice_presentation_received_sat(&mut *snapshot, inv.id)
        .await?
        .unwrap_or_else(|| inv.paid_amount_sat.unwrap_or(0));
    let remaining_sat = remaining_amount_from_received(&inv, received_sat);
    let sat_fixed_instructions_payable = sat_fixed_payment_instructions_are_payable(&inv);
    let lightning_offer = if sat_fixed_instructions_payable {
        latest_reusable_lightning_offer(&mut *snapshot, &inv, remaining_sat).await?
    } else {
        None
    };
    let bitcoin_chain_offer = if sat_fixed_instructions_payable {
        db::latest_payer_exposable_chain_swap_for_invoice(&mut *snapshot, inv.id, remaining_sat)
            .await?
    } else {
        None
    };
    let bitcoin_chain_offer = bitcoin_chain_offer
        .as_ref()
        .and_then(payer_exposable_bitcoin_chain_offer);
    let tolerance_sat = payment_tolerance_sat(
        &inv,
        db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
    );
    let bitcoin_direct_observations =
        db::list_invoice_payment_observations(&mut *snapshot, inv.id, 10)
            .await?
            .into_iter()
            .map(|obs| BitcoinDirectObservationResponse {
                source: obs.source,
                rail: obs.rail,
                txid: obs.txid,
                vout: obs.vout,
                address: obs.address,
                amount_sat: obs.amount_sat,
                confirmations: obs.confirmations,
                block_height: obs.block_height,
                state: obs.last_seen_state,
                first_seen_at_unix: obs.first_seen_at_unix,
                last_seen_at_unix: obs.last_seen_at_unix,
            })
            .collect();
    snapshot.commit().await?;
    let direct_addresses = public_direct_payment_addresses(&inv);
    let bitcoin_address = direct_addresses.bitcoin.map(str::to_owned);
    let liquid_address = direct_addresses.liquid.map(str::to_owned);
    let liquid_amount_sat = liquid_address
        .as_ref()
        .filter(|_| sat_fixed_instructions_payable && remaining_sat > 0)
        .map(|_| remaining_sat);
    let quote_rail_availability = payer_quote_rail_availability(&inv);

    Ok(Json(InvoiceStatusResponse {
        status: inv.status,
        presentation_status: inv.presentation_status,
        pricing_mode: inv.pricing_mode,
        settlement_status: inv.settlement_status,
        amount_sat: inv.amount_sat,
        fiat_amount_minor: inv.fiat_amount_minor,
        fiat_currency: inv.fiat_currency,
        remaining_amount_sat: remaining_sat,
        payment_tolerance_sat: tolerance_sat,
        rate_minor_per_btc: inv.rate_minor_per_btc,
        rate_locks_until_unix: inv.rate_locks_until_unix,
        expires_at_unix: inv.expires_at_unix,
        paid_via: inv.paid_via,
        paid_at_unix: inv.paid_at_unix,
        paid_amount_sat: inv.paid_amount_sat,
        lightning_pr: lightning_offer.as_ref().map(|offer| offer.pr.clone()),
        lightning_amount_sat: lightning_offer.as_ref().map(|offer| offer.payer_amount_sat),
        liquid_amount_sat,
        liquid_address,
        bitcoin_address,
        bitcoin_direct_observations,
        bitcoin_chain_address: bitcoin_chain_offer.map(|offer| offer.lockup_address.to_owned()),
        bitcoin_chain_bip21: bitcoin_chain_offer.and_then(|offer| {
            public_bitcoin_chain_bip21(offer.lockup_address, offer.payer_amount_sat)
        }),
        bitcoin_chain_amount_sat: bitcoin_chain_offer.map(|offer| offer.payer_amount_sat),
        accept_btc: inv.accept_btc,
        accept_ln: inv.accept_ln,
        accept_liquid: inv.accept_liquid,
        quote_rail_availability,
    }))
}

// =====================================================================
// POST /api/v1/invoices/:id/lightning — lazy create / re-fetch the offer
// =====================================================================

#[derive(Serialize)]
pub struct LightningOfferResponse {
    pub pr: String,
    pub lightning_amount_sat: i64,
}

/// One explicit payer-selected rail.  Missing `rail` preserves the approved
/// Lightning-default checkout behavior without making a GET manufacture a
/// provider obligation.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayerQuoteRail {
    #[default]
    Lightning,
    Liquid,
    Bitcoin,
}

impl PayerQuoteRail {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lightning => "lightning",
            Self::Liquid => "liquid",
            Self::Bitcoin => "bitcoin",
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayerDemandQuoteRequest {
    #[serde(default)]
    pub rail: PayerQuoteRail,
}

#[derive(Debug, Serialize)]
pub struct PayerQuoteRailAvailability {
    pub lightning: bool,
    pub liquid: bool,
    pub bitcoin: bool,
}

#[derive(Debug, Serialize)]
pub struct FiatQuoteView {
    pub quote_version_id: Uuid,
    pub version_number: i32,
    pub fiat_face_amount_minor: i32,
    pub fiat_target_amount_minor: i32,
    pub fiat_currency: String,
    pub rate_minor_per_btc: i64,
    pub rate_source: String,
    pub rate_observed_at_unix: i64,
    pub rate_fetched_at_unix: i64,
    pub rate_fresh_until_unix: i64,
    pub merchant_amount_sat: i64,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

impl From<&db::InvoiceQuoteVersion> for FiatQuoteView {
    fn from(quote: &db::InvoiceQuoteVersion) -> Self {
        Self {
            quote_version_id: quote.id,
            version_number: quote.version_number,
            fiat_face_amount_minor: quote.fiat_face_amount_minor,
            fiat_target_amount_minor: quote.fiat_target_amount_minor,
            fiat_currency: quote.fiat_currency.clone(),
            rate_minor_per_btc: quote.rate_minor_per_btc,
            rate_source: quote.rate_source.clone(),
            rate_observed_at_unix: quote.rate_observed_at_unix,
            rate_fetched_at_unix: quote.rate_fetched_at_unix,
            rate_fresh_until_unix: quote.rate_fresh_until_unix,
            merchant_amount_sat: quote.merchant_amount_sat,
            created_at_unix: quote.created_at_unix,
            expires_at_unix: quote.expires_at_unix,
        }
    }
}

/// A quote response contains exactly one complete selected-rail instruction.
/// Serde's tagged enum prevents nullable address/amount/offer combinations.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VersionedPayerInstruction {
    LiquidDirect {
        address: String,
        payer_amount_sat: i64,
    },
    BitcoinDirect {
        address: String,
        bip21: String,
        payer_amount_sat: i64,
    },
    LightningBoltzReverse {
        quote_offer_id: Uuid,
        pr: String,
        payer_amount_sat: i64,
    },
    BitcoinBoltzChain {
        quote_offer_id: Uuid,
        address: String,
        bip21: String,
        payer_amount_sat: i64,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "pricing_mode", rename_all = "snake_case")]
pub enum PayerDemandQuoteResponse {
    FiatFixed {
        invoice_id: Uuid,
        selected_rail: PayerQuoteRail,
        quote: FiatQuoteView,
        instruction: VersionedPayerInstruction,
    },
}

/// `POST /api/v1/invoices/:id/quote` is the sole payer-demand mutation
/// boundary for versioned quotes.  Status/render/crawler GETs remain pure
/// projections and never call this handler internally.
pub async fn payer_demand_quote(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(request): Json<PayerDemandQuoteRequest>,
) -> Result<Json<PayerDemandQuoteResponse>, AppError> {
    check_payer_offer_rate_limit(&state, peer_opt, &headers, &id_str).await?;

    let id = parse_invoice_id(&id_str)?;
    let invoice = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;
    if !invoice_payment_rails_are_payable(&invoice) {
        return Err(AppError::InvalidAmount(format!(
            "invoice is {} (not payable); no payer quote available",
            invoice.status
        )));
    }
    if invoice.pricing_mode != "fiat_fixed" {
        return Err(AppError::InvalidAmount(
            "sat-fixed invoices retain the remaining-aware status and Lightning offer flow".into(),
        ));
    }
    validate_payer_quote_rail(&invoice, request.rail)?;
    let quote = resolve_current_fiat_quote(&state, &invoice).await?;
    let instruction =
        versioned_instruction_for_rail(&state, &invoice, &quote, request.rail).await?;
    let response = PayerDemandQuoteResponse::FiatFixed {
        invoice_id: invoice.id,
        selected_rail: request.rail,
        quote: FiatQuoteView::from(&quote),
        instruction,
    };
    Ok(Json(response))
}

fn payer_quote_rail_availability(invoice: &db::Invoice) -> Option<PayerQuoteRailAvailability> {
    if invoice.pricing_mode != "fiat_fixed" {
        return None;
    }
    let payable = invoice_payment_rails_are_payable(invoice);
    let checkout_descriptor_surface = invoice.origin == "checkout" && invoice.nym_owner.is_some();
    let wallet_direct_bitcoin =
        invoice.origin == "wallet" && invoice.accept_btc && invoice.bitcoin_address.is_some();
    Some(PayerQuoteRailAvailability {
        lightning: payable && invoice.accept_ln,
        liquid: payable
            && invoice.accept_liquid
            && invoice.liquid_address.is_some()
            && invoice.liquid_blinding_key_hex.is_some(),
        // Checkout/POS Bitcoin remains provider-backed and settles to Liquid.
        // Wallet-origin Bitcoin pays the stable invoice address directly; its
        // version-bound quote changes only the amount and BIP21 envelope.
        bitcoin: payable
            && (wallet_direct_bitcoin
                || (checkout_descriptor_surface && invoice.liquid_address.is_some())),
    })
}

fn validate_payer_quote_rail(invoice: &db::Invoice, rail: PayerQuoteRail) -> Result<(), AppError> {
    let availability = payer_quote_rail_availability(invoice)
        .ok_or_else(|| AppError::InvalidAmount("invoice does not support fiat quotes".into()))?;
    match rail {
        PayerQuoteRail::Lightning if !availability.lightning => Err(AppError::InvalidAmount(
            "invoice does not accept Lightning".into(),
        )),
        PayerQuoteRail::Liquid if !availability.liquid => Err(AppError::InvalidAmount(
            "invoice does not accept Liquid".into(),
        )),
        PayerQuoteRail::Bitcoin if !availability.bitcoin => Err(AppError::InvalidAmount(
            "invoice does not accept Bitcoin".into(),
        )),
        _ => Ok(()),
    }
}

async fn check_payer_offer_rate_limit(
    state: &AppState,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    invoice_id: &str,
) -> Result<(), AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, headers, state.config.rate_limit.trust_forwarded_for);
    let whitelisted = ip
        .map(|address| state.ip_whitelist.contains(address))
        .unwrap_or(false);
    let certification_allowed = certification::allows_scope(
        state,
        CertificationScope::LiveMoneyOffer,
        peer,
        headers,
        "invoice_payer_quote",
        Some(invoice_id),
    );
    if !whitelisted && !certification_allowed {
        if let Some(address) = ip {
            state
                .rate_limiter
                .check_lightning_per_source(address)
                .await?;
        }
    }
    Ok(())
}

async fn resolve_current_fiat_quote(
    state: &AppState,
    invoice: &db::Invoice,
) -> Result<db::InvoiceQuoteVersion, AppError> {
    if let Some(quote) = db::current_invoice_quote(&state.db, invoice.id).await? {
        return Ok(quote);
    }
    if invoice.expires_at_unix < unix_now().saturating_add(FIAT_QUOTE_WINDOW_SECS) {
        return Err(AppError::ServiceUnavailable(
            "invoice lifetime cannot contain a complete five-minute quote".into(),
        ));
    }
    let currency = invoice
        .fiat_currency
        .as_deref()
        .ok_or_else(|| AppError::DbError("fiat-fixed invoice is missing its currency".into()))?;
    let rate = state
        .pricer
        .get_rate(currency)
        .await
        .map_err(|_| AppError::ServiceUnavailable("fresh fiat quote unavailable".into()))?;
    if unix_now() as u64 >= rate.expires_at_unix {
        return Err(AppError::ServiceUnavailable(
            "fresh fiat quote unavailable".into(),
        ));
    }

    let min_sat = (state.config.limits.min_sendable_msat / 1_000) as i64;
    let max_sat = (state.config.limits.max_sendable_msat / 1_000) as i64;

    let candidate = db::NewInvoiceQuoteVersion {
        rate_minor_per_btc: rate.minor_per_btc,
        rate_source: &rate.source,
        rate_observed_at_unix: i64::try_from(rate.observed_at_unix)
            .map_err(|_| AppError::DbError("rate observation time exceeds storage range".into()))?,
        rate_fetched_at_unix: i64::try_from(rate.fetched_at_unix)
            .map_err(|_| AppError::DbError("rate fetch time exceeds storage range".into()))?,
        rate_fresh_until_unix: i64::try_from(rate.expires_at_unix)
            .map_err(|_| AppError::DbError("rate expiry exceeds storage range".into()))?,
        minimum_merchant_amount_sat: min_sat,
        maximum_merchant_amount_sat: max_sat,
    };
    Ok(
        db::create_or_reuse_current_invoice_quote(&state.db, invoice.id, &candidate)
            .await?
            .quote,
    )
}

fn quote_offer_request_key(quote_id: Uuid, rail: PayerQuoteRail, kind: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"bullnym-invoice-quote-offer-v1\0");
    hash.update(quote_id.as_bytes());
    hash.update([0]);
    hash.update(rail.as_str().as_bytes());
    hash.update([0]);
    hash.update(kind.as_bytes());
    hex::encode(hash.finalize())
}

pub async fn fetch_lightning_offer(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Result<Json<LightningOfferResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::LiveMoneyOffer,
        peer,
        &headers,
        "invoice_lightning_offer",
        Some(&id_str),
    );

    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state.rate_limiter.check_lightning_per_source(ip).await?;
        }
    }

    let id = parse_invoice_id(&id_str)?;
    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;
    if inv.pricing_mode == "fiat_fixed" {
        return Err(AppError::InvalidAmount(
            "fiat-fixed invoices require the selected-rail quote endpoint".into(),
        ));
    }
    if !invoice_payment_rails_are_payable(&inv) {
        return Err(AppError::InvalidAmount(format!(
            "invoice is {} (not payable); no Lightning offer available",
            inv.status
        )));
    }
    if !inv.accept_ln {
        return Err(AppError::InvalidAmount(
            "invoice does not accept Lightning".into(),
        ));
    }

    let offer = ensure_reusable_lightning_offer(&state, &inv)
        .await?
        .ok_or_else(|| {
            AppError::InvalidAmount("invoice expired; no Lightning offer available".into())
        })?;
    Ok(Json(LightningOfferResponse {
        pr: offer.pr,
        lightning_amount_sat: offer.payer_amount_sat,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LightningOffer {
    pr: String,
    payer_amount_sat: i64,
}

/// Reconstruct the exact public payer instruction from persisted BOLT11
/// authority. Historical face-value reverse swaps are deliberately withheld:
/// fixed checkout requires a distinct provider-cost gross-up.
fn fixed_checkout_lightning_offer(pr: String, merchant_amount_sat: i64) -> Option<LightningOffer> {
    let invoice = Bolt11Invoice::from_str(&pr).ok()?;
    let amount_msat = invoice.amount_milli_satoshis()?;
    if amount_msat % 1_000 != 0 {
        return None;
    }
    let payer_amount_sat = i64::try_from(amount_msat / 1_000).ok()?;
    if merchant_amount_sat <= 0 || payer_amount_sat <= merchant_amount_sat {
        return None;
    }
    Some(LightningOffer {
        pr,
        payer_amount_sat,
    })
}

/// Return the latest still-payable BOLT11 for an invoice, refreshing it
/// through Boltz when the previous offer has expired. The server presentation
/// projection decides payability: unpaid and partial may create a replacement,
/// while sufficient, incident, and unknown evidence cannot.
/// The outer invoice `expires_at` remains the hard merchant lifetime;
/// after that deadline, this helper will not create another swap.
async fn ensure_reusable_lightning_offer(
    state: &AppState,
    inv: &db::Invoice,
) -> Result<Option<LightningOffer>, AppError> {
    if !invoice_payment_rails_are_payable(inv) || !inv.accept_ln {
        return Ok(None);
    }

    let lock_key = db::invoice_lightning_lock_key(inv.id);
    // Serialize creation with a session advisory lock on one checked-out
    // connection. Once acquired, the RAII guard unlocks on normal paths and
    // closes the backend session only if cancellation/error drops it while
    // still locked. This lets allocation autocommit before Boltz without
    // churning a physical pool connection on every cached-offer request.
    let mut pooled_connection = state
        .db
        .acquire()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(&lock_key)
        .fetch_one(&mut *pooled_connection)
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    if !acquired {
        // Another offer request or a direct-payment reducer owns the invoice
        // projection boundary. Never answer from the pre-lock snapshot: the
        // exact payable amount may be changing. Signal a short retry instead.
        drop(pooled_connection);
        return Err(AppError::ServiceUnavailable(
            "invoice payment state is changing; retry the Lightning offer request".into(),
        ));
    }
    let mut connection = InvoiceOfferAdvisoryLock::new(pooled_connection, lock_key);

    // Holding the same advisory boundary as the direct-payment reducer: reload
    // every mutable projection and recompute exact presentation value. This
    // prevents a pre-lock partial/sufficient payment from minting a stale
    // full-value offer.
    let current = db::get_invoice_by_id(&mut *connection, inv.id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(inv.id.to_string()))?;
    if !invoice_payment_rails_are_payable(&current) || !current.accept_ln {
        connection.unlock().await?;
        return Ok(None);
    }
    let now = unix_now();
    if current.expires_at_unix <= now {
        connection.unlock().await?;
        return Ok(None);
    }
    let received_sat = db::invoice_presentation_received_sat(&mut *connection, current.id)
        .await?
        .unwrap_or_else(|| current.paid_amount_sat.unwrap_or(0));
    let amount_sat = remaining_amount_from_received(&current, received_sat);
    if amount_sat <= 0 {
        connection.unlock().await?;
        return Ok(None);
    }

    // Double-check the latest offer under the serialization boundary and
    // create only when its amount/expiry no longer matches.
    let latest = db::latest_lightning_pr_for_invoice(&mut *connection, inv.id).await?;
    if let Some((pr, pr_amount_sat)) = latest {
        if pr_amount_sat == amount_sat && bolt11_is_reusable_at(&pr, now) {
            let offer = fixed_checkout_lightning_offer(pr, amount_sat);
            connection.unlock().await?;
            if offer.is_some() {
                return Ok(offer);
            }
        }
        tracing::info!(
            invoice_id = %current.id,
            "latest BOLT11 expired or presentation amount changed; requesting replacement offer from Boltz",
        );
    }

    // Keep every database operation on the connection that owns the advisory
    // boundary. Otherwise N concurrent offers can each hold one pooled
    // connection here and deadlock while waiting for a second connection.
    state
        .admission
        .enforce(Rail::LightningReverse)
        .map_err(|_| AppError::MoneyAdmissionUnavailable)?;
    let swap_key_index = db::next_swap_key_index(&mut *connection)
        .await
        .map_err(|e| AppError::BoltzError(format!("swap key allocation failed: {e}")))?;
    let derived_key = state.boltz.derive_swap_key(swap_key_index)?;
    let claim_public_key_hex = derived_key.public_key_hex();
    let preimage_hash_hex = derived_key.preimage_hash_hex();
    let key_allocation_id = db::reserve_swap_key_allocation(
        &mut *connection,
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
    let prepared = request_lightning_offer(
        state,
        derived_key,
        amount_sat as u64,
        payment_page_mrh_address(&current),
    )
    .await?;

    // The allocation above is already durable. Start a short transaction only
    // for provider-result persistence plus the final invoice revalidation.
    let mut tx = connection
        .begin()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;

    db::record_swap_in_tx_with_lineage(
        &mut tx,
        &prepared.as_new_swap_record(
            lightning_swap_nym(&current),
            amount_sat as u64,
            current.id,
            swap_key_index,
            state.swap_key_root_fingerprint.as_str(),
        ),
        &db::ReverseSwapLineage {
            allocation_id: key_allocation_id,
            key_epoch: state.config.boltz.key_epoch,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: &preimage_hash_hex,
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("failed to record swap {}: {e}", prepared.swap_id)))?;

    // Expiry/partial terminalization does not use this offer advisory lock.
    // Re-read after the remote call and after durable result persistence. A
    // provider-created offer is always retained for recovery, but it is never
    // surfaced when payability, exact remaining amount, or the hard deadline
    // changed while the request was in flight.
    let _: Uuid = sqlx::query_scalar("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
        .bind(current.id)
        .fetch_one(&mut *tx)
        .await?;
    let final_invoice = db::get_invoice_by_id(&mut *tx, current.id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(current.id.to_string()))?;
    let final_received_sat = db::invoice_presentation_received_sat(&mut *tx, current.id)
        .await?
        .unwrap_or_else(|| final_invoice.paid_amount_sat.unwrap_or(0));
    let final_amount_sat = remaining_amount_from_received(&final_invoice, final_received_sat);
    let still_payable = invoice_payment_rails_are_payable(&final_invoice)
        && final_invoice.accept_ln
        && final_invoice.expires_at_unix > unix_now()
        && final_amount_sat == amount_sat
        && bolt11_uses_generic_description(&prepared.lightning_pr);
    pause_at_invoice_integration_test_hook(InvoiceIntegrationTestHookPoint::OfferBeforeCommit)
        .await;

    tx.commit()
        .await
        .map_err(|e| AppError::DbError(e.to_string()))?;
    // Release the single-flight session lock before acquiring from the pool in
    // the best-effort callback touch below (also required for pool_size=1).
    connection.unlock().await?;
    drop(connection);
    if let Some(nym) = lightning_swap_nym(&current) {
        db::touch_user_callback(&state.db, nym).await;
    }
    if !still_payable {
        return Err(AppError::ServiceUnavailable(
            "invoice payment state changed while creating the Lightning offer; refresh and retry"
                .into(),
        ));
    }
    Ok(Some(prepared.public_offer()))
}

async fn versioned_instruction_for_rail(
    state: &AppState,
    invoice: &db::Invoice,
    quote: &db::InvoiceQuoteVersion,
    rail: PayerQuoteRail,
) -> Result<VersionedPayerInstruction, AppError> {
    match rail {
        PayerQuoteRail::Liquid => {
            if !invoice.accept_liquid {
                return Err(AppError::InvalidAmount(
                    "invoice does not accept Liquid".into(),
                ));
            }
            let address = invoice.liquid_address.clone().ok_or_else(|| {
                AppError::DbError(
                    "direct Liquid quote is missing its stable invoice address".into(),
                )
            })?;
            Ok(VersionedPayerInstruction::LiquidDirect {
                address,
                payer_amount_sat: quote.merchant_amount_sat,
            })
        }
        PayerQuoteRail::Lightning => {
            if !invoice.accept_ln {
                return Err(AppError::InvalidAmount(
                    "invoice does not accept Lightning".into(),
                ));
            }
            let (offer_id, offer) = ensure_versioned_lightning_offer(state, invoice, quote).await?;
            Ok(VersionedPayerInstruction::LightningBoltzReverse {
                quote_offer_id: offer_id,
                pr: offer.pr,
                payer_amount_sat: offer.payer_amount_sat,
            })
        }
        PayerQuoteRail::Bitcoin => {
            if invoice.origin == "wallet" {
                if !invoice.accept_btc {
                    return Err(AppError::InvalidAmount(
                        "invoice does not accept Bitcoin".into(),
                    ));
                }
                let address = invoice.bitcoin_address.clone().ok_or_else(|| {
                    AppError::DbError(
                        "direct Bitcoin quote is missing its stable invoice address".into(),
                    )
                })?;
                let amount_sat = u64::try_from(quote.merchant_amount_sat).map_err(|_| {
                    AppError::DbError("direct Bitcoin quote amount is invalid".into())
                })?;
                return Ok(VersionedPayerInstruction::BitcoinDirect {
                    bip21: build_direct_bitcoin_bip21(&address, amount_sat),
                    address,
                    payer_amount_sat: quote.merchant_amount_sat,
                });
            }
            let (offer_id, offer) =
                ensure_versioned_bitcoin_chain_offer(state, invoice, quote).await?;
            let bip21 = offer.lockup_bip21.ok_or_else(|| {
                AppError::DbError("versioned Bitcoin offer is missing its BIP21".into())
            })?;
            Ok(VersionedPayerInstruction::BitcoinBoltzChain {
                quote_offer_id: offer_id,
                address: offer.lockup_address,
                bip21,
                payer_amount_sat: offer.payer_amount_sat,
            })
        }
    }
}

/// Fiat quote-aware counterpart to the sat-fixed lazy Lightning helper. The durable
/// quote exists before provider I/O; exact quote-offer identity and the swap
/// row commit together before any BOLT11 is returned.
async fn ensure_versioned_lightning_offer(
    state: &AppState,
    invoice: &db::Invoice,
    requested_quote: &db::InvoiceQuoteVersion,
) -> Result<(Uuid, LightningOffer), AppError> {
    let lock_key = db::invoice_lightning_lock_key(invoice.id);
    let mut pooled_connection = state
        .db
        .acquire()
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(&lock_key)
        .fetch_one(&mut *pooled_connection)
        .await
        .map_err(|error| AppError::DbError(error.to_string()))?;
    if !acquired {
        return Err(AppError::ServiceUnavailable(
            "invoice quote is changing; retry the payer quote request".into(),
        ));
    }
    let mut connection = InvoiceOfferAdvisoryLock::new(pooled_connection, lock_key);

    let current = db::get_invoice_by_id(&mut *connection, invoice.id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(invoice.id.to_string()))?;
    let quote = db::current_invoice_quote(&mut *connection, invoice.id)
        .await?
        .ok_or_else(|| {
            AppError::ServiceUnavailable("invoice quote expired; refresh and retry".into())
        })?;
    if quote.id != requested_quote.id
        || !invoice_payment_rails_are_payable(&current)
        || !current.accept_ln
    {
        connection.unlock().await?;
        return Err(AppError::ServiceUnavailable(
            "invoice quote changed; refresh and retry".into(),
        ));
    }

    if let Some(persisted) =
        db::invoice_quote_offer_for_rail(&mut *connection, current.id, quote.id, "lightning")
            .await?
    {
        if persisted.offer_kind != "boltz_reverse"
            || persisted.provider.as_deref() != Some("boltz")
            || persisted.provider_attempt_id.is_none()
        {
            connection.unlock().await?;
            return Err(AppError::DbError(
                "persisted Lightning quote offer has invalid authority".into(),
            ));
        }
        let instruction = db::lightning_pr_for_invoice_quote_offer(
            &mut *connection,
            current.id,
            quote.id,
            persisted.id,
            persisted.provider_offer_id.as_deref().ok_or_else(|| {
                AppError::DbError("persisted Lightning offer is missing provider identity".into())
            })?,
        )
        .await?;
        connection.unlock().await?;
        let (pr, merchant_amount_sat) = instruction.ok_or_else(|| {
            AppError::ServiceUnavailable(
                "persisted Lightning quote offer is not currently payable".into(),
            )
        })?;
        let validated = fixed_checkout_lightning_offer(pr, merchant_amount_sat);
        if merchant_amount_sat != quote.merchant_amount_sat
            || validated.as_ref().map(|offer| offer.payer_amount_sat)
                != Some(persisted.payer_amount_sat)
            || !validated
                .as_ref()
                .is_some_and(|offer| bolt11_is_reusable_at(&offer.pr, unix_now()))
        {
            return Err(AppError::ServiceUnavailable(
                "persisted Lightning quote offer is not currently payable".into(),
            ));
        }
        return Ok((persisted.id, validated.expect("validated above")));
    }

    // Never start a provider mutation so close to the immutable quote expiry
    // that a bounded response cannot be durably attributed before exposure.
    if quote.expires_at_unix
        <= unix_now().saturating_add(i64::try_from(BOLT11_REFRESH_MARGIN_SECS).unwrap_or(120))
    {
        connection.unlock().await?;
        return Err(AppError::ServiceUnavailable(
            "invoice quote is near expiry; refresh after the countdown".into(),
        ));
    }

    let request_key = quote_offer_request_key(quote.id, PayerQuoteRail::Lightning, "boltz_reverse");
    let existing_provider_attempt =
        db::invoice_quote_provider_attempt(&mut *connection, quote.id, "lightning", &request_key)
            .await?;
    let merchant_amount_sat = u64::try_from(quote.merchant_amount_sat)
        .map_err(|_| AppError::InvalidAmount("invalid quoted amount".into()))?;

    let (
        provider_attempt,
        provider_create,
        swap_key_index,
        allocation_id,
        claim_public_key_hex,
        preimage_hash_hex,
    ) = if let Some(attempt) = existing_provider_attempt {
        if attempt.completed {
            connection.unlock().await?;
            return Err(AppError::DbError(
                "completed Lightning provider attempt is missing its atomic offer".into(),
            ));
        }
        let swap_key_index = u64::try_from(attempt.claim_child_index)
            .map_err(|_| AppError::DbError("invalid persisted reverse child index".into()))?;
        let derived_key = state.boltz.derive_swap_key(swap_key_index)?;
        let claim_public_key_hex = derived_key.public_key_hex();
        let preimage_hash_hex = derived_key.preimage_hash_hex();
        let provider_create = state.boltz.restore_prepared_fixed_checkout_reverse_swap(
            derived_key,
            &attempt.request_authority_json,
            &attempt.request_authority_sha256,
            payment_page_mrh_address(&current),
        )?;
        (
            attempt.clone(),
            provider_create,
            swap_key_index,
            attempt.claim_key_allocation_id,
            claim_public_key_hex,
            preimage_hash_hex,
        )
    } else {
        state
            .admission
            .enforce(Rail::LightningReverse)
            .map_err(|_| AppError::MoneyAdmissionUnavailable)?;
        let swap_key_index = db::next_swap_key_index(&mut *connection)
            .await
            .map_err(|error| {
                AppError::BoltzError(format!("swap key allocation failed: {error}"))
            })?;
        let derived_key = state.boltz.derive_swap_key(swap_key_index)?;
        let claim_public_key_hex = derived_key.public_key_hex();
        let preimage_hash_hex = derived_key.preimage_hash_hex();
        let allocation_id = db::reserve_swap_key_allocation(
            &mut *connection,
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
        .map_err(|error| AppError::DbError(format!("swap key reservation failed: {error}")))?;
        let provider_create = prepare_lightning_provider_create(
            state,
            derived_key,
            merchant_amount_sat,
            payment_page_mrh_address(&current),
        )?;
        let (request_authority_json, request_authority_sha256) =
            provider_create.canonical_authority()?;
        let (attempt, _) = db::record_or_reuse_invoice_quote_provider_attempt(
            &mut *connection,
            &db::NewInvoiceQuoteProviderAttempt {
                invoice_id: current.id,
                quote_version_id: quote.id,
                rail: "lightning",
                request_key: &request_key,
                operation: "fixed_checkout_reverse",
                merchant_amount_sat: quote.merchant_amount_sat,
                request_authority_json: &request_authority_json,
                request_authority_sha256: &request_authority_sha256,
                claim_key_allocation_id: allocation_id,
                refund_key_allocation_id: None,
            },
        )
        .await
        .map_err(|error| {
            AppError::DbError(format!("provider attempt reservation failed: {error}"))
        })?;
        (
            attempt,
            provider_create,
            swap_key_index,
            allocation_id,
            claim_public_key_hex,
            preimage_hash_hex,
        )
    };

    pause_at_invoice_integration_test_hook(
        InvoiceIntegrationTestHookPoint::ProviderAttemptBeforeDispatch,
    )
    .await;
    let owns_dispatch = db::record_invoice_quote_provider_dispatch(
        &mut *connection,
        provider_attempt.id,
        &provider_attempt.request_authority_sha256,
    )
    .await?;
    let provider_result = if owns_dispatch {
        match state
            .boltz
            .submit_fixed_checkout_reverse_swap(provider_create)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                db::record_invoice_quote_provider_integrity_hold(
                    &mut *connection,
                    provider_attempt.id,
                    "provider_outcome_unknown",
                )
                .await?;
                connection.unlock().await?;
                return Err(error);
            }
        }
    } else {
        let claim_child_index = u32::try_from(swap_key_index)
            .map_err(|_| AppError::DbError("reverse child index exceeds provider range".into()))?;
        let response = match state
            .boltz
            .recover_reverse_create_response(claim_child_index)
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => {
                db::record_invoice_quote_provider_integrity_hold(
                    &mut *connection,
                    provider_attempt.id,
                    "restore_absent",
                )
                .await?;
                connection.unlock().await?;
                return Err(AppError::ServiceUnavailable(
                    "Lightning provider outcome remains under integrity hold".into(),
                ));
            }
            Err(_) => {
                db::record_invoice_quote_provider_integrity_hold(
                    &mut *connection,
                    provider_attempt.id,
                    "restore_unavailable",
                )
                .await?;
                connection.unlock().await?;
                return Err(AppError::ServiceUnavailable(
                    "Lightning provider reconciliation is unavailable".into(),
                ));
            }
        };
        if response.invoice.is_none() {
            db::record_invoice_quote_provider_integrity_hold(
                &mut *connection,
                provider_attempt.id,
                "restored_response_incomplete",
            )
            .await?;
            connection.unlock().await?;
            return Err(AppError::ServiceUnavailable(
                "restored Lightning obligation lacks a recoverable invoice".into(),
            ));
        }
        match state
            .boltz
            .complete_fixed_checkout_reverse_swap(provider_create, response)
        {
            Ok(result) => result,
            Err(_) => {
                db::record_invoice_quote_provider_integrity_hold(
                    &mut *connection,
                    provider_attempt.id,
                    "restored_response_invalid",
                )
                .await?;
                connection.unlock().await?;
                return Err(AppError::ServiceUnavailable(
                    "restored Lightning provider response failed validation".into(),
                ));
            }
        }
    };
    let prepared = prepared_lightning_offer_from_result(provider_result)?;
    pause_at_invoice_integration_test_hook(
        InvoiceIntegrationTestHookPoint::ProviderResponseBeforeCommit,
    )
    .await;

    let mut tx = connection.begin().await?;
    let resolution = db::record_or_reuse_invoice_quote_offer_in_tx(
        &mut tx,
        &db::NewInvoiceQuoteOffer {
            invoice_id: current.id,
            quote_version_id: quote.id,
            rail: "lightning",
            offer_kind: "boltz_reverse",
            request_key: &request_key,
            provider: Some("boltz"),
            provider_offer_id: Some(&prepared.swap_id),
            provider_attempt_id: Some(provider_attempt.id),
            payer_amount_sat: prepared.payer_amount_sat,
            expires_at_unix: quote.expires_at_unix,
        },
    )
    .await?;
    db::record_swap_in_tx_with_lineage_and_quote_attribution(
        &mut tx,
        &prepared.as_new_swap_record(
            lightning_swap_nym(&current),
            quote.merchant_amount_sat as u64,
            current.id,
            swap_key_index,
            state.swap_key_root_fingerprint.as_str(),
        ),
        &db::ReverseSwapLineage {
            allocation_id,
            key_epoch: state.config.boltz.key_epoch,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: &preimage_hash_hex,
        },
        db::InvoiceQuoteAttribution {
            quote_version_id: quote.id,
            quote_offer_id: resolution.offer.id,
        },
    )
    .await
    .map_err(|error| {
        AppError::DbError(format!(
            "failed to persist versioned Lightning offer {}: {error}",
            prepared.swap_id
        ))
    })?;
    db::record_invoice_quote_provider_completion(
        &mut *tx,
        provider_attempt.id,
        resolution.offer.id,
        &prepared.swap_id,
        &prepared.provider_response_sha256,
    )
    .await?;
    tx.commit().await?;
    pause_at_invoice_integration_test_hook(
        InvoiceIntegrationTestHookPoint::ProviderOfferAfterCommit,
    )
    .await;
    let still_current = db::current_invoice_quote(&mut *connection, current.id).await?;
    if still_current.as_ref().map(|candidate| candidate.id) != Some(quote.id)
        || quote.expires_at_unix <= unix_now()
    {
        connection.unlock().await?;
        return Err(AppError::ServiceUnavailable(
            "invoice quote expired while creating the Lightning offer; refresh and retry".into(),
        ));
    }
    connection.unlock().await?;
    drop(connection);
    if let Some(nym) = lightning_swap_nym(&current) {
        db::touch_user_callback(&state.db, nym).await;
    }
    if !bolt11_uses_generic_description(&prepared.lightning_pr) {
        return Err(AppError::ServiceUnavailable(
            "Lightning offer uses retired private metadata; refresh the quote and retry".into(),
        ));
    }
    Ok((resolution.offer.id, prepared.public_offer()))
}

async fn ensure_versioned_bitcoin_chain_offer(
    state: &AppState,
    invoice: &db::Invoice,
    requested_quote: &db::InvoiceQuoteVersion,
) -> Result<(Uuid, BitcoinChainOffer), AppError> {
    let liquid_address = invoice.liquid_address.as_deref().ok_or_else(|| {
        AppError::InvalidAmount("invoice does not support Bitcoin-to-Liquid payment".into())
    })?;
    let merchant_liquid_destination = validators::canonical_liquid_mainnet_address(liquid_address)
        .map_err(|error| {
            AppError::BoltzError(format!(
                "chain swap invoice has an invalid Liquid destination: {error}"
            ))
        })?;
    let nym = invoice.nym_owner.as_deref().ok_or_else(|| {
        AppError::InvalidAmount("invoice does not support a Bitcoin chain offer".into())
    })?;

    let mut lookup_connection = state.db.acquire().await?;
    if let ReusableVersionedBitcoinOffer::Ready { offer_id, offer } =
        reusable_versioned_bitcoin_chain_offer(&mut lookup_connection, invoice, requested_quote)
            .await?
    {
        return Ok((offer_id, offer));
    }
    drop(lookup_connection);

    state
        .admission
        .enforce(Rail::BitcoinChain)
        .map_err(|_| AppError::MoneyAdmissionUnavailable)?;
    // Page/POS ownership and the recovery contract are permanent. Taking the
    // separate Lightning Address product offline must close LNURL without
    // disabling an already-enabled checkout surface's Bitcoin quote.
    let owner = db::get_user_by_nym(&state.db, nym).await?.ok_or_else(|| {
        AppError::ServiceUnavailable("Bitcoin recovery owner is unavailable".into())
    })?;
    if owner.npub != invoice.npub_owner {
        return Err(AppError::DbError(
            "Bitcoin recovery owner does not match invoice recipient".into(),
        ));
    }
    let recovery_commitment =
        db::select_current_recovery_address_commitment(&state.db, &owner.npub)
            .await
            .map_err(|error| {
                AppError::DbError(format!(
                    "failed to resolve chain-swap recovery commitment: {error}"
                ))
            })?
            .ok_or_else(|| {
                AppError::ServiceUnavailable("Bitcoin recovery commitment is unavailable".into())
            })?;
    let recovery_runtime = state.recovery_manifest_runtime_v1().ok_or_else(|| {
        AppError::ServiceUnavailable("chain-swap recovery capability is unavailable".into())
    })?;

    let mut permit = ChainSwapCreationPermit::acquire(&state.db, recovery_runtime)
        .await
        .map_err(|error| {
            AppError::ServiceUnavailable(format!(
                "chain-swap creation boundary is unavailable: {error}"
            ))
        })?;

    let invoice_lock_key = db::invoice_lightning_lock_key(invoice.id);
    let invoice_lock_acquired: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
            .bind(&invoice_lock_key)
            .fetch_one(permit.connection_mut())
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
    if !invoice_lock_acquired {
        return Err(AppError::ServiceUnavailable(
            "invoice quote is changing; retry the Bitcoin offer request".into(),
        ));
    }

    let current = db::get_invoice_by_id(permit.connection_mut(), invoice.id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(invoice.id.to_string()))?;
    let quote = db::current_invoice_quote(permit.connection_mut(), invoice.id)
        .await?
        .ok_or_else(|| {
            AppError::ServiceUnavailable("invoice quote expired; refresh and retry".into())
        })?;
    if quote.id != requested_quote.id || !invoice_payment_rails_are_payable(&current) {
        return Err(AppError::ServiceUnavailable(
            "invoice quote changed; refresh and retry".into(),
        ));
    }
    match reusable_versioned_bitcoin_chain_offer(permit.connection_mut(), &current, &quote).await? {
        ReusableVersionedBitcoinOffer::Ready { offer_id, offer } => {
            permit.release().await.map_err(|error| {
                AppError::DbError(format!(
                    "chain-swap creation permit release failed: {error}"
                ))
            })?;
            return Ok((offer_id, offer));
        }
        ReusableVersionedBitcoinOffer::ExistingNotExposable => {
            return Err(AppError::ServiceUnavailable(
                "persisted Bitcoin quote offer is not currently payer-exposable".into(),
            ));
        }
        ReusableVersionedBitcoinOffer::Missing => {}
    }
    if quote.expires_at_unix <= unix_now().saturating_add(120) {
        return Err(AppError::ServiceUnavailable(
            "invoice quote is near expiry; refresh after the countdown".into(),
        ));
    }

    let request_key = quote_offer_request_key(quote.id, PayerQuoteRail::Bitcoin, "boltz_chain");
    let existing_provider_attempt = db::invoice_quote_provider_attempt(
        permit.connection_mut(),
        quote.id,
        "bitcoin",
        &request_key,
    )
    .await?;
    let merchant_amount_sat = u64::try_from(quote.merchant_amount_sat)
        .map_err(|_| AppError::InvalidAmount("invalid quoted amount".into()))?;
    let (
        provider_attempt,
        provider_create,
        claim_key_index,
        refund_key_index,
        claim_allocation_id,
        refund_allocation_id,
    ) = if let Some(attempt) = existing_provider_attempt {
        if attempt.completed {
            return Err(AppError::DbError(
                "completed Bitcoin provider attempt is missing its atomic offer".into(),
            ));
        }
        let claim_key_index = u64::try_from(attempt.claim_child_index)
            .map_err(|_| AppError::DbError("invalid persisted chain claim index".into()))?;
        let refund_key_index = u64::try_from(attempt.refund_child_index.ok_or_else(|| {
            AppError::DbError("persisted chain attempt lacks refund index".into())
        })?)
        .map_err(|_| AppError::DbError("invalid persisted chain refund index".into()))?;
        let claim_key = state.boltz.derive_swap_key(claim_key_index)?;
        let refund_key = state.boltz.derive_swap_key(refund_key_index)?;
        let provider_create = state.boltz.restore_prepared_btc_to_lbtc_chain_swap(
            claim_key,
            refund_key,
            &attempt.request_authority_json,
            &attempt.request_authority_sha256,
        )?;
        (
            attempt.clone(),
            provider_create,
            claim_key_index,
            refund_key_index,
            attempt.claim_key_allocation_id,
            attempt.refund_key_allocation_id.ok_or_else(|| {
                AppError::DbError("persisted chain attempt lacks refund allocation".into())
            })?,
        )
    } else {
        let claim_key_index = db::next_swap_key_index(permit.connection_mut())
            .await
            .map_err(|error| {
                AppError::BoltzError(format!("chain claim key allocation failed: {error}"))
            })?;
        let refund_key_index = db::next_swap_key_index(permit.connection_mut())
            .await
            .map_err(|error| {
                AppError::BoltzError(format!("chain refund key allocation failed: {error}"))
            })?;
        let claim_key = state.boltz.derive_swap_key(claim_key_index)?;
        let refund_key = state.boltz.derive_swap_key(refund_key_index)?;
        let claim_public_key_hex = claim_key.public_key_hex();
        let refund_public_key_hex = refund_key.public_key_hex();
        let preimage_hash_hex = claim_key.preimage_hash_hex();
        let claim_allocation_id = db::reserve_swap_key_allocation(
            permit.connection_mut(),
            &db::NewSwapKeyAllocation {
                root_fingerprint: state.swap_key_root_fingerprint.as_str(),
                key_epoch: state.config.boltz.key_epoch,
                derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
                child_index: claim_key_index as i64,
                purpose: db::SwapKeyPurpose::ChainClaim,
                public_key_hex: &claim_public_key_hex,
                preimage_hash_hex: Some(&preimage_hash_hex),
            },
        )
        .await
        .map_err(|error| {
            AppError::DbError(format!("chain claim key reservation failed: {error}"))
        })?;
        let refund_allocation_id = db::reserve_swap_key_allocation(
            permit.connection_mut(),
            &db::NewSwapKeyAllocation {
                root_fingerprint: state.swap_key_root_fingerprint.as_str(),
                key_epoch: state.config.boltz.key_epoch,
                derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
                child_index: refund_key_index as i64,
                purpose: db::SwapKeyPurpose::ChainRefund,
                public_key_hex: &refund_public_key_hex,
                preimage_hash_hex: None,
            },
        )
        .await
        .map_err(|error| {
            AppError::DbError(format!("chain refund key reservation failed: {error}"))
        })?;
        let provider_create = state
            .boltz
            .prepare_btc_to_lbtc_chain_swap(claim_key, refund_key, merchant_amount_sat)
            .await?;
        let (request_authority_json, request_authority_sha256) =
            provider_create.canonical_authority()?;
        let (attempt, _) = db::record_or_reuse_invoice_quote_provider_attempt(
            permit.connection_mut(),
            &db::NewInvoiceQuoteProviderAttempt {
                invoice_id: current.id,
                quote_version_id: quote.id,
                rail: "bitcoin",
                request_key: &request_key,
                operation: "chain_create",
                merchant_amount_sat: quote.merchant_amount_sat,
                request_authority_json: &request_authority_json,
                request_authority_sha256: &request_authority_sha256,
                claim_key_allocation_id: claim_allocation_id,
                refund_key_allocation_id: Some(refund_allocation_id),
            },
        )
        .await
        .map_err(|error| {
            AppError::DbError(format!("provider attempt reservation failed: {error}"))
        })?;
        (
            attempt,
            provider_create,
            claim_key_index,
            refund_key_index,
            claim_allocation_id,
            refund_allocation_id,
        )
    };

    pause_at_invoice_integration_test_hook(
        InvoiceIntegrationTestHookPoint::ProviderAttemptBeforeDispatch,
    )
    .await;
    let owns_dispatch = db::record_invoice_quote_provider_dispatch(
        permit.connection_mut(),
        provider_attempt.id,
        &provider_attempt.request_authority_sha256,
    )
    .await?;
    let provider_result = if owns_dispatch {
        match state
            .boltz
            .submit_btc_to_lbtc_chain_swap(provider_create)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                db::record_invoice_quote_provider_integrity_hold(
                    permit.connection_mut(),
                    provider_attempt.id,
                    "provider_outcome_unknown",
                )
                .await?;
                return Err(error);
            }
        }
    } else {
        let claim_child_index = u32::try_from(claim_key_index)
            .map_err(|_| AppError::DbError("chain claim index exceeds provider range".into()))?;
        let refund_child_index = u32::try_from(refund_key_index)
            .map_err(|_| AppError::DbError("chain refund index exceeds provider range".into()))?;
        let response = match state
            .boltz
            .recover_chain_create_response(claim_child_index, refund_child_index)
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => {
                db::record_invoice_quote_provider_integrity_hold(
                    permit.connection_mut(),
                    provider_attempt.id,
                    "restore_absent",
                )
                .await?;
                return Err(AppError::ServiceUnavailable(
                    "Bitcoin provider outcome remains under integrity hold".into(),
                ));
            }
            Err(_) => {
                db::record_invoice_quote_provider_integrity_hold(
                    permit.connection_mut(),
                    provider_attempt.id,
                    "restore_unavailable",
                )
                .await?;
                return Err(AppError::ServiceUnavailable(
                    "Bitcoin provider reconciliation is unavailable".into(),
                ));
            }
        };
        match state
            .boltz
            .complete_btc_to_lbtc_chain_swap(provider_create, response)
        {
            Ok(result) => result,
            Err(_) => {
                db::record_invoice_quote_provider_integrity_hold(
                    permit.connection_mut(),
                    provider_attempt.id,
                    "restored_response_invalid",
                )
                .await?;
                return Err(AppError::ServiceUnavailable(
                    "restored Bitcoin provider response failed validation".into(),
                ));
            }
        }
    };
    pause_at_invoice_integration_test_hook(
        InvoiceIntegrationTestHookPoint::ProviderResponseBeforeCommit,
    )
    .await;
    let lockup_bip21 = build_bitcoin_chain_bip21(
        &provider_result.lockup_address,
        provider_result.user_lock_amount_sat,
    );
    let payer_amount_sat = i64::try_from(provider_result.user_lock_amount_sat)
        .map_err(|_| AppError::BoltzError("Bitcoin payer amount exceeds storage range".into()))?;
    let provider_response_sha256 = provider_result
        .creation_terms
        .creation_response_sha256
        .clone();
    let merchant_policy = crate::swap_manifest::MerchantPolicyReferencesV1::new(
        current.id,
        nym,
        &merchant_liquid_destination,
        Some((
            recovery_commitment.commitment_id,
            recovery_commitment.canonical_btc_address(),
        )),
    );
    let prepared = crate::swap_manifest_persistence::prepare_created_chain_swap_persistence(
        crate::swap_manifest_persistence::CreatedChainSwapPersistenceInput {
            chain_swap: &provider_result,
            lockup_bip21: &lockup_bip21,
            lineage: crate::swap_manifest_persistence::CreatedChainSwapLineage {
                root_fingerprint: state.swap_key_root_fingerprint.as_str(),
                key_epoch: state.config.boltz.key_epoch,
                derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
                claim_allocation_id,
                refund_allocation_id,
                claim_child_index: claim_key_index as i64,
                refund_child_index: refund_key_index as i64,
            },
            merchant_policy: &merchant_policy,
            manifest_id: Uuid::new_v4(),
        },
    )
    .map_err(|_| AppError::DbError("invalid chain-swap persistence evidence".into()))?;
    let parts = prepared.coordinator_request_parts();
    let creation_evidence = db::NewChainSwapCreationEvidence {
        creation_terms: parts.creation_terms,
        recovery_address_commitment_id: merchant_policy.emergency_bitcoin_commitment_id,
    };
    let mut tx = permit.connection_mut().begin().await?;
    let (canonical, offer) = db::record_chain_swap_with_quote_offer_in_tx(
        &mut tx,
        &parts.swap,
        &parts.lineage,
        &creation_evidence,
        &db::NewInvoiceQuoteOffer {
            invoice_id: current.id,
            quote_version_id: quote.id,
            rail: "bitcoin",
            offer_kind: "boltz_chain",
            request_key: &request_key,
            provider: Some("boltz"),
            provider_offer_id: Some(&provider_result.swap_id),
            provider_attempt_id: Some(provider_attempt.id),
            payer_amount_sat,
            expires_at_unix: quote.expires_at_unix,
        },
    )
    .await
    .map_err(|error| {
        AppError::DbError(format!(
            "failed to persist versioned Bitcoin offer {}: {error}",
            provider_result.swap_id
        ))
    })?;
    db::record_invoice_quote_provider_completion(
        &mut *tx,
        provider_attempt.id,
        offer.id,
        &provider_result.swap_id,
        &provider_response_sha256,
    )
    .await?;
    tx.commit().await?;
    pause_at_invoice_integration_test_hook(
        InvoiceIntegrationTestHookPoint::ProviderOfferAfterCommit,
    )
    .await;

    match crate::swap_manifest_persistence::repair_oldest_manifestless_chain_swap(
        &state.db,
        recovery_runtime,
    )
    .await
    .map_err(|_| {
        AppError::ServiceUnavailable(
            "Bitcoin offer recovery manifest could not be delivered".into(),
        )
    })? {
        crate::swap_manifest_persistence::ManifestlessChainSwapRepairOutcome::Repaired {
            identity,
        } if identity.chain_swap_id == canonical.id => {}
        _ => {
            return Err(AppError::DbError(
                "Bitcoin offer recovery manifest repaired an unexpected obligation".into(),
            ));
        }
    }

    let still_current = db::current_invoice_quote(permit.connection_mut(), current.id).await?;
    if still_current.as_ref().map(|candidate| candidate.id) != Some(quote.id)
        || quote.expires_at_unix <= unix_now()
    {
        return Err(AppError::ServiceUnavailable(
            "invoice quote expired while creating the Bitcoin offer; refresh and retry".into(),
        ));
    }
    let exposed = db::payer_exposable_chain_swap_for_quote_offer(
        permit.connection_mut(),
        current.id,
        quote.id,
        offer.id,
        &provider_result.swap_id,
    )
    .await?
    .ok_or_else(|| {
        AppError::ServiceUnavailable("Bitcoin offer is not yet payer-exposable".into())
    })?;
    let payer_amount_sat = validated_payer_chain_amount_sat(
        exposed.user_lock_amount_sat,
        exposed.server_lock_amount_sat,
    )
    .ok_or_else(|| AppError::DbError("Bitcoin offer amount evidence is invalid".into()))?;
    permit.release().await.map_err(|error| {
        AppError::DbError(format!(
            "chain-swap creation permit release failed: {error}"
        ))
    })?;
    Ok((
        offer.id,
        BitcoinChainOffer {
            lockup_bip21: public_bitcoin_chain_bip21(&exposed.lockup_address, payer_amount_sat),
            lockup_address: exposed.lockup_address,
            payer_amount_sat,
        },
    ))
}

enum ReusableVersionedBitcoinOffer {
    Missing,
    ExistingNotExposable,
    Ready {
        offer_id: Uuid,
        offer: BitcoinChainOffer,
    },
}

async fn reusable_versioned_bitcoin_chain_offer(
    executor: &mut sqlx::PgConnection,
    invoice: &db::Invoice,
    quote: &db::InvoiceQuoteVersion,
) -> Result<ReusableVersionedBitcoinOffer, AppError> {
    // The offer row is the durable idempotency authority. If it exists but its
    // recovery manifest is not yet delivered, withhold the address and let the
    // next permit acquisition repair it instead of creating another provider
    // obligation.
    let Some(offer) =
        db::invoice_quote_offer_for_rail(&mut *executor, invoice.id, quote.id, "bitcoin").await?
    else {
        return Ok(ReusableVersionedBitcoinOffer::Missing);
    };
    if offer.offer_kind != "boltz_chain"
        || offer.provider.as_deref() != Some("boltz")
        || offer.provider_attempt_id.is_none()
    {
        return Err(AppError::DbError(
            "persisted Bitcoin quote offer has invalid authority".into(),
        ));
    }
    let exposed = db::payer_exposable_chain_swap_for_quote_offer(
        &mut *executor,
        invoice.id,
        quote.id,
        offer.id,
        offer.provider_offer_id.as_deref().ok_or_else(|| {
            AppError::DbError("persisted Bitcoin offer is missing provider identity".into())
        })?,
    )
    .await?;
    let Some(exposed) = exposed else {
        return Ok(ReusableVersionedBitcoinOffer::ExistingNotExposable);
    };
    let payer_amount_sat = validated_payer_chain_amount_sat(
        exposed.user_lock_amount_sat,
        exposed.server_lock_amount_sat,
    )
    .ok_or_else(|| AppError::DbError("Bitcoin offer amount evidence is invalid".into()))?;
    if exposed.server_lock_amount_sat != quote.merchant_amount_sat
        || payer_amount_sat != offer.payer_amount_sat
    {
        return Err(AppError::DbError(
            "persisted Bitcoin quote offer amount does not match its version".into(),
        ));
    }
    Ok(ReusableVersionedBitcoinOffer::Ready {
        offer_id: offer.id,
        offer: BitcoinChainOffer {
            lockup_bip21: public_bitcoin_chain_bip21(&exposed.lockup_address, payer_amount_sat),
            lockup_address: exposed.lockup_address,
            payer_amount_sat,
        },
    })
}

/// Read-only counterpart to `ensure_reusable_lightning_offer`.
///
/// Status polling must not create Boltz swaps. It may return the latest
/// still-payable BOLT11, but if the latest offer is expired, the wrong
/// amount, or absent, callers must explicitly hit
/// `POST /api/v1/invoices/:id/lightning` to create/refresh the offer.
async fn latest_reusable_lightning_offer<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    inv: &db::Invoice,
    amount_sat: i64,
) -> Result<Option<LightningOffer>, AppError> {
    if !invoice_payment_rails_are_payable(inv) || !inv.accept_ln {
        return Ok(None);
    }

    if amount_sat <= 0 || inv.expires_at_unix <= unix_now() {
        return Ok(None);
    }

    let Some((pr, pr_amount_sat)) = db::latest_lightning_pr_for_invoice(executor, inv.id).await?
    else {
        return Ok(None);
    };
    if pr_amount_sat == amount_sat && bolt11_is_reusable_at(&pr, unix_now()) {
        Ok(fixed_checkout_lightning_offer(pr, amount_sat))
    } else {
        Ok(None)
    }
}

fn remaining_amount_from_received(inv: &db::Invoice, received_sat: i64) -> i64 {
    inv.amount_sat.saturating_sub(received_sat).max(0)
}

fn payment_tolerance_sat(inv: &db::Invoice, tolerances: db::InvoiceAccountingTolerances) -> i64 {
    db::invoice_payment_tolerance_sat(
        inv.amount_sat,
        inv.accept_btc,
        inv.accept_liquid,
        inv.accept_ln,
        tolerances,
    )
}

const BOLT11_REFRESH_MARGIN_SECS: u64 = 120;
const BOLTZ_INVOICE_DESCRIPTION: &str = "Bullnym payment";

fn bolt11_uses_generic_description(pr: &str) -> bool {
    Bolt11Invoice::from_str(pr)
        .is_ok_and(|invoice| invoice.description().to_string() == BOLTZ_INVOICE_DESCRIPTION)
}

fn bolt11_is_fresh_at(pr: &str, now_unix: i64) -> bool {
    let Ok(now) = u64::try_from(now_unix) else {
        return false;
    };
    let Ok(invoice) = Bolt11Invoice::from_str(pr) else {
        return false;
    };
    let now_with_margin = now.saturating_add(BOLT11_REFRESH_MARGIN_SECS);
    !invoice.would_expire(Duration::from_secs(now_with_margin))
}

fn bolt11_is_reusable_at(pr: &str, now_unix: i64) -> bool {
    bolt11_uses_generic_description(pr) && bolt11_is_fresh_at(pr, now_unix)
}

fn lightning_swap_nym(invoice: &db::Invoice) -> Option<&str> {
    invoice.nym_owner.as_deref()
}

fn build_bitcoin_chain_bip21(address: &str, amount_sat: u64) -> String {
    let whole_btc = amount_sat / 100_000_000;
    let fractional_sat = amount_sat % 100_000_000;
    format!(
        "bitcoin:{address}?amount={whole_btc}.{fractional_sat:08}&label=Send%20to%20L-BTC%20address"
    )
}

fn public_bitcoin_chain_bip21(address: &str, payer_amount_sat: i64) -> Option<String> {
    let amount_sat = u64::try_from(payer_amount_sat).ok()?;
    Some(build_bitcoin_chain_bip21(address, amount_sat))
}

fn build_direct_bitcoin_bip21(address: &str, amount_sat: u64) -> String {
    let whole_btc = amount_sat / 100_000_000;
    let fractional_sat = amount_sat % 100_000_000;
    format!("bitcoin:{address}?amount={whole_btc}.{fractional_sat:08}")
}

struct PreparedLightningOffer {
    swap_id: String,
    lightning_pr: String,
    payer_amount_sat: i64,
    preimage_hex: String,
    claim_key_hex: String,
    boltz_response_json: String,
    provider_response_sha256: String,
    mrh_address: Option<String>,
}

impl PreparedLightningOffer {
    fn public_offer(&self) -> LightningOffer {
        LightningOffer {
            pr: self.lightning_pr.clone(),
            payer_amount_sat: self.payer_amount_sat,
        }
    }

    fn as_new_swap_record<'a>(
        &'a self,
        swap_nym: Option<&'a str>,
        amount_sat: u64,
        invoice_id: Uuid,
        swap_key_index: u64,
        root_fingerprint: &'a str,
    ) -> db::NewSwapRecord<'a> {
        db::NewSwapRecord {
            nym: swap_nym,
            boltz_swap_id: &self.swap_id,
            // Payment Page swaps persist their already-allocated claim
            // destination because the same address is also the MRH direct
            // payment authority. Other surfaces continue resolving it from
            // the invoice at claim time.
            address: self.mrh_address.as_deref(),
            address_index: None,
            amount_sat,
            invoice: &self.lightning_pr,
            preimage_hex: &self.preimage_hex,
            claim_key_hex: &self.claim_key_hex,
            boltz_response_json: &self.boltz_response_json,
            invoice_id: Some(invoice_id),
            key_index: Some(swap_key_index as i64),
            root_fingerprint: Some(root_fingerprint),
        }
    }
}

async fn request_lightning_offer(
    state: &AppState,
    derived_key: crate::boltz::DerivedSwapKey,
    amount_sat: u64,
    mrh_address: Option<&str>,
) -> Result<PreparedLightningOffer, AppError> {
    let prepared = prepare_lightning_provider_create(state, derived_key, amount_sat, mrh_address)?;
    let result = state
        .boltz
        .submit_fixed_checkout_reverse_swap(prepared)
        .await?;
    prepared_lightning_offer_from_result(result)
}

fn prepare_lightning_provider_create(
    state: &AppState,
    derived_key: crate::boltz::DerivedSwapKey,
    amount_sat: u64,
    mrh_address: Option<&str>,
) -> Result<crate::boltz::PreparedFixedCheckoutReverseCreate, AppError> {
    state.boltz.prepare_fixed_checkout_reverse_swap(
        derived_key,
        amount_sat,
        Some(BOLTZ_INVOICE_DESCRIPTION),
        None,
        mrh_address,
    )
}

fn payment_page_mrh_address(invoice: &db::Invoice) -> Option<&str> {
    (invoice.origin == "checkout"
        && invoice.accept_liquid
        && invoice.checkout_surface_kind.as_deref() == Some(db::KIND_PAYMENT_PAGE))
    .then_some(invoice.liquid_address.as_deref())
    .flatten()
}

fn prepared_lightning_offer_from_result(
    result: crate::boltz::FixedCheckoutReverseSwapResult,
) -> Result<PreparedLightningOffer, AppError> {
    let payer_amount_sat = i64::try_from(result.payer_amount_sat)
        .map_err(|_| AppError::BoltzError("fixed checkout payer amount exceeds i64".into()))?;
    let swap = result.swap;
    let (boltz_response_json, provider_response_sha256) =
        crate::canonical_json::canonical_json_and_sha256(&swap.boltz_response).map_err(
            |error| AppError::BoltzError(format!("failed to canonicalize boltz response: {error}")),
        )?;
    Ok(PreparedLightningOffer {
        swap_id: swap.swap_id,
        lightning_pr: swap.invoice,
        payer_amount_sat,
        preimage_hex: hex::encode(&swap.preimage),
        claim_key_hex: hex::encode(swap.claim_keypair.secret_bytes()),
        boltz_response_json,
        provider_response_sha256,
        mrh_address: result.mrh_address,
    })
}

/// Internal: create a Boltz reverse swap and record it as the Lightning
/// offer for `invoice`. The `invoice_id` association is what lets the
/// claimer's invoice-flip hook pair the Boltz settlement back to this
/// invoice on payment.
async fn create_lightning_offer(
    state: &AppState,
    swap_nym: Option<&str>,
    amount_sat: u64,
    invoice: &db::Invoice,
) -> Result<LightningOffer, AppError> {
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
    let prepared = request_lightning_offer(
        state,
        derived_key,
        amount_sat,
        payment_page_mrh_address(invoice),
    )
    .await?;

    db::record_swap_with_lineage(
        &state.db,
        &prepared.as_new_swap_record(
            swap_nym,
            amount_sat,
            invoice.id,
            swap_key_index,
            state.swap_key_root_fingerprint.as_str(),
        ),
        &db::ReverseSwapLineage {
            allocation_id: key_allocation_id,
            key_epoch: state.config.boltz.key_epoch,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: &preimage_hash_hex,
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("failed to record swap {}: {e}", prepared.swap_id)))?;

    if let Some(nym) = swap_nym {
        db::touch_user_callback(&state.db, nym).await;
    }
    if !bolt11_uses_generic_description(&prepared.lightning_pr) {
        return Err(AppError::ServiceUnavailable(
            "Lightning offer uses retired private metadata; refresh and retry".into(),
        ));
    }
    Ok(prepared.public_offer())
}

struct BitcoinChainOffer {
    lockup_address: String,
    lockup_bip21: Option<String>,
    payer_amount_sat: i64,
}

/// Borrowed, all-or-none public projection of one persisted payer offer.
///
/// Gross-up is valid only when the exact payer lock amount is positive and at
/// least the merchant/server lock amount. If historical/corrupt data violates
/// that relationship, withhold the entire chain instruction instead of
/// exposing an address with no trustworthy amount.
#[derive(Clone, Copy)]
struct PayerExposableBitcoinChainOffer<'a> {
    lockup_address: &'a str,
    payer_amount_sat: i64,
}

fn payer_exposable_bitcoin_chain_offer(
    swap: &db::ChainSwapRecord,
) -> Option<PayerExposableBitcoinChainOffer<'_>> {
    if swap.lockup_address.is_empty() {
        return None;
    }
    Some(PayerExposableBitcoinChainOffer {
        lockup_address: &swap.lockup_address,
        payer_amount_sat: validated_payer_chain_amount_sat(
            swap.user_lock_amount_sat,
            swap.server_lock_amount_sat,
        )?,
    })
}

fn validated_payer_chain_amount_sat(
    user_lock_amount_sat: i64,
    server_lock_amount_sat: i64,
) -> Option<i64> {
    (server_lock_amount_sat > 0 && user_lock_amount_sat >= server_lock_amount_sat)
        .then_some(user_lock_amount_sat)
}

fn retain_persisted_offer_after_permit_release(
    offer: BitcoinChainOffer,
    release: Result<(), ChainSwapCreationPermitError>,
) -> BitcoinChainOffer {
    if let Err(error) = release {
        tracing::error!(
            event = "chain_swap_creation_permit_release_failed_after_persistence",
            error = %error,
            "chain-swap creation permit release failed after durable local persistence; returning the persisted payer offer"
        );
    }
    offer
}

/// Internal: create a Boltz BTC-to-LBTC chain swap for a Donation Page
/// checkout invoice. The payer sees a Bitcoin lockup address; after
/// Boltz locks LBTC on the server side, the chain-swap claimer spends
/// that LBTC to `invoice.liquid_address`.
async fn create_bitcoin_chain_offer(
    state: &AppState,
    swap_nym: Option<&str>,
    amount_sat: u64,
    invoice: &db::Invoice,
) -> Result<Option<BitcoinChainOffer>, AppError> {
    let faults = crate::swap_manifest_persistence::NoChainSwapPersistenceFaults;
    create_bitcoin_chain_offer_with_faults(state, swap_nym, amount_sat, invoice, &faults).await
}

async fn create_bitcoin_chain_offer_with_faults(
    state: &AppState,
    swap_nym: Option<&str>,
    amount_sat: u64,
    invoice: &db::Invoice,
    persistence_faults: &dyn crate::swap_manifest_persistence::ChainSwapPersistenceFaultInjector,
) -> Result<Option<BitcoinChainOffer>, AppError> {
    let Some(liquid_address) = invoice.liquid_address.as_deref() else {
        return Ok(None);
    };
    let merchant_liquid_destination = validators::canonical_liquid_mainnet_address(liquid_address)
        .map_err(|error| {
            AppError::BoltzError(format!(
                "chain swap invoice has an invalid Liquid destination: {error}"
            ))
        })?;

    // Recovery invariant (SF1, #44): a chain swap MUST belong to a nym-owned
    // invoice so its immutable merchant recovery policy, automatic executor,
    // and signed read-only status all share one stable owner. Today all chain
    // offers are created from nym-owned checkout, so this guards future callers
    // from silently minting swaps without an attributable recovery policy.
    let (Some(swap_nym), Some(nym_owner)) = (swap_nym, invoice.nym_owner.as_deref()) else {
        tracing::error!(
            event = "chain_swap_offer_without_nym_refused",
            invoice_id = %invoice.id,
            has_swap_nym = swap_nym.is_some(),
            has_nym_owner = invoice.nym_owner.is_some(),
            "refusing to create a chain-swap offer without an owning nym — automatic recovery would have no attributable merchant policy (operator P1)"
        );
        return Ok(None);
    };
    if swap_nym != nym_owner {
        tracing::error!(
            event = "chain_swap_offer_nym_owner_mismatch_refused",
            invoice_id = %invoice.id,
            "refusing to create a chain-swap offer with mismatched swap and invoice ownership"
        );
        return Ok(None);
    }

    // A completed post-provider retry must rediscover the exact durable payer
    // instruction before any admission, identity-rotation, key-allocation, or
    // provider boundary. The public invoice renderer uses this same predicate.
    // This is what turns a process loss after provider creation into one remote
    // swap rather than a second mutating request.
    let amount_i64 = i64::try_from(amount_sat)
        .map_err(|_| AppError::BoltzError("chain swap amount exceeds storage range".into()))?;
    if let Some(existing) =
        db::latest_payer_exposable_chain_swap_for_invoice(&state.db, invoice.id, amount_i64).await?
    {
        let payer_amount_sat = validated_payer_chain_amount_sat(
            existing.user_lock_amount_sat,
            existing.server_lock_amount_sat,
        )
        .ok_or_else(|| {
            AppError::DbError(
                "payer-exposable chain swap has an invalid persisted amount pair".into(),
            )
        })?;
        return Ok(Some(BitcoinChainOffer {
            lockup_bip21: public_bitcoin_chain_bip21(&existing.lockup_address, payer_amount_sat),
            lockup_address: existing.lockup_address,
            payer_amount_sat,
        }));
    }

    state
        .admission
        .enforce(Rail::BitcoinChain)
        .map_err(|_| AppError::MoneyAdmissionUnavailable)?;

    // Page/POS availability and its permanent recovery policy are independent
    // of Lightning Address availability. Taking the LA product offline closes
    // new public LNURL instructions, but must not strip Bitcoin from an
    // otherwise-live merchant checkout.
    let Some(owner) = db::get_user_by_nym(&state.db, nym_owner).await? else {
        tracing::warn!(
            event = "chain_swap_offer_recovery_owner_unavailable_refused",
            invoice_id = %invoice.id,
            "refusing to create a chain-swap offer because its permanent merchant owner is unavailable"
        );
        return Ok(None);
    };
    if owner.npub != invoice.npub_owner {
        tracing::error!(
            event = "chain_swap_offer_recipient_identity_mismatch_refused",
            invoice_id = %invoice.id,
            "refusing to create a chain-swap offer whose permanent nym owner and invoice recipient identities differ"
        );
        return Ok(None);
    }
    let Some(recovery_commitment) =
        db::select_current_recovery_address_commitment(&state.db, &owner.npub)
            .await
            .map_err(|error| {
                AppError::DbError(format!(
                    "failed to resolve chain-swap recovery commitment: {error}"
                ))
            })?
    else {
        tracing::warn!(
            event = "chain_swap_offer_missing_recovery_commitment_refused",
            invoice_id = %invoice.id,
            "refusing to create a chain-swap offer without a current merchant recovery commitment"
        );
        return Ok(None);
    };
    // Keep the selected immutable record in scope so the durable swap insert
    // atomically binds its `commitment_id` and exact address without a second,
    // rotation-sensitive lookup.
    pause_at_invoice_integration_test_hook(
        InvoiceIntegrationTestHookPoint::ChainOfferBeforeRecoveryGate,
    )
    .await;
    let Some(recovery_runtime) = state.recovery_manifest_runtime_v1() else {
        tracing::warn!(
            event = "chain_swap_creation_recovery_runtime_unavailable",
            "chain-swap creation refused before key allocation because protected recovery runtime is unavailable"
        );
        return Err(AppError::ServiceUnavailable(
            "chain-swap recovery capability is unavailable".into(),
        ));
    };
    let creation_permit = ChainSwapCreationPermit::acquire(&state.db, recovery_runtime)
        .await
        .map_err(|error| {
            tracing::warn!(
                event = "chain_swap_creation_permit_refused",
                error = %error,
                "chain-swap creation refused before key allocation"
            );
            AppError::ServiceUnavailable("chain-swap creation boundary is unavailable".into())
        })?;

    let claim_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("chain claim key allocation failed: {e}")))?;
    let refund_key_index = db::next_swap_key_index(&state.db)
        .await
        .map_err(|e| AppError::BoltzError(format!("chain refund key allocation failed: {e}")))?;

    let claim_key = state.boltz.derive_swap_key(claim_key_index)?;
    let refund_key = state.boltz.derive_swap_key(refund_key_index)?;
    let claim_public_key_hex = claim_key.public_key_hex();
    let refund_public_key_hex = refund_key.public_key_hex();
    let preimage_hash_hex = claim_key.preimage_hash_hex();
    let claim_key_allocation_id = db::reserve_swap_key_allocation(
        &state.db,
        &db::NewSwapKeyAllocation {
            root_fingerprint: state.swap_key_root_fingerprint.as_str(),
            key_epoch: state.config.boltz.key_epoch,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            child_index: claim_key_index as i64,
            purpose: db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &claim_public_key_hex,
            preimage_hash_hex: Some(&preimage_hash_hex),
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("chain claim key reservation failed: {e}")))?;
    let refund_key_allocation_id = db::reserve_swap_key_allocation(
        &state.db,
        &db::NewSwapKeyAllocation {
            root_fingerprint: state.swap_key_root_fingerprint.as_str(),
            key_epoch: state.config.boltz.key_epoch,
            derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
            child_index: refund_key_index as i64,
            purpose: db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &refund_public_key_hex,
            preimage_hash_hex: None,
        },
    )
    .await
    .map_err(|e| AppError::DbError(format!("chain refund key reservation failed: {e}")))?;

    // Allocate retry identity before the mutating provider call. The exact ID
    // follows this provider result through canonical persistence and durable
    // delivery; it is never regenerated after Boltz has accepted the swap.
    let manifest_id = Uuid::new_v4();
    let merchant_policy = crate::swap_manifest::MerchantPolicyReferencesV1::new(
        invoice.id,
        swap_nym,
        &merchant_liquid_destination,
        Some((
            recovery_commitment.commitment_id,
            recovery_commitment.canonical_btc_address(),
        )),
    );
    let result = state
        .boltz
        .create_btc_to_lbtc_chain_swap(claim_key, refund_key, amount_sat)
        .await?;
    // Never forward the provider's BIP21. Its address and amount are merely
    // response fields until the complete response passes local validation;
    // this URI is constructed from those validated values under our own fixed
    // parameter policy.
    let lockup_bip21 =
        build_bitcoin_chain_bip21(&result.lockup_address, result.user_lock_amount_sat);
    let payer_amount_sat = i64::try_from(result.user_lock_amount_sat).map_err(|_| {
        AppError::BoltzError(
            "validated chain-swap payer amount is outside the response range".into(),
        )
    })?;

    crate::swap_manifest_persistence::persist_created_chain_swap_with_faults(
        &state.db,
        recovery_runtime,
        crate::swap_manifest_persistence::CreatedChainSwapPersistenceInput {
            chain_swap: &result,
            lockup_bip21: &lockup_bip21,
            lineage: crate::swap_manifest_persistence::CreatedChainSwapLineage {
                root_fingerprint: state.swap_key_root_fingerprint.as_str(),
                key_epoch: state.config.boltz.key_epoch,
                derivation_scheme_version: db::DERIVATION_SCHEME_VERSION,
                claim_allocation_id: claim_key_allocation_id,
                refund_allocation_id: refund_key_allocation_id,
                claim_child_index: claim_key_index as i64,
                refund_child_index: refund_key_index as i64,
            },
            merchant_policy: &merchant_policy,
            manifest_id,
        },
        persistence_faults,
    )
    .await
    .map_err(|error| AppError::DbError(error.to_string()))?;

    let offer = BitcoinChainOffer {
        lockup_address: result.lockup_address,
        lockup_bip21: Some(lockup_bip21),
        payer_amount_sat,
    };
    let release = creation_permit.release().await;
    Ok(Some(retain_persisted_offer_after_permit_release(
        offer, release,
    )))
}

/// Focused integration seam for the chain-offer creation boundary.
///
/// It executes the exact production path while avoiding checkout's separate
/// eager Lightning attempt, so integration tests can attribute key and
/// provider mutations solely to chain-offer creation.
#[doc(hidden)]
pub async fn exercise_bitcoin_chain_offer_creation(
    state: &AppState,
    swap_nym: Option<&str>,
    amount_sat: u64,
    invoice: &db::Invoice,
) -> Result<Option<(String, Option<String>)>, AppError> {
    Ok(
        create_bitcoin_chain_offer(state, swap_nym, amount_sat, invoice)
            .await?
            .map(|offer| (offer.lockup_address, offer.lockup_bip21)),
    )
}

/// Focused integration seam for deterministic process-loss checkpoints inside
/// the exact production creation and recovery-manifest path.
#[doc(hidden)]
pub async fn exercise_bitcoin_chain_offer_creation_with_faults(
    state: &AppState,
    swap_nym: Option<&str>,
    amount_sat: u64,
    invoice: &db::Invoice,
    persistence_faults: &dyn crate::swap_manifest_persistence::ChainSwapPersistenceFaultInjector,
) -> Result<Option<(String, Option<String>)>, AppError> {
    Ok(create_bitcoin_chain_offer_with_faults(
        state,
        swap_nym,
        amount_sat,
        invoice,
        persistence_faults,
    )
    .await?
    .map(|offer| (offer.lockup_address, offer.lockup_bip21)))
}

// =====================================================================
// Schnorr-signed (recipient-side, wallet) endpoints — v2 wire format
//
// `bullpay-la-v2` byte sequence:
//   <domain>\0<action>\0<npub_hex>\0<nym_or_empty>\0(<field>\0)*<timestamp>
//
// Linked path (`POST /api/v1/<nym>/invoices`): nym_or_empty = path nym.
// Unlinked path (`POST /api/v1/invoices`): nym_or_empty = "".
//
// Both paths share `create_invoice_inner` after sig verify + ownership
// check. The `nym` is the only structural divergence; everything else —
// payload validation, address validation, fiat resolution, Lightning eager
// offer — is identical.
// =====================================================================

/// Verify the signing npub permanently owns `nym`. Linked invoice management
/// remains available while the separate Lightning Address product is offline.
async fn assert_nym_owner(state: &AppState, nym: &str, npub: &str) -> Result<db::User, AppError> {
    let user = db::get_user_by_npub_any(&state.db, npub)
        .await?
        .ok_or_else(|| AppError::AuthError("no permanent registration for this key".into()))?;
    if user.nym != nym {
        return Err(AppError::AuthError("signer does not own this nym".into()));
    }
    Ok(user)
}

// --- Field-order helpers (v2 Schnorr signing) ---
//
// Optional fields that are absent become EMPTY STRINGS (not skipped) so
// the byte sequence is invariant under field presence. The mobile's
// `core/nostr/bullpay_la_v2_signing.dart` must produce the same byte
// sequence — these arrays are the wire contract.
//
// IMPORTANT: nym is NOT part of these payload helpers. It is passed
// separately as `nym_or_empty` to `auth::verify_la_v2` / `build_la_v2_message`.

/// 12 fields in fixed order. The byte sequence is the wire contract.
#[allow(clippy::too_many_arguments)]
fn create_payload_fields<'a>(
    amount_sat_or_empty: &'a str,
    fiat_amount_minor_or_empty: &'a str,
    fiat_currency_or_empty: &'a str,
    client_request_id: &'a str,
    presentation_envelope: &'a str,
    accept_btc_bool: &'a str,
    accept_ln_bool: &'a str,
    accept_liquid_bool: &'a str,
    bitcoin_address_or_empty: &'a str,
    liquid_address_or_empty: &'a str,
    liquid_blinding_key_hex_or_empty: &'a str,
    expires_at_unix: &'a str,
) -> [&'a str; 12] {
    [
        amount_sat_or_empty,
        fiat_amount_minor_or_empty,
        fiat_currency_or_empty,
        client_request_id,
        presentation_envelope,
        accept_btc_bool,
        accept_ln_bool,
        accept_liquid_bool,
        bitcoin_address_or_empty,
        liquid_address_or_empty,
        liquid_blinding_key_hex_or_empty,
        expires_at_unix,
    ]
}

fn private_invoice_create_digest(npub: &str, nym_or_empty: &str, fields: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_INVOICE_CREATE_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(npub.as_bytes());
    hasher.update([0]);
    hasher.update(nym_or_empty.as_bytes());
    hasher.update([0]);
    for field in fields {
        hasher.update(field.as_bytes());
        hasher.update([0]);
    }
    hasher.finalize().into()
}

fn decode_private_invoice_presentation(value: &str) -> Result<Vec<u8>, AppError> {
    if value.len() != PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BASE64_LEN {
        return Err(AppError::InvalidAmount(format!(
            "presentation_envelope must be exactly {PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BASE64_LEN} base64url characters"
        )));
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        AppError::InvalidAmount(
            "presentation_envelope must use canonical unpadded base64url".into(),
        )
    })?;
    if decoded.len() != PRIVATE_INVOICE_PRESENTATION_ENVELOPE_BYTES
        || decoded.first().copied() != Some(PRIVATE_INVOICE_PRESENTATION_VERSION)
        || URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(AppError::InvalidAmount(
            "presentation_envelope is not a canonical private-invoice-v1 envelope".into(),
        ));
    }
    Ok(decoded)
}

fn cancel_payload_fields(invoice_id: &str) -> [&str; 1] {
    [invoice_id]
}

fn list_payload_fields<'a>(
    page: &'a str,
    page_size: &'a str,
    status_filter_or_empty: &'a str,
) -> [&'a str; 3] {
    [page, page_size, status_filter_or_empty]
}

/// Signed-payload fields for `ACTION_RECOVERY_LIST` (the recoverable-swaps
/// detection endpoint). ZERO fields: the action carries no request parameters
/// that affect authorization or output shape — scope comes entirely from the
/// `npub` already embedded in the LA-v2 message, and the response is the full
/// (tiny, uncapped-by-client) recovery set for that identity. If parameters are
/// ever added (pagination, filters) they MUST be appended here AND in the
/// mobile signer in lockstep, or every signature will fail to verify.
fn recovery_list_payload_fields() -> [&'static str; 0] {
    []
}

// =====================================================================
// POST /api/v1/<nym>/invoices  (linked)
// POST /api/v1/invoices        (unlinked)
// =====================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSignedRequest {
    pub npub: String,
    pub amount_sat: Option<i64>,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub client_request_id: Uuid,
    pub presentation_envelope: String,
    #[serde(default)]
    pub accept_btc: bool,
    #[serde(default)]
    pub accept_ln: bool,
    #[serde(default)]
    pub accept_liquid: bool,
    pub bitcoin_address: Option<String>,
    pub liquid_address: Option<String>,
    pub liquid_blinding_key_hex: Option<String>,
    pub expires_at_unix: Option<i64>,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct CreateSignedResponse {
    pub invoice_id: Uuid,
    /// Fragmentless base URL. Mobile appends its locally held viewing key and
    /// exposes only that complete private link through Copy/Share/QR.
    pub invoice_url: String,
}

fn private_invoice_base_url(state: &AppState, linked_nym: Option<&str>, id: Uuid) -> String {
    match linked_nym {
        Some(nym) => format!("https://{}/{}/i/{}", state.config.domain, nym, id),
        None => format!("https://{}/invoice/{}", state.config.domain, id),
    }
}

fn create_signed_response(
    state: &AppState,
    linked_nym: Option<&str>,
    resolution: db::WalletInvoiceCreateResolution,
) -> Result<Json<CreateSignedResponse>, AppError> {
    let invoice = match resolution {
        db::WalletInvoiceCreateResolution::Created(invoice) => invoice,
        db::WalletInvoiceCreateResolution::Reused(invoice) => {
            tracing::info!(
                event = "invoice_create_reused",
                invoice_id = %invoice.id,
                "returning existing wallet-origin invoice for idempotent create retry"
            );
            invoice
        }
        db::WalletInvoiceCreateResolution::Conflict => return Err(AppError::InvoiceCreateConflict),
    };
    Ok(Json(CreateSignedResponse {
        invoice_id: invoice.id,
        invoice_url: private_invoice_base_url(state, linked_nym, invoice.id),
    }))
}

pub async fn create_signed_linked(
    State(state): State<AppState>,
    Path(nym): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateSignedRequest>,
) -> Result<Json<CreateSignedResponse>, AppError> {
    create_invoice_inner(&state, Some(nym), peer_opt, headers, req).await
}

pub async fn create_signed_unlinked(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CreateSignedRequest>,
) -> Result<Json<CreateSignedResponse>, AppError> {
    create_invoice_inner(&state, None, peer_opt, headers, req).await
}

async fn create_invoice_inner(
    state: &AppState,
    linked_nym: Option<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    req: CreateSignedRequest,
) -> Result<Json<CreateSignedResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        state,
        CertificationScope::InvoiceCreate,
        peer,
        &headers,
        "signed_invoice_create",
        Some(&req.npub),
    );

    // Pre-verify per-IP cheap gate. The per-npub gate runs AFTER signature
    // verify so a forged npub cannot grief a legitimate user's bucket.
    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state.rate_limiter.check_api_per_ip(ip).await?;
        }
    }

    // ---- Cheap input validation (BEFORE Schnorr verify) ----
    // The server validates only the opaque envelope framing. It never parses,
    // validates, indexes, or logs the private presentation plaintext.
    if req.client_request_id.get_version_num() != 4 {
        return Err(AppError::InvalidAmount(
            "client_request_id must be a random UUID v4".into(),
        ));
    }
    let presentation_envelope = decode_private_invoice_presentation(&req.presentation_envelope)?;

    // ---- Build v2 payload + verify Schnorr sig ----
    let amount_sat_str = req.amount_sat.map(|n| n.to_string()).unwrap_or_default();
    let fiat_minor_str = req
        .fiat_amount_minor
        .map(|n| n.to_string())
        .unwrap_or_default();
    let fiat_currency_str = req.fiat_currency.clone().unwrap_or_default();
    let client_request_id_str = req.client_request_id.to_string();
    let accept_btc_str = req.accept_btc.to_string();
    let accept_ln_str = req.accept_ln.to_string();
    let accept_liquid_str = req.accept_liquid.to_string();
    let bitcoin_address_str = req.bitcoin_address.clone().unwrap_or_default();
    let liquid_address_str = req.liquid_address.clone().unwrap_or_default();
    let liquid_blinding_key_str = req.liquid_blinding_key_hex.clone().unwrap_or_default();
    let expires_str = req
        .expires_at_unix
        .map(|expires_at_unix| expires_at_unix.to_string())
        .unwrap_or_default();
    let fields = create_payload_fields(
        &amount_sat_str,
        &fiat_minor_str,
        &fiat_currency_str,
        &client_request_id_str,
        &req.presentation_envelope,
        &accept_btc_str,
        &accept_ln_str,
        &accept_liquid_str,
        &bitcoin_address_str,
        &liquid_address_str,
        &liquid_blinding_key_str,
        &expires_str,
    );
    let nym_or_empty = linked_nym.as_deref().unwrap_or("");
    auth::verify_la_v2(
        ACTION_CREATE,
        &req.npub,
        nym_or_empty,
        &fields,
        req.timestamp,
        &req.signature,
    )?;
    let request_digest = private_invoice_create_digest(&req.npub, nym_or_empty, &fields);

    // ---- Ownership check: linked vs unlinked ----
    if let Some(nym) = linked_nym.as_deref() {
        assert_nym_owner(state, nym, &req.npub).await?;
    }
    // For unlinked: signing npub IS the canonical npub_owner. No nym
    // assertion needed; the v2 byte sequence binds nym_or_empty="" to the
    // sig already.

    // A response-loss retry resolves before rate/admission/provider gates. A
    // matching request returns the original URL; a reused identifier with a
    // different signed payload is an explicit conflict.
    if let Some(resolution) = db::resolve_wallet_invoice_create(
        &state.db,
        &req.npub,
        req.client_request_id,
        &request_digest,
    )
    .await?
    {
        return create_signed_response(state, linked_nym.as_deref(), resolution);
    }

    // Rail coherence — server-side echo of the SQL CHECKs in migration 021.
    // Exact authenticated retries have already returned above, so changes to
    // validators or the wall clock cannot invalidate an operation that was
    // durably committed before its response was lost.
    if !req.accept_btc && !req.accept_ln && !req.accept_liquid {
        return Err(AppError::InvalidAmount(
            "at least one of accept_btc / accept_ln / accept_liquid must be true".into(),
        ));
    }
    if req.accept_btc && req.bitcoin_address.is_none() {
        return Err(AppError::InvalidAmount(
            "accept_btc=true requires bitcoin_address".into(),
        ));
    }
    if (req.accept_ln || req.accept_liquid) && req.liquid_address.is_none() {
        return Err(AppError::InvalidAmount(
            "accept_ln/accept_liquid=true requires liquid_address".into(),
        ));
    }
    let canonical_bitcoin_address = if let Some(addr) = req.bitcoin_address.as_deref() {
        Some(validators::canonical_btc_mainnet_address(addr)?)
    } else {
        None
    };
    let canonical_liquid_address = if let Some(addr) = req.liquid_address.as_deref() {
        let canonical = validators::canonical_liquid_mainnet_address(addr)?;
        if req.accept_liquid {
            let key = req.liquid_blinding_key_hex.as_deref().ok_or_else(|| {
                AppError::InvalidAmount(
                    "accept_liquid=true requires liquid_blinding_key_hex".into(),
                )
            })?;
            validators::validate_liquid_blinding_key_matches_address(&canonical, key)?;
        }
        Some(canonical)
    } else {
        None
    };

    // Outer expiry window: now+60s to now+30d. Omitted expiry defaults to
    // the server cap; the signed payload uses an empty expiry field in that
    // case, so clients do not need to know server time to create an invoice.
    let now = unix_now();
    let expires_in_secs = match req.expires_at_unix {
        Some(expires_at_unix) => {
            if expires_at_unix < now + 60 {
                return Err(AppError::InvalidAmount(
                    "expires_at_unix must be at least 60 seconds in the future".into(),
                ));
            }
            if expires_at_unix > now + MAX_WALLET_EXPIRES_SECS {
                return Err(AppError::InvalidAmount(format!(
                    "expires_at_unix beyond {MAX_WALLET_EXPIRES_SECS}s cap"
                )));
            }
            expires_at_unix - now
        }
        None => MAX_WALLET_EXPIRES_SECS,
    };

    // Per-npub bucket AFTER sig verify and retry resolution (auth-bound).
    if !is_whitelisted && !is_certification_allowed {
        state
            .rate_limiter
            .check_invoice_create_per_npub(&req.npub)
            .await?;
    }

    let anon_shape = CreateAnonymousRequest {
        amount_sat: req.amount_sat,
        fiat_amount_minor: req.fiat_amount_minor,
        fiat_currency: req.fiat_currency.clone(),
        // Only used for amount parsing here; the signed path sets memo via its
        // own request fields, not this anonymous shape.
        note: None,
    };
    let (amount_sat, fiat) = parse_create_request(&anon_shape, state)?;

    // Direct addresses are immediately present on the signed invoice, so all
    // requested direct rails must be observable before the row is published.
    // Lightning creates its instruction separately: an LN-only invoice must
    // be ready now, while a multi-rail invoice may remain payable on a healthy
    // direct rail and retry Lightning lazily after readiness recovers.
    if req.accept_btc {
        state
            .admission
            .enforce(Rail::DirectBitcoin)
            .map_err(|_| AppError::MoneyAdmissionUnavailable)?;
    }
    if req.accept_liquid {
        state
            .admission
            .enforce(Rail::DirectLiquid)
            .map_err(|_| AppError::MoneyAdmissionUnavailable)?;
    }
    if req.accept_ln && !req.accept_btc && !req.accept_liquid {
        state
            .admission
            .enforce(Rail::LightningReverse)
            .map_err(|_| AppError::MoneyAdmissionUnavailable)?;
    }

    let new_invoice = db::NewInvoice {
        nym_owner: linked_nym.as_deref(),
        public_slug: None,
        npub_owner: &req.npub,
        origin: "wallet",
        checkout_surface_kind: None,
        fiat_amount_minor: fiat.as_ref().map(|(amt, _)| *amt),
        fiat_currency: fiat.as_ref().map(|(_, cur)| cur.as_str()),
        amount_sat,
        rate_minor_per_btc: None,
        rate_lock_secs: expires_in_secs,
        memo: None,
        accept_btc: req.accept_btc,
        accept_ln: req.accept_ln,
        accept_liquid: req.accept_liquid,
        bitcoin_address: canonical_bitcoin_address.as_deref(),
        liquid_address: canonical_liquid_address.as_deref(),
        liquid_blinding_key_hex: req.liquid_blinding_key_hex.as_deref(),
        expires_in_secs,
    };
    let private_create = db::PrivateInvoiceCreate {
        client_request_id: req.client_request_id,
        request_digest: &request_digest,
        presentation_envelope: &presentation_envelope,
    };
    let resolution =
        db::insert_or_reuse_wallet_invoice(&state.db, &new_invoice, &private_create).await?;
    let invoice = match resolution {
        db::WalletInvoiceCreateResolution::Created(invoice) => invoice,
        other => return create_signed_response(state, linked_nym.as_deref(), other),
    };

    // Fiat-fixed invoices defer every provider obligation until an explicit
    // selected-rail quote request has durably created/reused its version.
    // Sat-fixed wallet invoices retain their current eager Lightning behavior.
    if invoice.accept_ln && fiat.is_none() {
        if let Err(e) = create_lightning_offer(
            state,
            lightning_swap_nym(&invoice),
            amount_sat as u64,
            &invoice,
        )
        .await
        {
            tracing::warn!(
                invoice_id = %invoice.id,
                npub_tag = npub_log_tag(&req.npub),
                "wallet-origin eager Lightning offer failed (page can retry): {e}",
            );
        }
    }

    tracing::info!(
        event = "invoice_created",
        invoice_id = %invoice.id,
        npub_tag = npub_log_tag(&req.npub),
        nym_or_unlinked = nym_or_empty,
        accept_btc = invoice.accept_btc,
        accept_ln = invoice.accept_ln,
        accept_liquid = invoice.accept_liquid,
        amount_sat = invoice.amount_sat,
        "wallet-origin invoice created"
    );
    create_signed_response(
        state,
        linked_nym.as_deref(),
        db::WalletInvoiceCreateResolution::Created(invoice),
    )
}

// =====================================================================
// DELETE /api/v1/<nym>/invoices/<id>  (linked)
// DELETE /api/v1/invoices/<id>        (unlinked)
// =====================================================================

#[derive(Deserialize)]
pub struct CancelRequest {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct CancelResponse {
    pub invoice_id: Uuid,
    pub status: String,
}

pub async fn cancel_linked(
    State(state): State<AppState>,
    Path((nym, id_str)): Path<(String, String)>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, AppError> {
    cancel_invoice_inner(&state, Some(nym), id_str, peer_opt, headers, req).await
}

pub async fn cancel_unlinked(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, AppError> {
    cancel_invoice_inner(&state, None, id_str, peer_opt, headers, req).await
}

async fn cancel_invoice_inner(
    state: &AppState,
    linked_nym: Option<String>,
    id_str: String,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    req: CancelRequest,
) -> Result<Json<CancelResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        state,
        CertificationScope::MetadataLookup,
        peer,
        &headers,
        "signed_invoice_cancel",
        Some(&req.npub),
    );

    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state.rate_limiter.check_api_per_ip(ip).await?;
        }
    }

    let id = parse_invoice_id(&id_str)?;
    let nym_or_empty = linked_nym.as_deref().unwrap_or("");
    let fields = cancel_payload_fields(&id_str);
    auth::verify_la_v2(
        ACTION_CANCEL,
        &req.npub,
        nym_or_empty,
        &fields,
        req.timestamp,
        &req.signature,
    )?;

    if let Some(nym) = linked_nym.as_deref() {
        assert_nym_owner(state, nym, &req.npub).await?;
    }

    let inv = db::get_invoice_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::InvoiceNotFound(id_str.clone()))?;

    // Ownership defense-in-depth: signed nym must match invoice.nym_owner
    // (linked path), and signing npub must match invoice.npub_owner
    // (both paths). The npub_owner check is the authoritative gate — it
    // catches the case where a signer who owns nym A tampers with the
    // URL to cancel an invoice owned by nym B.
    if inv.npub_owner != req.npub {
        return Err(AppError::InvoiceNotFound(id_str));
    }
    if let Some(nym) = linked_nym.as_deref() {
        if inv.nym_owner.as_deref() != Some(nym) {
            return Err(AppError::InvoiceNotFound(id_str));
        }
    }

    let (rows, final_status) = db::cancel_invoice(&state.db, id).await?;
    tracing::info!(
        event = "invoice_cancelled",
        invoice_id = %id,
        npub_tag = npub_log_tag(&req.npub),
        nym_or_unlinked = nym_or_empty,
        rows = rows,
        "invoice cancel"
    );
    Ok(Json(CancelResponse {
        invoice_id: id,
        status: final_status,
    }))
}

// =====================================================================
// GET /api/v1/invoices?npub=...  (npub-keyed signed list, linked + unlinked)
// =====================================================================

#[derive(Deserialize)]
pub struct ListSignedQuery {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
    pub page: i64,
    #[serde(rename = "pageSize")]
    pub page_size: i64,
    /// Optional. One of the seven invoice statuses, or empty/absent for
    /// unfiltered. The wire format treats absent + empty identically.
    pub status: Option<String>,
}

#[derive(Serialize)]
pub struct InvoiceListItem {
    pub id: Uuid,
    /// `nym_owner`: linked invoices carry the merchant nym; unlinked
    /// invoices carry `null`. The mobile decides URL construction from
    /// this field (`/<nym>/i/<id>` vs `/invoice/<id>`).
    pub nym_owner: Option<String>,
    pub origin: String,
    pub status: String,
    pub presentation_status: Option<String>,
    pub pricing_mode: String,
    pub settlement_status: String,
    pub amount_sat: i64,
    pub remaining_amount_sat: i64,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    /// Private note attached at checkout (PoS description / donor message).
    /// Returned only on this signed, npub-verified list — never on the public
    /// status or render paths.
    pub memo: Option<String>,
    pub accept_btc: bool,
    pub accept_ln: bool,
    pub accept_liquid: bool,
    pub bitcoin_address: Option<String>,
    pub liquid_address: Option<String>,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    pub paid_via: Option<String>,
    pub paid_at_unix: Option<i64>,
    pub paid_amount_sat: Option<i64>,
}

#[derive(Serialize)]
pub struct ListInvoicesResponse {
    pub invoices: Vec<InvoiceListItem>,
    pub page: i64,
    #[serde(rename = "pageSize")]
    pub page_size: i64,
    pub has_more: bool,
}

pub async fn list_signed(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(params): Query<ListSignedQuery>,
) -> Result<Json<ListInvoicesResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::MetadataLookup,
        peer,
        &headers,
        "signed_invoice_list",
        Some(&params.npub),
    );

    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state.rate_limiter.check_api_per_ip(ip).await?;
        }
    }

    if params.page < 1 {
        return Err(AppError::InvalidAmount("page must be >= 1".into()));
    }
    if params.page > 1000 {
        return Err(AppError::InvalidAmount("page must be <= 1000".into()));
    }
    if params.page_size < 1 {
        return Err(AppError::InvalidAmount("pageSize must be >= 1".into()));
    }
    let page_size = params.page_size.min(LIST_LIMIT_MAX);

    let status_filter: Option<&str> = match params.status.as_deref() {
        None | Some("") => None,
        Some(s)
            if matches!(
                s,
                "unpaid"
                    | "in_progress"
                    | "partially_paid"
                    | "paid"
                    | "underpaid"
                    | "overpaid"
                    | "expired"
                    | "cancelled"
            ) =>
        {
            Some(s)
        }
        Some(other) => {
            return Err(AppError::InvalidAmount(format!(
                "status must be one of unpaid|in_progress|partially_paid|paid|underpaid|overpaid|expired|cancelled, or empty (got '{other}')"
            )));
        }
    };

    let page_str = params.page.to_string();
    let page_size_str = page_size.to_string();
    let status_str = status_filter.unwrap_or("");
    let fields = list_payload_fields(&page_str, &page_size_str, status_str);
    // Nym ALWAYS empty on the npub-keyed list — the action is identity-
    // wide, not per-nym.
    auth::verify_la_v2(
        ACTION_LIST,
        &params.npub,
        "",
        &fields,
        params.timestamp,
        &params.signature,
    )?;

    // npub equality is structural here: the signed message embeds
    // `params.npub` and we filter the DB on the same value. A mismatch
    // would require a forged signature — unreachable past verify_la_v2.

    let mut snapshot = begin_invoice_read_snapshot(&state.db).await?;
    let rows = db::list_invoices_by_npub(
        &mut *snapshot,
        &params.npub,
        status_filter,
        params.page,
        page_size,
    )
    .await?;
    pause_at_invoice_integration_test_hook(InvoiceIntegrationTestHookPoint::ListAfterInvoiceRead)
        .await;
    let has_more = rows.len() >= page_size as usize;
    let invoice_ids = rows.iter().map(|invoice| invoice.id).collect::<Vec<_>>();
    let presentation_received =
        db::invoice_presentation_received_sats(&mut *snapshot, &invoice_ids).await?;
    snapshot.commit().await?;
    let invoices = rows
        .into_iter()
        .map(|inv| {
            let received = presentation_received
                .get(&inv.id)
                .copied()
                .unwrap_or_else(|| inv.paid_amount_sat.unwrap_or(0));
            let remaining = remaining_amount_from_received(&inv, received);
            InvoiceListItem {
                id: inv.id,
                nym_owner: inv.nym_owner,
                origin: inv.origin,
                status: inv.status,
                presentation_status: inv.presentation_status,
                pricing_mode: inv.pricing_mode,
                settlement_status: inv.settlement_status,
                amount_sat: inv.amount_sat,
                remaining_amount_sat: remaining,
                fiat_amount_minor: inv.fiat_amount_minor,
                fiat_currency: inv.fiat_currency,
                memo: inv.memo,
                accept_btc: inv.accept_btc,
                accept_ln: inv.accept_ln,
                accept_liquid: inv.accept_liquid,
                bitcoin_address: inv.bitcoin_address,
                liquid_address: inv.liquid_address,
                created_at_unix: inv.created_at_unix,
                expires_at_unix: inv.expires_at_unix,
                paid_via: inv.paid_via,
                paid_at_unix: inv.paid_at_unix,
                paid_amount_sat: inv.paid_amount_sat,
            }
        })
        .collect();

    Ok(Json(ListInvoicesResponse {
        invoices,
        page: params.page,
        page_size,
        has_more,
    }))
}

/// Hard cap on rows returned by the recoverable-swaps detection endpoint. The
/// populated size of this set is stuck-swap incidents for one merchant
/// (expected 0); a merchant exceeding this is an operator incident, signalled
/// to the client via `has_more: true` so it routes to "contact support" rather
/// than paginating. Keeping this fixed server-side also keeps the signed
/// payload at zero fields (see `recovery_list_payload_fields`).
const RECOVERABLE_LIST_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct RecoverableListQuery {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct RecoverableInvoiceContext {
    pub status: String,
    pub amount_sat: i64,
    pub fiat_amount_minor: Option<i32>,
    pub fiat_currency: Option<String>,
    pub created_at_unix: i64,
}

#[derive(Serialize)]
pub struct RecoverableItem {
    pub invoice_id: Uuid,
    /// Owning nym, included as read-only identity context.
    pub nym: String,
    /// "refund_due" | "refunding" | "refunded" | "confirmed" | "finalized".
    pub recovery_status: String,
    pub user_lock_amount_sat: i64,
    /// Renegotiation-aware (COALESCE(renegotiated, original)).
    pub server_lock_amount_sat: i64,
    pub lockup_address: String,
    /// Immutable automatic-recovery destination, or null until materialized.
    /// Clients may display this value but cannot select or override it.
    pub refund_address: Option<String>,
    /// Broadcast recovery txid, or null until `refunded`.
    pub refund_txid: Option<String>,
    pub swap_created_at_unix: i64,
    pub swap_updated_at_unix: i64,
    pub invoice: RecoverableInvoiceContext,
}

#[derive(Serialize)]
pub struct RecoverableListResponse {
    pub items: Vec<RecoverableItem>,
    pub count: usize,
    /// True iff the hard `RECOVERABLE_LIST_LIMIT` cap was hit — an operator
    /// incident; the client routes to "contact support" rather than paging.
    pub has_more: bool,
}

/// `GET /api/v1/invoices/recoverable` — signed, npub-keyed read-only recovery
/// lifecycle status. Automatic execution is internal; this endpoint cannot
/// choose a destination or trigger a broadcast. Mirrors `list_signed`'s auth
/// exactly — Schnorr `verify_la_v2` over an EMPTY nym and ZERO payload fields;
/// npub scoping is structural (the signed message embeds `params.npub` and the
/// query filters on the same value). It does not require an active
/// registration, so a lapsed merchant can still observe stranded funds. Emits
/// no key material (the DB projection selects none).
pub async fn list_recoverable_signed(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(params): Query<RecoverableListQuery>,
) -> Result<Json<RecoverableListResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|ip| state.ip_whitelist.contains(ip))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::MetadataLookup,
        peer,
        &headers,
        "signed_invoice_recovery_status",
        Some(&params.npub),
    );

    if !is_whitelisted && !is_certification_allowed {
        if let Some(ip) = ip {
            state.rate_limiter.check_api_per_ip(ip).await?;
        }
    }

    let fields = recovery_list_payload_fields();
    // Nym ALWAYS empty on the npub-keyed detection list — the action is
    // identity-wide (an npub may own swaps across nyms; each row carries its
    // own nym as read-only ownership context).
    auth::verify_la_v2(
        ACTION_RECOVERY_LIST,
        &params.npub,
        "",
        &fields,
        params.timestamp,
        &params.signature,
    )?;

    // npub scoping is structural: the signed message embeds `params.npub` and
    // the query filters on the same value; a mismatch would need a forged
    // signature, unreachable past verify_la_v2.
    let rows = db::list_recoverable_chain_swaps_for_npub(
        &state.db,
        &params.npub,
        RECOVERABLE_LIST_LIMIT + 1,
    )
    .await?;
    let has_more = rows.len() as i64 > RECOVERABLE_LIST_LIMIT;

    let mut items = Vec::with_capacity(rows.len().min(RECOVERABLE_LIST_LIMIT as usize));
    for row in rows.into_iter().take(RECOVERABLE_LIST_LIMIT as usize) {
        // SF1 guarantees every mintable swap has a nym; a NULL row is legacy or
        // manually-inserted data without attributable merchant policy. Skip and
        // alert rather than emit ambiguous ownership context.
        let Some(nym) = row.nym else {
            tracing::error!(
                event = "recoverable_swap_without_nym_skipped",
                invoice_id = %row.invoice_id,
                status = %row.status,
                "recoverable chain swap has no owning nym — omitting from detection response (operator P1)"
            );
            continue;
        };
        items.push(RecoverableItem {
            invoice_id: row.invoice_id,
            nym,
            recovery_status: row.status,
            user_lock_amount_sat: row.user_lock_amount_sat,
            server_lock_amount_sat: row.effective_server_lock_amount_sat,
            lockup_address: row.lockup_address,
            refund_address: row.refund_address,
            refund_txid: row.refund_txid,
            swap_created_at_unix: row.swap_created_at_unix,
            swap_updated_at_unix: row.swap_updated_at_unix,
            invoice: RecoverableInvoiceContext {
                status: row.invoice_status,
                amount_sat: row.invoice_amount_sat,
                fiat_amount_minor: row.invoice_fiat_amount_minor,
                fiat_currency: row.invoice_fiat_currency,
                created_at_unix: row.invoice_created_at_unix,
            },
        });
    }

    Ok(Json(RecoverableListResponse {
        count: items.len(),
        items,
        has_more,
    }))
}

#[cfg(test)]
mod tests;
