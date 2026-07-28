//! Write-ahead Bull Bitcoin order lifecycle and narrow reconciliation worker.
//!
//! A create crosses `reserved -> dispatch_started` before the one provider
//! call. Any surviving ambiguous dispatch is abandoned to Bitcoin and never
//! retried. Exact bound orders are the only rows the reconciler may query.

use sqlx::postgres::PgAdvisoryLock;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::bull_bitcoin::{
    BitcoinAmountSat, BitcoinNetwork, BullBitcoinError, CreateSellRequest, CreatedSellOrder,
    CredentialCipher, FiatCurrency, PayerInstruction, Product,
};
use crate::config::BullBitcoinEncryptionKey;
use crate::db::{
    self, BullBitcoinSettlementStoreError, NewBullBitcoinSettlement, StoredBullBitcoinSettlement,
};
use crate::AppState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackCategory {
    BelowMinimum,
    InvalidSplit,
    ConversionUnavailable,
    AmbiguousCreate,
}

impl FallbackCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BelowMinimum => "below_minimum",
            Self::InvalidSplit => "invalid_split",
            Self::ConversionUnavailable => "conversion_unavailable",
            Self::AmbiguousCreate => "ambiguous_create",
        }
    }

    fn parse(value: &str) -> Result<Self, SettlementServiceError> {
        match value {
            "below_minimum" => Ok(Self::BelowMinimum),
            "invalid_split" => Ok(Self::InvalidSplit),
            "conversion_unavailable" => Ok(Self::ConversionUnavailable),
            "ambiguous_create" => Ok(Self::AmbiguousCreate),
            _ => Err(SettlementServiceError::StoredState),
        }
    }
}

/// Stable public/audit projection for persisted fallback categories. Keep
/// known causes distinct; corrupt, missing, or future values are explicit
/// instead of being silently relabelled as a conversion outage.
pub fn projected_fallback_reason(value: Option<&str>) -> &'static str {
    match value {
        Some("below_minimum") => "below_minimum",
        Some("invalid_split") => "invalid_split",
        Some("conversion_unavailable") => "conversion_unavailable",
        Some("ambiguous_create") => "ambiguous_create",
        Some(_) | None => "unknown",
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FallbackDecisionLogFields<'a> {
    event: &'static str,
    category: &'static str,
    requested_sats: i64,
    fiat_currency: &'a str,
    fiat_amount_minor: Option<i64>,
    invoice_id: Option<Uuid>,
    reverse_swap_id: Option<Uuid>,
    chain_swap_id: Option<Uuid>,
    settlement_id: Uuid,
    selected_fallback_rail: &'static str,
    speculative: bool,
    transition: &'static str,
}

fn fallback_decision_log_fields<'a>(
    stored: &'a StoredBullBitcoinSettlement,
    category: FallbackCategory,
    transition: &'static str,
) -> FallbackDecisionLogFields<'a> {
    FallbackDecisionLogFields {
        event: "bull_bitcoin_fallback_committed",
        category: category.as_str(),
        requested_sats: stored.requested_bitcoin_sat,
        fiat_currency: &stored.fiat_currency,
        fiat_amount_minor: stored.quoted_fiat_minor,
        invoice_id: stored.invoice_id,
        reverse_swap_id: stored.reverse_swap_id,
        chain_swap_id: stored.chain_swap_id,
        settlement_id: stored.id,
        selected_fallback_rail: "bitcoin",
        speculative: matches!(stored.purpose.as_str(), "mixed" | "provider_only")
            && stored.funding_committed_at_unix.is_none(),
        transition,
    }
}

fn emit_committed_fallback_decision(
    stored: &StoredBullBitcoinSettlement,
    category: FallbackCategory,
    transition: &'static str,
) {
    let fields = fallback_decision_log_fields(stored, category, transition);
    tracing::info!(
        event = fields.event,
        category = fields.category,
        requested_sats = fields.requested_sats,
        fiat_currency = fields.fiat_currency,
        fiat_amount_minor = ?fields.fiat_amount_minor,
        invoice_id = ?fields.invoice_id,
        reverse_swap_id = ?fields.reverse_swap_id,
        chain_swap_id = ?fields.chain_swap_id,
        settlement_id = %fields.settlement_id,
        selected_fallback_rail = fields.selected_fallback_rail,
        speculative = fields.speculative,
        transition = fields.transition,
        "Bull Bitcoin conversion fell back after the local decision committed"
    );
}

async fn abandon_dispatch_with_log(
    connection: &mut sqlx::PgConnection,
    stored: &StoredBullBitcoinSettlement,
    category: FallbackCategory,
) -> Result<bool, SettlementServiceError> {
    let committed = db::abandon_bull_bitcoin_dispatch(connection, stored.id, category.as_str())
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    if committed {
        emit_committed_fallback_decision(stored, category, "dispatch_abandoned");
    }
    Ok(committed)
}

async fn route_unfunded_mixed_with_log(
    connection: &mut sqlx::PgConnection,
    stored: &StoredBullBitcoinSettlement,
    category: FallbackCategory,
) -> Result<bool, SettlementServiceError> {
    let committed =
        db::route_unfunded_mixed_settlement_to_fallback(connection, stored.id, category.as_str())
            .await
            .map_err(|_| SettlementServiceError::Database)?;
    if committed {
        emit_committed_fallback_decision(stored, category, "unfunded_binding_routed");
    }
    Ok(committed)
}

async fn preserve_ambiguous_dispatch(
    connection: &mut sqlx::PgConnection,
    stored: &StoredBullBitcoinSettlement,
    candidate_order_id: Option<Uuid>,
) -> Result<(), SettlementServiceError> {
    let committed =
        db::record_ambiguous_bull_bitcoin_dispatch(connection, stored.id, candidate_order_id)
            .await
            .map_err(|_| SettlementServiceError::Database)?;
    if !committed {
        return Err(SettlementServiceError::StoredState);
    }
    tracing::warn!(
        event = "bull_bitcoin_create_ambiguous",
        settlement_id = %stored.id,
        provider_order_id_retained = candidate_order_id.is_some(),
        "Bull Bitcoin create may have reached the provider; fallback and retry remain closed"
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct FiatOnlyInstructionRequest<'a> {
    pub owner_npub: &'a str,
    pub invoice_id: Option<Uuid>,
    /// Immutable Bullnym payer quote which denominates an invoice pay-in.
    /// Fiat-fixed invoice instructions require it; sat-fixed invoices and
    /// Lightning Address settlements deliberately have no quote authority.
    pub invoice_quote_version_id: Option<Uuid>,
    pub product: Product,
    pub credential_id: Uuid,
    pub request_key: &'a str,
    pub fiat_currency: FiatCurrency,
    pub network: BitcoinNetwork,
    pub bitcoin_amount: BitcoinAmountSat,
    pub use_payjoin: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FiatOnlyInstructionOutcome {
    BullBitcoin {
        settlement_id: Uuid,
        order_id: Uuid,
        instruction: PayerInstruction,
        expires_at_unix: Option<i64>,
    },
    BitcoinFallback {
        settlement_id: Uuid,
        category: FallbackCategory,
    },
}

/// Claim-time decision for a captured swap-backed fiat policy. Percentages
/// 1-99 produce the mixed merchant/provider outputs; a 100%-fiat Lightning
/// Address produces the sole provider output. The Bull Bitcoin address is
/// deliberately available only while the claim is still unjournaled; once
/// output evidence commits, retries use the immutable transaction and hashes.
pub enum MixedSettlementPreparation {
    BitcoinFallback {
        settlement_id: Uuid,
        category: FallbackCategory,
    },
    BullBitcoinOutput {
        settlement_id: Uuid,
        confidential_address: String,
        bull_bitcoin_amount_sat: i64,
        fiat_percentage: i16,
        provider_only: bool,
    },
    Journaled {
        settlement_id: Uuid,
        bull_bitcoin_amount_sat: i64,
        fiat_percentage: i16,
        provider_only: bool,
    },
}

/// Exact fee basis established from the same Liquid claim shape that will be
/// constructed. The additional-output script length binds the estimate to the
/// destination shape returned by Bull Bitcoin before an order can be funded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixedClaimBasis {
    pub net_settlement_sat: i64,
    pub additional_output_script_len: usize,
    pub provider_only: bool,
}

#[derive(Clone, Copy)]
enum MixedSwapSource {
    Reverse(Uuid),
    Chain(Uuid),
}

impl MixedSwapSource {
    fn id(self) -> Uuid {
        match self {
            Self::Reverse(id) | Self::Chain(id) => id,
        }
    }

    fn payer_rail(self) -> &'static str {
        match self {
            Self::Reverse(_) => "lightning",
            Self::Chain(_) => "bitcoin",
        }
    }

    fn request_key(self) -> String {
        match self {
            Self::Reverse(id) => format!("mixed-reverse:{id}"),
            Self::Chain(id) => format!("mixed-chain:{id}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementServiceError {
    SourceIdentityUnavailable,
    CredentialUnavailable,
    RequestKeyConflict,
    ProviderCreateAmbiguous,
    StoredState,
    Database,
}

impl fmt::Display for SettlementServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceIdentityUnavailable => "fiat-settlement identity is unavailable",
            Self::CredentialUnavailable => "fiat-settlement credential is unavailable",
            Self::RequestKeyConflict => "fiat-settlement request identity conflicts",
            Self::ProviderCreateAmbiguous => {
                "fiat-settlement provider create requires reconciliation"
            }
            Self::StoredState => "fiat-settlement state is invalid",
            Self::Database => "fiat-settlement persistence failed",
        })
    }
}

impl std::error::Error for SettlementServiceError {}

pub async fn create_fiat_only_instruction(
    state: &AppState,
    request: &FiatOnlyInstructionRequest<'_>,
) -> Result<FiatOnlyInstructionOutcome, SettlementServiceError> {
    if request.use_payjoin && request.network != BitcoinNetwork::Bitcoin {
        return Err(SettlementServiceError::StoredState);
    }

    // Hold one session advisory lock across the bounded provider call. This
    // serializes an exact retry without holding a database transaction open.
    let lock = PgAdvisoryLock::new(format!(
        "bullnym-bull-bitcoin:{}:{}",
        request.owner_npub, request.request_key
    ));
    let connection = state
        .db
        .acquire()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let mut guard = lock
        .acquire(connection)
        .await
        .map_err(|_| SettlementServiceError::Database)?;

    let result = create_fiat_only_instruction_locked(state, request, &mut guard).await;
    guard
        .release_now()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    result
}

/// Replay an already-reserved fiat-only instruction without admitting a new
/// provider order. This is used when binding the first order has changed the
/// invoice aggregate to `pending`, but the payer lost the original response
/// and retries the still-current quote.
pub async fn replay_existing_fiat_only_instruction(
    state: &AppState,
    request: &FiatOnlyInstructionRequest<'_>,
) -> Result<Option<FiatOnlyInstructionOutcome>, SettlementServiceError> {
    if request.use_payjoin && request.network != BitcoinNetwork::Bitcoin {
        return Err(SettlementServiceError::StoredState);
    }

    let lock = PgAdvisoryLock::new(format!(
        "bullnym-bull-bitcoin:{}:{}",
        request.owner_npub, request.request_key
    ));
    let connection = state
        .db
        .acquire()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let mut guard = lock
        .acquire(connection)
        .await
        .map_err(|_| SettlementServiceError::Database)?;

    let existing = db::load_bull_bitcoin_settlement_by_request_key(
        &mut guard,
        request.owner_npub,
        request.request_key,
    )
    .await
    .map_err(|_| SettlementServiceError::Database)?;
    let result = if existing.is_some() {
        create_fiat_only_instruction_locked(state, request, &mut guard)
            .await
            .map(Some)
    } else {
        Ok(None)
    };
    guard
        .release_now()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    result
}

/// Replay a previously reserved Lightning Address fiat-only intent without
/// consulting the merchant's current setting. Settings govern new callbacks;
/// once a payer-facing destination (or a durable all-Bitcoin fallback) exists,
/// an exact callback retry must return that same decision and must never create
/// a second payable instruction on a different rail.
pub async fn replay_fiat_only_instruction(
    state: &AppState,
    owner_npub: &str,
    request_key: &str,
    product: Product,
    network: BitcoinNetwork,
    bitcoin_amount: BitcoinAmountSat,
) -> Result<Option<FiatOnlyInstructionOutcome>, SettlementServiceError> {
    let lock = PgAdvisoryLock::new(format!("bullnym-bull-bitcoin:{owner_npub}:{request_key}"));
    let connection = state
        .db
        .acquire()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let mut guard = lock
        .acquire(connection)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let existing =
        db::load_bull_bitcoin_settlement_by_request_key(&mut guard, owner_npub, request_key)
            .await
            .map_err(|_| SettlementServiceError::Database)?;
    let result = if let Some(existing) = existing {
        if existing.owner_npub != owner_npub
            || existing.invoice_id.is_some()
            || existing.reverse_swap_id.is_some()
            || existing.chain_swap_id.is_some()
            || existing.product != product.as_str()
            || existing.purpose != "fiat_only"
            || existing.payer_rail != network.as_str()
            || existing.request_key != request_key
            || existing.fiat_percentage != 100
            || existing.requested_bitcoin_sat != bitcoin_amount.as_sat()
        {
            Err(SettlementServiceError::RequestKeyConflict)
        } else {
            match FiatCurrency::from_str(&existing.fiat_currency) {
                Ok(currency) => {
                    let persisted_request = FiatOnlyInstructionRequest {
                        owner_npub,
                        invoice_id: None,
                        invoice_quote_version_id: None,
                        product,
                        credential_id: existing.credential_id,
                        request_key,
                        fiat_currency: currency,
                        network,
                        bitcoin_amount,
                        use_payjoin: false,
                    };
                    create_fiat_only_instruction_locked(state, &persisted_request, &mut guard)
                        .await
                        .map(Some)
                }
                Err(_) => Err(SettlementServiceError::StoredState),
            }
        }
    } else {
        Ok(None)
    };
    guard
        .release_now()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    result
}

async fn create_fiat_only_instruction_locked(
    state: &AppState,
    request: &FiatOnlyInstructionRequest<'_>,
    connection: &mut sqlx::PgConnection,
) -> Result<FiatOnlyInstructionOutcome, SettlementServiceError> {
    let reservation = NewBullBitcoinSettlement {
        owner_npub: request.owner_npub,
        invoice_id: request.invoice_id,
        invoice_quote_version_id: request.invoice_quote_version_id,
        reverse_swap_id: None,
        chain_swap_id: None,
        credential_id: request.credential_id,
        product: request.product.as_str(),
        purpose: "fiat_only",
        payer_rail: request.network.as_str(),
        request_key: request.request_key,
        fiat_percentage: 100,
        fiat_currency: request.fiat_currency.as_str(),
        requested_bitcoin_sat: request.bitcoin_amount.as_sat(),
        expected_instruction_script_len: None,
    };
    let mut stored = db::reserve_bull_bitcoin_settlement(connection, &reservation)
        .await
        .map_err(map_store_error)?;

    match stored.provider_state.as_str() {
        "bound" | "abandoned" => return stored_outcome(&stored),
        // With the session lock held, a pre-existing dispatch cannot belong to
        // a concurrent exact caller. It survived a crash/cancellation and is
        // therefore ambiguous; never issue a second create.
        "dispatch_started" => {
            return Err(SettlementServiceError::ProviderCreateAmbiguous);
        }
        "reserved" => {}
        _ => return Err(SettlementServiceError::StoredState),
    }

    if !db::begin_bull_bitcoin_dispatch(connection, stored.id)
        .await
        .map_err(|_| SettlementServiceError::Database)?
    {
        stored = db::load_bull_bitcoin_settlement(connection, stored.id)
            .await
            .map_err(|_| SettlementServiceError::Database)?;
        return stored_outcome(&stored);
    }

    let credential = db::load_bull_bitcoin_credential(connection, stored.credential_id)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let Some(credential) = credential else {
        return abandon_and_return(connection, &stored, FallbackCategory::ConversionUnavailable)
            .await;
    };
    if credential.owner_npub != stored.owner_npub {
        return Err(SettlementServiceError::StoredState);
    }
    let Some(encryption_key) = state.config.bull_bitcoin_credential_encryption_key.clone() else {
        return abandon_and_return(connection, &stored, FallbackCategory::ConversionUnavailable)
            .await;
    };
    let scoped_key = match CredentialCipher::new(encryption_key).decrypt(
        credential.id,
        &credential.owner_npub,
        &credential.encrypted,
    ) {
        Ok(key) => key,
        Err(_) => {
            return abandon_and_return(connection, &stored, FallbackCategory::ConversionUnavailable)
                .await
        }
    };

    let provider_request = CreateSellRequest {
        request_id: stored.id,
        currency: request.fiat_currency,
        network: request.network,
        bitcoin_amount: request.bitcoin_amount,
        use_payjoin: request.use_payjoin,
    };
    let provider_result = state
        .bull_bitcoin
        .create_sell_to_balance(&scoped_key, &provider_request)
        .await;
    drop(scoped_key);

    match provider_result {
        Ok(order) => {
            if order.currency != request.fiat_currency
                || order.network != request.network
                || order.requested_bitcoin != request.bitcoin_amount
                || instruction_network(&order.instruction) != request.network
            {
                preserve_ambiguous_dispatch(connection, &stored, Some(order.order_id)).await?;
                return Err(SettlementServiceError::ProviderCreateAmbiguous);
            }
            let (kind, instruction) = instruction_parts(&order.instruction);
            let retention_secs =
                i64::try_from(state.config.bull_bitcoin.late_payment_retention_secs)
                    .map_err(|_| SettlementServiceError::StoredState)?;
            let bound = db::bind_bull_bitcoin_order(
                connection,
                stored.id,
                order.order_id,
                kind,
                instruction,
                order.expires_at_unix,
                retention_secs,
                order.quoted_fiat.map(|quote| quote.as_minor()),
            )
            .await
            .map_err(|_| SettlementServiceError::Database)?;
            if !bound {
                return Err(SettlementServiceError::StoredState);
            }
            stored = db::load_bull_bitcoin_settlement(connection, stored.id)
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            stored_outcome(&stored)
        }
        Err(failure) => {
            if failure.order_id.is_some() {
                preserve_ambiguous_dispatch(connection, &stored, failure.order_id).await?;
                return Err(SettlementServiceError::ProviderCreateAmbiguous);
            }
            let Some(category) = fallback_for_definite_create_rejection(failure.error) else {
                preserve_ambiguous_dispatch(connection, &stored, None).await?;
                return Err(SettlementServiceError::ProviderCreateAmbiguous);
            };
            abandon_dispatch_with_log(connection, &stored, category).await?;
            if failure.error == BullBitcoinError::Authentication {
                // This call has no exposed destination. Disable the proven
                // invalid generation and all future settings after the local
                // state is durably routed to Bitcoin.
                db::invalidate_bull_bitcoin_credential_on_connection(
                    connection,
                    stored.credential_id,
                )
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            }
            Ok(FiatOnlyInstructionOutcome::BitcoinFallback {
                settlement_id: stored.id,
                category,
            })
        }
    }
}

pub async fn prepare_reverse_mixed_settlement(
    state: &AppState,
    reverse_swap_id: Uuid,
    basis: MixedClaimBasis,
) -> Result<Option<MixedSettlementPreparation>, SettlementServiceError> {
    prepare_mixed_settlement(
        state,
        MixedSwapSource::Reverse(reverse_swap_id),
        Some(basis),
    )
    .await
}

pub async fn prepare_chain_mixed_settlement(
    state: &AppState,
    chain_swap_id: Uuid,
    basis: MixedClaimBasis,
) -> Result<Option<MixedSettlementPreparation>, SettlementServiceError> {
    prepare_mixed_settlement(state, MixedSwapSource::Chain(chain_swap_id), Some(basis)).await
}

pub(crate) async fn prepare_reverse_mixed_settlement_on_locked_connection(
    state: &AppState,
    reverse_swap_id: Uuid,
    basis: Option<MixedClaimBasis>,
    connection: &mut sqlx::PgConnection,
) -> Result<Option<MixedSettlementPreparation>, SettlementServiceError> {
    prepare_mixed_settlement_locked(
        state,
        MixedSwapSource::Reverse(reverse_swap_id),
        basis,
        connection,
    )
    .await
}

pub(crate) async fn prepare_chain_mixed_settlement_on_locked_connection(
    state: &AppState,
    chain_swap_id: Uuid,
    basis: Option<MixedClaimBasis>,
    connection: &mut sqlx::PgConnection,
) -> Result<Option<MixedSettlementPreparation>, SettlementServiceError> {
    prepare_mixed_settlement_locked(
        state,
        MixedSwapSource::Chain(chain_swap_id),
        basis,
        connection,
    )
    .await
}

async fn prepare_mixed_settlement(
    state: &AppState,
    source: MixedSwapSource,
    basis: Option<MixedClaimBasis>,
) -> Result<Option<MixedSettlementPreparation>, SettlementServiceError> {
    // Interoperate with the existing `pg_try_advisory_xact_lock(hashtext())`
    // claim guard. While provider I/O owns this session lock, webhook/sweep
    // claim attempts skip rather than racing a second order reservation.
    let lock_key = match source {
        MixedSwapSource::Reverse(id) => format!("claim:{id}"),
        MixedSwapSource::Chain(id) => format!("chain-claim:{id}"),
    };
    let mut connection = state
        .db
        .acquire()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    sqlx::query("SELECT pg_advisory_lock(hashtext($1)::bigint)")
        .bind(&lock_key)
        .execute(&mut *connection)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let mut guard = MixedClaimSessionLock::new(connection, lock_key);
    let result = prepare_mixed_settlement_locked(state, source, basis, &mut guard).await;
    guard.unlock().await?;
    result
}

/// Own the backend session carrying a `hashtext()` claim lock. Cancellation or
/// an early error closes that session instead of returning a still-locked
/// connection to the pool.
struct MixedClaimSessionLock {
    connection: sqlx::pool::PoolConnection<sqlx::Postgres>,
    lock_key: String,
    locked: bool,
}

impl MixedClaimSessionLock {
    fn new(connection: sqlx::pool::PoolConnection<sqlx::Postgres>, lock_key: String) -> Self {
        Self {
            connection,
            lock_key,
            locked: true,
        }
    }

    async fn unlock(&mut self) -> Result<(), SettlementServiceError> {
        let lock_key = self.lock_key.clone();
        let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(hashtext($1)::bigint)")
            .bind(lock_key)
            .fetch_one(&mut **self)
            .await
            .map_err(|_| SettlementServiceError::Database)?;
        if !released {
            return Err(SettlementServiceError::Database);
        }
        self.locked = false;
        Ok(())
    }
}

impl Deref for MixedClaimSessionLock {
    type Target = sqlx::PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for MixedClaimSessionLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

impl Drop for MixedClaimSessionLock {
    fn drop(&mut self) {
        if self.locked {
            self.connection.close_on_drop();
        }
    }
}

async fn prepare_mixed_settlement_locked(
    state: &AppState,
    source: MixedSwapSource,
    basis: Option<MixedClaimBasis>,
    connection: &mut sqlx::PgConnection,
) -> Result<Option<MixedSettlementPreparation>, SettlementServiceError> {
    let policy = match source {
        MixedSwapSource::Reverse(id) => {
            db::reverse_swap_fiat_settlement_policy(connection, id).await
        }
        MixedSwapSource::Chain(id) => db::chain_swap_fiat_settlement_policy(connection, id).await,
    }
    .map_err(|_| SettlementServiceError::Database)?;
    let Some(policy) = policy else {
        return Ok(None);
    };
    if policy.reverse_swap_id
        != matches!(source, MixedSwapSource::Reverse(_)).then_some(source.id())
        || policy.chain_swap_id
            != matches!(source, MixedSwapSource::Chain(_)).then_some(source.id())
        || !(1..=100).contains(&policy.fiat_percentage)
    {
        return Err(SettlementServiceError::StoredState);
    }

    let request_key = source.request_key();
    let product =
        Product::from_str(&policy.product).map_err(|_| SettlementServiceError::StoredState)?;
    let currency = FiatCurrency::from_str(&policy.fiat_currency)
        .map_err(|_| SettlementServiceError::StoredState)?;
    let existing = db::load_bull_bitcoin_settlement_by_request_key(
        connection,
        &policy.owner_npub,
        &request_key,
    )
    .await
    .map_err(|_| SettlementServiceError::Database)?;
    if let Some(stored) = existing.as_ref() {
        if !mixed_reservation_matches_policy(stored, &policy, source, &request_key) {
            return Err(SettlementServiceError::StoredState);
        }
        match (
            stored.provider_state.as_str(),
            stored.funding_route.as_deref(),
            stored.funding_committed_at_unix,
        ) {
            ("bound", Some("bull_bitcoin"), Some(_))
            | ("bound", Some("bitcoin_fallback"), None)
            | ("abandoned", Some("bitcoin_fallback"), None) => {
                return mixed_stored_outcome(stored).map(Some);
            }
            ("dispatch_started", None, None) => {
                return Err(SettlementServiceError::ProviderCreateAmbiguous);
            }
            _ => {}
        }
    }

    let basis = basis.ok_or(SettlementServiceError::StoredState)?;
    if basis.net_settlement_sat <= 0
        || basis.additional_output_script_len == 0
        || basis.additional_output_script_len > 10_000
    {
        return Err(SettlementServiceError::StoredState);
    }
    if basis.provider_only != (policy.fiat_percentage == 100) {
        return Err(SettlementServiceError::StoredState);
    }
    let numerator = basis
        .net_settlement_sat
        .checked_mul(i64::from(policy.fiat_percentage))
        .ok_or(SettlementServiceError::StoredState)?;
    // A positive one-satoshi target lets Bull Bitcoin's authoritative minimum
    // policy produce the ordinary all-Bitcoin fallback for tiny splits.
    let rounded_bull_bitcoin_amount_sat = numerator / 100;
    let split_rounds_to_zero = rounded_bull_bitcoin_amount_sat == 0;
    let bull_bitcoin_amount_sat = rounded_bull_bitcoin_amount_sat.max(1);
    let merchant_amount_sat = basis
        .net_settlement_sat
        .checked_sub(bull_bitcoin_amount_sat)
        .ok_or(SettlementServiceError::StoredState)?;
    let provider_only = policy.fiat_percentage == 100;
    let amount = BitcoinAmountSat::new(bull_bitcoin_amount_sat)
        .map_err(|_| SettlementServiceError::StoredState)?;
    let reservation = NewBullBitcoinSettlement {
        owner_npub: &policy.owner_npub,
        invoice_id: policy.invoice_id,
        invoice_quote_version_id: None,
        reverse_swap_id: policy.reverse_swap_id,
        chain_swap_id: policy.chain_swap_id,
        credential_id: policy.credential_id,
        product: product.as_str(),
        purpose: if provider_only {
            "provider_only"
        } else {
            "mixed"
        },
        payer_rail: source.payer_rail(),
        request_key: &request_key,
        fiat_percentage: policy.fiat_percentage,
        fiat_currency: currency.as_str(),
        requested_bitcoin_sat: bull_bitcoin_amount_sat,
        expected_instruction_script_len: Some(
            i32::try_from(basis.additional_output_script_len)
                .map_err(|_| SettlementServiceError::StoredState)?,
        ),
    };
    let mut stored = if let Some(existing) = existing {
        let address_shape_changed = existing.provider_state == "bound"
            && existing.funding_route.is_none()
            && existing
                .payer_instruction
                .as_deref()
                .and_then(liquid_script_pubkey_len)
                != Some(basis.additional_output_script_len);
        if existing.requested_bitcoin_sat != bull_bitcoin_amount_sat || address_shape_changed {
            route_unfunded_mixed_to_invalid_split(connection, &existing).await?;
            let stored = db::load_bull_bitcoin_settlement(connection, existing.id)
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            return mixed_stored_outcome(&stored).map(Some);
        }
        existing
    } else {
        db::reserve_bull_bitcoin_settlement(connection, &reservation)
            .await
            .map_err(map_store_error)?
    };

    if (!provider_only && merchant_amount_sat <= 0) || split_rounds_to_zero {
        match stored.provider_state.as_str() {
            "reserved" => {
                abandon_dispatch_with_log(connection, &stored, FallbackCategory::InvalidSplit)
                    .await?;
            }
            "dispatch_started" => return Err(SettlementServiceError::ProviderCreateAmbiguous),
            "bound" if stored.funding_route.is_none() => {
                route_unfunded_mixed_with_log(connection, &stored, FallbackCategory::InvalidSplit)
                    .await?;
            }
            _ => {}
        }
        return Ok(Some(MixedSettlementPreparation::BitcoinFallback {
            settlement_id: stored.id,
            category: FallbackCategory::InvalidSplit,
        }));
    }

    match stored.provider_state.as_str() {
        "bound" | "abandoned" => return mixed_stored_outcome(&stored).map(Some),
        "dispatch_started" => return Err(SettlementServiceError::StoredState),
        "reserved" => {}
        _ => return Err(SettlementServiceError::StoredState),
    }

    if !db::begin_bull_bitcoin_dispatch(connection, stored.id)
        .await
        .map_err(|_| SettlementServiceError::Database)?
    {
        stored = db::load_bull_bitcoin_settlement(connection, stored.id)
            .await
            .map_err(|_| SettlementServiceError::Database)?;
        return mixed_stored_outcome(&stored).map(Some);
    }

    let credential = db::load_bull_bitcoin_credential(connection, stored.credential_id)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let Some(credential) = credential else {
        abandon_dispatch_with_log(connection, &stored, FallbackCategory::ConversionUnavailable)
            .await?;
        return Ok(Some(MixedSettlementPreparation::BitcoinFallback {
            settlement_id: stored.id,
            category: FallbackCategory::ConversionUnavailable,
        }));
    };
    if credential.owner_npub != policy.owner_npub {
        return Err(SettlementServiceError::StoredState);
    }
    let Some(encryption_key) = state.config.bull_bitcoin_credential_encryption_key.clone() else {
        abandon_dispatch_with_log(connection, &stored, FallbackCategory::ConversionUnavailable)
            .await?;
        return Ok(Some(MixedSettlementPreparation::BitcoinFallback {
            settlement_id: stored.id,
            category: FallbackCategory::ConversionUnavailable,
        }));
    };
    let scoped_key = match decrypt_credential(encryption_key, &credential) {
        Ok(key) => key,
        Err(_) => {
            abandon_dispatch_with_log(connection, &stored, FallbackCategory::ConversionUnavailable)
                .await?;
            return Ok(Some(MixedSettlementPreparation::BitcoinFallback {
                settlement_id: stored.id,
                category: FallbackCategory::ConversionUnavailable,
            }));
        }
    };
    let provider_result = state
        .bull_bitcoin
        .create_sell_to_balance(
            &scoped_key,
            &CreateSellRequest {
                request_id: stored.id,
                currency,
                network: BitcoinNetwork::Liquid,
                bitcoin_amount: amount,
                use_payjoin: false,
            },
        )
        .await;
    drop(scoped_key);

    match provider_result {
        Ok(CreatedSellOrder {
            order_id,
            currency: order_currency,
            network: BitcoinNetwork::Liquid,
            requested_bitcoin,
            instruction:
                PayerInstruction::Liquid {
                    confidential_address,
                },
            expires_at_unix,
            quoted_fiat,
        }) if order_currency == currency && requested_bitcoin == amount => {
            if liquid_script_pubkey_len(&confidential_address)
                != Some(basis.additional_output_script_len)
            {
                preserve_ambiguous_dispatch(connection, &stored, Some(order_id)).await?;
                return Err(SettlementServiceError::ProviderCreateAmbiguous);
            }
            let retention_secs =
                i64::try_from(state.config.bull_bitcoin.late_payment_retention_secs)
                    .map_err(|_| SettlementServiceError::StoredState)?;
            let bound = db::bind_bull_bitcoin_order(
                connection,
                stored.id,
                order_id,
                "liquid",
                &confidential_address,
                expires_at_unix,
                retention_secs,
                quoted_fiat.map(|quote| quote.as_minor()),
            )
            .await
            .map_err(|_| SettlementServiceError::Database)?;
            if !bound {
                return Err(SettlementServiceError::StoredState);
            }
            Ok(Some(MixedSettlementPreparation::BullBitcoinOutput {
                settlement_id: stored.id,
                confidential_address,
                bull_bitcoin_amount_sat,
                fiat_percentage: policy.fiat_percentage,
                provider_only,
            }))
        }
        Ok(order) => {
            preserve_ambiguous_dispatch(connection, &stored, Some(order.order_id)).await?;
            Err(SettlementServiceError::ProviderCreateAmbiguous)
        }
        Err(failure) => {
            if failure.order_id.is_some() {
                preserve_ambiguous_dispatch(connection, &stored, failure.order_id).await?;
                return Err(SettlementServiceError::ProviderCreateAmbiguous);
            }
            let Some(category) = fallback_for_definite_create_rejection(failure.error) else {
                preserve_ambiguous_dispatch(connection, &stored, None).await?;
                return Err(SettlementServiceError::ProviderCreateAmbiguous);
            };
            abandon_dispatch_with_log(connection, &stored, category).await?;
            if failure.error == BullBitcoinError::Authentication {
                db::invalidate_bull_bitcoin_credential_on_connection(
                    connection,
                    stored.credential_id,
                )
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            }
            Ok(Some(MixedSettlementPreparation::BitcoinFallback {
                settlement_id: stored.id,
                category,
            }))
        }
    }
}

fn mixed_stored_outcome(
    stored: &StoredBullBitcoinSettlement,
) -> Result<MixedSettlementPreparation, SettlementServiceError> {
    match (
        stored.provider_state.as_str(),
        stored.funding_route.as_deref(),
        stored.funding_committed_at_unix,
    ) {
        ("bound", None, None) => {
            let address = stored
                .payer_instruction
                .as_ref()
                .filter(|_| stored.instruction_kind.as_deref() == Some("liquid"))
                .ok_or(SettlementServiceError::StoredState)?;
            Ok(MixedSettlementPreparation::BullBitcoinOutput {
                settlement_id: stored.id,
                confidential_address: address.clone(),
                bull_bitcoin_amount_sat: stored.requested_bitcoin_sat,
                fiat_percentage: stored.fiat_percentage,
                provider_only: stored.purpose == "provider_only",
            })
        }
        ("bound", Some("bull_bitcoin"), Some(_)) => Ok(MixedSettlementPreparation::Journaled {
            settlement_id: stored.id,
            bull_bitcoin_amount_sat: stored.requested_bitcoin_sat,
            fiat_percentage: stored.fiat_percentage,
            provider_only: stored.purpose == "provider_only",
        }),
        ("abandoned", Some("bitcoin_fallback"), None)
        | ("bound", Some("bitcoin_fallback"), None) => {
            Ok(MixedSettlementPreparation::BitcoinFallback {
                settlement_id: stored.id,
                category: FallbackCategory::parse(
                    stored
                        .fallback_category
                        .as_deref()
                        .ok_or(SettlementServiceError::StoredState)?,
                )?,
            })
        }
        _ => Err(SettlementServiceError::StoredState),
    }
}

fn mixed_reservation_matches_policy(
    stored: &StoredBullBitcoinSettlement,
    policy: &db::SwapFiatSettlementPolicy,
    source: MixedSwapSource,
    request_key: &str,
) -> bool {
    stored.owner_npub == policy.owner_npub
        && stored.invoice_id == policy.invoice_id
        && stored.reverse_swap_id == policy.reverse_swap_id
        && stored.chain_swap_id == policy.chain_swap_id
        && stored.credential_id == policy.credential_id
        && stored.product == policy.product
        && stored.purpose
            == if policy.fiat_percentage == 100 {
                "provider_only"
            } else {
                "mixed"
            }
        && stored.payer_rail == source.payer_rail()
        && stored.request_key == request_key
        && stored.fiat_percentage == policy.fiat_percentage
        && stored.fiat_currency == policy.fiat_currency
}

async fn route_unfunded_mixed_to_invalid_split(
    connection: &mut sqlx::PgConnection,
    stored: &StoredBullBitcoinSettlement,
) -> Result<(), SettlementServiceError> {
    match stored.provider_state.as_str() {
        "reserved" | "dispatch_started" => {
            if abandon_dispatch_with_log(connection, stored, FallbackCategory::InvalidSplit).await?
            {
                Ok(())
            } else {
                Err(SettlementServiceError::StoredState)
            }
        }
        "bound" if stored.funding_route.is_none() && stored.funding_committed_at_unix.is_none() => {
            let routed =
                route_unfunded_mixed_with_log(connection, stored, FallbackCategory::InvalidSplit)
                    .await?;
            if routed {
                Ok(())
            } else {
                Err(SettlementServiceError::StoredState)
            }
        }
        _ => Err(SettlementServiceError::StoredState),
    }
}

fn liquid_script_pubkey_len(address: &str) -> Option<usize> {
    let address = boltz_client::elements::Address::from_str(address).ok()?;
    (address.params == &boltz_client::elements::AddressParams::LIQUID
        && address.blinding_pubkey.is_some())
    .then(|| address.script_pubkey().len())
}

async fn abandon_and_return(
    connection: &mut sqlx::PgConnection,
    stored: &StoredBullBitcoinSettlement,
    category: FallbackCategory,
) -> Result<FiatOnlyInstructionOutcome, SettlementServiceError> {
    abandon_dispatch_with_log(connection, stored, category).await?;
    Ok(FiatOnlyInstructionOutcome::BitcoinFallback {
        settlement_id: stored.id,
        category,
    })
}

fn stored_outcome(
    stored: &StoredBullBitcoinSettlement,
) -> Result<FiatOnlyInstructionOutcome, SettlementServiceError> {
    match (
        stored.provider_state.as_str(),
        stored.funding_route.as_deref(),
    ) {
        ("bound", Some("bull_bitcoin")) => {
            if stored.provider_missing_since_unix_micros.is_some() {
                // Retain the exact original instruction in durable storage for
                // audit and provider-authoritative recovery, but never project
                // it to a payer while the provider denies the order exists.
                return Err(SettlementServiceError::StoredState);
            }
            if stored.actual_received_sat.is_some() {
                // A provider funding observation permanently closes payer
                // admission even while payout reconciliation is still pending.
                return Err(SettlementServiceError::StoredState);
            }
            let order_id = stored
                .bull_bitcoin_order_id
                .ok_or(SettlementServiceError::StoredState)?;
            let kind = stored
                .instruction_kind
                .as_deref()
                .ok_or(SettlementServiceError::StoredState)?;
            let value = stored
                .payer_instruction
                .as_ref()
                .ok_or(SettlementServiceError::StoredState)?;
            Ok(FiatOnlyInstructionOutcome::BullBitcoin {
                settlement_id: stored.id,
                order_id,
                instruction: instruction_from_parts(kind, value)?,
                expires_at_unix: stored.instruction_expires_at_unix,
            })
        }
        ("abandoned", Some("bitcoin_fallback")) | ("bound", Some("bitcoin_fallback")) => {
            let category = FallbackCategory::parse(
                stored
                    .fallback_category
                    .as_deref()
                    .ok_or(SettlementServiceError::StoredState)?,
            )?;
            Ok(FiatOnlyInstructionOutcome::BitcoinFallback {
                settlement_id: stored.id,
                category,
            })
        }
        _ => Err(SettlementServiceError::StoredState),
    }
}

fn instruction_parts(instruction: &PayerInstruction) -> (&'static str, &str) {
    match instruction {
        PayerInstruction::Bitcoin { address_or_bip21 } => ("bitcoin", address_or_bip21),
        PayerInstruction::Lightning { bolt11 } => ("lightning", bolt11),
        PayerInstruction::Liquid {
            confidential_address,
        } => ("liquid", confidential_address),
    }
}

fn instruction_network(instruction: &PayerInstruction) -> BitcoinNetwork {
    match instruction {
        PayerInstruction::Bitcoin { .. } => BitcoinNetwork::Bitcoin,
        PayerInstruction::Lightning { .. } => BitcoinNetwork::Lightning,
        PayerInstruction::Liquid { .. } => BitcoinNetwork::Liquid,
    }
}

fn instruction_from_parts(
    kind: &str,
    value: &str,
) -> Result<PayerInstruction, SettlementServiceError> {
    match kind {
        "bitcoin" => Ok(PayerInstruction::Bitcoin {
            address_or_bip21: value.to_owned(),
        }),
        "lightning" => Ok(PayerInstruction::Lightning {
            bolt11: value.to_owned(),
        }),
        "liquid" => Ok(PayerInstruction::Liquid {
            confidential_address: value.to_owned(),
        }),
        _ => Err(SettlementServiceError::StoredState),
    }
}

fn fallback_for_definite_create_rejection(error: BullBitcoinError) -> Option<FallbackCategory> {
    match error {
        BullBitcoinError::Minimum => Some(FallbackCategory::BelowMinimum),
        BullBitcoinError::Maximum
        | BullBitcoinError::BenchmarkEligibilityDenied
        | BullBitcoinError::Authentication
        | BullBitcoinError::InvalidApiKey
        | BullBitcoinError::InvalidOwner
        | BullBitcoinError::InvalidProduct
        | BullBitcoinError::InvalidCurrency
        | BullBitcoinError::InvalidBitcoinAmount
        | BullBitcoinError::InvalidFiatAmount
        | BullBitcoinError::CredentialEncryption => Some(FallbackCategory::ConversionUnavailable),
        BullBitcoinError::Policy
        | BullBitcoinError::NotFound
        | BullBitcoinError::Timeout
        | BullBitcoinError::Transport
        | BullBitcoinError::Upstream
        | BullBitcoinError::MalformedResponse
        | BullBitcoinError::Integrity => None,
    }
}

pub async fn run_reconciler(state: AppState, cancel: CancellationToken) {
    let interval_secs = state.config.bull_bitcoin.reconcile_interval_secs;
    let stale_after_secs = state
        .config
        .bull_bitcoin
        .request_timeout_ms
        .div_ceil(1_000)
        .saturating_add(5);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {
                if let Err(error) = reconcile_once(&state, stale_after_secs).await {
                    tracing::error!(error = %error, "Bull Bitcoin settlement reconciliation tick failed");
                }
            }
        }
    }
}

async fn reconcile_once(
    state: &AppState,
    stale_after_secs: u64,
) -> Result<(), SettlementServiceError> {
    let stale_after_secs =
        i64::try_from(stale_after_secs).map_err(|_| SettlementServiceError::StoredState)?;
    let batch_size = i64::from(state.config.bull_bitcoin.reconcile_batch_size);
    let lease_secs = i64::try_from(
        state
            .config
            .bull_bitcoin
            .request_timeout_ms
            .div_ceil(1_000)
            .saturating_add(state.config.bull_bitcoin.reconcile_interval_secs),
    )
    .map_err(|_| SettlementServiceError::StoredState)?;
    let ambiguous_dispatches = db::claim_ambiguous_bull_bitcoin_dispatches(
        &state.db,
        stale_after_secs,
        lease_secs,
        batch_size,
    )
    .await
    .map_err(|_| SettlementServiceError::Database)?;
    let ambiguous_selected = ambiguous_dispatches.len();
    let mut first_row_error = None;
    for settlement in ambiguous_dispatches {
        let settlement_id = settlement.id;
        if let Err(error) = reconcile_ambiguous_dispatch(state, settlement).await {
            if error == SettlementServiceError::Database {
                return Err(error);
            }
            tracing::error!(
                %settlement_id,
                error = %error,
                "Ambiguous Bull Bitcoin create reconciliation row failed closed"
            );
            first_row_error.get_or_insert(error);
        }
    }

    let expired = db::expire_bull_bitcoin_retention(&state.db)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let settlements =
        db::claim_bull_bitcoin_reconciliation_batch(&state.db, batch_size, lease_secs)
            .await
            .map_err(|_| SettlementServiceError::Database)?;
    let selected = settlements.len();
    for settlement in settlements {
        let settlement_id = settlement.id;
        if let Err(error) = reconcile_settlement(state, settlement).await {
            if error == SettlementServiceError::Database {
                return Err(error);
            }
            tracing::error!(
                %settlement_id,
                error = %error,
                "Bull Bitcoin settlement reconciliation row failed closed"
            );
            first_row_error.get_or_insert(error);
        }
    }
    let erased = db::finalize_drained_bull_bitcoin_credentials(&state.db)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    if ambiguous_selected > 0 || expired > 0 || selected > 0 || erased > 0 {
        tracing::info!(
            ambiguous_create_dispatches = ambiguous_selected,
            expired_retention_rows = expired,
            reconciled_rows = selected,
            erased_drained_credentials = erased,
            "Bull Bitcoin settlement reconciliation progress"
        );
    }
    first_row_error.map_or(Ok(()), Err)
}

async fn reconcile_ambiguous_dispatch(
    state: &AppState,
    settlement: StoredBullBitcoinSettlement,
) -> Result<(), SettlementServiceError> {
    if settlement.provider_state != "dispatch_started"
        || settlement.funding_route.is_some()
        || settlement.settlement_status != "none"
        || settlement.funding_committed_at_unix.is_some()
        || settlement.provider_final
    {
        return Err(SettlementServiceError::StoredState);
    }
    let expected_order_id = settlement.bull_bitcoin_order_id;
    let currency = FiatCurrency::from_str(&settlement.fiat_currency)
        .map_err(|_| SettlementServiceError::StoredState)?;
    let network = if matches!(settlement.purpose.as_str(), "mixed" | "provider_only") {
        BitcoinNetwork::Liquid
    } else {
        match settlement.payer_rail.as_str() {
            "bitcoin" => BitcoinNetwork::Bitcoin,
            "lightning" => BitcoinNetwork::Lightning,
            "liquid" => BitcoinNetwork::Liquid,
            _ => return Err(SettlementServiceError::StoredState),
        }
    };
    let request = CreateSellRequest {
        request_id: settlement.id,
        currency,
        network,
        bitcoin_amount: BitcoinAmountSat::new(settlement.requested_bitcoin_sat)
            .map_err(|_| SettlementServiceError::StoredState)?,
        use_payjoin: false,
    };

    let mut connection = state
        .db
        .acquire()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let credential = db::load_bull_bitcoin_credential(&mut connection, settlement.credential_id)
        .await
        .map_err(|_| SettlementServiceError::Database)?
        .ok_or(SettlementServiceError::CredentialUnavailable)?;
    if credential.owner_npub != settlement.owner_npub {
        return Err(SettlementServiceError::StoredState);
    }
    let encryption_key = state
        .config
        .bull_bitcoin_credential_encryption_key
        .clone()
        .ok_or(SettlementServiceError::CredentialUnavailable)?;
    let scoped_key = decrypt_credential(encryption_key, &credential)
        .map_err(|_| SettlementServiceError::CredentialUnavailable)?;
    drop(connection);

    let recovered = match expected_order_id {
        Some(order_id) => {
            state
                .bull_bitcoin
                .recover_created_sell_to_balance(&scoped_key, order_id, &request)
                .await
        }
        None => {
            state
                .bull_bitcoin
                .recover_created_sell_to_balance_by_request_id(&scoped_key, &request)
                .await
        }
    };
    drop(scoped_key);
    let order = match recovered {
        Ok(order) => order,
        Err(BullBitcoinError::Authentication) => {
            db::invalidate_bull_bitcoin_credential(&state.db, settlement.credential_id)
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            return Ok(());
        }
        // A read-side NotFound cannot prove that a timed-out create handler
        // will never commit later. Keep the dispatch ambiguous and retry the
        // immutable request correlation instead of opening a second funding
        // route that could create two financial obligations.
        Err(BullBitcoinError::NotFound) if expected_order_id.is_none() => {
            tracing::warn!(
                event = "bull_bitcoin_request_correlation_not_found",
                settlement_id = %settlement.id,
                "Provider request correlation has not located the ambiguous create"
            );
            return Ok(());
        }
        Err(
            BullBitcoinError::NotFound
            | BullBitcoinError::Timeout
            | BullBitcoinError::Transport
            | BullBitcoinError::Upstream
            | BullBitcoinError::MalformedResponse
            | BullBitcoinError::Integrity,
        ) => return Ok(()),
        Err(_) => return Err(SettlementServiceError::StoredState),
    };
    if expected_order_id.is_some_and(|order_id| order.order_id != order_id)
        || order.currency != currency
        || order.network != network
        || order.requested_bitcoin != request.bitcoin_amount
        || instruction_network(&order.instruction) != network
        || (matches!(settlement.purpose.as_str(), "mixed" | "provider_only")
            && settlement
                .expected_instruction_script_len
                .and_then(|expected| usize::try_from(expected).ok())
                != match &order.instruction {
                    PayerInstruction::Liquid {
                        confidential_address,
                    } => liquid_script_pubkey_len(confidential_address),
                    _ => None,
                })
    {
        return Err(SettlementServiceError::StoredState);
    }

    let (kind, instruction) = instruction_parts(&order.instruction);
    let retention_secs = i64::try_from(state.config.bull_bitcoin.late_payment_retention_secs)
        .map_err(|_| SettlementServiceError::StoredState)?;
    let mut connection = state
        .db
        .acquire()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let bound = db::bind_bull_bitcoin_order(
        &mut connection,
        settlement.id,
        order.order_id,
        kind,
        instruction,
        order.expires_at_unix,
        retention_secs,
        order.quoted_fiat.map(|quote| quote.as_minor()),
    )
    .await
    .map_err(|_| SettlementServiceError::Database)?;
    if !bound {
        return Err(SettlementServiceError::StoredState);
    }
    tracing::info!(
        event = "bull_bitcoin_ambiguous_create_reconciled",
        settlement_id = %settlement.id,
        "Ambiguous Bull Bitcoin create was bound to its exact recovered order"
    );
    Ok(())
}

/// Run one bounded maintenance pass. The server normally uses
/// [`run_reconciler`]; this entry point lets deployment smoke tests exercise
/// the exact same work without waiting for the production cadence.
#[doc(hidden)]
pub async fn run_reconciliation_once(state: &AppState) -> Result<(), SettlementServiceError> {
    let stale_after_secs = state
        .config
        .bull_bitcoin
        .request_timeout_ms
        .div_ceil(1_000)
        .saturating_add(5);
    reconcile_once(state, stale_after_secs).await
}

async fn reconcile_settlement(
    state: &AppState,
    settlement: StoredBullBitcoinSettlement,
) -> Result<(), SettlementServiceError> {
    // A crash may commit provider finality before the idempotent invoice event.
    // The reconciliation selector includes exactly those rows, so repair uses
    // the already-normalized local values without another provider read.
    if settlement.settlement_status == "settled" {
        return record_final_invoice_payment(state, &settlement).await;
    }
    let order_id = settlement
        .bull_bitcoin_order_id
        .ok_or(SettlementServiceError::StoredState)?;
    let mut connection = state
        .db
        .acquire()
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let credential = db::load_bull_bitcoin_credential(&mut connection, settlement.credential_id)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let Some(credential) = credential else {
        db::record_bull_bitcoin_retry(
            &state.db,
            settlement.id,
            retry_delay_secs(state, settlement.reconcile_attempts),
            late_payment_watch_delay_secs(state),
        )
        .await
        .map_err(|_| SettlementServiceError::Database)?;
        return Ok(());
    };
    let Some(encryption_key) = state.config.bull_bitcoin_credential_encryption_key.clone() else {
        db::record_bull_bitcoin_retry(
            &state.db,
            settlement.id,
            retry_delay_secs(state, settlement.reconcile_attempts),
            late_payment_watch_delay_secs(state),
        )
        .await
        .map_err(|_| SettlementServiceError::Database)?;
        return Ok(());
    };
    let scoped_key = match decrypt_credential(encryption_key, &credential) {
        Ok(key) => key,
        Err(_) => {
            db::record_bull_bitcoin_terminal_problem(&state.db, settlement.id, "integrity_error")
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            return Ok(());
        }
    };
    // Do not reserve a database-pool slot across provider I/O. In particular,
    // a one-connection worker pool must still be able to persist the result.
    drop(connection);
    let observation = state
        .bull_bitcoin
        .get_created_order(&scoped_key, order_id)
        .await;
    // A 404 proves the endpoint answered, but not that the configured route
    // and credential still reach the authenticated provider method. Require a
    // read-only authenticated preflight before the persistent-missing state
    // can be entered; temporary 404 evidence is still recorded if this probe
    // is unavailable.
    let provider_health_after_not_found = if observation == Err(BullBitcoinError::NotFound) {
        Some(
            state
                .bull_bitcoin
                .validate_sell_to_balance(&scoped_key)
                .await,
        )
    } else {
        None
    };
    drop(scoped_key);

    match observation {
        Ok(observation) => {
            if observation.order_id != order_id
                || observation.currency.as_str() != settlement.fiat_currency
            {
                db::record_bull_bitcoin_terminal_problem(
                    &state.db,
                    settlement.id,
                    "integrity_error",
                )
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            } else {
                let prefetched_rate = if settlement.actual_received_sat.is_none()
                    && observation.actual_received_sat.is_some()
                {
                    match settlement.invoice_id {
                        Some(invoice_id) => {
                            crate::invoice::prefetch_provider_observation_rate(
                                state,
                                invoice_id,
                                settlement.invoice_quote_version_id,
                            )
                            .await
                        }
                        None => None,
                    }
                } else {
                    None
                };
                let valuation_candidate = prefetched_rate
                    .as_ref()
                    .and_then(crate::invoice::quote_candidate_from_rate);
                db::record_bull_bitcoin_observation(
                    &state.db,
                    settlement.id,
                    &observation,
                    i64::try_from(state.config.bull_bitcoin.reconcile_interval_secs)
                        .map_err(|_| SettlementServiceError::StoredState)?,
                    late_payment_watch_delay_secs(state),
                    valuation_candidate.as_ref(),
                )
                .await
                .map_err(|_| SettlementServiceError::Database)?;
                if settlement.provider_missing_since_unix_micros.is_some() {
                    let financial_evidence_present =
                        db::bull_bitcoin_financial_evidence_present(&state.db, settlement.id)
                            .await
                            .map_err(|_| SettlementServiceError::Database)?;
                    tracing::info!(
                        event = "bull_bitcoin_provider_order_missing_resolved",
                        settlement_id = %settlement.id,
                        financial_evidence_present,
                        "A persistent exact-order NotFound hold was resolved by an authoritative provider observation"
                    );
                }
                if observation.provider_final {
                    let mut connection = state
                        .db
                        .acquire()
                        .await
                        .map_err(|_| SettlementServiceError::Database)?;
                    let finalized =
                        db::load_bull_bitcoin_settlement(&mut connection, settlement.id)
                            .await
                            .map_err(|_| SettlementServiceError::Database)?;
                    drop(connection);
                    record_final_invoice_payment(state, &finalized).await?;
                }
            }
        }
        Err(BullBitcoinError::Authentication) => {
            db::record_bull_bitcoin_provider_authentication_retry(
                &state.db,
                settlement.id,
                retry_delay_secs(state, settlement.reconcile_attempts),
                late_payment_watch_delay_secs(state),
            )
            .await
            .map_err(|_| SettlementServiceError::Database)?;
            tracing::error!(
                event = "bull_bitcoin_provider_order_read_authentication_failure",
                settlement_id = %settlement.id,
                persistent_missing = settlement.provider_missing_since_unix_micros.is_some(),
                "A previously bound Bull Bitcoin order could not be read with its retained credential generation"
            );
        }
        Err(BullBitcoinError::Integrity | BullBitcoinError::MalformedResponse) => {
            db::record_bull_bitcoin_terminal_problem(&state.db, settlement.id, "integrity_error")
                .await
                .map_err(|_| SettlementServiceError::Database)?;
        }
        Err(BullBitcoinError::NotFound) => {
            if provider_health_after_not_found == Some(Err(BullBitcoinError::Authentication)) {
                db::record_bull_bitcoin_provider_authentication_retry(
                    &state.db,
                    settlement.id,
                    retry_delay_secs(state, settlement.reconcile_attempts),
                    late_payment_watch_delay_secs(state),
                )
                .await
                .map_err(|_| SettlementServiceError::Database)?;
                tracing::error!(
                    event = "bull_bitcoin_provider_order_read_authentication_failure",
                    settlement_id = %settlement.id,
                    persistent_missing = settlement.provider_missing_since_unix_micros.is_some(),
                    "An exact-order NotFound could not be qualified because the authenticated preflight failed"
                );
                return Ok(());
            }
            let provider_api_healthy = matches!(
                provider_health_after_not_found,
                Some(Ok(())) | Some(Err(BullBitcoinError::BenchmarkEligibilityDenied))
            );
            let escalation_attempts = i32::try_from(
                state
                    .config
                    .bull_bitcoin
                    .provider_not_found_escalation_attempts,
            )
            .map_err(|_| SettlementServiceError::StoredState)?;
            let escalation_secs =
                i64::try_from(state.config.bull_bitcoin.provider_not_found_escalation_secs)
                    .map_err(|_| SettlementServiceError::StoredState)?;
            let outcome = db::record_bull_bitcoin_provider_not_found(
                &state.db,
                settlement.id,
                retry_delay_secs(state, settlement.reconcile_attempts),
                late_payment_watch_delay_secs(state),
                escalation_attempts,
                escalation_secs,
                provider_api_healthy,
            )
            .await
            .map_err(|_| SettlementServiceError::Database)?;
            if outcome.escalated_now {
                tracing::error!(
                    event = provider_not_found_event(&outcome, provider_api_healthy),
                    settlement_id = %settlement.id,
                    consecutive_not_found = outcome.consecutive,
                    financial_evidence_present = outcome.financial_evidence_present,
                    provider_api_healthy,
                    "A previously bound Bull Bitcoin order remained missing past both escalation thresholds"
                );
            } else if outcome.persistent_missing {
                tracing::warn!(
                    event = provider_not_found_event(&outcome, provider_api_healthy),
                    settlement_id = %settlement.id,
                    consecutive_not_found = outcome.consecutive,
                    financial_evidence_present = outcome.financial_evidence_present,
                    provider_api_healthy,
                    "A persistent missing-order hold remains under low-cadence exact-order watch"
                );
            } else if provider_api_healthy {
                tracing::warn!(
                    event = provider_not_found_event(&outcome, provider_api_healthy),
                    settlement_id = %settlement.id,
                    consecutive_not_found = outcome.consecutive,
                    persistent_missing = outcome.persistent_missing,
                    provider_api_healthy,
                    "An authenticated exact-order read returned NotFound"
                );
            } else {
                tracing::warn!(
                    event = provider_not_found_event(&outcome, provider_api_healthy),
                    settlement_id = %settlement.id,
                    consecutive_not_found = outcome.consecutive,
                    provider_api_healthy,
                    "An exact-order NotFound did not qualify because provider health could not be authenticated"
                );
            }
        }
        Err(
            BullBitcoinError::Timeout | BullBitcoinError::Transport | BullBitcoinError::Upstream,
        ) => {
            db::record_bull_bitcoin_provider_transient_retry(
                &state.db,
                settlement.id,
                retry_delay_secs(state, settlement.reconcile_attempts),
                late_payment_watch_delay_secs(state),
            )
            .await
            .map_err(|_| SettlementServiceError::Database)?;
            tracing::warn!(
                event = "bull_bitcoin_provider_order_read_transient_failure",
                settlement_id = %settlement.id,
                persistent_missing = settlement.provider_missing_since_unix_micros.is_some(),
                "A retryable exact-order provider read failed"
            );
        }
        Err(_) => {
            db::record_bull_bitcoin_terminal_problem(&state.db, settlement.id, "integrity_error")
                .await
                .map_err(|_| SettlementServiceError::Database)?;
        }
    }
    Ok(())
}

async fn record_final_invoice_payment(
    state: &AppState,
    settlement: &StoredBullBitcoinSettlement,
) -> Result<(), SettlementServiceError> {
    if !settlement.provider_final
        || settlement.settlement_status != "settled"
        || settlement.funding_route.as_deref() != Some("bull_bitcoin")
        || settlement.funding_committed_at_unix.is_none()
    {
        return Err(SettlementServiceError::StoredState);
    }
    let Some(invoice_id) = settlement.invoice_id else {
        // Lightning Address settlement accounting has no invoice projection.
        return Ok(());
    };
    if settlement.purpose == "mixed" {
        // The Bitcoin amount was already recorded from immutable vout=1 claim
        // evidence. Provider finality supplies only the exact fiat projection;
        // inserting another satoshi event here would double-count the payment.
        return Ok(());
    }
    let amount_sat = settlement
        .actual_received_sat
        .filter(|amount| *amount > 0)
        .ok_or(SettlementServiceError::StoredState)?;
    settlement
        .credited_fiat_minor
        .filter(|amount| *amount > 0)
        .ok_or(SettlementServiceError::StoredState)?;
    let event_key = format!("bull_bitcoin_fiat:{}", settlement.id);
    db::record_invoice_payment(
        &state.db,
        invoice_id,
        db::InvoicePaymentEvidence {
            rail: &settlement.payer_rail,
            source: "bull_bitcoin_fiat",
            event_key: &event_key,
            amount_sat,
            txid: None,
            vout: None,
            boltz_swap_id: None,
            address: None,
            bull_bitcoin_settlement_id: Some(settlement.id),
        },
        db::InvoiceAccountingTolerances::from(&state.config.invoice_accounting),
    )
    .await
    .map_err(|_| SettlementServiceError::Database)?;
    Ok(())
}

fn decrypt_credential(
    key: BullBitcoinEncryptionKey,
    credential: &db::StoredEncryptedCredential,
) -> Result<crate::bull_bitcoin::ScopedApiKey, BullBitcoinError> {
    CredentialCipher::new(key).decrypt(credential.id, &credential.owner_npub, &credential.encrypted)
}

fn retry_delay_secs(state: &AppState, attempts: i32) -> i64 {
    let exponent = u32::try_from(attempts.max(0)).unwrap_or(0).min(20);
    let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    let delay = state
        .config
        .bull_bitcoin
        .reconcile_interval_secs
        .saturating_mul(multiplier)
        .min(state.config.bull_bitcoin.retry_backoff_cap_secs);
    i64::try_from(delay).unwrap_or(i64::MAX)
}

fn late_payment_watch_delay_secs(state: &AppState) -> i64 {
    i64::try_from(state.config.bull_bitcoin.late_payment_watch_interval_secs).unwrap_or(i64::MAX)
}

fn provider_not_found_event(
    outcome: &db::ProviderNotFoundOutcome,
    provider_api_healthy: bool,
) -> &'static str {
    if outcome.escalated_now {
        "bull_bitcoin_provider_order_persistently_missing"
    } else if outcome.persistent_missing {
        "bull_bitcoin_provider_order_persistent_missing_watch"
    } else if provider_api_healthy {
        "bull_bitcoin_provider_order_temporarily_not_found"
    } else {
        "bull_bitcoin_provider_order_not_found_unverified"
    }
}

fn map_store_error(error: BullBitcoinSettlementStoreError) -> SettlementServiceError {
    match error {
        BullBitcoinSettlementStoreError::SourceIdentityNotActive => {
            SettlementServiceError::SourceIdentityUnavailable
        }
        BullBitcoinSettlementStoreError::CredentialUnavailable => {
            SettlementServiceError::CredentialUnavailable
        }
        BullBitcoinSettlementStoreError::RequestKeyConflict => {
            SettlementServiceError::RequestKeyConflict
        }
        BullBitcoinSettlementStoreError::IllegalState => SettlementServiceError::StoredState,
        BullBitcoinSettlementStoreError::Sqlx(_) => SettlementServiceError::Database,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_settlement_for_log() -> StoredBullBitcoinSettlement {
        StoredBullBitcoinSettlement {
            id: Uuid::new_v4(),
            owner_npub: "owner-secret-canary".into(),
            invoice_id: Some(Uuid::new_v4()),
            invoice_quote_version_id: None,
            reverse_swap_id: Some(Uuid::new_v4()),
            chain_swap_id: None,
            credential_id: Uuid::new_v4(),
            product: "api-orders".into(),
            purpose: "mixed".into(),
            payer_rail: "lightning".into(),
            request_key: "request-secret-canary".into(),
            fiat_percentage: 40,
            fiat_currency: "CAD".into(),
            provider_state: "abandoned".into(),
            funding_route: Some("bitcoin_fallback".into()),
            fallback_category: Some("below_minimum".into()),
            settlement_status: "none".into(),
            requested_bitcoin_sat: 7_794,
            bull_bitcoin_order_id: None,
            order_correlation_source: None,
            order_correlated_at_unix_micros: None,
            expected_instruction_script_len: None,
            instruction_kind: Some("liquid".into()),
            payer_instruction: Some("payer-instruction-secret-canary".into()),
            instruction_expires_at_unix: None,
            funding_committed_at_unix: None,
            retention_until_unix: None,
            reconcile_attempts: 0,
            actual_received_sat: None,
            provider_payment_first_observed_at_unix_micros: None,
            quote_payment_first_observed_at_unix_micros: None,
            credited_fiat_minor: Some(500),
            quoted_fiat_minor: Some(500),
            execution_rate_minor_per_btc: None,
            provider_final: false,
            provider_last_read_error_class: None,
            provider_last_read_error_at_unix_micros: None,
            provider_last_success_at_unix_micros: None,
            provider_not_found_first_at_unix_micros: None,
            provider_not_found_consecutive: 0,
            provider_missing_since_unix_micros: None,
            provider_missing_last_resolved_at_unix_micros: None,
        }
    }

    #[test]
    fn provider_not_found_event_taxonomy_is_stable_and_persistent_is_not_temporary() {
        let temporary = db::ProviderNotFoundOutcome {
            consecutive: 1,
            escalated_now: false,
            persistent_missing: false,
            financial_evidence_present: false,
        };
        assert_eq!(
            provider_not_found_event(&temporary, true),
            "bull_bitcoin_provider_order_temporarily_not_found"
        );
        assert_eq!(
            provider_not_found_event(&temporary, false),
            "bull_bitcoin_provider_order_not_found_unverified"
        );

        let persistent = db::ProviderNotFoundOutcome {
            consecutive: 0,
            escalated_now: false,
            persistent_missing: true,
            financial_evidence_present: true,
        };
        assert_eq!(
            provider_not_found_event(&persistent, false),
            "bull_bitcoin_provider_order_persistent_missing_watch"
        );

        let escalated = db::ProviderNotFoundOutcome {
            consecutive: 3,
            escalated_now: true,
            persistent_missing: true,
            financial_evidence_present: true,
        };
        assert_eq!(
            provider_not_found_event(&escalated, true),
            "bull_bitcoin_provider_order_persistently_missing"
        );
    }

    #[test]
    fn create_error_fallbacks_are_conservative() {
        assert_eq!(
            fallback_for_definite_create_rejection(BullBitcoinError::Minimum),
            Some(FallbackCategory::BelowMinimum)
        );
        for error in [
            BullBitcoinError::Timeout,
            BullBitcoinError::Transport,
            BullBitcoinError::Upstream,
            BullBitcoinError::MalformedResponse,
            BullBitcoinError::Integrity,
        ] {
            assert_eq!(fallback_for_definite_create_rejection(error), None);
        }
        assert_eq!(
            fallback_for_definite_create_rejection(BullBitcoinError::BenchmarkEligibilityDenied),
            Some(FallbackCategory::ConversionUnavailable)
        );
        assert_eq!(
            fallback_for_definite_create_rejection(BullBitcoinError::Policy),
            None
        );
    }

    #[test]
    fn public_fallback_projection_preserves_known_categories() {
        for known in [
            "below_minimum",
            "invalid_split",
            "conversion_unavailable",
            "ambiguous_create",
        ] {
            assert_eq!(projected_fallback_reason(Some(known)), known);
        }
        assert_eq!(projected_fallback_reason(None), "unknown");
        assert_eq!(
            projected_fallback_reason(Some("future_category")),
            "unknown"
        );
    }

    #[test]
    fn committed_fallback_log_fields_are_stable_and_privacy_minimal() {
        let stored = stored_settlement_for_log();
        let fields = fallback_decision_log_fields(
            &stored,
            FallbackCategory::BelowMinimum,
            "dispatch_abandoned",
        );
        assert_eq!(fields.event, "bull_bitcoin_fallback_committed");
        assert_eq!(fields.category, "below_minimum");
        assert_eq!(fields.requested_sats, 7_794);
        assert_eq!(fields.fiat_currency, "CAD");
        assert_eq!(fields.fiat_amount_minor, Some(500));
        assert_eq!(fields.invoice_id, stored.invoice_id);
        assert_eq!(fields.settlement_id, stored.id);
        assert_eq!(fields.selected_fallback_rail, "bitcoin");
        assert!(fields.speculative);

        let rendered = format!("{fields:?}");
        for secret in [
            "owner-secret-canary",
            "request-secret-canary",
            "payer-instruction-secret-canary",
        ] {
            assert!(!rendered.contains(secret));
        }
    }
}
