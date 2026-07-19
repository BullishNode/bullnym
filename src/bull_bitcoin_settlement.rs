//! Write-ahead Bull Bitcoin order lifecycle and narrow reconciliation worker.
//!
//! A create crosses `reserved -> dispatch_started` before the one provider
//! call. Any surviving ambiguous dispatch is abandoned to Bitcoin and never
//! retried. Exact bound orders are the only rows the reconciler may query.

use sqlx::postgres::PgAdvisoryLock;
use std::fmt;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::bull_bitcoin::{
    BitcoinAmountSat, BitcoinNetwork, BullBitcoinError, CreateSellRequest, CredentialCipher,
    FiatCurrency, PayerInstruction, Product, TERMS_VERSION,
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

#[derive(Clone, Debug)]
pub struct FiatOnlyInstructionRequest<'a> {
    pub owner_npub: &'a str,
    pub invoice_id: Option<Uuid>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementServiceError {
    SourceIdentityUnavailable,
    CredentialUnavailable,
    RequestKeyConflict,
    StoredState,
    Database,
}

impl fmt::Display for SettlementServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SourceIdentityUnavailable => "fiat-settlement identity is unavailable",
            Self::CredentialUnavailable => "fiat-settlement credential is unavailable",
            Self::RequestKeyConflict => "fiat-settlement request identity conflicts",
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

async fn create_fiat_only_instruction_locked(
    state: &AppState,
    request: &FiatOnlyInstructionRequest<'_>,
    connection: &mut sqlx::PgConnection,
) -> Result<FiatOnlyInstructionOutcome, SettlementServiceError> {
    let reservation = NewBullBitcoinSettlement {
        owner_npub: request.owner_npub,
        invoice_id: request.invoice_id,
        credential_id: request.credential_id,
        product: request.product.as_str(),
        purpose: "fiat_only",
        payer_rail: request.network.as_str(),
        request_key: request.request_key,
        fiat_percentage: 100,
        fiat_currency: request.fiat_currency.as_str(),
        terms_version: TERMS_VERSION,
        requested_bitcoin_sat: request.bitcoin_amount.as_sat(),
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
            db::abandon_bull_bitcoin_dispatch(
                connection,
                stored.id,
                FallbackCategory::AmbiguousCreate.as_str(),
            )
            .await
            .map_err(|_| SettlementServiceError::Database)?;
            stored = db::load_bull_bitcoin_settlement(connection, stored.id)
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            return stored_outcome(&stored);
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
        return abandon_and_return(
            connection,
            stored.id,
            FallbackCategory::ConversionUnavailable,
        )
        .await;
    };
    if credential.owner_npub != stored.owner_npub {
        return Err(SettlementServiceError::StoredState);
    }
    let Some(encryption_key) = state.config.bull_bitcoin_credential_encryption_key.clone() else {
        return abandon_and_return(
            connection,
            stored.id,
            FallbackCategory::ConversionUnavailable,
        )
        .await;
    };
    let scoped_key = match CredentialCipher::new(encryption_key).decrypt(
        credential.id,
        &credential.owner_npub,
        &credential.encrypted,
    ) {
        Ok(key) => key,
        Err(_) => {
            return abandon_and_return(
                connection,
                stored.id,
                FallbackCategory::ConversionUnavailable,
            )
            .await
        }
    };

    let provider_request = CreateSellRequest {
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
                db::abandon_bull_bitcoin_dispatch(
                    connection,
                    stored.id,
                    FallbackCategory::AmbiguousCreate.as_str(),
                )
                .await
                .map_err(|_| SettlementServiceError::Database)?;
                return Ok(FiatOnlyInstructionOutcome::BitcoinFallback {
                    settlement_id: stored.id,
                    category: FallbackCategory::AmbiguousCreate,
                });
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
        Err(error) => {
            let category = fallback_for_create_error(error);
            db::abandon_bull_bitcoin_dispatch(connection, stored.id, category.as_str())
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            if error == BullBitcoinError::Authentication {
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

async fn abandon_and_return(
    connection: &mut sqlx::PgConnection,
    settlement_id: Uuid,
    category: FallbackCategory,
) -> Result<FiatOnlyInstructionOutcome, SettlementServiceError> {
    db::abandon_bull_bitcoin_dispatch(connection, settlement_id, category.as_str())
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    Ok(FiatOnlyInstructionOutcome::BitcoinFallback {
        settlement_id,
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

fn fallback_for_create_error(error: BullBitcoinError) -> FallbackCategory {
    match error {
        BullBitcoinError::Minimum => FallbackCategory::BelowMinimum,
        BullBitcoinError::Maximum
        | BullBitcoinError::Policy
        | BullBitcoinError::Authentication
        | BullBitcoinError::NotFound
        | BullBitcoinError::InvalidApiKey
        | BullBitcoinError::InvalidOwner
        | BullBitcoinError::InvalidProduct
        | BullBitcoinError::InvalidCurrency
        | BullBitcoinError::InvalidBitcoinAmount
        | BullBitcoinError::InvalidFiatAmount
        | BullBitcoinError::CredentialEncryption => FallbackCategory::ConversionUnavailable,
        BullBitcoinError::Timeout
        | BullBitcoinError::Transport
        | BullBitcoinError::Upstream
        | BullBitcoinError::MalformedResponse
        | BullBitcoinError::Integrity => FallbackCategory::AmbiguousCreate,
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
    let recovered = db::recover_stale_bull_bitcoin_dispatches(&state.db, stale_after_secs)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    let expired = db::expire_bull_bitcoin_retention(&state.db)
        .await
        .map_err(|_| SettlementServiceError::Database)?;

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
    let settlements =
        db::claim_bull_bitcoin_reconciliation_batch(&state.db, batch_size, lease_secs)
            .await
            .map_err(|_| SettlementServiceError::Database)?;
    let selected = settlements.len();
    for settlement in settlements {
        reconcile_settlement(state, settlement).await?;
    }
    let erased = db::finalize_drained_bull_bitcoin_credentials(&state.db)
        .await
        .map_err(|_| SettlementServiceError::Database)?;
    if recovered > 0 || expired > 0 || selected > 0 || erased > 0 {
        tracing::info!(
            recovered_ambiguous_dispatches = recovered,
            expired_retention_rows = expired,
            reconciled_rows = selected,
            erased_drained_credentials = erased,
            "Bull Bitcoin settlement reconciliation progress"
        );
    }
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
                db::record_bull_bitcoin_observation(
                    &state.db,
                    settlement.id,
                    &observation,
                    i64::try_from(state.config.bull_bitcoin.reconcile_interval_secs)
                        .map_err(|_| SettlementServiceError::StoredState)?,
                )
                .await
                .map_err(|_| SettlementServiceError::Database)?;
            }
        }
        Err(BullBitcoinError::Authentication) => {
            db::invalidate_bull_bitcoin_credential(&state.db, settlement.credential_id)
                .await
                .map_err(|_| SettlementServiceError::Database)?;
        }
        Err(BullBitcoinError::Integrity | BullBitcoinError::MalformedResponse) => {
            db::record_bull_bitcoin_terminal_problem(&state.db, settlement.id, "integrity_error")
                .await
                .map_err(|_| SettlementServiceError::Database)?;
        }
        Err(
            BullBitcoinError::Timeout
            | BullBitcoinError::Transport
            | BullBitcoinError::Upstream
            | BullBitcoinError::NotFound,
        ) => {
            db::record_bull_bitcoin_retry(
                &state.db,
                settlement.id,
                retry_delay_secs(state, settlement.reconcile_attempts),
            )
            .await
            .map_err(|_| SettlementServiceError::Database)?;
        }
        Err(_) => {
            db::record_bull_bitcoin_terminal_problem(&state.db, settlement.id, "integrity_error")
                .await
                .map_err(|_| SettlementServiceError::Database)?;
        }
    }
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

    #[test]
    fn create_error_fallbacks_are_conservative() {
        assert_eq!(
            fallback_for_create_error(BullBitcoinError::Minimum),
            FallbackCategory::BelowMinimum
        );
        for error in [
            BullBitcoinError::Timeout,
            BullBitcoinError::Transport,
            BullBitcoinError::Upstream,
            BullBitcoinError::MalformedResponse,
            BullBitcoinError::Integrity,
        ] {
            assert_eq!(
                fallback_for_create_error(error),
                FallbackCategory::AmbiguousCreate
            );
        }
    }
}
