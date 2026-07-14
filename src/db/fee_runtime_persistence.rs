use std::fmt;

use async_trait::async_trait;
use sqlx::PgPool;

use crate::current_fee_snapshot::{CurrentBitcoinFee, CurrentFeeSnapshot, CurrentLiquidFee};
use crate::fee_policy::{BitcoinFeePolicy, FeeRail, LiquidFeePolicy};
use crate::fee_runtime::{FeePersistenceDisposition, FeePersistenceError, FeeRuntimePersistence};

use super::{
    load_fee_last_known_good, persist_fee_last_known_good, AcceptedFeeObservation,
    PersistFeeObservationOutcome, PersistedFeeObservation,
};

/// Production PostgreSQL adapter for runtime fee restore and accepted-live
/// persistence. Clones share SQLx's bounded pool.
#[derive(Clone)]
pub struct PgFeeRuntimePersistence {
    pool: PgPool,
}

impl PgFeeRuntimePersistence {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn persist_bitcoin(
        &self,
        snapshot: &CurrentFeeSnapshot,
        candidate: AcceptedFeeObservation,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
        let outcome = persist_fee_last_known_good(&self.pool, &candidate)
            .await
            .map_err(|_| FeePersistenceError::WriteFailed)?;
        match outcome {
            PersistFeeObservationOutcome::Applied(row)
            | PersistFeeObservationOutcome::Unchanged(row) => {
                if !row.authorizes(&candidate) {
                    return Err(FeePersistenceError::WriteFailed);
                }
                restore_bitcoin(snapshot, &row, FeePersistenceError::WriteFailed)?;
                Ok(FeePersistenceDisposition::AcceptedLive)
            }
            PersistFeeObservationOutcome::IgnoredStale(row) => {
                if row.accepted().rail() != FeeRail::Bitcoin
                    || row.accepted().observed_at_unix() <= candidate.observed_at_unix()
                {
                    return Err(FeePersistenceError::WriteFailed);
                }
                restore_bitcoin(snapshot, &row, FeePersistenceError::WriteFailed)?;
                Ok(FeePersistenceDisposition::RestoredAuthoritative)
            }
        }
    }

    async fn persist_liquid(
        &self,
        snapshot: &CurrentFeeSnapshot,
        candidate: AcceptedFeeObservation,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
        let outcome = persist_fee_last_known_good(&self.pool, &candidate)
            .await
            .map_err(|_| FeePersistenceError::WriteFailed)?;
        match outcome {
            PersistFeeObservationOutcome::Applied(row)
            | PersistFeeObservationOutcome::Unchanged(row) => {
                if !row.authorizes(&candidate) {
                    return Err(FeePersistenceError::WriteFailed);
                }
                restore_liquid(snapshot, &row, FeePersistenceError::WriteFailed)?;
                Ok(FeePersistenceDisposition::AcceptedLive)
            }
            PersistFeeObservationOutcome::IgnoredStale(row) => {
                if row.accepted().rail() != FeeRail::Liquid
                    || row.accepted().observed_at_unix() <= candidate.observed_at_unix()
                {
                    return Err(FeePersistenceError::WriteFailed);
                }
                restore_liquid(snapshot, &row, FeePersistenceError::WriteFailed)?;
                Ok(FeePersistenceDisposition::RestoredAuthoritative)
            }
        }
    }
}

impl fmt::Debug for PgFeeRuntimePersistence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgFeeRuntimePersistence")
            .field("pool", &"<redacted>")
            .finish()
    }
}

#[async_trait]
impl FeeRuntimePersistence for PgFeeRuntimePersistence {
    async fn restore(&self, snapshot: &CurrentFeeSnapshot) -> Result<(), FeePersistenceError> {
        let (bitcoin, liquid) = tokio::try_join!(
            load_fee_last_known_good(&self.pool, FeeRail::Bitcoin),
            load_fee_last_known_good(&self.pool, FeeRail::Liquid),
        )
        .map_err(|_| FeePersistenceError::RestoreFailed)?;

        // Validate both rows and build both typed values before mutating the
        // process snapshot, so malformed cross-rail persistence fails closed.
        let bitcoin = bitcoin
            .as_ref()
            .map(PersistedFeeObservation::restore_bitcoin_last_known_good)
            .transpose()
            .map_err(|_| FeePersistenceError::RestoreFailed)?;
        let liquid = liquid
            .as_ref()
            .map(PersistedFeeObservation::restore_liquid_last_known_good)
            .transpose()
            .map_err(|_| FeePersistenceError::RestoreFailed)?;

        if let Some(bitcoin) = bitcoin {
            snapshot
                .restore_bitcoin_last_known_good(bitcoin)
                .map_err(|_| FeePersistenceError::RestoreFailed)?;
        }
        if let Some(liquid) = liquid {
            snapshot
                .restore_liquid_last_known_good(liquid)
                .map_err(|_| FeePersistenceError::RestoreFailed)?;
        }
        Ok(())
    }

    async fn persist_accepted_bitcoin(
        &self,
        snapshot: &CurrentFeeSnapshot,
        current: &CurrentBitcoinFee,
        policy: &BitcoinFeePolicy,
        accepted_at_unix: u64,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
        let candidate = AcceptedFeeObservation::bitcoin(current, policy, accepted_at_unix)
            .map_err(|_| FeePersistenceError::WriteFailed)?;
        self.persist_bitcoin(snapshot, candidate).await
    }

    async fn persist_accepted_liquid(
        &self,
        snapshot: &CurrentFeeSnapshot,
        current: &CurrentLiquidFee,
        policy: &LiquidFeePolicy,
        accepted_at_unix: u64,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
        let candidate = AcceptedFeeObservation::liquid(current, policy, accepted_at_unix)
            .map_err(|_| FeePersistenceError::WriteFailed)?;
        self.persist_liquid(snapshot, candidate).await
    }
}

fn restore_bitcoin(
    snapshot: &CurrentFeeSnapshot,
    row: &PersistedFeeObservation,
    error: FeePersistenceError,
) -> Result<(), FeePersistenceError> {
    let observation = row.restore_bitcoin_last_known_good().map_err(|_| error)?;
    snapshot
        .restore_bitcoin_last_known_good(observation)
        .map_err(|_| error)?;
    Ok(())
}

fn restore_liquid(
    snapshot: &CurrentFeeSnapshot,
    row: &PersistedFeeObservation,
    error: FeePersistenceError,
) -> Result<(), FeePersistenceError> {
    let observation = row.restore_liquid_last_known_good().map_err(|_| error)?;
    snapshot
        .restore_liquid_last_known_good(observation)
        .map_err(|_| error)?;
    Ok(())
}
