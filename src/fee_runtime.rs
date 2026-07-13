use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::admission::MoneyAdmission;
use crate::config::FeePolicyConfig;
use crate::current_fee_snapshot::{CurrentBitcoinFee, CurrentFeeSnapshot, CurrentLiquidFee};
use crate::fee_decision_record::{FeeConstructionPurpose, FeeDecisionRecord};
use crate::fee_policy::{
    BitcoinFeeDecision, BitcoinFeePolicy, FeeObservationSource, FeePolicyError, FeeRail,
    LiquidFeeDecision, LiquidFeePolicy,
};
use crate::fee_refresh_cycle::{
    FeeRailRefreshOutcome, FeeRefreshClockError, FeeRefreshCycle, FeeRefreshCycleOutcome,
};
use crate::runtime_fee_sources::{RuntimeFeeSourceProjectionError, RuntimeFeeSourceSets};

/// Persistence boundary owned by the runtime coordinator. Implementations must
/// restore only validated, same-rail LKG evidence and must durably persist an
/// accepted live decision before returning success.
#[async_trait]
pub trait FeeRuntimePersistence: Send + Sync {
    async fn restore(&self, snapshot: &CurrentFeeSnapshot) -> Result<(), FeePersistenceError>;

    async fn persist_accepted_bitcoin(
        &self,
        snapshot: &CurrentFeeSnapshot,
        current: &CurrentBitcoinFee,
        policy: &BitcoinFeePolicy,
        accepted_at_unix: u64,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError>;

    async fn persist_accepted_liquid(
        &self,
        snapshot: &CurrentFeeSnapshot,
        current: &CurrentLiquidFee,
        policy: &LiquidFeePolicy,
        accepted_at_unix: u64,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError>;
}

/// Standalone composition placeholder. It deliberately fails every operation,
/// so it cannot make a production process ready before the database adapter is
/// supplied by the persistence lane.
#[derive(Debug, Default)]
pub struct UnavailableFeeRuntimePersistence;

#[async_trait]
impl FeeRuntimePersistence for UnavailableFeeRuntimePersistence {
    async fn restore(&self, _snapshot: &CurrentFeeSnapshot) -> Result<(), FeePersistenceError> {
        Err(FeePersistenceError::Unavailable)
    }

    async fn persist_accepted_bitcoin(
        &self,
        _snapshot: &CurrentFeeSnapshot,
        _current: &CurrentBitcoinFee,
        _policy: &BitcoinFeePolicy,
        _accepted_at_unix: u64,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
        Err(FeePersistenceError::Unavailable)
    }

    async fn persist_accepted_liquid(
        &self,
        _snapshot: &CurrentFeeSnapshot,
        _current: &CurrentLiquidFee,
        _policy: &LiquidFeePolicy,
        _accepted_at_unix: u64,
    ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
        Err(FeePersistenceError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeePersistenceError {
    Unavailable,
    RestoreFailed,
    WriteFailed,
}

impl fmt::Display for FeePersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "fee persistence is unavailable",
            Self::RestoreFailed => "fee persistence restore failed",
            Self::WriteFailed => "fee persistence write failed",
        })
    }
}

impl Error for FeePersistenceError {}

/// Whether the just-observed live candidate became durable or lost a
/// cross-process ordering race to a newer row that the adapter restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeePersistenceDisposition {
    AcceptedLive,
    RestoredAuthoritative,
}

#[derive(Debug)]
pub enum FeeRuntimeBuildError {
    Sources(RuntimeFeeSourceProjectionError),
    Policy(FeePolicyError),
}

impl fmt::Display for FeeRuntimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sources(error) => write!(formatter, "invalid runtime fee sources: {error}"),
            Self::Policy(error) => write!(formatter, "invalid runtime fee policy: {error}"),
        }
    }
}

impl Error for FeeRuntimeBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sources(error) => Some(error),
            Self::Policy(error) => Some(error),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeRuntimeUnavailable {
    Clock,
    Bitcoin,
    Liquid,
    NotDurable(FeeRail),
    DecisionRecord,
}

impl fmt::Display for FeeRuntimeUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Clock => "fee runtime clock is unavailable",
            Self::Bitcoin => "current Bitcoin fee decision is unavailable",
            Self::Liquid => "current Liquid fee decision is unavailable",
            Self::NotDurable(FeeRail::Bitcoin) => {
                "current Bitcoin fee decision is not durably accepted"
            }
            Self::NotDurable(FeeRail::Liquid) => {
                "current Liquid fee decision is not durably accepted"
            }
            Self::DecisionRecord => "current fee decision metadata is unavailable",
        })
    }
}

impl Error for FeeRuntimeUnavailable {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeRuntimeReadiness {
    bitcoin: bool,
    liquid: bool,
}

impl FeeRuntimeReadiness {
    pub const fn bitcoin_ready(self) -> bool {
        self.bitcoin
    }

    pub const fn liquid_ready(self) -> bool {
        self.liquid
    }

    pub const fn ready(self) -> bool {
        self.bitcoin && self.liquid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeRailPersistenceOutcome {
    NotUpdated,
    Persisted,
    AuthoritativeRetained,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRuntimeRefreshReport {
    refresh: FeeRefreshCycleOutcome,
    bitcoin_persistence: FeeRailPersistenceOutcome,
    liquid_persistence: FeeRailPersistenceOutcome,
    readiness: FeeRuntimeReadiness,
}

impl FeeRuntimeRefreshReport {
    pub const fn refresh(self) -> FeeRefreshCycleOutcome {
        self.refresh
    }

    pub const fn bitcoin_persistence(self) -> FeeRailPersistenceOutcome {
        self.bitcoin_persistence
    }

    pub const fn liquid_persistence(self) -> FeeRailPersistenceOutcome {
        self.liquid_persistence
    }

    pub const fn readiness(self) -> FeeRuntimeReadiness {
        self.readiness
    }
}

/// Shared production coordinator for fee acquisition, accepted-state
/// persistence, readiness, and construction-boundary decision reads.
pub struct FeeRuntime {
    source_sets: RuntimeFeeSourceSets,
    bitcoin_policy: BitcoinFeePolicy,
    liquid_policy: LiquidFeePolicy,
    snapshot: CurrentFeeSnapshot,
    persistence: Arc<dyn FeeRuntimePersistence>,
    bitcoin_refresh_interval: Duration,
    liquid_refresh_interval: Duration,
    refresh_lock: tokio::sync::Mutex<()>,
    bitcoin_persisted_generation: AtomicU64,
    liquid_persisted_generation: AtomicU64,
    bitcoin_lkg_authorized: AtomicBool,
    liquid_lkg_authorized: AtomicBool,
}

impl FeeRuntime {
    pub fn from_config(
        config: &FeePolicyConfig,
        persistence: Arc<dyn FeeRuntimePersistence>,
    ) -> Result<Self, FeeRuntimeBuildError> {
        let source_sets =
            RuntimeFeeSourceSets::from_config(config).map_err(FeeRuntimeBuildError::Sources)?;
        let bitcoin_settings = source_sets.bitcoin_settings();
        let liquid_settings = source_sets.liquid_settings();
        let bitcoin_policy = BitcoinFeePolicy::new(
            bitcoin_settings.floor(),
            bitcoin_settings.cap(),
            bitcoin_settings.live_max_age().as_secs(),
            bitcoin_settings.last_known_good_max_age().as_secs(),
        )
        .map_err(FeeRuntimeBuildError::Policy)?;
        let liquid_policy = LiquidFeePolicy::with_freshness(
            liquid_settings.floor(),
            liquid_settings.cap(),
            liquid_settings.live_max_age().as_secs(),
            liquid_settings.last_known_good_max_age().as_secs(),
        )
        .map_err(FeeRuntimeBuildError::Policy)?;
        Ok(Self {
            source_sets,
            bitcoin_policy,
            liquid_policy,
            snapshot: CurrentFeeSnapshot::new(),
            persistence,
            bitcoin_refresh_interval: bitcoin_settings.refresh_interval(),
            liquid_refresh_interval: liquid_settings.refresh_interval(),
            refresh_lock: tokio::sync::Mutex::new(()),
            bitcoin_persisted_generation: AtomicU64::new(0),
            liquid_persisted_generation: AtomicU64::new(0),
            bitcoin_lkg_authorized: AtomicBool::new(false),
            liquid_lkg_authorized: AtomicBool::new(false),
        })
    }

    /// Restore persisted evidence, refresh both live rails, persist newly
    /// accepted live decisions, and only then compute the startup fact.
    pub async fn initialize(&self) -> FeeRuntimeRefreshReport {
        match self.persistence.restore(&self.snapshot).await {
            Ok(()) => self.authorize_restored_evidence(),
            Err(error) => tracing::warn!(
                event = "fee_lkg_restore_failed",
                error = %error,
                "persisted fee evidence could not be restored; fee readiness remains closed"
            ),
        }
        self.refresh_once().await
    }

    pub async fn refresh_once(&self) -> FeeRuntimeRefreshReport {
        let _guard = self.refresh_lock.lock().await;
        let now = unix_now();
        let cycle = FeeRefreshCycle::new(
            &self.source_sets,
            &self.bitcoin_policy,
            &self.liquid_policy,
            &self.snapshot,
        );
        let refresh = match now {
            Ok(now_unix) => cycle.refresh_once(|_| Ok(now_unix)).await,
            Err(_) => {
                cycle
                    .refresh_once(|_| Err(FeeRefreshClockError::Unavailable))
                    .await
            }
        };

        let (bitcoin_persistence, liquid_persistence) = match now {
            Ok(now_unix) => {
                let bitcoin = self
                    .persist_bitcoin_if_updated(refresh.bitcoin(), now_unix)
                    .await;
                let liquid = self
                    .persist_liquid_if_updated(refresh.liquid(), now_unix)
                    .await;
                (bitcoin, liquid)
            }
            Err(_) => (
                FeeRailPersistenceOutcome::NotUpdated,
                FeeRailPersistenceOutcome::NotUpdated,
            ),
        };
        let readiness = now
            .map(|now_unix| self.readiness_at(now_unix))
            .unwrap_or_default();

        FeeRuntimeRefreshReport {
            refresh,
            bitcoin_persistence,
            liquid_persistence,
            readiness,
        }
    }

    pub fn readiness_now(&self) -> FeeRuntimeReadiness {
        unix_now()
            .map(|now_unix| self.readiness_at(now_unix))
            .unwrap_or_default()
    }

    pub fn bitcoin_decision_now(&self) -> Result<BitcoinFeeDecision, FeeRuntimeUnavailable> {
        let now_unix = unix_now()?;
        self.bitcoin_current_at(now_unix)
            .map(|current| current.decision().clone())
    }

    pub fn liquid_decision_now(&self) -> Result<LiquidFeeDecision, FeeRuntimeUnavailable> {
        let now_unix = unix_now()?;
        self.liquid_current_at(now_unix)
            .map(|current| current.decision().clone())
    }

    /// Read and bind a Bitcoin construction decision at one clock instant.
    pub fn bitcoin_construction_decision_now(
        &self,
        purpose: FeeConstructionPurpose,
    ) -> Result<(BitcoinFeeDecision, FeeDecisionRecord), FeeRuntimeUnavailable> {
        let now_unix = unix_now()?;
        let decision = self.bitcoin_current_at(now_unix)?.decision().clone();
        let record =
            FeeDecisionRecord::from_bitcoin(purpose, &decision, &self.bitcoin_policy, now_unix)
                .map_err(|_| FeeRuntimeUnavailable::DecisionRecord)?;
        Ok((decision, record))
    }

    /// Read and bind a Liquid construction decision at one clock instant.
    pub fn liquid_construction_decision_now(
        &self,
        purpose: FeeConstructionPurpose,
    ) -> Result<(LiquidFeeDecision, FeeDecisionRecord), FeeRuntimeUnavailable> {
        let now_unix = unix_now()?;
        let decision = self.liquid_current_at(now_unix)?.decision().clone();
        let record =
            FeeDecisionRecord::from_liquid(purpose, &decision, &self.liquid_policy, now_unix)
                .map_err(|_| FeeRuntimeUnavailable::DecisionRecord)?;
        Ok((decision, record))
    }

    pub fn spawn_background(
        self: Arc<Self>,
        admission: MoneyAdmission,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let readiness_runtime = self.clone();
            let readiness_admission = admission.clone();
            let readiness_loop = async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                // Startup initialization supplied the first fact.
                tick.tick().await;
                loop {
                    tick.tick().await;
                    readiness_admission
                        .set_fee_policy_ready(readiness_runtime.readiness_now().ready());
                }
            };

            let refresh_loop = async move {
                let mut bitcoin_tick = tokio::time::interval(self.bitcoin_refresh_interval);
                let mut liquid_tick = tokio::time::interval(self.liquid_refresh_interval);
                // Startup initialization supplied both first observations.
                bitcoin_tick.tick().await;
                liquid_tick.tick().await;
                loop {
                    tokio::select! {
                        _ = bitcoin_tick.tick() => {
                            let (outcome, persistence, readiness) =
                                self.refresh_rail(FeeRail::Bitcoin).await;
                            admission.set_fee_policy_ready(readiness.ready());
                            tracing::info!(
                                event = "fee_refresh_completed",
                                rail = FeeRail::Bitcoin.as_str(),
                                outcome = ?outcome,
                                persistence = ?persistence,
                                ready = readiness.ready(),
                                "runtime Bitcoin fee refresh completed"
                            );
                        }
                        _ = liquid_tick.tick() => {
                            let (outcome, persistence, readiness) =
                                self.refresh_rail(FeeRail::Liquid).await;
                            admission.set_fee_policy_ready(readiness.ready());
                            tracing::info!(
                                event = "fee_refresh_completed",
                                rail = FeeRail::Liquid.as_str(),
                                outcome = ?outcome,
                                persistence = ?persistence,
                                ready = readiness.ready(),
                                "runtime Liquid fee refresh completed"
                            );
                        }
                    }
                }
            };

            // Keep freshness admission responsive while an acquisition is
            // waiting on remote I/O. Cancellation drops both loops together.
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = readiness_loop => {}
                _ = refresh_loop => {}
            }
        })
    }

    async fn refresh_rail(
        &self,
        rail: FeeRail,
    ) -> (
        FeeRailRefreshOutcome,
        FeeRailPersistenceOutcome,
        FeeRuntimeReadiness,
    ) {
        let _guard = self.refresh_lock.lock().await;
        let now = unix_now();
        let cycle = FeeRefreshCycle::new(
            &self.source_sets,
            &self.bitcoin_policy,
            &self.liquid_policy,
            &self.snapshot,
        );
        let outcome = match (rail, now) {
            (FeeRail::Bitcoin, Ok(now_unix)) => cycle.refresh_bitcoin_once(|_| Ok(now_unix)).await,
            (FeeRail::Liquid, Ok(now_unix)) => cycle.refresh_liquid_once(|_| Ok(now_unix)).await,
            (FeeRail::Bitcoin, Err(_)) => {
                cycle
                    .refresh_bitcoin_once(|_| Err(FeeRefreshClockError::Unavailable))
                    .await
            }
            (FeeRail::Liquid, Err(_)) => {
                cycle
                    .refresh_liquid_once(|_| Err(FeeRefreshClockError::Unavailable))
                    .await
            }
        };
        let persistence = match (rail, now) {
            (FeeRail::Bitcoin, Ok(now_unix)) => {
                self.persist_bitcoin_if_updated(outcome, now_unix).await
            }
            (FeeRail::Liquid, Ok(now_unix)) => {
                self.persist_liquid_if_updated(outcome, now_unix).await
            }
            (_, Err(_)) => FeeRailPersistenceOutcome::NotUpdated,
        };
        let readiness = now
            .map(|now_unix| self.readiness_at(now_unix))
            .unwrap_or_default();
        (outcome, persistence, readiness)
    }

    fn authorize_restored_evidence(&self) {
        let Ok(now_unix) = unix_now() else {
            return;
        };
        if self
            .snapshot
            .read_bitcoin(&self.bitcoin_policy, now_unix)
            .is_ok_and(|current| {
                current.decision().source() == FeeObservationSource::BitcoinLastKnownGood
            })
        {
            self.bitcoin_lkg_authorized.store(true, Ordering::Release);
        }
        if self
            .snapshot
            .read_liquid(&self.liquid_policy, now_unix)
            .is_ok_and(|current| {
                current.decision().source() == FeeObservationSource::LiquidLastKnownGood
            })
        {
            self.liquid_lkg_authorized.store(true, Ordering::Release);
        }
    }

    async fn persist_bitcoin_if_updated(
        &self,
        outcome: FeeRailRefreshOutcome,
        now_unix: u64,
    ) -> FeeRailPersistenceOutcome {
        if !matches!(outcome, FeeRailRefreshOutcome::Updated { .. }) {
            return FeeRailPersistenceOutcome::NotUpdated;
        }
        let Ok(current) = self.snapshot.read_bitcoin(&self.bitcoin_policy, now_unix) else {
            self.bitcoin_persisted_generation
                .store(0, Ordering::Release);
            let _ = self.snapshot.clear_bitcoin();
            return FeeRailPersistenceOutcome::Failed;
        };
        let decision = current.decision().clone();
        let disposition = match self
            .persistence
            .persist_accepted_bitcoin(&self.snapshot, &current, &self.bitcoin_policy, now_unix)
            .await
        {
            Ok(disposition) => disposition,
            Err(_) => {
                self.bitcoin_persisted_generation
                    .store(0, Ordering::Release);
                let _ = self.snapshot.clear_bitcoin();
                return FeeRailPersistenceOutcome::Failed;
            }
        };
        if disposition == FeePersistenceDisposition::RestoredAuthoritative {
            self.bitcoin_persisted_generation
                .store(0, Ordering::Release);
            if self.snapshot.clear_bitcoin().is_err() {
                return FeeRailPersistenceOutcome::Failed;
            }
            let restored = self
                .snapshot
                .read_bitcoin(&self.bitcoin_policy, now_unix)
                .is_ok_and(|current| {
                    current.decision().source() == FeeObservationSource::BitcoinLastKnownGood
                });
            self.bitcoin_lkg_authorized
                .store(restored, Ordering::Release);
            return if restored {
                FeeRailPersistenceOutcome::AuthoritativeRetained
            } else {
                FeeRailPersistenceOutcome::Failed
            };
        }
        let Ok(current) = self.snapshot.read_bitcoin(&self.bitcoin_policy, now_unix) else {
            self.bitcoin_persisted_generation
                .store(0, Ordering::Release);
            let _ = self.snapshot.clear_bitcoin();
            return FeeRailPersistenceOutcome::Failed;
        };
        if current.decision() != &decision {
            self.bitcoin_persisted_generation
                .store(0, Ordering::Release);
            let _ = self.snapshot.clear_bitcoin();
            return FeeRailPersistenceOutcome::Failed;
        }
        self.bitcoin_persisted_generation
            .store(current.generation().as_u64(), Ordering::Release);
        self.bitcoin_lkg_authorized.store(true, Ordering::Release);
        FeeRailPersistenceOutcome::Persisted
    }

    async fn persist_liquid_if_updated(
        &self,
        outcome: FeeRailRefreshOutcome,
        now_unix: u64,
    ) -> FeeRailPersistenceOutcome {
        if !matches!(outcome, FeeRailRefreshOutcome::Updated { .. }) {
            return FeeRailPersistenceOutcome::NotUpdated;
        }
        let Ok(current) = self.snapshot.read_liquid(&self.liquid_policy, now_unix) else {
            self.liquid_persisted_generation.store(0, Ordering::Release);
            let _ = self.snapshot.clear_liquid();
            return FeeRailPersistenceOutcome::Failed;
        };
        let decision = current.decision().clone();
        let disposition = match self
            .persistence
            .persist_accepted_liquid(&self.snapshot, &current, &self.liquid_policy, now_unix)
            .await
        {
            Ok(disposition) => disposition,
            Err(_) => {
                self.liquid_persisted_generation.store(0, Ordering::Release);
                let _ = self.snapshot.clear_liquid();
                return FeeRailPersistenceOutcome::Failed;
            }
        };
        if disposition == FeePersistenceDisposition::RestoredAuthoritative {
            self.liquid_persisted_generation.store(0, Ordering::Release);
            if self.snapshot.clear_liquid().is_err() {
                return FeeRailPersistenceOutcome::Failed;
            }
            let restored = self
                .snapshot
                .read_liquid(&self.liquid_policy, now_unix)
                .is_ok_and(|current| {
                    current.decision().source() == FeeObservationSource::LiquidLastKnownGood
                });
            self.liquid_lkg_authorized
                .store(restored, Ordering::Release);
            return if restored {
                FeeRailPersistenceOutcome::AuthoritativeRetained
            } else {
                FeeRailPersistenceOutcome::Failed
            };
        }
        let Ok(current) = self.snapshot.read_liquid(&self.liquid_policy, now_unix) else {
            self.liquid_persisted_generation.store(0, Ordering::Release);
            let _ = self.snapshot.clear_liquid();
            return FeeRailPersistenceOutcome::Failed;
        };
        if current.decision() != &decision {
            self.liquid_persisted_generation.store(0, Ordering::Release);
            let _ = self.snapshot.clear_liquid();
            return FeeRailPersistenceOutcome::Failed;
        }
        self.liquid_persisted_generation
            .store(current.generation().as_u64(), Ordering::Release);
        self.liquid_lkg_authorized.store(true, Ordering::Release);
        FeeRailPersistenceOutcome::Persisted
    }

    fn readiness_at(&self, now_unix: u64) -> FeeRuntimeReadiness {
        FeeRuntimeReadiness {
            bitcoin: self.bitcoin_current_at(now_unix).is_ok(),
            liquid: self.liquid_current_at(now_unix).is_ok(),
        }
    }

    fn bitcoin_current_at(
        &self,
        now_unix: u64,
    ) -> Result<CurrentBitcoinFee, FeeRuntimeUnavailable> {
        let current = self
            .snapshot
            .read_bitcoin(&self.bitcoin_policy, now_unix)
            .map_err(|_| FeeRuntimeUnavailable::Bitcoin)?;
        match current.decision().source() {
            FeeObservationSource::LiveBitcoin
                if self.bitcoin_persisted_generation.load(Ordering::Acquire)
                    == current.generation().as_u64() =>
            {
                Ok(current)
            }
            FeeObservationSource::BitcoinLastKnownGood
                if self.bitcoin_lkg_authorized.load(Ordering::Acquire) =>
            {
                Ok(current)
            }
            _ => Err(FeeRuntimeUnavailable::NotDurable(FeeRail::Bitcoin)),
        }
    }

    fn liquid_current_at(&self, now_unix: u64) -> Result<CurrentLiquidFee, FeeRuntimeUnavailable> {
        let current = self
            .snapshot
            .read_liquid(&self.liquid_policy, now_unix)
            .map_err(|_| FeeRuntimeUnavailable::Liquid)?;
        match current.decision().source() {
            FeeObservationSource::LiveLiquid
                if self.liquid_persisted_generation.load(Ordering::Acquire)
                    == current.generation().as_u64() =>
            {
                Ok(current)
            }
            FeeObservationSource::LiquidLastKnownGood
                if self.liquid_lkg_authorized.load(Ordering::Acquire) =>
            {
                Ok(current)
            }
            _ => Err(FeeRuntimeUnavailable::NotDurable(FeeRail::Liquid)),
        }
    }
}

impl fmt::Debug for FeeRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeeRuntime")
            .field("source_sets", &"<redacted>")
            .field("snapshot", &"<redacted>")
            .field("bitcoin_refresh_interval", &self.bitcoin_refresh_interval)
            .field("liquid_refresh_interval", &self.liquid_refresh_interval)
            .finish()
    }
}

fn unix_now() -> Result<u64, FeeRuntimeUnavailable> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| FeeRuntimeUnavailable::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_policy::{FeeProvenance, LiveBitcoin, LiveLiquid, SatPerVbyte};

    fn runtime() -> FeeRuntime {
        FeeRuntime::from_config(
            &FeePolicyConfig::default(),
            Arc::new(UnavailableFeeRuntimePersistence),
        )
        .unwrap()
    }

    #[test]
    fn readiness_requires_both_current_decisions_to_match_persisted_generations() {
        let runtime = runtime();
        let now = 10_000;
        let bitcoin_generation = runtime
            .snapshot
            .update_bitcoin(LiveBitcoin::new(
                SatPerVbyte::try_from(2.0).unwrap(),
                now,
                FeeProvenance::new("bitcoin-test").unwrap(),
            ))
            .unwrap();
        let liquid_generation = runtime
            .snapshot
            .update_liquid(LiveLiquid::new(
                SatPerVbyte::try_from(0.2).unwrap(),
                now,
                FeeProvenance::new("liquid-test").unwrap(),
            ))
            .unwrap();

        runtime
            .bitcoin_persisted_generation
            .store(bitcoin_generation.as_u64(), Ordering::Release);
        assert!(!runtime.readiness_at(now).ready());
        runtime
            .liquid_persisted_generation
            .store(liquid_generation.as_u64(), Ordering::Release);
        assert!(runtime.readiness_at(now).ready());

        runtime.snapshot.clear_liquid().unwrap();
        assert!(!runtime.readiness_at(now).ready());
    }

    #[test]
    fn stale_evidence_fails_closed_even_after_matching_persistence() {
        let runtime = runtime();
        let observed_at = 10_000;
        let bitcoin_generation = runtime
            .snapshot
            .update_bitcoin(LiveBitcoin::new(
                SatPerVbyte::try_from(2.0).unwrap(),
                observed_at,
                FeeProvenance::new("bitcoin-test").unwrap(),
            ))
            .unwrap();
        runtime
            .bitcoin_persisted_generation
            .store(bitcoin_generation.as_u64(), Ordering::Release);

        assert!(runtime.bitcoin_current_at(observed_at).is_ok());
        assert!(runtime
            .bitcoin_current_at(observed_at + runtime.bitcoin_policy.live_max_age_secs() + 1)
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn freshness_monitor_closes_admission_while_refresh_is_blocked() {
        let mut config = FeePolicyConfig::default();
        config.bitcoin.refresh_interval_secs = 1;
        config.liquid.refresh_interval_secs = 1;
        let runtime = Arc::new(
            FeeRuntime::from_config(&config, Arc::new(UnavailableFeeRuntimePersistence)).unwrap(),
        );
        let admission = MoneyAdmission::healthy_test_fixture();
        let cancel = CancellationToken::new();

        // Model a refresh held in slow source or persistence I/O. The
        // independent one-second freshness task must still close admission.
        let refresh_guard = runtime.refresh_lock.lock().await;
        let task = runtime
            .clone()
            .spawn_background(admission.clone(), cancel.clone());
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        assert!(!admission
            .decision(crate::admission::Rail::LightningReverse)
            .allowed());
        assert!(!admission
            .decision(crate::admission::Rail::BitcoinChain)
            .allowed());

        cancel.cancel();
        task.await.unwrap();
        drop(refresh_guard);
    }
}
