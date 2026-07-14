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
    unix_time_high_watermark: AtomicU64,
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
            unix_time_high_watermark: AtomicU64::new(0),
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
        self.refresh_once_with_clock(refresh_unix_now).await
    }

    async fn refresh_once_with_clock<C>(&self, clock: C) -> FeeRuntimeRefreshReport
    where
        C: Fn() -> Result<u64, FeeRefreshClockError> + Sync,
    {
        let _guard = self.refresh_lock.lock().await;
        let cycle = FeeRefreshCycle::new(
            &self.source_sets,
            &self.bitcoin_policy,
            &self.liquid_policy,
            &self.snapshot,
        );
        // The cycle invokes this clock only after an adapter has stamped its
        // validated response. Sample again after both acquisitions for durable
        // acceptance, then again after persistence for current readiness.
        let refresh = cycle
            .refresh_once(|_| self.sample_refresh_clock(&clock))
            .await;
        let persistence_now = self.sample_refresh_clock(&clock);

        let (bitcoin_persistence, liquid_persistence) = match persistence_now {
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
                self.discard_unpersisted_bitcoin(refresh.bitcoin()),
                self.discard_unpersisted_liquid(refresh.liquid()),
            ),
        };
        let readiness = self
            .sample_refresh_clock(&clock)
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
        self.effective_unix_now()
            .map(|now_unix| self.readiness_at(now_unix))
            .unwrap_or_default()
    }

    pub fn bitcoin_decision_now(&self) -> Result<BitcoinFeeDecision, FeeRuntimeUnavailable> {
        let now_unix = self.effective_unix_now()?;
        self.bitcoin_current_at(now_unix)
            .map(|current| current.decision().clone())
    }

    pub fn liquid_decision_now(&self) -> Result<LiquidFeeDecision, FeeRuntimeUnavailable> {
        let now_unix = self.effective_unix_now()?;
        self.liquid_current_at(now_unix)
            .map(|current| current.decision().clone())
    }

    /// Read and bind a Bitcoin construction decision at one clock instant.
    pub fn bitcoin_construction_decision_now(
        &self,
        purpose: FeeConstructionPurpose,
    ) -> Result<(BitcoinFeeDecision, FeeDecisionRecord), FeeRuntimeUnavailable> {
        let now_unix = self.effective_unix_now()?;
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
        let now_unix = self.effective_unix_now()?;
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
        // Startup may do substantial work after initialize() supplied the
        // admission seed. Re-sample synchronously so spawning never exposes a
        // stale startup readiness fact until the first one-second tick.
        admission.set_fee_policy_ready(self.readiness_now().ready());
        tokio::spawn(async move {
            let readiness_runtime = self.clone();
            let readiness_admission = admission.clone();
            let readiness_loop = async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                // The synchronous spawn handoff supplied the first fact.
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
        self.refresh_rail_with_clock(rail, refresh_unix_now).await
    }

    async fn refresh_rail_with_clock<C>(
        &self,
        rail: FeeRail,
        clock: C,
    ) -> (
        FeeRailRefreshOutcome,
        FeeRailPersistenceOutcome,
        FeeRuntimeReadiness,
    )
    where
        C: Fn() -> Result<u64, FeeRefreshClockError> + Sync,
    {
        let _guard = self.refresh_lock.lock().await;
        let cycle = FeeRefreshCycle::new(
            &self.source_sets,
            &self.bitcoin_policy,
            &self.liquid_policy,
            &self.snapshot,
        );
        // As above, policy time follows the response timestamp, durable
        // acceptance uses a post-acquisition sample, and readiness is sampled
        // only after persistence completes.
        let outcome = match rail {
            FeeRail::Bitcoin => {
                cycle
                    .refresh_bitcoin_once(|_| self.sample_refresh_clock(&clock))
                    .await
            }
            FeeRail::Liquid => {
                cycle
                    .refresh_liquid_once(|_| self.sample_refresh_clock(&clock))
                    .await
            }
        };
        let persistence_now = self.sample_refresh_clock(&clock);
        let persistence = match (rail, persistence_now) {
            (FeeRail::Bitcoin, Ok(now_unix)) => {
                self.persist_bitcoin_if_updated(outcome, now_unix).await
            }
            (FeeRail::Liquid, Ok(now_unix)) => {
                self.persist_liquid_if_updated(outcome, now_unix).await
            }
            (FeeRail::Bitcoin, Err(_)) => self.discard_unpersisted_bitcoin(outcome),
            (FeeRail::Liquid, Err(_)) => self.discard_unpersisted_liquid(outcome),
        };
        let readiness = self
            .sample_refresh_clock(&clock)
            .map(|now_unix| self.readiness_at(now_unix))
            .unwrap_or_default();
        (outcome, persistence, readiness)
    }

    fn authorize_restored_evidence(&self) {
        let Ok(now_unix) = self.effective_unix_now() else {
            return;
        };
        if self
            .snapshot
            .read_bitcoin(&self.bitcoin_policy, now_unix)
            .is_ok_and(|current| self.bitcoin_authority_is_consistent(&current))
        {
            self.bitcoin_lkg_authorized.store(true, Ordering::Release);
        }
        if self
            .snapshot
            .read_liquid(&self.liquid_policy, now_unix)
            .is_ok_and(|current| self.liquid_authority_is_consistent(&current))
        {
            self.liquid_lkg_authorized.store(true, Ordering::Release);
        }
    }

    fn sample_refresh_clock<C>(&self, clock: &C) -> Result<u64, FeeRefreshClockError>
    where
        C: Fn() -> Result<u64, FeeRefreshClockError> + ?Sized,
    {
        clock().map(|sample| self.retain_latest_unix_time(sample))
    }

    fn effective_unix_now(&self) -> Result<u64, FeeRuntimeUnavailable> {
        unix_now().map(|sample| self.retain_latest_unix_time(sample))
    }

    fn retain_latest_unix_time(&self, sample: u64) -> u64 {
        // Once evidence has aged out, a wall-clock rollback must not make the
        // same durable observation fresh again within this process.
        let previous = self
            .unix_time_high_watermark
            .fetch_max(sample, Ordering::AcqRel);
        previous.max(sample)
    }

    fn discard_unpersisted_bitcoin(
        &self,
        outcome: FeeRailRefreshOutcome,
    ) -> FeeRailPersistenceOutcome {
        if !matches!(outcome, FeeRailRefreshOutcome::Updated { .. }) {
            return FeeRailPersistenceOutcome::NotUpdated;
        }
        self.bitcoin_persisted_generation
            .store(0, Ordering::Release);
        let _ = self.snapshot.clear_bitcoin();
        FeeRailPersistenceOutcome::Failed
    }

    fn discard_unpersisted_liquid(
        &self,
        outcome: FeeRailRefreshOutcome,
    ) -> FeeRailPersistenceOutcome {
        if !matches!(outcome, FeeRailRefreshOutcome::Updated { .. }) {
            return FeeRailPersistenceOutcome::NotUpdated;
        }
        self.liquid_persisted_generation.store(0, Ordering::Release);
        let _ = self.snapshot.clear_liquid();
        FeeRailPersistenceOutcome::Failed
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
                .is_ok_and(|current| self.bitcoin_authority_is_consistent(&current));
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
                .is_ok_and(|current| self.liquid_authority_is_consistent(&current));
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
        if !self.bitcoin_authority_is_consistent(&current) {
            return Err(FeeRuntimeUnavailable::NotDurable(FeeRail::Bitcoin));
        }
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
        if !self.liquid_authority_is_consistent(&current) {
            return Err(FeeRuntimeUnavailable::NotDurable(FeeRail::Liquid));
        }
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

    fn bitcoin_authority_is_consistent(&self, current: &CurrentBitcoinFee) -> bool {
        matches!(
            current.decision().source(),
            FeeObservationSource::LiveBitcoin | FeeObservationSource::BitcoinLastKnownGood
        ) && self
            .source_sets
            .authorizes_bitcoin_provenance(current.decision().provenance())
    }

    fn liquid_authority_is_consistent(&self, current: &CurrentLiquidFee) -> bool {
        matches!(
            current.decision().source(),
            FeeObservationSource::LiveLiquid | FeeObservationSource::LiquidLastKnownGood
        ) && self
            .source_sets
            .authorizes_liquid_provenance(current.decision().provenance())
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

fn refresh_unix_now() -> Result<u64, FeeRefreshClockError> {
    unix_now().map_err(|_| FeeRefreshClockError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_fee_adapter::{MempoolFastestFeeAdapter, OrderedMempoolFeeSources};
    use crate::fee_policy::{
        FeeProvenance, LiquidLastKnownGood, LiveBitcoin, LiveLiquid, SatPerVbyte,
    };
    use crate::liquid_fee_adapter::LiquidEsploraTargetOneFeeAdapter;
    use crate::liquid_fee_sources::{LiquidFeeSource, LiquidFeeSourceId, LiquidFeeSources};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    const TEST_SOURCE_TIMEOUT: Duration = Duration::from_secs(2);
    const TEST_PERSISTENCE_TIME: u64 = i64::MAX as u64;
    const TEST_EVALUATION_TIME: u64 = TEST_PERSISTENCE_TIME - 1;
    const TEST_READINESS_TIME: u64 = u64::MAX;
    const DEFAULT_BITCOIN_PROVENANCE: &str = "mempool_precise_fastest_fee:bull-bitcoin";
    const DEFAULT_LIQUID_PROVENANCE: &str = "liquid_esplora_target_1_fee:liquid-network";
    const TEST_BITCOIN_PROVENANCE: &str = "mempool_precise_fastest_fee:bitcoin-test";
    const TEST_LIQUID_PROVENANCE: &str = "liquid_esplora_target_1_fee:liquid-test";

    #[derive(Default)]
    struct RecordingPersistence {
        accepted: Mutex<Vec<(FeeRail, u64, u64)>>,
    }

    impl RecordingPersistence {
        fn accepted(&self) -> Vec<(FeeRail, u64, u64)> {
            self.accepted.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl FeeRuntimePersistence for RecordingPersistence {
        async fn restore(&self, _snapshot: &CurrentFeeSnapshot) -> Result<(), FeePersistenceError> {
            Ok(())
        }

        async fn persist_accepted_bitcoin(
            &self,
            _snapshot: &CurrentFeeSnapshot,
            current: &CurrentBitcoinFee,
            _policy: &BitcoinFeePolicy,
            accepted_at_unix: u64,
        ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
            self.accepted.lock().unwrap().push((
                FeeRail::Bitcoin,
                current.decision().observed_at_unix(),
                accepted_at_unix,
            ));
            Ok(FeePersistenceDisposition::AcceptedLive)
        }

        async fn persist_accepted_liquid(
            &self,
            _snapshot: &CurrentFeeSnapshot,
            current: &CurrentLiquidFee,
            _policy: &LiquidFeePolicy,
            accepted_at_unix: u64,
        ) -> Result<FeePersistenceDisposition, FeePersistenceError> {
            self.accepted.lock().unwrap().push((
                FeeRail::Liquid,
                current.decision().observed_at_unix(),
                accepted_at_unix,
            ));
            Ok(FeePersistenceDisposition::AcceptedLive)
        }
    }

    struct HeldFeeServer {
        endpoint: String,
        response_released: Arc<AtomicBool>,
        request_seen: Option<oneshot::Receiver<()>>,
        release_response: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl HeldFeeServer {
        async fn spawn(body: &'static [u8]) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (request_seen_tx, request_seen) = oneshot::channel();
            let (release_response, release_response_rx) = oneshot::channel();
            let response_released = Arc::new(AtomicBool::new(false));
            let released = Arc::clone(&response_released);
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1_024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 || request.len() + read > 16 * 1_024 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                request_seen_tx.send(()).unwrap();
                release_response_rx.await.unwrap();
                released.store(true, Ordering::Release);
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
            });
            Self {
                endpoint: format!("http://{address}/fees"),
                response_released,
                request_seen: Some(request_seen),
                release_response: Some(release_response),
                task,
            }
        }

        async fn wait_until_requested(&mut self) {
            self.request_seen.take().unwrap().await.unwrap();
        }

        fn release(&mut self) {
            self.release_response.take().unwrap().send(()).unwrap();
        }

        async fn finish(self) {
            self.task.await.unwrap();
        }
    }

    fn runtime_sources(
        bitcoin_endpoint: &str,
        liquid_endpoint: Option<&str>,
    ) -> RuntimeFeeSourceSets {
        let bitcoin = OrderedMempoolFeeSources::new(vec![
            MempoolFastestFeeAdapter::new_for_test_loopback_http_with_identity(
                "bitcoin-test",
                bitcoin_endpoint,
                TEST_SOURCE_TIMEOUT,
            )
            .unwrap(),
        ])
        .unwrap();
        let liquid = match liquid_endpoint {
            Some(endpoint) => LiquidFeeSource::from_adapter(
                LiquidFeeSourceId::new("liquid-test").unwrap(),
                LiquidEsploraTargetOneFeeAdapter::new_for_test_loopback_http(
                    endpoint,
                    TEST_SOURCE_TIMEOUT,
                )
                .unwrap(),
            ),
            None => LiquidFeeSource::new("liquid-unused", "https://liquid.example/api").unwrap(),
        };
        RuntimeFeeSourceSets::with_source_sets_for_test(
            bitcoin,
            LiquidFeeSources::new(vec![liquid]).unwrap(),
        )
    }

    fn runtime_with_sources(
        source_sets: RuntimeFeeSourceSets,
        persistence: Arc<dyn FeeRuntimePersistence>,
    ) -> FeeRuntime {
        let mut runtime =
            FeeRuntime::from_config(&FeePolicyConfig::default(), persistence).unwrap();
        runtime.source_sets = source_sets;
        runtime.bitcoin_policy = BitcoinFeePolicy::new(
            SatPerVbyte::try_from(1.0).unwrap(),
            SatPerVbyte::try_from(500.0).unwrap(),
            TEST_PERSISTENCE_TIME,
            TEST_PERSISTENCE_TIME,
        )
        .unwrap();
        runtime.liquid_policy = LiquidFeePolicy::with_freshness(
            SatPerVbyte::try_from(0.1).unwrap(),
            SatPerVbyte::try_from(10.0).unwrap(),
            TEST_PERSISTENCE_TIME,
            TEST_PERSISTENCE_TIME,
        )
        .unwrap();
        runtime
    }

    fn runtime() -> FeeRuntime {
        FeeRuntime::from_config(
            &FeePolicyConfig::default(),
            Arc::new(UnavailableFeeRuntimePersistence),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn startup_refresh_clocks_after_io_and_rechecks_readiness_after_persistence() {
        let mut bitcoin = HeldFeeServer::spawn(br#"{"fastestFee":2.0,"minimumFee":1.0}"#).await;
        let mut liquid = HeldFeeServer::spawn(br#"{"1":0.2}"#).await;
        let persistence = Arc::new(RecordingPersistence::default());
        let runtime = Arc::new(runtime_with_sources(
            runtime_sources(&bitcoin.endpoint, Some(&liquid.endpoint)),
            persistence.clone(),
        ));
        let clock_calls = Arc::new(AtomicUsize::new(0));
        let bitcoin_released = Arc::clone(&bitcoin.response_released);
        let liquid_released = Arc::clone(&liquid.response_released);
        let refresh = {
            let runtime = Arc::clone(&runtime);
            let clock_calls = Arc::clone(&clock_calls);
            tokio::spawn(async move {
                runtime
                    .refresh_once_with_clock(move || {
                        assert!(
                            bitcoin_released.load(Ordering::Acquire)
                                || liquid_released.load(Ordering::Acquire),
                            "refresh clock ran before either delayed response was released"
                        );
                        let call = clock_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(match call {
                            0 | 1 => TEST_EVALUATION_TIME,
                            2 => TEST_PERSISTENCE_TIME,
                            _ => TEST_READINESS_TIME,
                        })
                    })
                    .await
            })
        };

        bitcoin.wait_until_requested().await;
        liquid.wait_until_requested().await;
        assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
        assert!(!refresh.is_finished());
        bitcoin.release();
        liquid.release();

        let report = refresh.await.unwrap();
        assert!(matches!(
            report.refresh().bitcoin(),
            FeeRailRefreshOutcome::Updated { .. }
        ));
        assert!(matches!(
            report.refresh().liquid(),
            FeeRailRefreshOutcome::Updated { .. }
        ));
        assert_eq!(
            report.bitcoin_persistence(),
            FeeRailPersistenceOutcome::Persisted
        );
        assert_eq!(
            report.liquid_persistence(),
            FeeRailPersistenceOutcome::Persisted
        );
        assert!(!report.readiness().bitcoin_ready());
        assert!(!report.readiness().liquid_ready());
        assert_eq!(clock_calls.load(Ordering::SeqCst), 4);
        let accepted = persistence.accepted();
        assert_eq!(accepted.len(), 2);
        assert!(accepted.iter().all(|(_, observed_at, accepted_at)| {
            *accepted_at == TEST_PERSISTENCE_TIME && *accepted_at >= *observed_at
        }));
        bitcoin.finish().await;
        liquid.finish().await;
    }

    #[tokio::test]
    async fn rail_refresh_clocks_after_io_and_rechecks_readiness_after_persistence() {
        let mut bitcoin = HeldFeeServer::spawn(br#"{"fastestFee":2.0,"minimumFee":1.0}"#).await;
        let persistence = Arc::new(RecordingPersistence::default());
        let runtime = Arc::new(runtime_with_sources(
            runtime_sources(&bitcoin.endpoint, None),
            persistence.clone(),
        ));
        let clock_calls = Arc::new(AtomicUsize::new(0));
        let response_released = Arc::clone(&bitcoin.response_released);
        let refresh = {
            let runtime = Arc::clone(&runtime);
            let clock_calls = Arc::clone(&clock_calls);
            tokio::spawn(async move {
                runtime
                    .refresh_rail_with_clock(FeeRail::Bitcoin, move || {
                        assert!(
                            response_released.load(Ordering::Acquire),
                            "rail clock ran before its delayed response was released"
                        );
                        let call = clock_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(match call {
                            0 => TEST_EVALUATION_TIME,
                            1 => TEST_PERSISTENCE_TIME,
                            _ => TEST_READINESS_TIME,
                        })
                    })
                    .await
            })
        };

        bitcoin.wait_until_requested().await;
        assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
        assert!(!refresh.is_finished());
        bitcoin.release();

        let (outcome, persistence_outcome, readiness) = refresh.await.unwrap();
        assert!(matches!(outcome, FeeRailRefreshOutcome::Updated { .. }));
        assert_eq!(persistence_outcome, FeeRailPersistenceOutcome::Persisted);
        assert!(!readiness.bitcoin_ready());
        assert_eq!(clock_calls.load(Ordering::SeqCst), 3);
        let accepted = persistence.accepted();
        assert_eq!(
            accepted,
            vec![(
                FeeRail::Bitcoin,
                runtime
                    .snapshot
                    .read_bitcoin(&runtime.bitcoin_policy, TEST_PERSISTENCE_TIME)
                    .unwrap()
                    .decision()
                    .observed_at_unix(),
                TEST_PERSISTENCE_TIME,
            )]
        );
        assert!(accepted[0].2 >= accepted[0].1);
        bitcoin.finish().await;
    }

    #[tokio::test]
    async fn failed_post_acquisition_clock_discards_live_and_retains_authorized_lkg() {
        let mut bitcoin = HeldFeeServer::spawn(br#"{"fastestFee":2.0,"minimumFee":1.0}"#).await;
        let mut liquid = HeldFeeServer::spawn(br#"{"1":0.2}"#).await;
        let runtime = Arc::new(runtime_with_sources(
            runtime_sources(&bitcoin.endpoint, Some(&liquid.endpoint)),
            Arc::new(RecordingPersistence::default()),
        ));
        runtime
            .snapshot
            .restore_bitcoin_last_known_good(crate::fee_policy::BitcoinLastKnownGood::new(
                SatPerVbyte::try_from(3.0).unwrap(),
                TEST_EVALUATION_TIME,
                FeeProvenance::new(TEST_BITCOIN_PROVENANCE).unwrap(),
            ))
            .unwrap();
        runtime
            .snapshot
            .restore_liquid_last_known_good(LiquidLastKnownGood::new(
                SatPerVbyte::try_from(0.3).unwrap(),
                TEST_EVALUATION_TIME,
                FeeProvenance::new(TEST_LIQUID_PROVENANCE).unwrap(),
            ))
            .unwrap();
        runtime
            .bitcoin_lkg_authorized
            .store(true, Ordering::Release);
        runtime.liquid_lkg_authorized.store(true, Ordering::Release);

        let clock_calls = Arc::new(AtomicUsize::new(0));
        let refresh = {
            let runtime = Arc::clone(&runtime);
            let clock_calls = Arc::clone(&clock_calls);
            tokio::spawn(async move {
                runtime
                    .refresh_once_with_clock(move || {
                        let call = clock_calls.fetch_add(1, Ordering::SeqCst);
                        match call {
                            0 | 1 | 3 => Ok(TEST_EVALUATION_TIME),
                            2 => Err(FeeRefreshClockError::Unavailable),
                            _ => panic!("unexpected refresh clock call {call}"),
                        }
                    })
                    .await
            })
        };

        bitcoin.wait_until_requested().await;
        liquid.wait_until_requested().await;
        bitcoin.release();
        liquid.release();
        let report = refresh.await.unwrap();

        assert!(matches!(
            report.refresh().bitcoin(),
            FeeRailRefreshOutcome::Updated { .. }
        ));
        assert!(matches!(
            report.refresh().liquid(),
            FeeRailRefreshOutcome::Updated { .. }
        ));
        assert_eq!(
            report.bitcoin_persistence(),
            FeeRailPersistenceOutcome::Failed
        );
        assert_eq!(
            report.liquid_persistence(),
            FeeRailPersistenceOutcome::Failed
        );
        assert!(report.readiness().ready());
        assert_eq!(clock_calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            runtime
                .bitcoin_current_at(TEST_EVALUATION_TIME)
                .unwrap()
                .decision()
                .source(),
            FeeObservationSource::BitcoinLastKnownGood
        );
        assert_eq!(
            runtime
                .liquid_current_at(TEST_EVALUATION_TIME)
                .unwrap()
                .decision()
                .source(),
            FeeObservationSource::LiquidLastKnownGood
        );
        bitcoin.finish().await;
        liquid.finish().await;
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
                FeeProvenance::new(DEFAULT_BITCOIN_PROVENANCE).unwrap(),
            ))
            .unwrap();
        let liquid_generation = runtime
            .snapshot
            .update_liquid(LiveLiquid::new(
                SatPerVbyte::try_from(0.2).unwrap(),
                now,
                FeeProvenance::new(DEFAULT_LIQUID_PROVENANCE).unwrap(),
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
                FeeProvenance::new(DEFAULT_BITCOIN_PROVENANCE).unwrap(),
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

    #[test]
    fn clock_high_watermark_prevents_stale_durable_evidence_reopening_after_rollback() {
        let runtime = runtime();
        let observed_at = 10_000;
        let bitcoin_generation = runtime
            .snapshot
            .update_bitcoin(LiveBitcoin::new(
                SatPerVbyte::try_from(2.0).unwrap(),
                observed_at,
                FeeProvenance::new(DEFAULT_BITCOIN_PROVENANCE).unwrap(),
            ))
            .unwrap();
        runtime
            .bitcoin_persisted_generation
            .store(bitcoin_generation.as_u64(), Ordering::Release);
        runtime
            .snapshot
            .restore_liquid_last_known_good(LiquidLastKnownGood::new(
                SatPerVbyte::try_from(0.2).unwrap(),
                observed_at,
                FeeProvenance::new(DEFAULT_LIQUID_PROVENANCE).unwrap(),
            ))
            .unwrap();
        runtime.liquid_lkg_authorized.store(true, Ordering::Release);

        let stale_at = observed_at
            + runtime
                .bitcoin_policy
                .live_max_age_secs()
                .max(runtime.liquid_policy.last_known_good_max_age_secs())
            + 1;
        assert!(runtime.readiness_at(observed_at).ready());
        assert!(!runtime.readiness_at(stale_at).ready());

        assert_eq!(runtime.sample_refresh_clock(&|| Ok(stale_at)), Ok(stale_at));
        assert_eq!(
            runtime.sample_refresh_clock(&|| Err(FeeRefreshClockError::Unavailable)),
            Err(FeeRefreshClockError::Unavailable)
        );
        let effective_rollback = runtime.sample_refresh_clock(&|| Ok(observed_at)).unwrap();
        assert_eq!(effective_rollback, stale_at);
        assert!(!runtime.readiness_at(effective_rollback).ready());
    }

    #[test]
    fn readiness_rejects_durable_evidence_from_unconfigured_or_incompatible_sources() {
        let runtime = runtime();
        let now = 10_000;
        runtime
            .snapshot
            .restore_bitcoin_last_known_good(crate::fee_policy::BitcoinLastKnownGood::new(
                SatPerVbyte::try_from(2.0).unwrap(),
                now,
                FeeProvenance::new(DEFAULT_BITCOIN_PROVENANCE).unwrap(),
            ))
            .unwrap();
        runtime
            .snapshot
            .restore_liquid_last_known_good(LiquidLastKnownGood::new(
                SatPerVbyte::try_from(0.2).unwrap(),
                now,
                FeeProvenance::new(DEFAULT_LIQUID_PROVENANCE).unwrap(),
            ))
            .unwrap();
        runtime
            .bitcoin_lkg_authorized
            .store(true, Ordering::Release);
        runtime.liquid_lkg_authorized.store(true, Ordering::Release);
        assert!(runtime.readiness_at(now).ready());

        runtime
            .snapshot
            .restore_bitcoin_last_known_good(crate::fee_policy::BitcoinLastKnownGood::new(
                SatPerVbyte::try_from(2.0).unwrap(),
                now,
                FeeProvenance::new("mempool_precise_fastest_fee:removed-source").unwrap(),
            ))
            .unwrap();
        assert!(!runtime.readiness_at(now).bitcoin_ready());
        assert!(runtime.readiness_at(now).liquid_ready());

        runtime
            .snapshot
            .restore_bitcoin_last_known_good(crate::fee_policy::BitcoinLastKnownGood::new(
                SatPerVbyte::try_from(2.0).unwrap(),
                now,
                FeeProvenance::new(DEFAULT_BITCOIN_PROVENANCE).unwrap(),
            ))
            .unwrap();
        runtime
            .snapshot
            .restore_liquid_last_known_good(LiquidLastKnownGood::new(
                SatPerVbyte::try_from(0.2).unwrap(),
                now,
                FeeProvenance::new("legacy-liquid-route:liquid-network").unwrap(),
            ))
            .unwrap();
        assert!(runtime.readiness_at(now).bitcoin_ready());
        assert!(!runtime.readiness_at(now).liquid_ready());
        assert!(!runtime.readiness_at(now).ready());
    }

    #[tokio::test(start_paused = true)]
    async fn spawn_handoff_and_freshness_monitor_close_admission_while_refresh_is_blocked() {
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

        assert!(!admission
            .decision(crate::admission::Rail::LightningReverse)
            .allowed());
        assert!(!admission
            .decision(crate::admission::Rail::BitcoinChain)
            .allowed());

        // Reopen only the fee fact so the assertions after the time advance
        // prove the independent monitor tick closed it again, rather than
        // merely observing the synchronous spawn handoff's closed state.
        admission.set_fee_policy_ready(true);
        assert!(admission
            .decision(crate::admission::Rail::LightningReverse)
            .allowed());
        assert!(admission
            .decision(crate::admission::Rail::BitcoinChain)
            .allowed());

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
