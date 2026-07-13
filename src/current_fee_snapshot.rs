use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::fee_policy::{
    BitcoinFeeDecision, BitcoinFeePolicy, BitcoinLastKnownGood, FeeObservationRejection,
    FeePolicyError, FeeRail, LiquidFeeDecision, LiquidFeePolicy, LiquidLastKnownGood, LiveBitcoin,
    LiveLiquid,
};

/// Current-process Bitcoin evidence accepted by the typed Bitcoin policy.
pub type LiveBitcoinFeeObservation = LiveBitcoin;
/// Current-process Liquid evidence accepted by the typed Liquid policy.
pub type LiveLiquidFeeObservation = LiveLiquid;

/// A rail-local mutation sequence. Zero means no explicit mutation has run in
/// this process; every update and clear advances it exactly once.
///
/// Concurrent ordering is the write-lock acquisition order, not observation
/// wall-clock order. Generation is diagnostic ordering metadata only and must
/// never be treated as fee evidence or policy authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CurrentFeeGeneration(u64);

impl CurrentFeeGeneration {
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    fn next(self, rail: FeeRail) -> Result<Self, CurrentFeeSnapshotError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(CurrentFeeSnapshotError::GenerationExhausted { rail })
    }
}

struct RailSnapshot<Live, LastKnownGood> {
    generation: CurrentFeeGeneration,
    live: Option<Live>,
    last_known_good: Option<LastKnownGood>,
}

impl<Live, LastKnownGood> Default for RailSnapshot<Live, LastKnownGood> {
    fn default() -> Self {
        Self {
            generation: CurrentFeeGeneration::default(),
            live: None,
            last_known_good: None,
        }
    }
}

/// A cloneable, process-local holder for the latest explicitly supplied live
/// fee evidence and the latest explicitly restored persisted observation on
/// each rail.
///
/// A new instance is empty. It performs no polling, database I/O, readiness
/// mutation, or transaction construction. Restored observations must come
/// through the typed same-rail restore methods. Clones share the same two
/// rail-local locks; separately constructed instances share nothing.
#[derive(Clone)]
pub struct CurrentFeeSnapshot {
    bitcoin: Arc<RwLock<RailSnapshot<LiveBitcoinFeeObservation, BitcoinLastKnownGood>>>,
    liquid: Arc<RwLock<RailSnapshot<LiveLiquidFeeObservation, LiquidLastKnownGood>>>,
}

impl CurrentFeeSnapshot {
    pub fn new() -> Self {
        Self {
            bitcoin: Arc::new(RwLock::new(RailSnapshot::default())),
            liquid: Arc::new(RwLock::new(RailSnapshot::default())),
        }
    }

    /// Replace the current-process Bitcoin observation and return the exact
    /// rail-local mutation generation assigned under the write lock.
    pub fn update_bitcoin(
        &self,
        observation: LiveBitcoinFeeObservation,
    ) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
        update_live(&self.bitcoin, FeeRail::Bitcoin, Some(observation))
    }

    /// Replace the current-process Liquid observation and return the exact
    /// rail-local mutation generation assigned under the write lock.
    pub fn update_liquid(
        &self,
        observation: LiveLiquidFeeObservation,
    ) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
        update_live(&self.liquid, FeeRail::Liquid, Some(observation))
    }

    /// Restore one persisted Bitcoin observation as typed same-rail LKG
    /// evidence. The caller remains responsible for database I/O and row
    /// validation before crossing this boundary.
    pub fn restore_bitcoin_last_known_good(
        &self,
        observation: BitcoinLastKnownGood,
    ) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
        restore_last_known_good(&self.bitcoin, FeeRail::Bitcoin, observation)
    }

    /// Restore one persisted Liquid observation as typed same-rail LKG
    /// evidence. The caller remains responsible for database I/O and row
    /// validation before crossing this boundary.
    pub fn restore_liquid_last_known_good(
        &self,
        observation: LiquidLastKnownGood,
    ) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
        restore_last_known_good(&self.liquid, FeeRail::Liquid, observation)
    }

    /// Explicitly clear current-process Bitcoin live evidence. A restored LKG
    /// remains available. Clearing an already-empty live slot still advances
    /// its generation so the clear remains an ordered process event.
    pub fn clear_bitcoin(&self) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
        update_live(&self.bitcoin, FeeRail::Bitcoin, None)
    }

    /// Explicitly clear current-process Liquid live evidence. A restored LKG
    /// remains available. Clearing an already-empty live slot still advances
    /// its generation so the clear remains an ordered process event.
    pub fn clear_liquid(&self) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
        update_live(&self.liquid, FeeRail::Liquid, None)
    }

    /// Re-evaluate the currently stored Bitcoin evidence against the supplied
    /// validated policy and deterministic clock, preferring usable live
    /// evidence and falling back only to explicitly restored same-rail LKG.
    pub fn read_bitcoin(
        &self,
        policy: &BitcoinFeePolicy,
        now_unix: u64,
    ) -> Result<CurrentBitcoinFee, CurrentFeeSnapshotError> {
        let (generation, live, last_known_good) = read_rail(&self.bitcoin, FeeRail::Bitcoin)?;
        policy
            .decide_typed(live.as_ref(), last_known_good.as_ref(), now_unix)
            .map(|decision| CurrentBitcoinFee {
                generation,
                decision,
            })
            .map_err(|error| policy_error(FeeRail::Bitcoin, generation, error))
    }

    /// Re-evaluate the currently stored Liquid evidence against the supplied
    /// validated policy and deterministic clock, preferring usable live
    /// evidence and falling back only to explicitly restored same-rail LKG.
    pub fn read_liquid(
        &self,
        policy: &LiquidFeePolicy,
        now_unix: u64,
    ) -> Result<CurrentLiquidFee, CurrentFeeSnapshotError> {
        let (generation, live, last_known_good) = read_rail(&self.liquid, FeeRail::Liquid)?;
        policy
            .decide_typed(live.as_ref(), last_known_good.as_ref(), now_unix)
            .map(|decision| CurrentLiquidFee {
                generation,
                decision,
            })
            .map_err(|error| policy_error(FeeRail::Liquid, generation, error))
    }

    /// Return the current Bitcoin live decision that is eligible to cross the
    /// persistence boundary. Restored LKG is deliberately excluded: reading a
    /// persisted row must never refresh its lifetime by persisting it again.
    pub fn accepted_bitcoin_for_persistence(
        &self,
        policy: &BitcoinFeePolicy,
        now_unix: u64,
    ) -> Result<CurrentBitcoinFee, CurrentFeeSnapshotError> {
        let (generation, live, _) = read_rail(&self.bitcoin, FeeRail::Bitcoin)?;
        policy
            .decide_typed(live.as_ref(), None, now_unix)
            .map(|decision| CurrentBitcoinFee {
                generation,
                decision,
            })
            .map_err(|error| policy_error(FeeRail::Bitcoin, generation, error))
    }

    /// Return the current Liquid live decision that is eligible to cross the
    /// persistence boundary. Restored LKG is deliberately excluded.
    pub fn accepted_liquid_for_persistence(
        &self,
        policy: &LiquidFeePolicy,
        now_unix: u64,
    ) -> Result<CurrentLiquidFee, CurrentFeeSnapshotError> {
        let (generation, live, _) = read_rail(&self.liquid, FeeRail::Liquid)?;
        policy
            .decide_typed(live.as_ref(), None, now_unix)
            .map(|decision| CurrentLiquidFee {
                generation,
                decision,
            })
            .map_err(|error| policy_error(FeeRail::Liquid, generation, error))
    }
}

impl Default for CurrentFeeSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CurrentFeeSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentFeeSnapshot")
            .field("bitcoin", &"<redacted>")
            .field("liquid", &"<redacted>")
            .finish()
    }
}

fn update_live<Live, LastKnownGood>(
    rail: &RwLock<RailSnapshot<Live, LastKnownGood>>,
    fee_rail: FeeRail,
    observation: Option<Live>,
) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
    let mut state = rail
        .write()
        .map_err(|_| CurrentFeeSnapshotError::StateUnavailable { rail: fee_rail })?;
    let generation = state.generation.next(fee_rail)?;
    state.live = observation;
    state.generation = generation;
    Ok(generation)
}

fn restore_last_known_good<Live, LastKnownGood>(
    rail: &RwLock<RailSnapshot<Live, LastKnownGood>>,
    fee_rail: FeeRail,
    observation: LastKnownGood,
) -> Result<CurrentFeeGeneration, CurrentFeeSnapshotError> {
    let mut state = rail
        .write()
        .map_err(|_| CurrentFeeSnapshotError::StateUnavailable { rail: fee_rail })?;
    let generation = state.generation.next(fee_rail)?;
    state.last_known_good = Some(observation);
    state.generation = generation;
    Ok(generation)
}

fn read_rail<Live: Clone, LastKnownGood: Clone>(
    rail: &RwLock<RailSnapshot<Live, LastKnownGood>>,
    fee_rail: FeeRail,
) -> Result<(CurrentFeeGeneration, Option<Live>, Option<LastKnownGood>), CurrentFeeSnapshotError> {
    let state = rail
        .read()
        .map_err(|_| CurrentFeeSnapshotError::StateUnavailable { rail: fee_rail })?;
    Ok((
        state.generation,
        state.live.clone(),
        state.last_known_good.clone(),
    ))
}

/// A Bitcoin policy decision tied to the rail-local mutation generation that
/// supplied its live observation.
#[derive(Clone, PartialEq)]
pub struct CurrentBitcoinFee {
    generation: CurrentFeeGeneration,
    decision: BitcoinFeeDecision,
}

impl CurrentBitcoinFee {
    pub const fn generation(&self) -> CurrentFeeGeneration {
        self.generation
    }

    pub const fn decision(&self) -> &BitcoinFeeDecision {
        &self.decision
    }
}

impl fmt::Debug for CurrentBitcoinFee {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentBitcoinFee")
            .field("generation", &self.generation)
            .field("decision", &"<redacted>")
            .finish()
    }
}

/// A Liquid policy decision tied to the rail-local mutation generation that
/// supplied its live observation.
#[derive(Clone, PartialEq)]
pub struct CurrentLiquidFee {
    generation: CurrentFeeGeneration,
    decision: LiquidFeeDecision,
}

impl CurrentLiquidFee {
    pub const fn generation(&self) -> CurrentFeeGeneration {
        self.generation
    }

    pub const fn decision(&self) -> &LiquidFeeDecision {
        &self.decision
    }
}

impl fmt::Debug for CurrentLiquidFee {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentLiquidFee")
            .field("generation", &self.generation)
            .field("decision", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentFeeUnavailableReason {
    Missing,
    Stale,
    FromFuture,
    OutsideBounds,
    PolicyRejected,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CurrentFeeSnapshotError {
    StateUnavailable {
        rail: FeeRail,
    },
    GenerationExhausted {
        rail: FeeRail,
    },
    Unavailable {
        rail: FeeRail,
        generation: CurrentFeeGeneration,
        reason: CurrentFeeUnavailableReason,
    },
}

impl CurrentFeeSnapshotError {
    pub const fn rail(self) -> FeeRail {
        match self {
            Self::StateUnavailable { rail }
            | Self::GenerationExhausted { rail }
            | Self::Unavailable { rail, .. } => rail,
        }
    }

    pub const fn generation(self) -> Option<CurrentFeeGeneration> {
        match self {
            Self::Unavailable { generation, .. } => Some(generation),
            Self::StateUnavailable { .. } | Self::GenerationExhausted { .. } => None,
        }
    }

    pub const fn reason(self) -> Option<CurrentFeeUnavailableReason> {
        match self {
            Self::Unavailable { reason, .. } => Some(reason),
            Self::StateUnavailable { .. } | Self::GenerationExhausted { .. } => None,
        }
    }
}

impl fmt::Debug for CurrentFeeSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut diagnostic = formatter.debug_struct("CurrentFeeSnapshotError");
        diagnostic.field("rail", &self.rail());
        if let Some(generation) = self.generation() {
            diagnostic.field("generation", &generation);
        }
        if let Some(reason) = self.reason() {
            diagnostic.field("reason", &reason);
        }
        diagnostic.field("observation", &"<redacted>").finish()
    }
}

impl fmt::Display for CurrentFeeSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateUnavailable { rail } => {
                write!(
                    formatter,
                    "current {} fee state is unavailable",
                    rail.as_str()
                )
            }
            Self::GenerationExhausted { rail } => write!(
                formatter,
                "current {} fee state exhausted its process generation",
                rail.as_str()
            ),
            Self::Unavailable { rail, reason, .. } => write!(
                formatter,
                "current {} fee observation is unavailable ({})",
                rail.as_str(),
                reason.as_str()
            ),
        }
    }
}

impl Error for CurrentFeeSnapshotError {}

impl CurrentFeeUnavailableReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Stale => "stale",
            Self::FromFuture => "future",
            Self::OutsideBounds => "outside bounds",
            Self::PolicyRejected => "policy rejected",
        }
    }
}

fn policy_error(
    rail: FeeRail,
    generation: CurrentFeeGeneration,
    error: FeePolicyError,
) -> CurrentFeeSnapshotError {
    let reason = match error {
        FeePolicyError::TemporarilyUnavailable {
            live,
            last_known_good,
            ..
        } => rejection_reason(
            if matches!(last_known_good, FeeObservationRejection::Missing) {
                live
            } else {
                last_known_good
            },
        ),
        _ => CurrentFeeUnavailableReason::PolicyRejected,
    };
    CurrentFeeSnapshotError::Unavailable {
        rail,
        generation,
        reason,
    }
}

fn rejection_reason(rejection: FeeObservationRejection) -> CurrentFeeUnavailableReason {
    match rejection {
        FeeObservationRejection::Missing => CurrentFeeUnavailableReason::Missing,
        FeeObservationRejection::Stale { .. } => CurrentFeeUnavailableReason::Stale,
        FeeObservationRejection::FromFuture { .. } => CurrentFeeUnavailableReason::FromFuture,
        FeeObservationRejection::OutsideBounds { .. } => CurrentFeeUnavailableReason::OutsideBounds,
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;
    use std::sync::Barrier;
    use std::thread;

    use crate::fee_policy::{
        BitcoinLastKnownGood, FeeFreshness, FeeObservationSource, FeeProvenance,
        LiquidLastKnownGood, SatPerVbyte,
    };

    use super::*;

    fn rate(value: f64) -> SatPerVbyte {
        SatPerVbyte::try_from(value).unwrap()
    }

    fn provenance(value: &str) -> FeeProvenance {
        FeeProvenance::new(value).unwrap()
    }

    fn bitcoin(value: f64, observed_at_unix: u64, source: &str) -> LiveBitcoinFeeObservation {
        LiveBitcoinFeeObservation::new(rate(value), observed_at_unix, provenance(source))
    }

    fn liquid(value: f64, observed_at_unix: u64, source: &str) -> LiveLiquidFeeObservation {
        LiveLiquidFeeObservation::new(rate(value), observed_at_unix, provenance(source))
    }

    fn bitcoin_lkg(value: f64, observed_at_unix: u64, source: &str) -> BitcoinLastKnownGood {
        BitcoinLastKnownGood::new(rate(value), observed_at_unix, provenance(source))
    }

    fn liquid_lkg(value: f64, observed_at_unix: u64, source: &str) -> LiquidLastKnownGood {
        LiquidLastKnownGood::new(rate(value), observed_at_unix, provenance(source))
    }

    #[test]
    fn new_and_restarted_snapshots_are_empty() {
        let first = CurrentFeeSnapshot::new();
        assert_eq!(
            first.read_bitcoin(&BitcoinFeePolicy::default(), 1_000),
            Err(CurrentFeeSnapshotError::Unavailable {
                rail: FeeRail::Bitcoin,
                generation: CurrentFeeGeneration(0),
                reason: CurrentFeeUnavailableReason::Missing,
            })
        );
        assert_eq!(
            first.read_liquid(&LiquidFeePolicy::default(), 1_000),
            Err(CurrentFeeSnapshotError::Unavailable {
                rail: FeeRail::Liquid,
                generation: CurrentFeeGeneration(0),
                reason: CurrentFeeUnavailableReason::Missing,
            })
        );

        first
            .update_bitcoin(bitcoin(2.0, 1_000, "first-process-secret"))
            .unwrap();
        let restarted = CurrentFeeSnapshot::new();
        assert_eq!(
            restarted
                .read_bitcoin(&BitcoinFeePolicy::default(), 1_000)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Missing)
        );
    }

    #[test]
    fn update_and_every_read_reapply_policy_at_the_supplied_clock() {
        let snapshot = CurrentFeeSnapshot::new();
        let policy = BitcoinFeePolicy::default();
        let generation = snapshot
            .update_bitcoin(bitcoin(7.5, 10_000, "private-bitcoin-source"))
            .unwrap();
        assert_eq!(generation.as_u64(), 1);

        let at_observation = snapshot.read_bitcoin(&policy, 10_000).unwrap();
        assert_eq!(at_observation.generation(), generation);
        assert_eq!(at_observation.decision().rate(), rate(7.5));
        assert_eq!(
            at_observation.decision().freshness(),
            FeeFreshness::Fresh {
                age_secs: 0,
                max_age_secs: policy.live_max_age_secs(),
            }
        );

        let at_boundary = snapshot
            .read_bitcoin(&policy, 10_000 + policy.live_max_age_secs())
            .unwrap();
        assert_eq!(
            at_boundary.decision().freshness(),
            FeeFreshness::Fresh {
                age_secs: policy.live_max_age_secs(),
                max_age_secs: policy.live_max_age_secs(),
            }
        );

        assert_eq!(
            snapshot
                .read_bitcoin(&policy, 10_001 + policy.live_max_age_secs())
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Stale)
        );
        assert!(snapshot.read_bitcoin(&policy, 10_000).is_ok());
    }

    #[test]
    fn generations_follow_explicit_per_rail_mutation_order() {
        let snapshot = CurrentFeeSnapshot::new();
        assert_eq!(
            snapshot
                .update_bitcoin(bitcoin(2.0, 1_000, "btc-one"))
                .unwrap()
                .as_u64(),
            1
        );
        assert_eq!(snapshot.clear_bitcoin().unwrap().as_u64(), 2);
        assert_eq!(snapshot.clear_bitcoin().unwrap().as_u64(), 3);
        assert_eq!(
            snapshot
                .update_bitcoin(bitcoin(3.0, 1_001, "btc-two"))
                .unwrap()
                .as_u64(),
            4
        );
        assert_eq!(
            snapshot
                .update_liquid(liquid(0.5, 1_001, "liquid-one"))
                .unwrap()
                .as_u64(),
            1
        );
        assert_eq!(
            snapshot
                .read_bitcoin(&BitcoinFeePolicy::default(), 1_001)
                .unwrap()
                .generation()
                .as_u64(),
            4
        );
        assert_eq!(
            snapshot
                .read_liquid(&LiquidFeePolicy::default(), 1_001)
                .unwrap()
                .generation()
                .as_u64(),
            1
        );
    }

    #[test]
    fn clear_removes_only_the_selected_rail() {
        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .update_bitcoin(bitcoin(2.0, 1_000, "btc-clear"))
            .unwrap();
        snapshot
            .update_liquid(liquid(0.5, 1_000, "liquid-retained"))
            .unwrap();

        assert_eq!(snapshot.clear_bitcoin().unwrap().as_u64(), 2);
        let missing = snapshot
            .read_bitcoin(&BitcoinFeePolicy::default(), 1_000)
            .unwrap_err();
        assert_eq!(missing.generation(), Some(CurrentFeeGeneration(2)));
        assert_eq!(missing.reason(), Some(CurrentFeeUnavailableReason::Missing));
        assert!(snapshot
            .read_liquid(&LiquidFeePolicy::default(), 1_000)
            .is_ok());
    }

    #[test]
    fn restored_lkg_is_same_rail_fallback_without_extending_its_observation_time() {
        let snapshot = CurrentFeeSnapshot::new();
        let bitcoin_policy = BitcoinFeePolicy::default();
        let liquid_policy = LiquidFeePolicy::default();

        assert_eq!(
            snapshot
                .restore_bitcoin_last_known_good(bitcoin_lkg(
                    3.25,
                    10_000,
                    "persisted-bitcoin-secret",
                ))
                .unwrap()
                .as_u64(),
            1
        );
        assert_eq!(
            snapshot
                .restore_liquid_last_known_good(
                    liquid_lkg(0.25, 10_000, "persisted-liquid-secret",)
                )
                .unwrap()
                .as_u64(),
            1
        );

        let bitcoin = snapshot.read_bitcoin(&bitcoin_policy, 10_100).unwrap();
        assert_eq!(bitcoin.decision().rate(), rate(3.25));
        assert_eq!(
            bitcoin.decision().source(),
            FeeObservationSource::BitcoinLastKnownGood
        );
        assert_eq!(bitcoin.decision().observed_at_unix(), 10_000);
        assert_eq!(
            bitcoin.decision().freshness(),
            FeeFreshness::Fresh {
                age_secs: 100,
                max_age_secs: bitcoin_policy.last_known_good_max_age_secs(),
            }
        );

        let liquid = snapshot.read_liquid(&liquid_policy, 10_100).unwrap();
        assert_eq!(liquid.decision().rate(), rate(0.25));
        assert_eq!(
            liquid.decision().source(),
            FeeObservationSource::LiquidLastKnownGood
        );
        assert_eq!(liquid.decision().observed_at_unix(), 10_000);

        assert_eq!(
            snapshot
                .read_bitcoin(
                    &bitcoin_policy,
                    10_001 + bitcoin_policy.last_known_good_max_age_secs(),
                )
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Stale)
        );
        assert_eq!(
            snapshot
                .accepted_bitcoin_for_persistence(&bitcoin_policy, 10_100)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Missing)
        );
        assert_eq!(
            snapshot
                .accepted_liquid_for_persistence(&liquid_policy, 10_100)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Missing)
        );
    }

    #[test]
    fn live_evidence_wins_and_only_live_is_persistable() {
        let snapshot = CurrentFeeSnapshot::new();
        let bitcoin_policy = BitcoinFeePolicy::default();
        snapshot
            .restore_bitcoin_last_known_good(bitcoin_lkg(2.0, 10_000, "persisted-bitcoin"))
            .unwrap();
        snapshot
            .update_bitcoin(bitcoin(7.0, 10_100, "current-process-bitcoin"))
            .unwrap();

        let selected = snapshot.read_bitcoin(&bitcoin_policy, 10_100).unwrap();
        let persistable = snapshot
            .accepted_bitcoin_for_persistence(&bitcoin_policy, 10_100)
            .unwrap();
        assert_eq!(selected.generation(), persistable.generation());
        assert_eq!(selected.decision(), persistable.decision());
        assert_eq!(
            persistable.decision().source(),
            FeeObservationSource::LiveBitcoin
        );

        snapshot.clear_bitcoin().unwrap();
        let fallback = snapshot.read_bitcoin(&bitcoin_policy, 10_100).unwrap();
        assert_eq!(fallback.decision().rate(), rate(2.0));
        assert_eq!(
            fallback.decision().source(),
            FeeObservationSource::BitcoinLastKnownGood
        );
        assert!(snapshot
            .accepted_bitcoin_for_persistence(&bitcoin_policy, 10_100)
            .is_err());
    }

    #[test]
    fn stale_future_and_out_of_bounds_evidence_stays_stored_but_fails_each_read() {
        let snapshot = CurrentFeeSnapshot::new();
        let bitcoin_policy = BitcoinFeePolicy::default();
        snapshot
            .update_bitcoin(bitcoin(2.0, 1_000, "btc-clock-secret"))
            .unwrap();
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, 999)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::FromFuture)
        );
        assert!(snapshot.read_bitcoin(&bitcoin_policy, 1_000).is_ok());
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, 1_001 + bitcoin_policy.live_max_age_secs())
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Stale)
        );

        let liquid_policy = LiquidFeePolicy::default();
        snapshot
            .update_liquid(liquid(10.01, 1_000, "liquid-bounds-secret"))
            .unwrap();
        assert_eq!(
            snapshot
                .read_liquid(&liquid_policy, 1_000)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::OutsideBounds)
        );
    }

    #[test]
    fn rail_updates_and_policy_decisions_are_independent() {
        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .update_bitcoin(bitcoin(11.0, 2_000, "bitcoin-independent"))
            .unwrap();
        snapshot
            .update_liquid(liquid(0.75, 2_000, "liquid-independent"))
            .unwrap();

        let bitcoin = snapshot
            .read_bitcoin(&BitcoinFeePolicy::default(), 2_000)
            .unwrap();
        let liquid = snapshot
            .read_liquid(&LiquidFeePolicy::default(), 2_000)
            .unwrap();
        assert_eq!(bitcoin.decision().rate(), rate(11.0));
        assert_eq!(
            bitcoin.decision().source(),
            FeeObservationSource::LiveBitcoin
        );
        assert_eq!(liquid.decision().rate(), rate(0.75));
        assert_eq!(liquid.decision().source(), FeeObservationSource::LiveLiquid);

        snapshot.clear_liquid().unwrap();
        assert!(snapshot
            .read_bitcoin(&BitcoinFeePolicy::default(), 2_000)
            .is_ok());
        assert!(snapshot
            .read_liquid(&LiquidFeePolicy::default(), 2_000)
            .is_err());
    }

    #[test]
    fn clones_share_state_and_concurrent_updates_are_linearized_per_rail() {
        const WRITERS: usize = 8;
        let snapshot = CurrentFeeSnapshot::new();
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles = (0..WRITERS)
            .map(|index| {
                let clone = snapshot.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    clone
                        .update_bitcoin(bitcoin(
                            2.0 + index as f64,
                            10_000,
                            &format!("concurrent-source-{index}"),
                        ))
                        .unwrap()
                        .as_u64()
                })
            })
            .collect::<Vec<_>>();

        let mut generations = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        generations.sort_unstable();
        assert_eq!(generations, (1..=WRITERS as u64).collect::<Vec<_>>());

        let latest = snapshot
            .read_bitcoin(&BitcoinFeePolicy::default(), 10_000)
            .unwrap();
        assert_eq!(latest.generation().as_u64(), WRITERS as u64);
        assert!((2.0..=9.0).contains(&latest.decision().rate().as_f64()));
    }

    #[test]
    fn rail_types_are_distinct_and_diagnostics_are_redacted() {
        assert_ne!(
            TypeId::of::<LiveBitcoinFeeObservation>(),
            TypeId::of::<LiveLiquidFeeObservation>()
        );

        let secret = "https://user:password@private.invalid/path?token=secret";
        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .update_bitcoin(bitcoin(2.0, 1_000, secret))
            .unwrap();
        let current = snapshot
            .read_bitcoin(&BitcoinFeePolicy::default(), 1_000)
            .unwrap();
        let stale = snapshot
            .read_bitcoin(&BitcoinFeePolicy::default(), 10_000)
            .unwrap_err();

        for diagnostic in [
            format!("{snapshot:?}"),
            format!("{current:?}"),
            format!("{stale:?}"),
        ] {
            assert!(diagnostic.contains("<redacted>"));
            assert!(!diagnostic.contains(secret));
            assert!(!diagnostic.contains("password"));
            assert!(!diagnostic.contains("token=secret"));
        }
        let display = stale.to_string();
        assert!(!display.contains(secret));
        assert!(!display.contains("password"));
        assert!(!display.contains("token=secret"));
    }

    #[test]
    fn generation_exhaustion_fails_closed_without_replacing_evidence() {
        let snapshot = CurrentFeeSnapshot::new();
        {
            let mut state = snapshot.bitcoin.write().unwrap();
            state.generation = CurrentFeeGeneration(u64::MAX);
            state.live = Some(bitcoin(2.0, 1_000, "retained-at-overflow"));
        }

        assert_eq!(
            snapshot.update_bitcoin(bitcoin(3.0, 1_000, "rejected-at-overflow")),
            Err(CurrentFeeSnapshotError::GenerationExhausted {
                rail: FeeRail::Bitcoin,
            })
        );
        let retained = snapshot
            .read_bitcoin(&BitcoinFeePolicy::default(), 1_000)
            .unwrap();
        assert_eq!(retained.generation().as_u64(), u64::MAX);
        assert_eq!(retained.decision().rate(), rate(2.0));
    }
}
