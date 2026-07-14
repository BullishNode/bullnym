//! Immutable construction-time fee metadata persisted beside new transaction bytes.
//!
//! The builders consume the smaller typed builder decisions. This record keeps
//! the complete Review-25 authority trail for the journal write that makes
//! those bytes durable. It never supplies a fallback rate and cannot be built
//! without an already-accepted rail-specific policy decision.

use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use crate::fee_policy::{
    BitcoinFeeDecision, BitcoinFeePolicy, FeeFreshness, FeeObservationSource, FeePolicyError,
    FeeProvenance, FeeRail, LiquidFeeDecision, LiquidFeePolicy, SatPerVbyte,
};

pub const FEE_POLICY_VERSION: &str = "review25-v1";

fn construction_authority_remaining(age_secs: u64, max_age_secs: u64) -> Option<Duration> {
    max_age_secs.checked_sub(age_secs).map(Duration::from_secs)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeConstructionPurpose {
    ReverseLiquidClaim,
    ChainLiquidClaim,
    BitcoinRecovery,
}

impl FeeConstructionPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReverseLiquidClaim => "reverse_liquid_claim",
            Self::ChainLiquidClaim => "chain_liquid_claim",
            Self::BitcoinRecovery => "bitcoin_recovery",
        }
    }

    pub const fn rail(self) -> FeeRail {
        match self {
            Self::ReverseLiquidClaim | Self::ChainLiquidClaim => FeeRail::Liquid,
            Self::BitcoinRecovery => FeeRail::Bitcoin,
        }
    }

    pub const fn target(self) -> FeeQuoteTarget {
        match self {
            Self::ReverseLiquidClaim | Self::ChainLiquidClaim => FeeQuoteTarget::LiquidTargetOne,
            Self::BitcoinRecovery => FeeQuoteTarget::BitcoinFastest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeQuoteTarget {
    BitcoinFastest,
    LiquidTargetOne,
}

impl FeeQuoteTarget {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BitcoinFastest => "fastestFee",
            Self::LiquidTargetOne => "1",
        }
    }
}

#[derive(Clone)]
pub struct FeeDecisionRecord {
    purpose: FeeConstructionPurpose,
    source: FeeObservationSource,
    rate: SatPerVbyte,
    quoted_at_unix: u64,
    evaluated_at_unix: u64,
    freshness_age_secs: u64,
    freshness_max_age_secs: u64,
    provenance: FeeProvenance,
    policy_floor: SatPerVbyte,
    policy_cap: SatPerVbyte,
    /// Process-local only: never persisted and deliberately omitted from
    /// diagnostics. It measures elapsed pool/lock/construction time without
    /// comparing production wall time to synthetic compatibility fixtures.
    construction_authority_captured_at: Instant,
    construction_authority_remaining: Duration,
    /// Persisted replay authority validates already-committed bytes but must
    /// never authorize construction of a new transaction template.
    construction_authority_replay_only: bool,
}

impl PartialEq for FeeDecisionRecord {
    fn eq(&self, other: &Self) -> bool {
        self.purpose == other.purpose
            && self.source == other.source
            && self.rate == other.rate
            && self.quoted_at_unix == other.quoted_at_unix
            && self.evaluated_at_unix == other.evaluated_at_unix
            && self.freshness_age_secs == other.freshness_age_secs
            && self.freshness_max_age_secs == other.freshness_max_age_secs
            && self.provenance == other.provenance
            && self.policy_floor == other.policy_floor
            && self.policy_cap == other.policy_cap
    }
}

impl FeeDecisionRecord {
    pub fn from_bitcoin(
        purpose: FeeConstructionPurpose,
        decision: &BitcoinFeeDecision,
        policy: &BitcoinFeePolicy,
        evaluated_at_unix: u64,
    ) -> Result<Self, FeeDecisionRecordError> {
        if purpose.rail() != FeeRail::Bitcoin {
            return Err(FeeDecisionRecordError::PurposeRailMismatch {
                purpose,
                expected: FeeRail::Bitcoin,
            });
        }
        if !matches!(
            decision.source(),
            FeeObservationSource::LiveBitcoin | FeeObservationSource::BitcoinLastKnownGood
        ) {
            return Err(FeeDecisionRecordError::DecisionSourceMismatch {
                rail: FeeRail::Bitcoin,
                source: decision.source(),
            });
        }
        Self::new(
            purpose,
            decision.source(),
            decision.rate(),
            decision.observed_at_unix(),
            decision.freshness(),
            decision.provenance().clone(),
            policy.floor(),
            policy.cap(),
            evaluated_at_unix,
        )
    }

    pub fn from_liquid(
        purpose: FeeConstructionPurpose,
        decision: &LiquidFeeDecision,
        policy: &LiquidFeePolicy,
        evaluated_at_unix: u64,
    ) -> Result<Self, FeeDecisionRecordError> {
        if purpose.rail() != FeeRail::Liquid {
            return Err(FeeDecisionRecordError::PurposeRailMismatch {
                purpose,
                expected: FeeRail::Liquid,
            });
        }
        if !matches!(
            decision.source(),
            FeeObservationSource::LiveLiquid | FeeObservationSource::LiquidLastKnownGood
        ) {
            return Err(FeeDecisionRecordError::DecisionSourceMismatch {
                rail: FeeRail::Liquid,
                source: decision.source(),
            });
        }
        Self::new(
            purpose,
            decision.source(),
            decision.rate(),
            decision.observed_at_unix(),
            decision.freshness(),
            decision.provenance().clone(),
            policy.floor(),
            policy.cap(),
            evaluated_at_unix,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        purpose: FeeConstructionPurpose,
        source: FeeObservationSource,
        rate: SatPerVbyte,
        quoted_at_unix: u64,
        freshness: FeeFreshness,
        provenance: FeeProvenance,
        policy_floor: SatPerVbyte,
        policy_cap: SatPerVbyte,
        evaluated_at_unix: u64,
    ) -> Result<Self, FeeDecisionRecordError> {
        if rate < policy_floor || rate > policy_cap {
            return Err(FeeDecisionRecordError::DecisionOutsidePolicyBounds);
        }
        let FeeFreshness::Fresh {
            age_secs,
            max_age_secs,
        } = freshness
        else {
            return Err(FeeDecisionRecordError::DecisionNotFresh);
        };
        if quoted_at_unix.checked_add(age_secs) != Some(evaluated_at_unix) {
            return Err(FeeDecisionRecordError::EvaluationClockMismatch);
        }
        let construction_authority_remaining =
            construction_authority_remaining(age_secs, max_age_secs)
                .ok_or(FeeDecisionRecordError::DecisionNotFresh)?;
        Ok(Self {
            purpose,
            source,
            rate,
            quoted_at_unix,
            evaluated_at_unix,
            freshness_age_secs: age_secs,
            freshness_max_age_secs: max_age_secs,
            provenance,
            policy_floor,
            policy_cap,
            construction_authority_captured_at: Instant::now(),
            construction_authority_remaining,
            construction_authority_replay_only: false,
        })
    }

    /// Rehydrate complete Bitcoin authority solely for persisting or checking
    /// bytes that the cooperative-signing journal already committed. This
    /// record deliberately fails every new-construction freshness check.
    #[allow(clippy::too_many_arguments, dead_code)] // Used by the #85 executor composition.
    pub(crate) fn from_persisted_bitcoin_authority(
        source: FeeObservationSource,
        rate: SatPerVbyte,
        quoted_at_unix: u64,
        evaluated_at_unix: u64,
        freshness_age_secs: u64,
        freshness_max_age_secs: u64,
        provenance: FeeProvenance,
        policy_floor: SatPerVbyte,
        policy_cap: SatPerVbyte,
    ) -> Result<Self, FeeDecisionRecordError> {
        if !matches!(
            source,
            FeeObservationSource::LiveBitcoin | FeeObservationSource::BitcoinLastKnownGood
        ) {
            return Err(FeeDecisionRecordError::DecisionSourceMismatch {
                rail: FeeRail::Bitcoin,
                source,
            });
        }
        let mut record = Self::new(
            FeeConstructionPurpose::BitcoinRecovery,
            source,
            rate,
            quoted_at_unix,
            FeeFreshness::Fresh {
                age_secs: freshness_age_secs,
                max_age_secs: freshness_max_age_secs,
            },
            provenance,
            policy_floor,
            policy_cap,
            evaluated_at_unix,
        )?;
        record.construction_authority_replay_only = true;
        Ok(record)
    }

    pub const fn purpose(&self) -> FeeConstructionPurpose {
        self.purpose
    }

    pub const fn rail(&self) -> FeeRail {
        self.purpose.rail()
    }

    pub const fn target(&self) -> FeeQuoteTarget {
        self.purpose.target()
    }

    pub const fn source(&self) -> FeeObservationSource {
        self.source
    }

    pub const fn rate(&self) -> SatPerVbyte {
        self.rate
    }

    pub const fn quoted_at_unix(&self) -> u64 {
        self.quoted_at_unix
    }

    pub const fn evaluated_at_unix(&self) -> u64 {
        self.evaluated_at_unix
    }

    pub const fn freshness_age_secs(&self) -> u64 {
        self.freshness_age_secs
    }

    pub const fn freshness_max_age_secs(&self) -> u64 {
        self.freshness_max_age_secs
    }

    /// Whether the decision's process-local monotonic window still authorizes
    /// new bytes at the supplied instant. Persisted wall-clock evidence remains
    /// unchanged and is not consulted again after initial policy acceptance.
    fn authorizes_construction_at(&self, now: Instant) -> bool {
        !self.construction_authority_replay_only
            && now
                .checked_duration_since(self.construction_authority_captured_at)
                .is_some_and(|elapsed| elapsed <= self.construction_authority_remaining)
    }

    /// Recheck fee authority after any pool/lock/construction delay.
    pub(crate) fn authorizes_construction_now(&self) -> bool {
        self.authorizes_construction_at(Instant::now())
    }

    pub fn provenance_for_persistence(&self) -> &str {
        self.provenance.expose_for_persistence()
    }

    pub const fn policy_floor(&self) -> SatPerVbyte {
        self.policy_floor
    }

    pub const fn policy_cap(&self) -> SatPerVbyte {
        self.policy_cap
    }

    /// Exact fee the accepted decision permits for the returned transaction's
    /// final virtual size. The pinned boltz-client constructor uses
    /// `ceil(rate * estimated_vsize)` and its cooperative/script witnesses are
    /// fixed-size, so the returned size must reproduce that integer fee. Record
    /// construction has already proven that the decision lies within the
    /// persisted policy floor and cap.
    pub(crate) fn exact_authorized_fee_sat(&self, vbytes: u64) -> Result<u64, FeePolicyError> {
        self.rate.checked_fee_for_vbytes(vbytes)
    }

    pub const fn policy_version(&self) -> &'static str {
        FEE_POLICY_VERSION
    }
}

impl fmt::Debug for FeeDecisionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeeDecisionRecord")
            .field("purpose", &self.purpose)
            .field("source", &self.source)
            .field("rate", &self.rate)
            .field("quoted_at_unix", &self.quoted_at_unix)
            .field("evaluated_at_unix", &self.evaluated_at_unix)
            .field("freshness_age_secs", &self.freshness_age_secs)
            .field("freshness_max_age_secs", &self.freshness_max_age_secs)
            .field("provenance", &"<redacted>")
            .field("policy_floor", &self.policy_floor)
            .field("policy_cap", &self.policy_cap)
            .field("policy_version", &FEE_POLICY_VERSION)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeDecisionRecordError {
    PurposeRailMismatch {
        purpose: FeeConstructionPurpose,
        expected: FeeRail,
    },
    DecisionSourceMismatch {
        rail: FeeRail,
        source: FeeObservationSource,
    },
    DecisionNotFresh,
    DecisionOutsidePolicyBounds,
    EvaluationClockMismatch,
}

impl fmt::Display for FeeDecisionRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PurposeRailMismatch { .. } => {
                formatter.write_str("fee construction purpose belongs to another rail")
            }
            Self::DecisionSourceMismatch { .. } => {
                formatter.write_str("fee decision source belongs to another rail")
            }
            Self::DecisionNotFresh => formatter.write_str("fee decision is not fresh"),
            Self::DecisionOutsidePolicyBounds => {
                formatter.write_str("fee decision rate is outside the recorded policy bounds")
            }
            Self::EvaluationClockMismatch => {
                formatter.write_str("fee decision evaluation clock does not match freshness")
            }
        }
    }
}

impl Error for FeeDecisionRecordError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_policy::{
        BitcoinLastKnownGood, FeeProvenance, LiquidLastKnownGood, LiveBitcoin, LiveLiquid,
    };

    fn rate(value: f64) -> SatPerVbyte {
        SatPerVbyte::try_from(value).unwrap()
    }

    fn provenance(value: &str) -> FeeProvenance {
        FeeProvenance::new(value).unwrap()
    }

    #[test]
    fn bitcoin_record_binds_live_quote_policy_and_clock() {
        let policy = BitcoinFeePolicy::new(rate(1.0), rate(100.0), 30, 300).unwrap();
        let decision = policy
            .decide_typed(
                Some(&LiveBitcoin::new(
                    rate(12.5),
                    1_000,
                    provenance("mempool_precise_fastest_fee:primary"),
                )),
                None,
                1_007,
            )
            .unwrap();

        let record = FeeDecisionRecord::from_bitcoin(
            FeeConstructionPurpose::BitcoinRecovery,
            &decision,
            &policy,
            1_007,
        )
        .unwrap();

        assert_eq!(record.rail(), FeeRail::Bitcoin);
        assert_eq!(record.target().as_str(), "fastestFee");
        assert_eq!(record.source(), FeeObservationSource::LiveBitcoin);
        assert_eq!(record.rate(), rate(12.5));
        assert_eq!(record.quoted_at_unix(), 1_000);
        assert_eq!(record.evaluated_at_unix(), 1_007);
        assert_eq!(record.freshness_age_secs(), 7);
        assert_eq!(record.freshness_max_age_secs(), 30);
        assert_eq!(record.policy_floor(), rate(1.0));
        assert_eq!(record.policy_cap(), rate(100.0));
        assert_eq!(record.policy_version(), "review25-v1");
    }

    #[test]
    fn liquid_record_preserves_lkg_authority_without_exposing_provenance() {
        let policy = LiquidFeePolicy::with_freshness(rate(0.1), rate(5.0), 30, 300).unwrap();
        let lkg = LiquidLastKnownGood::new(
            rate(0.75),
            900,
            provenance("liquid_esplora_target_1_fee:secret-endpoint"),
        );
        let decision = policy.decide_typed(None, Some(&lkg), 1_000).unwrap();
        let record = FeeDecisionRecord::from_liquid(
            FeeConstructionPurpose::ReverseLiquidClaim,
            &decision,
            &policy,
            1_000,
        )
        .unwrap();

        assert_eq!(record.target().as_str(), "1");
        assert_eq!(record.source(), FeeObservationSource::LiquidLastKnownGood);
        assert_eq!(record.freshness_age_secs(), 100);
        assert_eq!(record.freshness_max_age_secs(), 300);
        assert_eq!(
            record.provenance_for_persistence(),
            "liquid_esplora_target_1_fee:secret-endpoint"
        );
        let diagnostic = format!("{record:?}");
        assert!(diagnostic.contains("<redacted>"));
        assert!(!diagnostic.contains("secret-endpoint"));
        assert!(!diagnostic.contains("construction_authority"));
    }

    #[test]
    fn construction_authority_uses_remaining_freshness_on_a_monotonic_deadline() {
        let policy = BitcoinFeePolicy::new(rate(1.0), rate(100.0), 30, 300).unwrap();
        let decision = policy
            .decide_typed(
                Some(&LiveBitcoin::new(
                    rate(12.5),
                    1_000,
                    provenance("mempool_precise_fastest_fee:primary"),
                )),
                None,
                1_007,
            )
            .unwrap();
        let record = FeeDecisionRecord::from_bitcoin(
            FeeConstructionPurpose::BitcoinRecovery,
            &decision,
            &policy,
            1_007,
        )
        .unwrap();

        assert_eq!(
            construction_authority_remaining(7, 30),
            Some(Duration::from_secs(23))
        );
        assert_eq!(
            construction_authority_remaining(0, u64::MAX),
            Some(Duration::from_secs(u64::MAX))
        );
        assert!(construction_authority_remaining(31, 30).is_none());
        let captured_at = record.construction_authority_captured_at;
        let deadline = captured_at
            .checked_add(record.construction_authority_remaining)
            .unwrap();
        assert!(!record
            .authorizes_construction_at(captured_at.checked_sub(Duration::from_nanos(1)).unwrap()));
        assert!(record.authorizes_construction_at(captured_at));
        assert!(record.authorizes_construction_at(deadline));
        assert!(!record
            .authorizes_construction_at(deadline.checked_add(Duration::from_nanos(1)).unwrap()));
    }

    #[test]
    fn persisted_authority_equality_ignores_the_process_local_deadline() {
        let policy = BitcoinFeePolicy::new(rate(1.0), rate(100.0), 30, 300).unwrap();
        let decision = policy
            .decide_typed(
                Some(&LiveBitcoin::new(
                    rate(12.5),
                    1_000,
                    provenance("mempool_precise_fastest_fee:primary"),
                )),
                None,
                1_007,
            )
            .unwrap();
        let record = FeeDecisionRecord::from_bitcoin(
            FeeConstructionPurpose::BitcoinRecovery,
            &decision,
            &policy,
            1_007,
        )
        .unwrap();
        let mut same_persisted_authority = record.clone();
        assert_eq!(
            record.construction_authority_captured_at,
            same_persisted_authority.construction_authority_captured_at
        );
        assert_eq!(
            record.construction_authority_remaining,
            same_persisted_authority.construction_authority_remaining
        );
        same_persisted_authority.construction_authority_captured_at = same_persisted_authority
            .construction_authority_captured_at
            .checked_add(Duration::from_secs(1))
            .unwrap();

        assert_eq!(record, same_persisted_authority);
        same_persisted_authority.freshness_max_age_secs += 1;
        assert_ne!(record, same_persisted_authority);
    }

    #[test]
    fn rehydrated_authority_validates_committed_fee_but_never_constructs_new_bytes() {
        let replay = FeeDecisionRecord::from_persisted_bitcoin_authority(
            FeeObservationSource::LiveBitcoin,
            rate(12.5),
            1_000,
            1_007,
            7,
            30,
            provenance("persisted-cooperative-signing"),
            rate(1.0),
            rate(100.0),
        )
        .unwrap();

        assert!(!replay.authorizes_construction_now());
        assert_eq!(replay.exact_authorized_fee_sat(141).unwrap(), 1_763);
        assert_eq!(replay.purpose(), FeeConstructionPurpose::BitcoinRecovery);
    }

    #[test]
    fn exact_size_fee_authority_rejects_underpay_and_overpay() {
        let policy = BitcoinFeePolicy::new(rate(1.0), rate(100.0), 30, 300).unwrap();
        let decision = policy
            .decide_typed(
                Some(&LiveBitcoin::new(
                    rate(12.5),
                    1_000,
                    provenance("mempool_precise_fastest_fee:primary"),
                )),
                None,
                1_000,
            )
            .unwrap();
        let record = FeeDecisionRecord::from_bitcoin(
            FeeConstructionPurpose::BitcoinRecovery,
            &decision,
            &policy,
            1_000,
        )
        .unwrap();

        // boltz-client computes ceil(12.5 sat/vB * 141 vB) = 1_763 sat.
        let exact = record.exact_authorized_fee_sat(141).unwrap();
        assert_eq!(exact, 1_763);
        assert_ne!(1_762, exact);
        assert_ne!(1_764, exact);
    }

    #[test]
    fn record_rejects_decision_outside_the_supplied_policy_bounds() {
        let authorizing_policy = BitcoinFeePolicy::new(rate(1.0), rate(100.0), 30, 300).unwrap();
        let decision = authorizing_policy
            .decide_typed(
                Some(&LiveBitcoin::new(
                    rate(12.5),
                    1_000,
                    provenance("mempool_precise_fastest_fee:primary"),
                )),
                None,
                1_000,
            )
            .unwrap();

        for supplied_policy in [
            BitcoinFeePolicy::new(rate(1.0), rate(10.0), 30, 300).unwrap(),
            BitcoinFeePolicy::new(rate(20.0), rate(100.0), 30, 300).unwrap(),
        ] {
            assert_eq!(
                FeeDecisionRecord::from_bitcoin(
                    FeeConstructionPurpose::BitcoinRecovery,
                    &decision,
                    &supplied_policy,
                    1_000,
                ),
                Err(FeeDecisionRecordError::DecisionOutsidePolicyBounds)
            );
        }
    }

    #[test]
    fn typed_constructors_reject_wrong_purpose_or_evaluation_clock() {
        let bitcoin_policy = BitcoinFeePolicy::default();
        let bitcoin = BitcoinLastKnownGood::new(rate(5.0), 1_000, provenance("btc"));
        let decision = bitcoin_policy
            .decide_typed(None, Some(&bitcoin), 1_001)
            .unwrap();
        assert!(matches!(
            FeeDecisionRecord::from_bitcoin(
                FeeConstructionPurpose::ChainLiquidClaim,
                &decision,
                &bitcoin_policy,
                1_001,
            ),
            Err(FeeDecisionRecordError::PurposeRailMismatch { .. })
        ));
        assert_eq!(
            FeeDecisionRecord::from_bitcoin(
                FeeConstructionPurpose::BitcoinRecovery,
                &decision,
                &bitcoin_policy,
                1_002,
            ),
            Err(FeeDecisionRecordError::EvaluationClockMismatch)
        );

        let liquid_policy = LiquidFeePolicy::default();
        let live = LiveLiquid::new(rate(0.5), 1_000, provenance("liquid"));
        let liquid = liquid_policy
            .decide_typed(Some(&live), None, 1_000)
            .unwrap();
        assert!(FeeDecisionRecord::from_liquid(
            FeeConstructionPurpose::BitcoinRecovery,
            &liquid,
            &liquid_policy,
            1_000,
        )
        .is_err());
    }
}
