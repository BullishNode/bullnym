//! Immutable construction-time fee metadata persisted beside new transaction bytes.
//!
//! The builders consume the smaller typed builder decisions. This record keeps
//! the complete Review-25 authority trail for the journal write that makes
//! those bytes durable. It never supplies a fallback rate and cannot be built
//! without an already-accepted rail-specific policy decision.

use std::error::Error;
use std::fmt;

use crate::fee_policy::{
    BitcoinFeeDecision, BitcoinFeePolicy, FeeFreshness, FeeObservationSource, FeeProvenance,
    FeeRail, LiquidFeeDecision, LiquidFeePolicy, SatPerVbyte,
};

pub const FEE_POLICY_VERSION: &str = "review25-v1";

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

#[derive(Clone, PartialEq)]
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
        })
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

    pub fn provenance_for_persistence(&self) -> &str {
        self.provenance.expose_for_persistence()
    }

    pub const fn policy_floor(&self) -> SatPerVbyte {
        self.policy_floor
    }

    pub const fn policy_cap(&self) -> SatPerVbyte {
        self.policy_cap
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
