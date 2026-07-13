use async_trait::async_trait;
use pay_service::admission::{Dependency, MoneyAdmission, Rail, ReasonCode};
use pay_service::builder_fee::{BitcoinBuilderFeeDecision, LiquidBuilderFeeDecision};
use pay_service::current_fee_snapshot::{CurrentBitcoinFee, CurrentFeeSnapshot, CurrentLiquidFee};
use pay_service::fee_policy::{
    BitcoinFeeDecision, BitcoinFeePolicy, BitcoinLastKnownGood, FeeObservationSource,
    FeePolicyError, FeeProvenance, FeeRail, LiquidFeeDecision, LiquidFeePolicy,
    LiquidLastKnownGood, LiveBitcoin, LiveLiquid, SatPerVbyte,
};
use pay_service::fee_runtime::{FeePersistenceError, FeeRuntimePersistence};

pub const NOW_UNIX: u64 = 20_000;

pub fn rate(value: f64) -> SatPerVbyte {
    SatPerVbyte::new(value).expect("test fee rate must be representable")
}

pub fn provenance(value: &str) -> FeeProvenance {
    FeeProvenance::new(value).expect("test provenance must be valid")
}

pub fn live_bitcoin(value: f64, observed_at_unix: u64, source: &str) -> LiveBitcoin {
    LiveBitcoin::new(rate(value), observed_at_unix, provenance(source))
}

pub fn live_liquid(value: f64, observed_at_unix: u64, source: &str) -> LiveLiquid {
    LiveLiquid::new(rate(value), observed_at_unix, provenance(source))
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConstructionFee {
    pub rate_sat_per_vbyte: f64,
    pub fee_sat: u64,
}

pub fn bitcoin_construction_fee(
    decision: &BitcoinFeeDecision,
    virtual_bytes: u64,
) -> ConstructionFee {
    let rate = BitcoinBuilderFeeDecision::from(decision).rate();
    ConstructionFee {
        rate_sat_per_vbyte: rate.as_f64(),
        fee_sat: rate
            .checked_fee_for_vbytes(virtual_bytes)
            .expect("accepted Bitcoin fee must construct an integer fee"),
    }
}

pub fn liquid_construction_fee(
    decision: &LiquidFeeDecision,
    virtual_bytes: u64,
) -> ConstructionFee {
    let rate = LiquidBuilderFeeDecision::from(decision).rate();
    ConstructionFee {
        rate_sat_per_vbyte: rate.as_f64(),
        fee_sat: rate
            .checked_fee_for_vbytes(virtual_bytes)
            .expect("accepted Liquid fee must construct an integer fee"),
    }
}

/// The exact non-secret fields that cross the persistence boundary. The
/// production database lane owns SQL I/O; this fixture exercises the typed
/// restart boundary without duplicating that SQL implementation.
#[derive(Clone, Debug, PartialEq)]
pub struct PersistedLkgFixture {
    pub rail: FeeRail,
    pub original_source: FeeObservationSource,
    pub rate_sat_per_vbyte: f64,
    pub observed_at_unix: u64,
    pub provenance: String,
}

impl PersistedLkgFixture {
    pub fn capture_bitcoin(decision: &BitcoinFeeDecision) -> Self {
        Self {
            rail: FeeRail::Bitcoin,
            original_source: decision.source(),
            rate_sat_per_vbyte: decision.rate().as_f64(),
            observed_at_unix: decision.observed_at_unix(),
            provenance: decision.provenance().expose_for_persistence().to_owned(),
        }
    }

    pub fn capture_liquid(decision: &LiquidFeeDecision) -> Self {
        Self {
            rail: FeeRail::Liquid,
            original_source: decision.source(),
            rate_sat_per_vbyte: decision.rate().as_f64(),
            observed_at_unix: decision.observed_at_unix(),
            provenance: decision.provenance().expose_for_persistence().to_owned(),
        }
    }

    pub fn restore_bitcoin(&self) -> Result<BitcoinLastKnownGood, RestoreFixtureError> {
        if self.rail != FeeRail::Bitcoin {
            return Err(RestoreFixtureError::WrongRail {
                expected: FeeRail::Bitcoin,
                actual: self.rail,
            });
        }
        if self.original_source != FeeObservationSource::LiveBitcoin {
            return Err(RestoreFixtureError::WrongSource {
                expected: FeeObservationSource::LiveBitcoin,
                actual: self.original_source,
            });
        }
        Ok(BitcoinLastKnownGood::new(
            SatPerVbyte::new(self.rate_sat_per_vbyte).map_err(RestoreFixtureError::Policy)?,
            self.observed_at_unix,
            FeeProvenance::new(self.provenance.clone()).map_err(RestoreFixtureError::Policy)?,
        ))
    }

    pub fn restore_liquid(&self) -> Result<LiquidLastKnownGood, RestoreFixtureError> {
        if self.rail != FeeRail::Liquid {
            return Err(RestoreFixtureError::WrongRail {
                expected: FeeRail::Liquid,
                actual: self.rail,
            });
        }
        if self.original_source != FeeObservationSource::LiveLiquid {
            return Err(RestoreFixtureError::WrongSource {
                expected: FeeObservationSource::LiveLiquid,
                actual: self.original_source,
            });
        }
        Ok(LiquidLastKnownGood::new(
            SatPerVbyte::new(self.rate_sat_per_vbyte).map_err(RestoreFixtureError::Policy)?,
            self.observed_at_unix,
            FeeProvenance::new(self.provenance.clone()).map_err(RestoreFixtureError::Policy)?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RestoreFixtureError {
    WrongRail {
        expected: FeeRail,
        actual: FeeRail,
    },
    WrongSource {
        expected: FeeObservationSource,
        actual: FeeObservationSource,
    },
    Policy(FeePolicyError),
}

#[derive(Clone, Debug)]
pub struct RuntimeDecisions {
    pub bitcoin: Result<BitcoinFeeDecision, ()>,
    pub liquid: Result<LiquidFeeDecision, ()>,
}

#[derive(Clone, Debug)]
pub struct RestoringFeePersistence {
    bitcoin: Option<BitcoinLastKnownGood>,
    liquid: Option<LiquidLastKnownGood>,
}

impl RestoringFeePersistence {
    pub fn new(bitcoin: Option<BitcoinLastKnownGood>, liquid: Option<LiquidLastKnownGood>) -> Self {
        Self { bitcoin, liquid }
    }
}

#[async_trait]
impl FeeRuntimePersistence for RestoringFeePersistence {
    async fn restore(&self, snapshot: &CurrentFeeSnapshot) -> Result<(), FeePersistenceError> {
        if let Some(bitcoin) = self.bitcoin.clone() {
            snapshot
                .restore_bitcoin_last_known_good(bitcoin)
                .map_err(|_| FeePersistenceError::RestoreFailed)?;
        }
        if let Some(liquid) = self.liquid.clone() {
            snapshot
                .restore_liquid_last_known_good(liquid)
                .map_err(|_| FeePersistenceError::RestoreFailed)?;
        }
        Ok(())
    }

    async fn persist_accepted_bitcoin(
        &self,
        _snapshot: &CurrentFeeSnapshot,
        _current: &CurrentBitcoinFee,
        _policy: &BitcoinFeePolicy,
        _accepted_at_unix: u64,
    ) -> Result<(), FeePersistenceError> {
        Err(FeePersistenceError::WriteFailed)
    }

    async fn persist_accepted_liquid(
        &self,
        _snapshot: &CurrentFeeSnapshot,
        _current: &CurrentLiquidFee,
        _policy: &LiquidFeePolicy,
        _accepted_at_unix: u64,
    ) -> Result<(), FeePersistenceError> {
        Err(FeePersistenceError::WriteFailed)
    }
}

impl RuntimeDecisions {
    pub fn from_snapshot(
        snapshot: &CurrentFeeSnapshot,
        bitcoin_policy: &BitcoinFeePolicy,
        liquid_policy: &LiquidFeePolicy,
        now_unix: u64,
    ) -> Self {
        Self {
            bitcoin: snapshot
                .read_bitcoin(bitcoin_policy, now_unix)
                .map(|current| current.decision().clone())
                .map_err(|_| ()),
            liquid: snapshot
                .read_liquid(liquid_policy, now_unix)
                .map(|current| current.decision().clone())
                .map_err(|_| ()),
        }
    }

    pub fn ready(&self) -> bool {
        self.bitcoin.is_ok() && self.liquid.is_ok()
    }

    pub fn apply_to_admission(&self) -> MoneyAdmission {
        let admission = MoneyAdmission::healthy_test_fixture();
        admission.set_fee_policy_ready(self.ready());
        admission
    }
}

pub fn assert_swap_admission_closed_for_fee_policy(admission: &MoneyAdmission) {
    for rail in [Rail::LightningReverse, Rail::BitcoinChain] {
        let decision = admission.decision(rail);
        assert!(!decision.allowed(), "{rail:?} unexpectedly opened");
        assert!(decision.reasons.iter().any(|reason| {
            reason.dependency == Dependency::FeePolicy && reason.code == ReasonCode::Unavailable
        }));
    }
}

/// An immutable stand-in for bytes and fee evidence already committed by the
/// production write-ahead journal. Production replay is additionally covered
/// by `changed_fee_applies_before_journal_and_no_quote_replays_persisted_bytes`
/// in the PostgreSQL integration target.
#[derive(Clone, Debug, PartialEq)]
pub struct JournaledRecoveryFixture {
    pub raw_tx_hex: String,
    pub rate_sat_per_vbyte: f64,
    pub actual_fee_sat: u64,
    pub provenance: String,
}

impl JournaledRecoveryFixture {
    pub fn commit(decision: &BitcoinFeeDecision, virtual_bytes: u64) -> Self {
        let construction = bitcoin_construction_fee(decision, virtual_bytes);
        Self {
            raw_tx_hex: format!(
                "journaled-{:.8}-{}",
                construction.rate_sat_per_vbyte, construction.fee_sat
            ),
            rate_sat_per_vbyte: construction.rate_sat_per_vbyte,
            actual_fee_sat: construction.fee_sat,
            provenance: decision.provenance().expose_for_persistence().to_owned(),
        }
    }

    pub fn replay(&self, _later_decision: Option<&BitcoinFeeDecision>) -> Self {
        self.clone()
    }
}
