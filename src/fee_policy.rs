use std::error::Error;
use std::fmt;

pub const BITCOIN_FLOOR_SAT_PER_VBYTE: f64 = 1.0;
pub const BITCOIN_CAP_SAT_PER_VBYTE: f64 = 500.0;
pub const LIQUID_FLOOR_SAT_PER_VBYTE: f64 = 0.1;
pub const LIQUID_CAP_SAT_PER_VBYTE: f64 = 10.0;
pub const BITCOIN_LIVE_MAX_AGE_SECS: u64 = 120;
pub const BITCOIN_LAST_KNOWN_GOOD_MAX_AGE_SECS: u64 = 900;
pub const LIQUID_LIVE_MAX_AGE_SECS: u64 = 120;
pub const LIQUID_LAST_KNOWN_GOOD_MAX_AGE_SECS: u64 = 900;

const MAX_PROVENANCE_BYTES: usize = 512;

/// A finite positive fee rate measured in satoshis per virtual byte.
///
/// Rail separation happens at the observation and decision types.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct SatPerVbyte(f64);

impl SatPerVbyte {
    pub fn new(value: f64) -> Result<Self, FeePolicyError> {
        Self::try_from(value)
    }

    pub fn as_f64(self) -> f64 {
        self.0
    }

    /// Calculate the integer fee for an exact virtual size, rounding up so a
    /// fractional satoshi never underpays the selected rate.
    pub fn checked_fee_for_vbytes(self, vbytes: u64) -> Result<u64, FeePolicyError> {
        if vbytes == 0 {
            return Err(FeePolicyError::ZeroVirtualBytes);
        }
        let rounded = (self.0 * vbytes as f64).ceil();
        // u64::MAX as f64 rounds to 2^64. Equality is therefore overflow.
        if !rounded.is_finite() || rounded >= u64::MAX as f64 {
            return Err(FeePolicyError::FeeAmountOverflow);
        }
        Ok(rounded as u64)
    }
}

impl TryFrom<f64> for SatPerVbyte {
    type Error = FeePolicyError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(FeePolicyError::RateNotFinite);
        }
        if value <= 0.0 {
            return Err(FeePolicyError::RateMustBePositive);
        }
        if value.ceil() >= u64::MAX as f64 {
            return Err(FeePolicyError::RateCannotFitSats);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for SatPerVbyte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SatPerVbyte({} sat/vB)", self.0)
    }
}

/// Semantic origin of a rate observation. Endpoint details belong in the
/// redacted FeeProvenance value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeObservationSource {
    LiveBitcoin,
    BitcoinLastKnownGood,
    LiveLiquid,
    LiquidLastKnownGood,
    /// Compatibility marker for the rejected phase-1 configured-rate path.
    /// No policy decision accepts this source.
    ConfiguredLiquid,
}

impl FeeObservationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveBitcoin => "bitcoin_live",
            Self::BitcoinLastKnownGood => "bitcoin_last_known_good",
            Self::LiveLiquid => "liquid_live",
            Self::LiquidLastKnownGood => "liquid_last_known_good",
            Self::ConfiguredLiquid => "liquid_configured_rejected",
        }
    }
}

/// Opaque origin metadata suitable for persistence but never ordinary Debug
/// output. It may contain an endpoint or operator-controlled identifier.
#[derive(Clone, PartialEq, Eq)]
pub struct FeeProvenance(String);

impl FeeProvenance {
    pub fn new(value: impl Into<String>) -> Result<Self, FeePolicyError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(FeePolicyError::EmptyProvenance);
        }
        if value.len() > MAX_PROVENANCE_BYTES {
            return Err(FeePolicyError::ProvenanceTooLong {
                bytes: value.len(),
                max_bytes: MAX_PROVENANCE_BYTES,
            });
        }
        Ok(Self(value))
    }

    /// Explicitly expose the opaque value only at a persistence boundary.
    pub fn expose_for_persistence(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FeeProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FeeProvenance(<redacted>)")
    }
}

/// Freshness classification at a caller-supplied deterministic clock instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeFreshness {
    Fresh { age_secs: u64, max_age_secs: u64 },
    Stale { age_secs: u64, max_age_secs: u64 },
    FromFuture { lead_secs: u64, max_age_secs: u64 },
}

impl FeeFreshness {
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Fresh { .. })
    }
}

/// Compatibility transport shape. Correct policy entry points first convert
/// it to one of the four typed observations below.
#[derive(Clone, PartialEq)]
pub struct FeeObservation {
    rate: SatPerVbyte,
    observed_at_unix: u64,
    source: FeeObservationSource,
    provenance: FeeProvenance,
}

impl FeeObservation {
    pub fn new(
        rate: SatPerVbyte,
        observed_at_unix: u64,
        source: FeeObservationSource,
        provenance: FeeProvenance,
    ) -> Self {
        Self {
            rate,
            observed_at_unix,
            source,
            provenance,
        }
    }

    pub fn rate(&self) -> SatPerVbyte {
        self.rate
    }

    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    pub fn source(&self) -> FeeObservationSource {
        self.source
    }

    pub fn provenance(&self) -> &FeeProvenance {
        &self.provenance
    }

    pub fn freshness_at(&self, now_unix: u64, max_age_secs: u64) -> FeeFreshness {
        match now_unix.checked_sub(self.observed_at_unix) {
            Some(age_secs) if age_secs <= max_age_secs => FeeFreshness::Fresh {
                age_secs,
                max_age_secs,
            },
            Some(age_secs) => FeeFreshness::Stale {
                age_secs,
                max_age_secs,
            },
            None => FeeFreshness::FromFuture {
                lead_secs: self.observed_at_unix - now_unix,
                max_age_secs,
            },
        }
    }
}

impl fmt::Debug for FeeObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FeeObservation")
            .field("rate", &self.rate)
            .field("observed_at_unix", &self.observed_at_unix)
            .field("source", &self.source)
            .field("provenance", &self.provenance)
            .finish()
    }
}

macro_rules! typed_observation {
    ($name:ident, $source:expr) => {
        #[derive(Clone, PartialEq)]
        pub struct $name(FeeObservation);

        impl $name {
            pub fn new(
                rate: SatPerVbyte,
                observed_at_unix: u64,
                provenance: FeeProvenance,
            ) -> Self {
                Self(FeeObservation::new(
                    rate,
                    observed_at_unix,
                    $source,
                    provenance,
                ))
            }

            pub fn try_from_observation(
                observation: FeeObservation,
            ) -> Result<Self, FeePolicyError> {
                expect_source(&observation, $source)?;
                Ok(Self(observation))
            }

            pub fn rate(&self) -> SatPerVbyte {
                self.0.rate()
            }

            pub fn observed_at_unix(&self) -> u64 {
                self.0.observed_at_unix()
            }

            pub fn source(&self) -> FeeObservationSource {
                self.0.source()
            }

            pub fn provenance(&self) -> &FeeProvenance {
                self.0.provenance()
            }

            fn observation(&self) -> &FeeObservation {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}

typed_observation!(LiveBitcoin, FeeObservationSource::LiveBitcoin);
typed_observation!(
    BitcoinLastKnownGood,
    FeeObservationSource::BitcoinLastKnownGood
);
typed_observation!(LiveLiquid, FeeObservationSource::LiveLiquid);
typed_observation!(
    LiquidLastKnownGood,
    FeeObservationSource::LiquidLastKnownGood
);

#[derive(Clone, Copy, Debug, PartialEq)]
struct FeeRateBounds {
    floor: SatPerVbyte,
    cap: SatPerVbyte,
}

impl FeeRateBounds {
    fn new(floor: SatPerVbyte, cap: SatPerVbyte) -> Result<Self, FeePolicyError> {
        if floor > cap {
            return Err(FeePolicyError::FloorExceedsCap { floor, cap });
        }
        Ok(Self { floor, cap })
    }

    fn contains(self, rate: SatPerVbyte) -> bool {
        (self.floor..=self.cap).contains(&rate)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeRail {
    Bitcoin,
    Liquid,
}

impl FeeRail {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::Liquid => "liquid",
        }
    }
}

/// Why a typed candidate could not authorize a new construction attempt.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FeeObservationRejection {
    Missing,
    Stale {
        age_secs: u64,
        max_age_secs: u64,
    },
    FromFuture {
        lead_secs: u64,
        max_age_secs: u64,
    },
    OutsideBounds {
        rate: SatPerVbyte,
        floor: SatPerVbyte,
        cap: SatPerVbyte,
    },
}

#[derive(Clone, Debug, PartialEq)]
struct FeeDecisionCore {
    rate: SatPerVbyte,
    observed_at_unix: u64,
    source: FeeObservationSource,
    provenance: FeeProvenance,
    freshness: FeeFreshness,
}

impl FeeDecisionCore {
    fn from_observation(observation: &FeeObservation, freshness: FeeFreshness) -> Self {
        Self {
            rate: observation.rate,
            observed_at_unix: observation.observed_at_unix,
            source: observation.source,
            provenance: observation.provenance.clone(),
            freshness,
        }
    }
}

macro_rules! decision_type {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq)]
        pub struct $name(FeeDecisionCore);

        impl $name {
            pub fn rate(&self) -> SatPerVbyte {
                self.0.rate
            }

            pub fn observed_rate(&self) -> SatPerVbyte {
                self.0.rate
            }

            pub fn observed_at_unix(&self) -> u64 {
                self.0.observed_at_unix
            }

            pub fn source(&self) -> FeeObservationSource {
                self.0.source
            }

            pub fn provenance(&self) -> &FeeProvenance {
                &self.0.provenance
            }

            pub fn freshness(&self) -> FeeFreshness {
                self.0.freshness
            }
        }
    };
}

decision_type!(BitcoinFeeDecision);
decision_type!(LiquidFeeDecision);

fn evaluate_candidate(
    candidate: Option<&FeeObservation>,
    now_unix: u64,
    max_age_secs: u64,
    bounds: FeeRateBounds,
) -> Result<(&FeeObservation, FeeFreshness), FeeObservationRejection> {
    let Some(observation) = candidate else {
        return Err(FeeObservationRejection::Missing);
    };
    let freshness = observation.freshness_at(now_unix, max_age_secs);
    match freshness {
        FeeFreshness::Fresh { .. } => {}
        FeeFreshness::Stale {
            age_secs,
            max_age_secs,
        } => {
            return Err(FeeObservationRejection::Stale {
                age_secs,
                max_age_secs,
            });
        }
        FeeFreshness::FromFuture {
            lead_secs,
            max_age_secs,
        } => {
            return Err(FeeObservationRejection::FromFuture {
                lead_secs,
                max_age_secs,
            });
        }
    }
    if !bounds.contains(observation.rate) {
        return Err(FeeObservationRejection::OutsideBounds {
            rate: observation.rate,
            floor: bounds.floor,
            cap: bounds.cap,
        });
    }
    Ok((observation, freshness))
}

#[derive(Clone, Copy)]
struct FeeSelectionPolicy {
    rail: FeeRail,
    live_max_age_secs: u64,
    last_known_good_max_age_secs: u64,
    bounds: FeeRateBounds,
}

fn select_live_then_lkg(
    policy: FeeSelectionPolicy,
    live: Option<&FeeObservation>,
    last_known_good: Option<&FeeObservation>,
    now_unix: u64,
) -> Result<FeeDecisionCore, FeePolicyError> {
    match evaluate_candidate(live, now_unix, policy.live_max_age_secs, policy.bounds) {
        Ok((observation, freshness)) => {
            Ok(FeeDecisionCore::from_observation(observation, freshness))
        }
        Err(live_rejection) => {
            match evaluate_candidate(
                last_known_good,
                now_unix,
                policy.last_known_good_max_age_secs,
                policy.bounds,
            ) {
                Ok((observation, freshness)) => {
                    Ok(FeeDecisionCore::from_observation(observation, freshness))
                }
                Err(last_known_good_rejection) => Err(FeePolicyError::TemporarilyUnavailable {
                    rail: policy.rail,
                    live: live_rejection,
                    last_known_good: last_known_good_rejection,
                }),
            }
        }
    }
}

/// Bitcoin policy selects fresh in-bounds live evidence first, then a recent
/// persisted in-bounds same-rail observation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BitcoinFeePolicy {
    bounds: FeeRateBounds,
    live_max_age_secs: u64,
    last_known_good_max_age_secs: u64,
}

impl BitcoinFeePolicy {
    pub fn new(
        floor: SatPerVbyte,
        cap: SatPerVbyte,
        live_max_age_secs: u64,
        last_known_good_max_age_secs: u64,
    ) -> Result<Self, FeePolicyError> {
        validate_freshness_window(FeeObservationSource::LiveBitcoin, live_max_age_secs)?;
        validate_freshness_window(
            FeeObservationSource::BitcoinLastKnownGood,
            last_known_good_max_age_secs,
        )?;
        Ok(Self {
            bounds: FeeRateBounds::new(floor, cap)?,
            live_max_age_secs,
            last_known_good_max_age_secs,
        })
    }

    pub fn floor(&self) -> SatPerVbyte {
        self.bounds.floor
    }

    pub fn cap(&self) -> SatPerVbyte {
        self.bounds.cap
    }

    pub fn live_max_age_secs(&self) -> u64 {
        self.live_max_age_secs
    }

    pub fn last_known_good_max_age_secs(&self) -> u64 {
        self.last_known_good_max_age_secs
    }

    pub fn decide_typed(
        &self,
        live: Option<&LiveBitcoin>,
        last_known_good: Option<&BitcoinLastKnownGood>,
        now_unix: u64,
    ) -> Result<BitcoinFeeDecision, FeePolicyError> {
        select_live_then_lkg(
            FeeSelectionPolicy {
                rail: FeeRail::Bitcoin,
                live_max_age_secs: self.live_max_age_secs,
                last_known_good_max_age_secs: self.last_known_good_max_age_secs,
                bounds: self.bounds,
            },
            live.map(LiveBitcoin::observation),
            last_known_good.map(BitcoinLastKnownGood::observation),
            now_unix,
        )
        .map(BitcoinFeeDecision)
    }

    /// Compatibility entry point for the accepted Bitcoin adapter. It now
    /// rejects unsafe rates rather than clamping them.
    pub fn decide(
        &self,
        live: Option<&FeeObservation>,
        last_known_good: Option<&FeeObservation>,
        now_unix: u64,
    ) -> Result<BitcoinFeeDecision, FeePolicyError> {
        if let Some(observation) = live {
            expect_source(observation, FeeObservationSource::LiveBitcoin)?;
        }
        if let Some(observation) = last_known_good {
            expect_source(observation, FeeObservationSource::BitcoinLastKnownGood)?;
        }

        let live_freshness =
            live.map(|observation| observation.freshness_at(now_unix, self.live_max_age_secs));
        let last_known_good_freshness = last_known_good.map(|observation| {
            observation.freshness_at(now_unix, self.last_known_good_max_age_secs)
        });

        match select_live_then_lkg(
            FeeSelectionPolicy {
                rail: FeeRail::Bitcoin,
                live_max_age_secs: self.live_max_age_secs,
                last_known_good_max_age_secs: self.last_known_good_max_age_secs,
                bounds: self.bounds,
            },
            live,
            last_known_good,
            now_unix,
        ) {
            Ok(decision) => Ok(BitcoinFeeDecision(decision)),
            Err(FeePolicyError::TemporarilyUnavailable { .. }) => {
                Err(FeePolicyError::NoFreshBitcoinQuote {
                    live: live_freshness,
                    last_known_good: last_known_good_freshness,
                })
            }
            Err(error) => Err(error),
        }
    }
}

impl Default for BitcoinFeePolicy {
    fn default() -> Self {
        Self {
            bounds: FeeRateBounds {
                floor: SatPerVbyte(BITCOIN_FLOOR_SAT_PER_VBYTE),
                cap: SatPerVbyte(BITCOIN_CAP_SAT_PER_VBYTE),
            },
            live_max_age_secs: BITCOIN_LIVE_MAX_AGE_SECS,
            last_known_good_max_age_secs: BITCOIN_LAST_KNOWN_GOOD_MAX_AGE_SECS,
        }
    }
}

/// Liquid policy uses the same live-first/recent-persisted-only authority
/// model as Bitcoin, with Liquid-specific source types and bounds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LiquidFeePolicy {
    bounds: FeeRateBounds,
    live_max_age_secs: u64,
    last_known_good_max_age_secs: u64,
}

impl LiquidFeePolicy {
    /// Constructor using the explicit standard freshness windows.
    pub fn new(floor: SatPerVbyte, cap: SatPerVbyte) -> Result<Self, FeePolicyError> {
        Self::with_freshness(
            floor,
            cap,
            LIQUID_LIVE_MAX_AGE_SECS,
            LIQUID_LAST_KNOWN_GOOD_MAX_AGE_SECS,
        )
    }

    pub fn with_freshness(
        floor: SatPerVbyte,
        cap: SatPerVbyte,
        live_max_age_secs: u64,
        last_known_good_max_age_secs: u64,
    ) -> Result<Self, FeePolicyError> {
        validate_freshness_window(FeeObservationSource::LiveLiquid, live_max_age_secs)?;
        validate_freshness_window(
            FeeObservationSource::LiquidLastKnownGood,
            last_known_good_max_age_secs,
        )?;
        Ok(Self {
            bounds: FeeRateBounds::new(floor, cap)?,
            live_max_age_secs,
            last_known_good_max_age_secs,
        })
    }

    pub fn floor(&self) -> SatPerVbyte {
        self.bounds.floor
    }

    pub fn cap(&self) -> SatPerVbyte {
        self.bounds.cap
    }

    pub fn live_max_age_secs(&self) -> u64 {
        self.live_max_age_secs
    }

    pub fn last_known_good_max_age_secs(&self) -> u64 {
        self.last_known_good_max_age_secs
    }

    pub fn decide_typed(
        &self,
        live: Option<&LiveLiquid>,
        last_known_good: Option<&LiquidLastKnownGood>,
        now_unix: u64,
    ) -> Result<LiquidFeeDecision, FeePolicyError> {
        select_live_then_lkg(
            FeeSelectionPolicy {
                rail: FeeRail::Liquid,
                live_max_age_secs: self.live_max_age_secs,
                last_known_good_max_age_secs: self.last_known_good_max_age_secs,
                bounds: self.bounds,
            },
            live.map(LiveLiquid::observation),
            last_known_good.map(LiquidLastKnownGood::observation),
            now_unix,
        )
        .map(LiquidFeeDecision)
    }

    /// The old configured-rate path is deliberately retained only as a
    /// fail-closed compatibility seam until integration removes its callers.
    pub fn decide(
        &self,
        configured: &FeeObservation,
        _now_unix: u64,
    ) -> Result<LiquidFeeDecision, FeePolicyError> {
        expect_source(configured, FeeObservationSource::ConfiguredLiquid)?;
        Err(FeePolicyError::ConfiguredFeeRateRejected)
    }
}

impl Default for LiquidFeePolicy {
    fn default() -> Self {
        Self {
            bounds: FeeRateBounds {
                floor: SatPerVbyte(LIQUID_FLOOR_SAT_PER_VBYTE),
                cap: SatPerVbyte(LIQUID_CAP_SAT_PER_VBYTE),
            },
            live_max_age_secs: LIQUID_LIVE_MAX_AGE_SECS,
            last_known_good_max_age_secs: LIQUID_LAST_KNOWN_GOOD_MAX_AGE_SECS,
        }
    }
}

fn validate_freshness_window(
    source: FeeObservationSource,
    max_age_secs: u64,
) -> Result<(), FeePolicyError> {
    if max_age_secs == 0 {
        Err(FeePolicyError::FreshnessWindowMustBePositive { source })
    } else {
        Ok(())
    }
}

fn expect_source(
    observation: &FeeObservation,
    expected: FeeObservationSource,
) -> Result<(), FeePolicyError> {
    if observation.source == expected {
        Ok(())
    } else {
        Err(FeePolicyError::UnexpectedObservationSource {
            expected,
            actual: observation.source,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum FeePolicyError {
    RateNotFinite,
    RateMustBePositive,
    RateCannotFitSats,
    ZeroVirtualBytes,
    FeeAmountOverflow,
    FloorExceedsCap {
        floor: SatPerVbyte,
        cap: SatPerVbyte,
    },
    FreshnessWindowMustBePositive {
        source: FeeObservationSource,
    },
    EmptyProvenance,
    ProvenanceTooLong {
        bytes: usize,
        max_bytes: usize,
    },
    UnexpectedObservationSource {
        expected: FeeObservationSource,
        actual: FeeObservationSource,
    },
    TemporarilyUnavailable {
        rail: FeeRail,
        live: FeeObservationRejection,
        last_known_good: FeeObservationRejection,
    },
    /// Compatibility error for the accepted generic Bitcoin adapter.
    NoFreshBitcoinQuote {
        live: Option<FeeFreshness>,
        last_known_good: Option<FeeFreshness>,
    },
    ConfiguredFeeRateRejected,
}

impl fmt::Display for FeePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateNotFinite => f.write_str("fee rate must be finite sat/vByte"),
            Self::RateMustBePositive => f.write_str("fee rate must be greater than zero sat/vByte"),
            Self::RateCannotFitSats => f.write_str("fee rate cannot fit an integer-satoshi fee"),
            Self::ZeroVirtualBytes => f.write_str("transaction virtual size must be nonzero"),
            Self::FeeAmountOverflow => f.write_str("fee amount overflows integer satoshis"),
            Self::FloorExceedsCap { floor, cap } => {
                write!(f, "fee floor {floor:?} exceeds cap {cap:?}")
            }
            Self::FreshnessWindowMustBePositive { source } => {
                write!(f, "{} freshness window must be nonzero", source.as_str())
            }
            Self::EmptyProvenance => f.write_str("fee provenance must not be empty"),
            Self::ProvenanceTooLong { bytes, max_bytes } => write!(
                f,
                "fee provenance is {bytes} bytes; maximum is {max_bytes} bytes"
            ),
            Self::UnexpectedObservationSource { expected, actual } => write!(
                f,
                "expected {} fee observation, got {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::TemporarilyUnavailable { rail, .. } => write!(
                f,
                "no usable live or persisted {} fee observation",
                rail.as_str()
            ),
            Self::NoFreshBitcoinQuote { .. } => {
                f.write_str("no usable live or last-known-good Bitcoin fee quote")
            }
            Self::ConfiguredFeeRateRejected => {
                f.write_str("configured Liquid fee rates are not fee evidence")
            }
        }
    }
}

impl Error for FeePolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(value: f64) -> SatPerVbyte {
        SatPerVbyte::try_from(value).unwrap()
    }

    fn provenance(value: &str) -> FeeProvenance {
        FeeProvenance::new(value).unwrap()
    }

    fn live_bitcoin(value: f64, observed_at_unix: u64) -> LiveBitcoin {
        LiveBitcoin::new(rate(value), observed_at_unix, provenance("btc-live"))
    }

    fn bitcoin_lkg(value: f64, observed_at_unix: u64) -> BitcoinLastKnownGood {
        BitcoinLastKnownGood::new(rate(value), observed_at_unix, provenance("btc-lkg-row"))
    }

    fn live_liquid(value: f64, observed_at_unix: u64) -> LiveLiquid {
        LiveLiquid::new(rate(value), observed_at_unix, provenance("liquid-live"))
    }

    fn liquid_lkg(value: f64, observed_at_unix: u64) -> LiquidLastKnownGood {
        LiquidLastKnownGood::new(rate(value), observed_at_unix, provenance("liquid-lkg-row"))
    }

    #[test]
    fn four_typed_sources_are_distinct_and_stable() {
        let now = 1_000;
        let observations = [
            (
                live_bitcoin(2.0, now).source(),
                FeeObservationSource::LiveBitcoin,
                "bitcoin_live",
            ),
            (
                bitcoin_lkg(2.0, now).source(),
                FeeObservationSource::BitcoinLastKnownGood,
                "bitcoin_last_known_good",
            ),
            (
                live_liquid(0.5, now).source(),
                FeeObservationSource::LiveLiquid,
                "liquid_live",
            ),
            (
                liquid_lkg(0.5, now).source(),
                FeeObservationSource::LiquidLastKnownGood,
                "liquid_last_known_good",
            ),
        ];
        for (actual, expected, label) in observations {
            assert_eq!(actual, expected);
            assert_eq!(actual.as_str(), label);
        }
    }

    #[test]
    fn typed_conversion_rejects_every_wrong_source() {
        let now = 1_000;
        let raw =
            |source| FeeObservation::new(rate(2.0), now, source, provenance("typed-boundary"));
        assert!(LiveBitcoin::try_from_observation(raw(FeeObservationSource::LiveLiquid)).is_err());
        assert!(BitcoinLastKnownGood::try_from_observation(raw(
            FeeObservationSource::LiquidLastKnownGood
        ))
        .is_err());
        assert!(LiveLiquid::try_from_observation(raw(FeeObservationSource::LiveBitcoin)).is_err());
        assert!(LiquidLastKnownGood::try_from_observation(raw(
            FeeObservationSource::BitcoinLastKnownGood
        ))
        .is_err());
        assert!(
            LiveLiquid::try_from_observation(raw(FeeObservationSource::ConfiguredLiquid)).is_err()
        );
    }

    #[test]
    fn both_rails_prefer_fresh_live_over_recent_lkg() {
        let now = 10_000;
        let btc_live = live_bitcoin(8.0, now - 10);
        let btc_lkg = bitcoin_lkg(3.0, now);
        let btc = BitcoinFeePolicy::default()
            .decide_typed(Some(&btc_live), Some(&btc_lkg), now)
            .unwrap();
        assert_eq!(btc.rate(), rate(8.0));
        assert_eq!(btc.source(), FeeObservationSource::LiveBitcoin);

        let liquid_live = live_liquid(0.75, now - 10);
        let liquid_lkg = liquid_lkg(0.25, now);
        let liquid = LiquidFeePolicy::default()
            .decide_typed(Some(&liquid_live), Some(&liquid_lkg), now)
            .unwrap();
        assert_eq!(liquid.rate(), rate(0.75));
        assert_eq!(liquid.source(), FeeObservationSource::LiveLiquid);
    }

    #[test]
    fn rejected_live_uses_only_recent_same_rail_lkg() {
        let now = 10_000;
        let bitcoin = BitcoinFeePolicy::default();
        let btc_lkg = bitcoin_lkg(4.0, now);
        let bitcoin_rejections = [
            live_bitcoin(0.5, now),
            live_bitcoin(501.0, now),
            live_bitcoin(2.0, now - bitcoin.live_max_age_secs() - 1),
            live_bitcoin(2.0, now + 1),
        ];
        for rejected_live in bitcoin_rejections {
            let decision = bitcoin
                .decide_typed(Some(&rejected_live), Some(&btc_lkg), now)
                .unwrap();
            assert_eq!(
                decision.source(),
                FeeObservationSource::BitcoinLastKnownGood
            );
            assert_eq!(decision.rate(), rate(4.0));
        }

        let liquid = LiquidFeePolicy::default();
        let liquid_lkg = liquid_lkg(0.4, now);
        let liquid_rejections = [
            live_liquid(0.09, now),
            live_liquid(10.01, now),
            live_liquid(0.5, now - liquid.live_max_age_secs() - 1),
            live_liquid(0.5, now + 1),
        ];
        for rejected_live in liquid_rejections {
            let decision = liquid
                .decide_typed(Some(&rejected_live), Some(&liquid_lkg), now)
                .unwrap();
            assert_eq!(decision.source(), FeeObservationSource::LiquidLastKnownGood);
            assert_eq!(decision.rate(), rate(0.4));
        }
    }

    #[test]
    fn bounds_are_inclusive_and_never_change_the_observed_rate() {
        let now = 1_000;
        let bitcoin = BitcoinFeePolicy::default();
        for value in [bitcoin.floor().as_f64(), bitcoin.cap().as_f64()] {
            let observed = live_bitcoin(value, now);
            let decision = bitcoin.decide_typed(Some(&observed), None, now).unwrap();
            assert_eq!(decision.rate(), rate(value));
            assert_eq!(decision.observed_rate(), rate(value));
        }

        let liquid = LiquidFeePolicy::default();
        for value in [liquid.floor().as_f64(), liquid.cap().as_f64()] {
            let observed = live_liquid(value, now);
            let decision = liquid.decide_typed(Some(&observed), None, now).unwrap();
            assert_eq!(decision.rate(), rate(value));
            assert_eq!(decision.observed_rate(), rate(value));
        }
    }

    #[test]
    fn adjacent_out_of_bounds_values_are_rejected_not_clamped() {
        let now = 1_000;
        let bitcoin = BitcoinFeePolicy::default();
        let below_btc = f64::from_bits(bitcoin.floor().as_f64().to_bits() - 1);
        let above_btc = f64::from_bits(bitcoin.cap().as_f64().to_bits() + 1);
        for value in [below_btc, above_btc] {
            let observed = live_bitcoin(value, now);
            assert!(matches!(
                bitcoin.decide_typed(Some(&observed), None, now),
                Err(FeePolicyError::TemporarilyUnavailable {
                    rail: FeeRail::Bitcoin,
                    live: FeeObservationRejection::OutsideBounds { rate: rejected, .. },
                    last_known_good: FeeObservationRejection::Missing,
                }) if rejected == rate(value)
            ));
        }

        let liquid = LiquidFeePolicy::default();
        let below_liquid = f64::from_bits(liquid.floor().as_f64().to_bits() - 1);
        let above_liquid = f64::from_bits(liquid.cap().as_f64().to_bits() + 1);
        for value in [below_liquid, above_liquid] {
            let observed = live_liquid(value, now);
            assert!(matches!(
                liquid.decide_typed(Some(&observed), None, now),
                Err(FeePolicyError::TemporarilyUnavailable {
                    rail: FeeRail::Liquid,
                    live: FeeObservationRejection::OutsideBounds { rate: rejected, .. },
                    last_known_good: FeeObservationRejection::Missing,
                }) if rejected == rate(value)
            ));
        }
    }

    #[test]
    fn unsafe_or_stale_lkg_never_becomes_a_decision() {
        let now = 10_000;
        let bitcoin = BitcoinFeePolicy::default();
        for lkg in [
            bitcoin_lkg(0.5, now),
            bitcoin_lkg(501.0, now),
            bitcoin_lkg(2.0, now - bitcoin.last_known_good_max_age_secs() - 1),
            bitcoin_lkg(2.0, now + 1),
        ] {
            assert!(matches!(
                bitcoin.decide_typed(None, Some(&lkg), now),
                Err(FeePolicyError::TemporarilyUnavailable {
                    rail: FeeRail::Bitcoin,
                    live: FeeObservationRejection::Missing,
                    ..
                })
            ));
        }

        let liquid = LiquidFeePolicy::default();
        for lkg in [
            liquid_lkg(0.09, now),
            liquid_lkg(10.01, now),
            liquid_lkg(0.5, now - liquid.last_known_good_max_age_secs() - 1),
            liquid_lkg(0.5, now + 1),
        ] {
            assert!(matches!(
                liquid.decide_typed(None, Some(&lkg), now),
                Err(FeePolicyError::TemporarilyUnavailable {
                    rail: FeeRail::Liquid,
                    live: FeeObservationRejection::Missing,
                    ..
                })
            ));
        }
    }

    #[test]
    fn no_evidence_is_typed_temporary_unavailability_on_both_rails() {
        let now = 10_000;
        assert_eq!(
            BitcoinFeePolicy::default().decide_typed(None, None, now),
            Err(FeePolicyError::TemporarilyUnavailable {
                rail: FeeRail::Bitcoin,
                live: FeeObservationRejection::Missing,
                last_known_good: FeeObservationRejection::Missing,
            })
        );
        assert_eq!(
            LiquidFeePolicy::default().decide_typed(None, None, now),
            Err(FeePolicyError::TemporarilyUnavailable {
                rail: FeeRail::Liquid,
                live: FeeObservationRejection::Missing,
                last_known_good: FeeObservationRejection::Missing,
            })
        );
    }

    #[test]
    fn freshness_boundaries_are_exact_for_all_four_sources() {
        let now = 10_000;
        let bitcoin = BitcoinFeePolicy::default();
        let btc_live = live_bitcoin(2.0, now - bitcoin.live_max_age_secs());
        let btc_lkg = bitcoin_lkg(2.0, now - bitcoin.last_known_good_max_age_secs());
        assert!(bitcoin.decide_typed(Some(&btc_live), None, now).is_ok());
        assert!(bitcoin.decide_typed(None, Some(&btc_lkg), now).is_ok());

        let liquid = LiquidFeePolicy::default();
        let liquid_live = live_liquid(0.5, now - liquid.live_max_age_secs());
        let liquid_lkg = liquid_lkg(0.5, now - liquid.last_known_good_max_age_secs());
        assert!(liquid.decide_typed(Some(&liquid_live), None, now).is_ok());
        assert!(liquid.decide_typed(None, Some(&liquid_lkg), now).is_ok());
    }

    #[test]
    fn future_and_stale_rejections_preserve_exact_clock_evidence() {
        let now = 10_000;
        let bitcoin = BitcoinFeePolicy::default();
        let future = live_bitcoin(2.0, now + 1);
        let stale = bitcoin_lkg(2.0, now - bitcoin.last_known_good_max_age_secs() - 1);
        assert!(matches!(
            bitcoin.decide_typed(Some(&future), Some(&stale), now),
            Err(FeePolicyError::TemporarilyUnavailable {
                rail: FeeRail::Bitcoin,
                live: FeeObservationRejection::FromFuture {
                    lead_secs: 1,
                    max_age_secs: BITCOIN_LIVE_MAX_AGE_SECS,
                },
                last_known_good: FeeObservationRejection::Stale {
                    age_secs,
                    max_age_secs: BITCOIN_LAST_KNOWN_GOOD_MAX_AGE_SECS,
                },
            }) if age_secs == BITCOIN_LAST_KNOWN_GOOD_MAX_AGE_SECS + 1
        ));
    }

    #[test]
    fn configured_liquid_rate_is_never_fee_evidence() {
        let configured = FeeObservation::new(
            rate(0.1),
            1_000,
            FeeObservationSource::ConfiguredLiquid,
            provenance("config:fee_policy.liquid"),
        );
        assert_eq!(
            LiquidFeePolicy::default().decide(&configured, 1_000),
            Err(FeePolicyError::ConfiguredFeeRateRejected)
        );
        assert!(LiveLiquid::try_from_observation(configured.clone()).is_err());
        assert!(LiquidLastKnownGood::try_from_observation(configured).is_err());
    }

    #[test]
    fn compatibility_bitcoin_path_rejects_bounds_and_can_use_lkg() {
        let now = 1_000;
        let policy = BitcoinFeePolicy::default();
        let unsafe_live = FeeObservation::new(
            rate(0.5),
            now,
            FeeObservationSource::LiveBitcoin,
            provenance("legacy-live"),
        );
        let safe_lkg = FeeObservation::new(
            rate(3.0),
            now,
            FeeObservationSource::BitcoinLastKnownGood,
            provenance("legacy-lkg"),
        );
        let decision = policy
            .decide(Some(&unsafe_live), Some(&safe_lkg), now)
            .unwrap();
        assert_eq!(decision.rate(), rate(3.0));
        assert_eq!(
            decision.source(),
            FeeObservationSource::BitcoinLastKnownGood
        );
        assert!(policy.decide(Some(&unsafe_live), None, now).is_err());
    }

    #[test]
    fn policy_configuration_validates_bounds_and_all_windows() {
        assert!(BitcoinFeePolicy::new(rate(500.0), rate(1.0), 120, 900).is_err());
        assert!(LiquidFeePolicy::new(rate(10.0), rate(0.1)).is_err());

        assert!(BitcoinFeePolicy::new(rate(1.0), rate(500.0), 0, 900).is_err());
        assert!(BitcoinFeePolicy::new(rate(1.0), rate(500.0), 120, 0).is_err());
        assert!(LiquidFeePolicy::with_freshness(rate(0.1), rate(10.0), 0, 900).is_err());
        assert!(LiquidFeePolicy::with_freshness(rate(0.1), rate(10.0), 120, 0).is_err());
    }

    #[test]
    fn rate_validation_rejects_non_finite_non_positive_and_overflow() {
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                SatPerVbyte::try_from(invalid),
                Err(FeePolicyError::RateNotFinite)
            );
        }
        for invalid in [0.0, -0.0, -1.0] {
            assert_eq!(
                SatPerVbyte::try_from(invalid),
                Err(FeePolicyError::RateMustBePositive)
            );
        }
        assert_eq!(
            SatPerVbyte::try_from(u64::MAX as f64),
            Err(FeePolicyError::RateCannotFitSats)
        );
    }

    #[test]
    fn positive_sub_floor_rates_validate_as_units_but_cannot_authorize() {
        let now = 1_000;
        let policy = BitcoinFeePolicy::default();
        for raw in [f64::MIN_POSITIVE, 1e-12, 0.000_001, 0.1, 0.999_999] {
            let typed = SatPerVbyte::try_from(raw).unwrap();
            assert_eq!(typed.checked_fee_for_vbytes(1).unwrap(), 1);
            let observed = LiveBitcoin::new(typed, now, provenance("sub-floor"));
            assert!(matches!(
                policy.decide_typed(Some(&observed), None, now),
                Err(FeePolicyError::TemporarilyUnavailable {
                    live: FeeObservationRejection::OutsideBounds { rate, .. },
                    ..
                }) if rate == typed
            ));
        }
    }

    #[test]
    fn fee_calculation_rounds_up_and_never_saturates() {
        for (value, vbytes, expected) in [
            (0.1, 10, 1),
            (0.1, 11, 2),
            (0.5, 3, 2),
            (1.000_000_000_1, 1, 2),
            (2.0, 141, 282),
        ] {
            assert_eq!(
                rate(value).checked_fee_for_vbytes(vbytes).unwrap(),
                expected
            );
        }
        assert_eq!(
            rate(2.0).checked_fee_for_vbytes(0),
            Err(FeePolicyError::ZeroVirtualBytes)
        );
        assert_eq!(
            rate(1e18).checked_fee_for_vbytes(100),
            Err(FeePolicyError::FeeAmountOverflow)
        );
    }

    #[test]
    fn future_timestamp_math_never_overflows() {
        let observed = live_bitcoin(2.0, u64::MAX);
        assert_eq!(
            observed.observation().freshness_at(u64::MAX, 120),
            FeeFreshness::Fresh {
                age_secs: 0,
                max_age_secs: 120,
            }
        );
        assert_eq!(
            observed.observation().freshness_at(u64::MAX - 1, 120),
            FeeFreshness::FromFuture {
                lead_secs: 1,
                max_age_secs: 120,
            }
        );
    }

    #[test]
    fn provenance_and_temporary_errors_are_redacted() {
        let secret = "https://user:password@fee.invalid/private?token=secret";
        let live = LiveLiquid::new(rate(0.5), 1_000, provenance(secret));
        let decision = LiquidFeePolicy::default()
            .decide_typed(Some(&live), None, 1_001)
            .unwrap();
        for diagnostic in [format!("{live:?}"), format!("{decision:?}")] {
            assert!(diagnostic.contains("<redacted>"));
            assert!(!diagnostic.contains(secret));
            assert!(!diagnostic.contains("password"));
            assert!(!diagnostic.contains("token=secret"));
        }

        let stale_error = LiquidFeePolicy::default()
            .decide_typed(Some(&live), None, 10_000)
            .unwrap_err();
        for diagnostic in [format!("{stale_error:?}"), stale_error.to_string()] {
            assert!(!diagnostic.contains(secret));
            assert!(!diagnostic.contains("password"));
        }
        assert_eq!(decision.provenance().expose_for_persistence(), secret);
    }

    #[test]
    fn provenance_validation_is_bounded() {
        assert_eq!(
            FeeProvenance::new("   "),
            Err(FeePolicyError::EmptyProvenance)
        );
        let oversized = "x".repeat(MAX_PROVENANCE_BYTES + 1);
        assert!(matches!(
            FeeProvenance::new(oversized),
            Err(FeePolicyError::ProvenanceTooLong {
                bytes,
                max_bytes: MAX_PROVENANCE_BYTES,
            }) if bytes == MAX_PROVENANCE_BYTES + 1
        ));
    }

    #[test]
    fn cloned_decisions_keep_exact_immutable_metadata() {
        let live = live_bitcoin(5.5, 9_999);
        let decision = BitcoinFeePolicy::default()
            .decide_typed(Some(&live), None, 10_000)
            .unwrap();
        let cloned = decision.clone();
        assert_eq!(decision, cloned);
        assert_eq!(cloned.rate(), rate(5.5));
        assert_eq!(cloned.observed_rate(), rate(5.5));
        assert_eq!(cloned.observed_at_unix(), 9_999);
        assert_eq!(cloned.source(), FeeObservationSource::LiveBitcoin);
        assert_eq!(
            cloned.freshness(),
            FeeFreshness::Fresh {
                age_secs: 1,
                max_age_secs: BITCOIN_LIVE_MAX_AGE_SECS,
            }
        );
    }
}
