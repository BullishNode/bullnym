//! Pure provider-limit contract for truthful Lightning Address offers.
//!
//! Metadata and the later creation callback must each use a fresh, validated
//! snapshot of the exact BTC -> L-BTC reverse pair. This module deliberately
//! contains no transport, cache, persistence, or runtime wiring. Direct Liquid
//! admission is independent and is not represented here.
//!
//! The pinned `boltz-client` [`ReversePair`] has minimum and maximum fields but
//! no reverse-pair zero-conf field. [`ProviderZeroConfLimit`] keeps that absence
//! explicit. Standard reverse offers may use the validated minimum/maximum;
//! only a caller that requires zero-conf fails when it was not reported by the
//! same authoritative observation. Chain/submarine limits must not be borrowed.

use std::fmt;
use std::time::{Duration, Instant};

use boltz_client::swaps::boltz::ReversePair;

const MSAT_PER_SAT: u64 = 1_000;

/// Closed asset keys decoded from the provider response map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAsset {
    Bitcoin,
    LiquidBitcoin,
}

/// Low-cardinality, non-secret origin of a reverse-pair observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReversePairSource {
    BoltzV2ReversePairs,
}

/// Zero-conf data from the same authoritative reverse-pair observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderZeroConfLimit {
    ReportedInSnapshot(u64),
    NotReportedByReversePairContract,
}

/// Structured provider facts presented to the pure validation boundary.
///
/// This type intentionally has no `Debug` implementation so the SDK quote is
/// not accidentally treated as telemetry. The validated snapshot retains only
/// the small, safe subset required for decisions.
#[derive(Clone)]
pub struct ReversePairObservation {
    from: ProviderAsset,
    to: ProviderAsset,
    quote: ReversePair,
    zero_conf: ProviderZeroConfLimit,
    source: ReversePairSource,
    observed_at: Instant,
}

impl ReversePairObservation {
    pub fn new(
        from: ProviderAsset,
        to: ProviderAsset,
        quote: ReversePair,
        zero_conf: ProviderZeroConfLimit,
        source: ReversePairSource,
        observed_at: Instant,
    ) -> Self {
        Self {
            from,
            to,
            quote,
            zero_conf,
            source,
            observed_at,
        }
    }

    pub fn validate(self) -> Result<ReversePairSnapshot, ReversePairValidationError> {
        if (self.from, self.to) != (ProviderAsset::Bitcoin, ProviderAsset::LiquidBitcoin) {
            return Err(ReversePairValidationError::WrongPair);
        }
        if !is_lower_hex_32(&self.quote.hash) {
            return Err(ReversePairValidationError::InvalidPairHash);
        }
        if self.quote.rate.to_bits() != 1.0_f64.to_bits() {
            return Err(ReversePairValidationError::InvalidPairRate);
        }

        let minimum_sat = self.quote.limits.minimal;
        let maximum_sat = self.quote.limits.maximal;
        if minimum_sat == 0 {
            return Err(ReversePairValidationError::MinimumIsZero);
        }
        if maximum_sat < minimum_sat {
            return Err(ReversePairValidationError::MaximumBelowMinimum);
        }

        let maximum_zero_conf_sat = match self.zero_conf {
            ProviderZeroConfLimit::ReportedInSnapshot(value) => {
                if value > maximum_sat {
                    return Err(ReversePairValidationError::ZeroConfAboveMaximum);
                }
                if value != 0 && value < minimum_sat {
                    return Err(ReversePairValidationError::ZeroConfBelowMinimum);
                }
                Some(value)
            }
            ProviderZeroConfLimit::NotReportedByReversePairContract => None,
        };

        let minimum_msat = minimum_sat
            .checked_mul(MSAT_PER_SAT)
            .ok_or(ReversePairValidationError::MinimumMsatOverflow)?;
        let maximum_msat = maximum_sat
            .checked_mul(MSAT_PER_SAT)
            .ok_or(ReversePairValidationError::MaximumMsatOverflow)?;
        let maximum_zero_conf_msat = maximum_zero_conf_sat
            .map(|value| {
                value
                    .checked_mul(MSAT_PER_SAT)
                    .ok_or(ReversePairValidationError::MaximumMsatOverflow)
            })
            .transpose()?;

        Ok(ReversePairSnapshot {
            pair_hash: self.quote.hash,
            minimum_msat,
            maximum_msat,
            maximum_zero_conf_msat,
            source: self.source,
            observed_at: self.observed_at,
        })
    }
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Stable reasons a provider observation cannot safely drive an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReversePairValidationError {
    WrongPair,
    InvalidPairHash,
    InvalidPairRate,
    MinimumIsZero,
    MaximumBelowMinimum,
    ZeroConfAboveMaximum,
    ZeroConfBelowMinimum,
    MinimumMsatOverflow,
    MaximumMsatOverflow,
}

impl fmt::Display for ReversePairValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::WrongPair => "wrong_pair",
            Self::InvalidPairHash => "invalid_pair_hash",
            Self::InvalidPairRate => "invalid_pair_rate",
            Self::MinimumIsZero => "minimum_is_zero",
            Self::MaximumBelowMinimum => "maximum_below_minimum",
            Self::ZeroConfAboveMaximum => "zero_conf_above_maximum",
            Self::ZeroConfBelowMinimum => "zero_conf_below_minimum",
            Self::MinimumMsatOverflow => "minimum_msat_overflow",
            Self::MaximumMsatOverflow => "maximum_msat_overflow",
        };
        f.write_str(code)
    }
}

impl std::error::Error for ReversePairValidationError {}

/// Validated, safe facts for exactly one BTC -> L-BTC reverse-pair snapshot.
#[derive(Debug, Clone)]
pub struct ReversePairSnapshot {
    pair_hash: String,
    minimum_msat: u64,
    maximum_msat: u64,
    maximum_zero_conf_msat: Option<u64>,
    source: ReversePairSource,
    observed_at: Instant,
}

/// Current in-process snapshot value. This is not a cache implementation.
#[derive(Debug, Clone, Default)]
pub enum ReversePairSnapshotState {
    #[default]
    Missing,
    Invalid(ReversePairValidationError),
    Available(ReversePairSnapshot),
}

impl ReversePairSnapshotState {
    pub fn from_observation(observation: ReversePairObservation) -> Self {
        match observation.validate() {
            Ok(snapshot) => Self::Available(snapshot),
            Err(error) => Self::Invalid(error),
        }
    }
}

/// Whether the operation really requires a reported, non-zero zero-conf cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLimitMode {
    Standard,
    RequireZeroConf,
}

/// Retryable unavailability scoped only to Lightning Address behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightningAddressUnavailable {
    SnapshotMissing,
    SnapshotInvalid(ReversePairValidationError),
    SnapshotObservedInFuture,
    SnapshotStale,
    ZeroConfUnavailable,
    NoExecutableRange,
}

impl fmt::Display for LightningAddressUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::SnapshotMissing => "snapshot_missing",
            Self::SnapshotInvalid(_) => "snapshot_invalid",
            Self::SnapshotObservedInFuture => "snapshot_observed_in_future",
            Self::SnapshotStale => "snapshot_stale",
            Self::ZeroConfUnavailable => "zero_conf_unavailable",
            Self::NoExecutableRange => "no_executable_range",
        };
        write!(f, "lightning address temporarily unavailable: {code}")
    }
}

impl std::error::Error for LightningAddressUnavailable {}

/// Effective LNURL range plus safe evidence of the snapshot that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveLightningAddressRange {
    minimum_msat: u64,
    maximum_msat: u64,
    pair_hash: String,
    source: ReversePairSource,
    observed_at: Instant,
}

impl EffectiveLightningAddressRange {
    pub const fn limits_msat(&self) -> (u64, u64) {
        (self.minimum_msat, self.maximum_msat)
    }

    pub fn snapshot_evidence(&self) -> (&str, ReversePairSource, Instant) {
        (&self.pair_hash, self.source, self.observed_at)
    }
}

fn current_snapshot(
    state: &ReversePairSnapshotState,
    now: Instant,
    maximum_age: Duration,
) -> Result<&ReversePairSnapshot, LightningAddressUnavailable> {
    let snapshot = match state {
        ReversePairSnapshotState::Missing => {
            return Err(LightningAddressUnavailable::SnapshotMissing);
        }
        ReversePairSnapshotState::Invalid(error) => {
            return Err(LightningAddressUnavailable::SnapshotInvalid(*error));
        }
        ReversePairSnapshotState::Available(snapshot) => snapshot,
    };

    let Some(age) = now.checked_duration_since(snapshot.observed_at) else {
        return Err(LightningAddressUnavailable::SnapshotObservedInFuture);
    };
    if age > maximum_age {
        return Err(LightningAddressUnavailable::SnapshotStale);
    }
    Ok(snapshot)
}

/// Intersect product policy with one fresh provider snapshot.
///
/// The advertised minimum is exactly `max(product minimum, provider minimum)`.
/// Missing zero-conf data is valid in `Standard` mode and fails closed only in
/// `RequireZeroConf` mode.
pub fn effective_lightning_address_range(
    state: &ReversePairSnapshotState,
    product_minimum_msat: u64,
    product_maximum_msat: u64,
    mode: ProviderLimitMode,
    now: Instant,
    maximum_age: Duration,
) -> Result<EffectiveLightningAddressRange, LightningAddressUnavailable> {
    let snapshot = current_snapshot(state, now, maximum_age)?;
    let provider_maximum_msat = match mode {
        ProviderLimitMode::Standard => snapshot.maximum_msat,
        ProviderLimitMode::RequireZeroConf => match snapshot.maximum_zero_conf_msat {
            Some(value) if value != 0 => snapshot.maximum_msat.min(value),
            Some(_) | None => return Err(LightningAddressUnavailable::ZeroConfUnavailable),
        },
    };

    let minimum_msat = product_minimum_msat.max(snapshot.minimum_msat);
    let maximum_msat = product_maximum_msat.min(provider_maximum_msat);
    if minimum_msat > maximum_msat {
        return Err(LightningAddressUnavailable::NoExecutableRange);
    }

    Ok(EffectiveLightningAddressRange {
        minimum_msat,
        maximum_msat,
        pair_hash: snapshot.pair_hash.clone(),
        source: snapshot.source,
        observed_at: snapshot.observed_at,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightningAddressCreationError {
    TemporarilyUnavailable(LightningAddressUnavailable),
    AmountNotWholeSatoshi,
    BelowCurrentMinimum { minimum_msat: u64 },
    AboveCurrentMaximum { maximum_msat: u64 },
}

impl fmt::Display for LightningAddressCreationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TemporarilyUnavailable(error) => error.fmt(f),
            Self::AmountNotWholeSatoshi => f.write_str("amount must be a whole satoshi"),
            Self::BelowCurrentMinimum { minimum_msat } => {
                write!(f, "amount is below current minimum {minimum_msat} msat")
            }
            Self::AboveCurrentMaximum { maximum_msat } => {
                write!(f, "amount is above current maximum {maximum_msat} msat")
            }
        }
    }
}

impl std::error::Error for LightningAddressCreationError {}

/// Recompute the effective range from the current snapshot before mutation.
///
/// The returned range identifies the exact snapshot used by this decision; the
/// amount is returned in satoshis for a later provider adapter.
pub fn revalidate_lightning_address_creation(
    state: &ReversePairSnapshotState,
    product_minimum_msat: u64,
    product_maximum_msat: u64,
    mode: ProviderLimitMode,
    amount_msat: u64,
    now: Instant,
    maximum_age: Duration,
) -> Result<(u64, EffectiveLightningAddressRange), LightningAddressCreationError> {
    let range = effective_lightning_address_range(
        state,
        product_minimum_msat,
        product_maximum_msat,
        mode,
        now,
        maximum_age,
    )
    .map_err(LightningAddressCreationError::TemporarilyUnavailable)?;

    if !amount_msat.is_multiple_of(MSAT_PER_SAT) {
        return Err(LightningAddressCreationError::AmountNotWholeSatoshi);
    }
    if amount_msat < range.minimum_msat {
        return Err(LightningAddressCreationError::BelowCurrentMinimum {
            minimum_msat: range.minimum_msat,
        });
    }
    if amount_msat > range.maximum_msat {
        return Err(LightningAddressCreationError::AboveCurrentMaximum {
            maximum_msat: range.maximum_msat,
        });
    }

    Ok((amount_msat / MSAT_PER_SAT, range))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltz_client::swaps::boltz::{PairMinerFees, ReverseFees, ReverseLimits};

    const HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const FRESH_FOR: Duration = Duration::from_secs(30);

    fn quote(minimum_sat: u64, maximum_sat: u64) -> ReversePair {
        ReversePair {
            hash: HASH.to_owned(),
            rate: 1.0,
            limits: ReverseLimits {
                minimal: minimum_sat,
                maximal: maximum_sat,
            },
            fees: ReverseFees {
                percentage: 0.25,
                miner_fees: PairMinerFees {
                    lockup: 27,
                    claim: 20,
                },
            },
        }
    }

    fn observation(
        observed_at: Instant,
        minimum_sat: u64,
        maximum_sat: u64,
        zero_conf: ProviderZeroConfLimit,
    ) -> ReversePairObservation {
        ReversePairObservation::new(
            ProviderAsset::Bitcoin,
            ProviderAsset::LiquidBitcoin,
            quote(minimum_sat, maximum_sat),
            zero_conf,
            ReversePairSource::BoltzV2ReversePairs,
            observed_at,
        )
    }

    fn state(
        observed_at: Instant,
        minimum_sat: u64,
        maximum_sat: u64,
        zero_conf: ProviderZeroConfLimit,
    ) -> ReversePairSnapshotState {
        ReversePairSnapshotState::from_observation(observation(
            observed_at,
            minimum_sat,
            maximum_sat,
            zero_conf,
        ))
    }

    fn range(
        state: &ReversePairSnapshotState,
        product_minimum_msat: u64,
        product_maximum_msat: u64,
        now: Instant,
    ) -> Result<EffectiveLightningAddressRange, LightningAddressUnavailable> {
        effective_lightning_address_range(
            state,
            product_minimum_msat,
            product_maximum_msat,
            ProviderLimitMode::Standard,
            now,
            FRESH_FOR,
        )
    }

    #[test]
    fn validates_exact_pair_and_keeps_absent_zero_conf_explicitly_usable() {
        let now = Instant::now();
        let snapshot = observation(
            now,
            100,
            25_000_000,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        )
        .validate()
        .unwrap();

        assert_eq!(snapshot.pair_hash, HASH);
        assert_eq!(snapshot.minimum_msat, 100_000);
        assert_eq!(snapshot.maximum_msat, 25_000_000_000);
        assert_eq!(snapshot.maximum_zero_conf_msat, None);
        assert_eq!(snapshot.source, ReversePairSource::BoltzV2ReversePairs);
        assert_eq!(snapshot.observed_at, now);
    }

    #[test]
    fn rejects_all_wrong_directions_hashes_and_rates() {
        let now = Instant::now();
        for (from, to) in [
            (ProviderAsset::LiquidBitcoin, ProviderAsset::Bitcoin),
            (ProviderAsset::Bitcoin, ProviderAsset::Bitcoin),
            (ProviderAsset::LiquidBitcoin, ProviderAsset::LiquidBitcoin),
        ] {
            let error = ReversePairObservation::new(
                from,
                to,
                quote(100, 1_000),
                ProviderZeroConfLimit::NotReportedByReversePairContract,
                ReversePairSource::BoltzV2ReversePairs,
                now,
            )
            .validate()
            .unwrap_err();
            assert_eq!(error, ReversePairValidationError::WrongPair);
        }

        for invalid_hash in ["AA".repeat(32), "1".repeat(63), "g".repeat(64)] {
            let mut observation = observation(
                now,
                100,
                1_000,
                ProviderZeroConfLimit::NotReportedByReversePairContract,
            );
            observation.quote.hash = invalid_hash;
            assert_eq!(
                observation.validate().unwrap_err(),
                ReversePairValidationError::InvalidPairHash
            );
        }

        for invalid_rate in [0.0, 0.999, 1.001, f64::NAN, f64::INFINITY] {
            let mut observation = observation(
                now,
                100,
                1_000,
                ProviderZeroConfLimit::NotReportedByReversePairContract,
            );
            observation.quote.rate = invalid_rate;
            assert_eq!(
                observation.validate().unwrap_err(),
                ReversePairValidationError::InvalidPairRate
            );
        }
    }

    #[test]
    fn validates_minimum_maximum_zero_conf_and_conversion_boundaries() {
        let now = Instant::now();
        let cases = [
            (
                observation(now, 0, 1_000, ProviderZeroConfLimit::ReportedInSnapshot(0)),
                ReversePairValidationError::MinimumIsZero,
            ),
            (
                observation(now, 101, 100, ProviderZeroConfLimit::ReportedInSnapshot(0)),
                ReversePairValidationError::MaximumBelowMinimum,
            ),
            (
                observation(
                    now,
                    100,
                    1_000,
                    ProviderZeroConfLimit::ReportedInSnapshot(1_001),
                ),
                ReversePairValidationError::ZeroConfAboveMaximum,
            ),
            (
                observation(
                    now,
                    100,
                    1_000,
                    ProviderZeroConfLimit::ReportedInSnapshot(99),
                ),
                ReversePairValidationError::ZeroConfBelowMinimum,
            ),
        ];
        for (observation, expected) in cases {
            assert_eq!(observation.validate().unwrap_err(), expected);
        }

        for zero_conf in [0, 100, 1_000] {
            assert!(observation(
                now,
                100,
                1_000,
                ProviderZeroConfLimit::ReportedInSnapshot(zero_conf),
            )
            .validate()
            .is_ok());
        }

        let largest_safe_sat = u64::MAX / MSAT_PER_SAT;
        assert!(observation(
            now,
            largest_safe_sat,
            largest_safe_sat,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        )
        .validate()
        .is_ok());
        let first_unsafe_sat = largest_safe_sat + 1;
        assert_eq!(
            observation(
                now,
                first_unsafe_sat,
                first_unsafe_sat,
                ProviderZeroConfLimit::NotReportedByReversePairContract,
            )
            .validate()
            .unwrap_err(),
            ReversePairValidationError::MinimumMsatOverflow
        );
        assert_eq!(
            observation(
                now,
                1,
                first_unsafe_sat,
                ProviderZeroConfLimit::NotReportedByReversePairContract,
            )
            .validate()
            .unwrap_err(),
            ReversePairValidationError::MaximumMsatOverflow
        );
    }

    #[test]
    fn standard_uses_absent_zero_conf_while_required_mode_fails_closed() {
        let now = Instant::now();
        let state = state(
            now,
            100,
            1_000,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        );
        assert_eq!(
            range(&state, 50_000, 2_000_000, now).unwrap().limits_msat(),
            (100_000, 1_000_000)
        );
        assert_eq!(
            effective_lightning_address_range(
                &state,
                50_000,
                2_000_000,
                ProviderLimitMode::RequireZeroConf,
                now,
                FRESH_FOR,
            )
            .unwrap_err(),
            LightningAddressUnavailable::ZeroConfUnavailable
        );
    }

    #[test]
    fn effective_range_uses_stricter_minimum_and_conservative_maximum() {
        let now = Instant::now();
        let state = state(
            now,
            100,
            1_000,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        );
        for (product_minimum, expected) in
            [(100_000, 100_000), (200_000, 200_000), (50_000, 100_000)]
        {
            assert_eq!(
                range(&state, product_minimum, 2_000_000, now)
                    .unwrap()
                    .limits_msat(),
                (expected, 1_000_000)
            );
        }
        assert_eq!(
            range(&state, 50_000, 750_000, now).unwrap().limits_msat(),
            (100_000, 750_000)
        );
        assert_eq!(
            range(&state, 1_001_000, 2_000_000, now).unwrap_err(),
            LightningAddressUnavailable::NoExecutableRange
        );
    }

    #[test]
    fn reported_zero_conf_is_validated_capped_and_can_be_disabled() {
        let now = Instant::now();
        let capped = state(
            now,
            100,
            1_000,
            ProviderZeroConfLimit::ReportedInSnapshot(500),
        );
        assert_eq!(
            effective_lightning_address_range(
                &capped,
                100_000,
                1_000_000,
                ProviderLimitMode::RequireZeroConf,
                now,
                FRESH_FOR,
            )
            .unwrap()
            .limits_msat(),
            (100_000, 500_000)
        );

        let disabled = state(
            now,
            100,
            1_000,
            ProviderZeroConfLimit::ReportedInSnapshot(0),
        );
        assert!(range(&disabled, 100_000, 1_000_000, now).is_ok());
        assert_eq!(
            effective_lightning_address_range(
                &disabled,
                100_000,
                1_000_000,
                ProviderLimitMode::RequireZeroConf,
                now,
                FRESH_FOR,
            )
            .unwrap_err(),
            LightningAddressUnavailable::ZeroConfUnavailable
        );
    }

    #[test]
    fn missing_invalid_stale_and_future_states_are_lightning_only_errors() {
        let now = Instant::now();
        assert_eq!(
            range(&ReversePairSnapshotState::Missing, 100_000, 1_000_000, now).unwrap_err(),
            LightningAddressUnavailable::SnapshotMissing
        );

        let invalid = ReversePairSnapshotState::Invalid(ReversePairValidationError::WrongPair);
        assert_eq!(
            range(&invalid, 100_000, 1_000_000, now).unwrap_err(),
            LightningAddressUnavailable::SnapshotInvalid(ReversePairValidationError::WrongPair)
        );

        let boundary = now.checked_sub(FRESH_FOR).unwrap();
        assert!(range(
            &state(
                boundary,
                100,
                1_000,
                ProviderZeroConfLimit::NotReportedByReversePairContract,
            ),
            100_000,
            1_000_000,
            now,
        )
        .is_ok());

        let stale = boundary.checked_sub(Duration::from_nanos(1)).unwrap();
        assert_eq!(
            range(
                &state(
                    stale,
                    100,
                    1_000,
                    ProviderZeroConfLimit::NotReportedByReversePairContract,
                ),
                100_000,
                1_000_000,
                now,
            )
            .unwrap_err(),
            LightningAddressUnavailable::SnapshotStale
        );

        let future = now.checked_add(Duration::from_nanos(1)).unwrap();
        assert_eq!(
            range(
                &state(
                    future,
                    100,
                    1_000,
                    ProviderZeroConfLimit::NotReportedByReversePairContract,
                ),
                100_000,
                1_000_000,
                now,
            )
            .unwrap_err(),
            LightningAddressUnavailable::SnapshotObservedInFuture
        );

        // Direct Liquid is deliberately absent from this API and remains on
        // its independent healthy admission path.
    }

    #[test]
    fn creation_revalidates_boundaries_units_and_snapshot_evidence() {
        let now = Instant::now();
        let state = state(
            now,
            200,
            500,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        );
        for amount_msat in [200_000, 500_000] {
            let (amount_sat, range) = revalidate_lightning_address_creation(
                &state,
                100_000,
                1_000_000,
                ProviderLimitMode::Standard,
                amount_msat,
                now,
                FRESH_FOR,
            )
            .unwrap();
            assert_eq!(amount_sat, amount_msat / MSAT_PER_SAT);
            assert_eq!(
                range.snapshot_evidence(),
                (HASH, ReversePairSource::BoltzV2ReversePairs, now)
            );
        }

        for (amount_msat, expected) in [
            (
                199_000,
                LightningAddressCreationError::BelowCurrentMinimum {
                    minimum_msat: 200_000,
                },
            ),
            (
                501_000,
                LightningAddressCreationError::AboveCurrentMaximum {
                    maximum_msat: 500_000,
                },
            ),
            (
                200_001,
                LightningAddressCreationError::AmountNotWholeSatoshi,
            ),
        ] {
            assert_eq!(
                revalidate_lightning_address_creation(
                    &state,
                    100_000,
                    1_000_000,
                    ProviderLimitMode::Standard,
                    amount_msat,
                    now,
                    FRESH_FOR,
                )
                .unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn creation_refuses_limits_changed_since_metadata_and_unavailable_state() {
        let now = Instant::now();
        let metadata = state(
            now,
            100,
            1_000,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        );
        assert_eq!(
            range(&metadata, 100_000, 1_000_000, now)
                .unwrap()
                .limits_msat(),
            (100_000, 1_000_000)
        );

        let raised_minimum = state(
            now,
            250,
            1_000,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        );
        assert_eq!(
            revalidate_lightning_address_creation(
                &raised_minimum,
                100_000,
                1_000_000,
                ProviderLimitMode::Standard,
                100_000,
                now,
                FRESH_FOR,
            )
            .unwrap_err(),
            LightningAddressCreationError::BelowCurrentMinimum {
                minimum_msat: 250_000
            }
        );

        let lowered_maximum = state(
            now,
            100,
            400,
            ProviderZeroConfLimit::NotReportedByReversePairContract,
        );
        assert_eq!(
            revalidate_lightning_address_creation(
                &lowered_maximum,
                100_000,
                1_000_000,
                ProviderLimitMode::Standard,
                1_000_000,
                now,
                FRESH_FOR,
            )
            .unwrap_err(),
            LightningAddressCreationError::AboveCurrentMaximum {
                maximum_msat: 400_000
            }
        );

        assert_eq!(
            revalidate_lightning_address_creation(
                &ReversePairSnapshotState::Missing,
                100_000,
                1_000_000,
                ProviderLimitMode::Standard,
                100_000,
                now,
                FRESH_FOR,
            )
            .unwrap_err(),
            LightningAddressCreationError::TemporarilyUnavailable(
                LightningAddressUnavailable::SnapshotMissing
            )
        );
    }
}
