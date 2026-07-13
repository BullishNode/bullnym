use std::error::Error;
use std::fmt;

use sqlx::PgPool;

use crate::current_fee_snapshot::{CurrentBitcoinFee, CurrentLiquidFee};
use crate::fee_policy::{
    BitcoinFeePolicy, BitcoinLastKnownGood, FeeFreshness, FeeObservationSource, FeePolicyError,
    FeeProvenance, FeeRail, LiquidFeePolicy, LiquidLastKnownGood, LiveBitcoin, LiveLiquid,
    SatPerVbyte,
};

const FEE_OBSERVATION_COLUMNS: &str = "rail, generation, rate_sat_per_vbyte, \
    observed_at_unix, source, target, provenance, accepted_at_unix, \
    live_max_age_secs, last_known_good_max_age_secs";

/// Exact priority target selected by the rail-specific upstream API contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeQuoteTarget {
    BitcoinFastestFee,
    LiquidConfirmationTargetOne,
}

impl FeeQuoteTarget {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BitcoinFastestFee => "fastestFee",
            Self::LiquidConfirmationTargetOne => "1",
        }
    }
}

/// A live, policy-accepted quote ready to cross the persistence boundary.
///
/// This value deliberately has no database generation. PostgreSQL assigns the
/// next rail-local generation atomically so a process restart cannot regress
/// durable ordering by resetting process-local snapshot generations.
#[derive(Clone, PartialEq)]
pub struct AcceptedFeeObservation {
    rail: FeeRail,
    rate: SatPerVbyte,
    observed_at_unix: u64,
    source: FeeObservationSource,
    target: FeeQuoteTarget,
    provenance: FeeProvenance,
    accepted_at_unix: u64,
    live_max_age_secs: u64,
    last_known_good_max_age_secs: u64,
}

impl AcceptedFeeObservation {
    /// Capture an exact Bitcoin live decision and the freshness-policy inputs
    /// that admitted it. A fallback LKG decision cannot cross this boundary.
    pub fn bitcoin(
        current: &CurrentBitcoinFee,
        policy: &BitcoinFeePolicy,
        accepted_at_unix: u64,
    ) -> Result<Self, FeeObservationRepositoryError> {
        let decision = current.decision();
        if decision.source() != FeeObservationSource::LiveBitcoin {
            return Err(FeeObservationRepositoryError::NonLiveDecision {
                rail: FeeRail::Bitcoin,
                source: decision.source(),
            });
        }
        let live = LiveBitcoin::new(
            decision.rate(),
            decision.observed_at_unix(),
            decision.provenance().clone(),
        );
        let verified = policy
            .decide_typed(Some(&live), None, accepted_at_unix)
            .map_err(FeeObservationRepositoryError::Policy)?;
        if verified != *decision {
            return Err(FeeObservationRepositoryError::DecisionDoesNotMatchPolicy {
                rail: FeeRail::Bitcoin,
            });
        }
        Self::new(
            FeeRail::Bitcoin,
            decision.rate(),
            decision.observed_at_unix(),
            decision.source(),
            FeeQuoteTarget::BitcoinFastestFee,
            decision.provenance().clone(),
            accepted_at_unix,
            policy.live_max_age_secs(),
            policy.last_known_good_max_age_secs(),
        )
    }

    /// Capture an exact Liquid live decision and the freshness-policy inputs
    /// that admitted it. A fallback LKG decision cannot cross this boundary.
    pub fn liquid(
        current: &CurrentLiquidFee,
        policy: &LiquidFeePolicy,
        accepted_at_unix: u64,
    ) -> Result<Self, FeeObservationRepositoryError> {
        let decision = current.decision();
        if decision.source() != FeeObservationSource::LiveLiquid {
            return Err(FeeObservationRepositoryError::NonLiveDecision {
                rail: FeeRail::Liquid,
                source: decision.source(),
            });
        }
        let live = LiveLiquid::new(
            decision.rate(),
            decision.observed_at_unix(),
            decision.provenance().clone(),
        );
        let verified = policy
            .decide_typed(Some(&live), None, accepted_at_unix)
            .map_err(FeeObservationRepositoryError::Policy)?;
        if verified != *decision {
            return Err(FeeObservationRepositoryError::DecisionDoesNotMatchPolicy {
                rail: FeeRail::Liquid,
            });
        }
        Self::new(
            FeeRail::Liquid,
            decision.rate(),
            decision.observed_at_unix(),
            decision.source(),
            FeeQuoteTarget::LiquidConfirmationTargetOne,
            decision.provenance().clone(),
            accepted_at_unix,
            policy.live_max_age_secs(),
            policy.last_known_good_max_age_secs(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        rail: FeeRail,
        rate: SatPerVbyte,
        observed_at_unix: u64,
        source: FeeObservationSource,
        target: FeeQuoteTarget,
        provenance: FeeProvenance,
        accepted_at_unix: u64,
        live_max_age_secs: u64,
        last_known_good_max_age_secs: u64,
    ) -> Result<Self, FeeObservationRepositoryError> {
        expect_live_source(rail, source)?;
        expect_target(rail, target)?;
        checked_i64("observed_at_unix", observed_at_unix)?;
        checked_i64("accepted_at_unix", accepted_at_unix)?;
        checked_positive_i64("live_max_age_secs", live_max_age_secs)?;
        checked_positive_i64("last_known_good_max_age_secs", last_known_good_max_age_secs)?;
        if accepted_at_unix < observed_at_unix {
            return Err(FeeObservationRepositoryError::ObservationFromFuture { rail });
        }
        let age_secs = accepted_at_unix - observed_at_unix;
        if age_secs > live_max_age_secs {
            return Err(FeeObservationRepositoryError::ObservationWasStale { rail });
        }
        Ok(Self {
            rail,
            rate,
            observed_at_unix,
            source,
            target,
            provenance,
            accepted_at_unix,
            live_max_age_secs,
            last_known_good_max_age_secs,
        })
    }

    pub const fn rail(&self) -> FeeRail {
        self.rail
    }

    pub fn rate(&self) -> SatPerVbyte {
        self.rate
    }

    pub const fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    /// Original accepted source. This is always the corresponding live source,
    /// not the LKG semantic type used after restore.
    pub const fn source(&self) -> FeeObservationSource {
        self.source
    }

    pub const fn target(&self) -> FeeQuoteTarget {
        self.target
    }

    pub const fn provenance(&self) -> &FeeProvenance {
        &self.provenance
    }

    pub const fn accepted_at_unix(&self) -> u64 {
        self.accepted_at_unix
    }

    pub const fn live_max_age_secs(&self) -> u64 {
        self.live_max_age_secs
    }

    pub const fn last_known_good_max_age_secs(&self) -> u64 {
        self.last_known_good_max_age_secs
    }

    /// Exact freshness result at the construction-time acceptance clock.
    pub const fn accepted_freshness(&self) -> FeeFreshness {
        FeeFreshness::Fresh {
            age_secs: self.accepted_at_unix - self.observed_at_unix,
            max_age_secs: self.live_max_age_secs,
        }
    }

    fn same_observation_authority(&self, other: &Self) -> bool {
        self.rail == other.rail
            && self.rate.as_f64().to_bits() == other.rate.as_f64().to_bits()
            && self.observed_at_unix == other.observed_at_unix
            && self.source == other.source
            && self.target == other.target
            && self.provenance == other.provenance
            && self.live_max_age_secs == other.live_max_age_secs
            && self.last_known_good_max_age_secs == other.last_known_good_max_age_secs
    }
}

impl fmt::Debug for AcceptedFeeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedFeeObservation")
            .field("rail", &self.rail)
            .field("rate", &self.rate)
            .field("observed_at_unix", &self.observed_at_unix)
            .field("source", &self.source)
            .field("target", &self.target)
            .field("provenance", &"<redacted>")
            .field("accepted_at_unix", &self.accepted_at_unix)
            .field("live_max_age_secs", &self.live_max_age_secs)
            .field(
                "last_known_good_max_age_secs",
                &self.last_known_good_max_age_secs,
            )
            .finish()
    }
}

/// A validated durable quote with its PostgreSQL-assigned rail generation.
#[derive(Clone, PartialEq)]
pub struct PersistedFeeObservation {
    generation: u64,
    accepted: AcceptedFeeObservation,
}

impl PersistedFeeObservation {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn accepted(&self) -> &AcceptedFeeObservation {
        &self.accepted
    }

    /// Whether this row is the exact durable authority for a candidate quote.
    /// Acceptance time is deliberately excluded: retrying the same observed
    /// quote later must neither extend its lifetime nor make it a new quote.
    pub fn authorizes(&self, candidate: &AcceptedFeeObservation) -> bool {
        self.accepted.same_observation_authority(candidate)
    }

    /// Convert a validated Bitcoin row into typed fallback evidence. The
    /// original live source remains available through [`Self::accepted`]; the
    /// restored semantic source is intentionally BitcoinLastKnownGood.
    pub fn restore_bitcoin_last_known_good(
        &self,
    ) -> Result<BitcoinLastKnownGood, FeeObservationRepositoryError> {
        if self.accepted.rail != FeeRail::Bitcoin {
            return Err(FeeObservationRepositoryError::WrongRail {
                expected: FeeRail::Bitcoin,
                actual: self.accepted.rail,
            });
        }
        Ok(BitcoinLastKnownGood::new(
            self.accepted.rate,
            self.accepted.observed_at_unix,
            self.accepted.provenance.clone(),
        ))
    }

    /// Convert a validated Liquid row into typed fallback evidence. Rate,
    /// observation time, and opaque provenance are retained bit-for-bit.
    pub fn restore_liquid_last_known_good(
        &self,
    ) -> Result<LiquidLastKnownGood, FeeObservationRepositoryError> {
        if self.accepted.rail != FeeRail::Liquid {
            return Err(FeeObservationRepositoryError::WrongRail {
                expected: FeeRail::Liquid,
                actual: self.accepted.rail,
            });
        }
        Ok(LiquidLastKnownGood::new(
            self.accepted.rate,
            self.accepted.observed_at_unix,
            self.accepted.provenance.clone(),
        ))
    }
}

impl fmt::Debug for PersistedFeeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedFeeObservation")
            .field("generation", &self.generation)
            .field("accepted", &self.accepted)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PersistFeeObservationOutcome {
    /// The row was inserted or advanced to a strictly newer ordering key.
    Applied(PersistedFeeObservation),
    /// An exact retry of the currently persisted candidate changed nothing.
    Unchanged(PersistedFeeObservation),
    /// A delayed candidate was safely ignored; the returned row remains
    /// authoritative for restore.
    IgnoredStale(PersistedFeeObservation),
}

#[derive(sqlx::FromRow)]
struct FeeObservationRow {
    rail: String,
    generation: i64,
    rate_sat_per_vbyte: f64,
    observed_at_unix: i64,
    source: String,
    target: String,
    provenance: String,
    accepted_at_unix: i64,
    live_max_age_secs: i64,
    last_known_good_max_age_secs: i64,
}

impl TryFrom<FeeObservationRow> for PersistedFeeObservation {
    type Error = FeeObservationRepositoryError;

    fn try_from(row: FeeObservationRow) -> Result<Self, Self::Error> {
        let rail = parse_rail(&row.rail)?;
        let source = parse_source(&row.source)?;
        let target = parse_target(&row.target)?;
        let generation = checked_positive_u64("generation", row.generation)?;
        let rate = SatPerVbyte::try_from(row.rate_sat_per_vbyte)
            .map_err(FeeObservationRepositoryError::Policy)?;
        let observed_at_unix = checked_u64("observed_at_unix", row.observed_at_unix)?;
        let accepted_at_unix = checked_u64("accepted_at_unix", row.accepted_at_unix)?;
        let live_max_age_secs = checked_positive_u64("live_max_age_secs", row.live_max_age_secs)?;
        let last_known_good_max_age_secs = checked_positive_u64(
            "last_known_good_max_age_secs",
            row.last_known_good_max_age_secs,
        )?;
        let provenance =
            FeeProvenance::new(row.provenance).map_err(FeeObservationRepositoryError::Policy)?;
        let accepted = AcceptedFeeObservation::new(
            rail,
            rate,
            observed_at_unix,
            source,
            target,
            provenance,
            accepted_at_unix,
            live_max_age_secs,
            last_known_good_max_age_secs,
        )?;
        Ok(Self {
            generation,
            accepted,
        })
    }
}

/// Load the validated durable quote for exactly one rail.
pub async fn load_fee_last_known_good(
    pool: &PgPool,
    rail: FeeRail,
) -> Result<Option<PersistedFeeObservation>, FeeObservationRepositoryError> {
    let sql = format!(
        "SELECT {FEE_OBSERVATION_COLUMNS} \
           FROM fee_last_known_good_observations WHERE rail = $1"
    );
    sqlx::query_as::<_, FeeObservationRow>(&sql)
        .bind(rail.as_str())
        .fetch_optional(pool)
        .await
        .map_err(FeeObservationRepositoryError::Database)?
        .map(PersistedFeeObservation::try_from)
        .transpose()
}

/// Atomically insert or advance one rail's quote cache.
///
/// PostgreSQL's `ON CONFLICT` row lock serializes competing writers for the
/// same rail while allowing Bitcoin and Liquid to advance independently. The
/// observation timestamp is the sole durable monotonic authority. Acceptance
/// time is audit evidence only and can never extend or replace an equal-time
/// quote.
pub async fn persist_fee_last_known_good(
    pool: &PgPool,
    candidate: &AcceptedFeeObservation,
) -> Result<PersistFeeObservationOutcome, FeeObservationRepositoryError> {
    let sql = format!(
        "INSERT INTO fee_last_known_good_observations \
            ({FEE_OBSERVATION_COLUMNS}) \
         VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (rail) DO UPDATE SET \
            generation = fee_last_known_good_observations.generation + 1, \
            rate_sat_per_vbyte = EXCLUDED.rate_sat_per_vbyte, \
            observed_at_unix = EXCLUDED.observed_at_unix, \
            source = EXCLUDED.source, \
            target = EXCLUDED.target, \
            provenance = EXCLUDED.provenance, \
            accepted_at_unix = EXCLUDED.accepted_at_unix, \
            live_max_age_secs = EXCLUDED.live_max_age_secs, \
            last_known_good_max_age_secs = EXCLUDED.last_known_good_max_age_secs \
         WHERE EXCLUDED.observed_at_unix \
             > fee_last_known_good_observations.observed_at_unix \
         RETURNING {FEE_OBSERVATION_COLUMNS}"
    );
    let applied = sqlx::query_as::<_, FeeObservationRow>(&sql)
        .bind(candidate.rail.as_str())
        .bind(candidate.rate.as_f64())
        .bind(checked_i64("observed_at_unix", candidate.observed_at_unix)?)
        .bind(candidate.source.as_str())
        .bind(candidate.target.as_str())
        .bind(candidate.provenance.expose_for_persistence())
        .bind(checked_i64("accepted_at_unix", candidate.accepted_at_unix)?)
        .bind(checked_positive_i64(
            "live_max_age_secs",
            candidate.live_max_age_secs,
        )?)
        .bind(checked_positive_i64(
            "last_known_good_max_age_secs",
            candidate.last_known_good_max_age_secs,
        )?)
        .fetch_optional(pool)
        .await
        .map_err(FeeObservationRepositoryError::Database)?;

    if let Some(row) = applied {
        return Ok(PersistFeeObservationOutcome::Applied(row.try_into()?));
    }

    let current = load_fee_last_known_good(pool, candidate.rail)
        .await?
        .ok_or(FeeObservationRepositoryError::RowMissingAfterConflict {
            rail: candidate.rail,
        })?;
    classify_unapplied(current, candidate)
}

fn classify_unapplied(
    current: PersistedFeeObservation,
    candidate: &AcceptedFeeObservation,
) -> Result<PersistFeeObservationOutcome, FeeObservationRepositoryError> {
    if candidate.observed_at_unix < current.accepted.observed_at_unix {
        return Ok(PersistFeeObservationOutcome::IgnoredStale(current));
    }
    if candidate.observed_at_unix == current.accepted.observed_at_unix
        && current.accepted.same_observation_authority(candidate)
    {
        return Ok(PersistFeeObservationOutcome::Unchanged(current));
    }
    Err(FeeObservationRepositoryError::ConflictingObservation {
        rail: candidate.rail,
        observed_at_unix: candidate.observed_at_unix,
        accepted_at_unix: candidate.accepted_at_unix,
        current_generation: current.generation,
    })
}

fn expect_live_source(
    rail: FeeRail,
    source: FeeObservationSource,
) -> Result<(), FeeObservationRepositoryError> {
    let expected = match rail {
        FeeRail::Bitcoin => FeeObservationSource::LiveBitcoin,
        FeeRail::Liquid => FeeObservationSource::LiveLiquid,
    };
    if source == expected {
        Ok(())
    } else {
        Err(FeeObservationRepositoryError::InvalidStoredSource { rail, source })
    }
}

fn expect_target(
    rail: FeeRail,
    target: FeeQuoteTarget,
) -> Result<(), FeeObservationRepositoryError> {
    let expected = match rail {
        FeeRail::Bitcoin => FeeQuoteTarget::BitcoinFastestFee,
        FeeRail::Liquid => FeeQuoteTarget::LiquidConfirmationTargetOne,
    };
    if target == expected {
        Ok(())
    } else {
        Err(FeeObservationRepositoryError::InvalidStoredTarget { rail, target })
    }
}

fn parse_rail(value: &str) -> Result<FeeRail, FeeObservationRepositoryError> {
    match value {
        "bitcoin" => Ok(FeeRail::Bitcoin),
        "liquid" => Ok(FeeRail::Liquid),
        _ => Err(FeeObservationRepositoryError::InvalidStoredText { field: "rail" }),
    }
}

fn parse_source(value: &str) -> Result<FeeObservationSource, FeeObservationRepositoryError> {
    match value {
        "bitcoin_live" => Ok(FeeObservationSource::LiveBitcoin),
        "liquid_live" => Ok(FeeObservationSource::LiveLiquid),
        _ => Err(FeeObservationRepositoryError::InvalidStoredText { field: "source" }),
    }
}

fn parse_target(value: &str) -> Result<FeeQuoteTarget, FeeObservationRepositoryError> {
    match value {
        "fastestFee" => Ok(FeeQuoteTarget::BitcoinFastestFee),
        "1" => Ok(FeeQuoteTarget::LiquidConfirmationTargetOne),
        _ => Err(FeeObservationRepositoryError::InvalidStoredText { field: "target" }),
    }
}

fn checked_i64(field: &'static str, value: u64) -> Result<i64, FeeObservationRepositoryError> {
    i64::try_from(value).map_err(|_| FeeObservationRepositoryError::ValueOutOfRange { field })
}

fn checked_positive_i64(
    field: &'static str,
    value: u64,
) -> Result<i64, FeeObservationRepositoryError> {
    if value == 0 {
        return Err(FeeObservationRepositoryError::ValueOutOfRange { field });
    }
    checked_i64(field, value)
}

fn checked_u64(field: &'static str, value: i64) -> Result<u64, FeeObservationRepositoryError> {
    u64::try_from(value).map_err(|_| FeeObservationRepositoryError::InvalidStoredInteger { field })
}

fn checked_positive_u64(
    field: &'static str,
    value: i64,
) -> Result<u64, FeeObservationRepositoryError> {
    if value <= 0 {
        return Err(FeeObservationRepositoryError::InvalidStoredInteger { field });
    }
    checked_u64(field, value)
}

pub enum FeeObservationRepositoryError {
    Database(sqlx::Error),
    Policy(FeePolicyError),
    NonLiveDecision {
        rail: FeeRail,
        source: FeeObservationSource,
    },
    DecisionDoesNotMatchPolicy {
        rail: FeeRail,
    },
    ObservationFromFuture {
        rail: FeeRail,
    },
    ObservationWasStale {
        rail: FeeRail,
    },
    WrongRail {
        expected: FeeRail,
        actual: FeeRail,
    },
    InvalidStoredSource {
        rail: FeeRail,
        source: FeeObservationSource,
    },
    InvalidStoredTarget {
        rail: FeeRail,
        target: FeeQuoteTarget,
    },
    InvalidStoredText {
        field: &'static str,
    },
    InvalidStoredInteger {
        field: &'static str,
    },
    ValueOutOfRange {
        field: &'static str,
    },
    ConflictingObservation {
        rail: FeeRail,
        observed_at_unix: u64,
        accepted_at_unix: u64,
        current_generation: u64,
    },
    RowMissingAfterConflict {
        rail: FeeRail,
    },
}

impl fmt::Debug for FeeObservationRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeeObservationRepositoryError")
            .field("kind", &self.kind())
            .field("details", &"<redacted>")
            .finish()
    }
}

impl FeeObservationRepositoryError {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Database(_) => "database",
            Self::Policy(_) => "policy",
            Self::NonLiveDecision { .. } => "non_live_decision",
            Self::DecisionDoesNotMatchPolicy { .. } => "decision_policy_mismatch",
            Self::ObservationFromFuture { .. } => "observation_from_future",
            Self::ObservationWasStale { .. } => "observation_was_stale",
            Self::WrongRail { .. } => "wrong_rail",
            Self::InvalidStoredSource { .. } => "invalid_stored_source",
            Self::InvalidStoredTarget { .. } => "invalid_stored_target",
            Self::InvalidStoredText { .. } => "invalid_stored_text",
            Self::InvalidStoredInteger { .. } => "invalid_stored_integer",
            Self::ValueOutOfRange { .. } => "value_out_of_range",
            Self::ConflictingObservation { .. } => "conflicting_observation",
            Self::RowMissingAfterConflict { .. } => "row_missing_after_conflict",
        }
    }
}

impl fmt::Display for FeeObservationRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => f_write(formatter, "fee observation database operation failed"),
            Self::Policy(_) => f_write(formatter, "fee observation policy validation failed"),
            Self::NonLiveDecision { rail, .. } => write!(
                formatter,
                "persisted {} fee candidate is not current live evidence",
                rail.as_str()
            ),
            Self::DecisionDoesNotMatchPolicy { rail } => write!(
                formatter,
                "persisted {} fee candidate does not match the supplied policy",
                rail.as_str()
            ),
            Self::ObservationFromFuture { rail } => write!(
                formatter,
                "persisted {} fee candidate was observed after acceptance",
                rail.as_str()
            ),
            Self::ObservationWasStale { rail } => write!(
                formatter,
                "persisted {} fee candidate was stale at acceptance",
                rail.as_str()
            ),
            Self::WrongRail { expected, actual } => write!(
                formatter,
                "cannot restore {} fee evidence as {}",
                actual.as_str(),
                expected.as_str()
            ),
            Self::InvalidStoredSource { rail, .. } => write!(
                formatter,
                "stored {} fee observation has an invalid source",
                rail.as_str()
            ),
            Self::InvalidStoredTarget { rail, .. } => write!(
                formatter,
                "stored {} fee observation has an invalid target",
                rail.as_str()
            ),
            Self::InvalidStoredText { field }
            | Self::InvalidStoredInteger { field }
            | Self::ValueOutOfRange { field } => {
                write!(formatter, "fee observation field {field} is invalid")
            }
            Self::ConflictingObservation { rail, .. } => write!(
                formatter,
                "conflicting {} fee observation has the same ordering key",
                rail.as_str()
            ),
            Self::RowMissingAfterConflict { rail } => write!(
                formatter,
                "{} fee observation disappeared during atomic persistence",
                rail.as_str()
            ),
        }
    }
}

fn f_write(formatter: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    formatter.write_str(value)
}

impl Error for FeeObservationRepositoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Policy(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::current_fee_snapshot::CurrentFeeSnapshot;

    fn rate(value: f64) -> SatPerVbyte {
        SatPerVbyte::try_from(value).unwrap()
    }

    fn provenance(value: &str) -> FeeProvenance {
        FeeProvenance::new(value).unwrap()
    }

    fn accepted_bitcoin(
        value: f64,
        observed_at_unix: u64,
        accepted_at_unix: u64,
        source: &str,
    ) -> AcceptedFeeObservation {
        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .update_bitcoin(LiveBitcoin::new(
                rate(value),
                observed_at_unix,
                provenance(source),
            ))
            .unwrap();
        let policy = BitcoinFeePolicy::default();
        let current = snapshot
            .accepted_bitcoin_for_persistence(&policy, accepted_at_unix)
            .unwrap();
        AcceptedFeeObservation::bitcoin(&current, &policy, accepted_at_unix).unwrap()
    }

    fn persisted(generation: u64, accepted: AcceptedFeeObservation) -> PersistedFeeObservation {
        PersistedFeeObservation {
            generation,
            accepted,
        }
    }

    #[test]
    fn accepted_candidates_preserve_exact_decision_and_freshness_inputs() {
        let bitcoin = accepted_bitcoin(7.125, 10_000, 10_025, "private-bitcoin-source");
        assert_eq!(bitcoin.rail(), FeeRail::Bitcoin);
        assert_eq!(bitcoin.rate().as_f64().to_bits(), 7.125_f64.to_bits());
        assert_eq!(bitcoin.observed_at_unix(), 10_000);
        assert_eq!(bitcoin.accepted_at_unix(), 10_025);
        assert_eq!(bitcoin.source(), FeeObservationSource::LiveBitcoin);
        assert_eq!(bitcoin.target(), FeeQuoteTarget::BitcoinFastestFee);
        assert_eq!(
            bitcoin.accepted_freshness(),
            FeeFreshness::Fresh {
                age_secs: 25,
                max_age_secs: BitcoinFeePolicy::default().live_max_age_secs(),
            }
        );
        assert_eq!(
            bitcoin.provenance().expose_for_persistence(),
            "private-bitcoin-source"
        );
        assert_eq!(
            bitcoin.live_max_age_secs(),
            BitcoinFeePolicy::default().live_max_age_secs()
        );
        assert_eq!(
            bitcoin.last_known_good_max_age_secs(),
            BitcoinFeePolicy::default().last_known_good_max_age_secs()
        );

        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .update_liquid(LiveLiquid::new(
                rate(0.25),
                20_000,
                provenance("private-liquid-source"),
            ))
            .unwrap();
        let policy = LiquidFeePolicy::default();
        let current = snapshot
            .accepted_liquid_for_persistence(&policy, 20_010)
            .unwrap();
        let liquid = AcceptedFeeObservation::liquid(&current, &policy, 20_010).unwrap();
        assert_eq!(liquid.rail(), FeeRail::Liquid);
        assert_eq!(liquid.source(), FeeObservationSource::LiveLiquid);
        assert_eq!(liquid.target(), FeeQuoteTarget::LiquidConfirmationTargetOne);
        assert_eq!(liquid.rate().as_f64().to_bits(), 0.25_f64.to_bits());
        assert_eq!(liquid.accepted_at_unix(), 20_010);
    }

    #[test]
    fn restore_changes_only_semantic_source_and_rejects_cross_rail_conversion() {
        let secret = "https://private.invalid/fee?token=do-not-log";
        let bitcoin = persisted(9, accepted_bitcoin(8.5, 10_000, 10_001, secret));
        let restored = bitcoin.restore_bitcoin_last_known_good().unwrap();
        assert_eq!(restored.rate().as_f64().to_bits(), 8.5_f64.to_bits());
        assert_eq!(restored.observed_at_unix(), 10_000);
        assert_eq!(
            restored.source(),
            FeeObservationSource::BitcoinLastKnownGood
        );
        assert_eq!(restored.provenance().expose_for_persistence(), secret);
        assert!(matches!(
            bitcoin.restore_liquid_last_known_good(),
            Err(FeeObservationRepositoryError::WrongRail {
                expected: FeeRail::Liquid,
                actual: FeeRail::Bitcoin,
            })
        ));
        for diagnostic in [format!("{bitcoin:?}"), format!("{:?}", bitcoin.accepted())] {
            assert!(diagnostic.contains("<redacted>"));
            assert!(!diagnostic.contains(secret));
            assert!(!diagnostic.contains("token=do-not-log"));
        }
    }

    #[test]
    fn monotonic_classification_is_idempotent_forward_safe_and_fail_closed() {
        let current_candidate = accepted_bitcoin(3.0, 10_100, 10_110, "current");
        let current = persisted(12, current_candidate.clone());
        assert!(matches!(
            classify_unapplied(current.clone(), &current_candidate).unwrap(),
            PersistFeeObservationOutcome::Unchanged(row) if row.generation() == 12
        ));

        let later_retry = accepted_bitcoin(3.0, 10_100, 10_120, "current");
        assert!(matches!(
            classify_unapplied(current.clone(), &later_retry).unwrap(),
            PersistFeeObservationOutcome::Unchanged(row)
                if row.generation() == 12 && row.accepted().accepted_at_unix() == 10_110
        ));

        let delayed = accepted_bitcoin(2.0, 10_000, 10_010, "delayed");
        assert!(matches!(
            classify_unapplied(current.clone(), &delayed).unwrap(),
            PersistFeeObservationOutcome::IgnoredStale(row) if row.generation() == 12
        ));

        let conflict = accepted_bitcoin(4.0, 10_100, 10_110, "disagreement");
        assert!(matches!(
            classify_unapplied(current, &conflict),
            Err(FeeObservationRepositoryError::ConflictingObservation {
                rail: FeeRail::Bitcoin,
                observed_at_unix: 10_100,
                accepted_at_unix: 10_110,
                current_generation: 12,
            })
        ));

        let current = persisted(12, current_candidate);
        let later_disagreement = accepted_bitcoin(4.0, 10_100, 10_120, "disagreement");
        assert!(matches!(
            classify_unapplied(current, &later_disagreement),
            Err(FeeObservationRepositoryError::ConflictingObservation {
                rail: FeeRail::Bitcoin,
                observed_at_unix: 10_100,
                accepted_at_unix: 10_120,
                current_generation: 12,
            })
        ));
    }

    #[test]
    fn stored_row_validation_rejects_wrong_source_and_invalid_integer_domains() {
        let wrong_source = FeeObservationRow {
            rail: "bitcoin".into(),
            generation: 1,
            rate_sat_per_vbyte: 2.0,
            observed_at_unix: 10,
            source: "liquid_live".into(),
            target: FeeQuoteTarget::BitcoinFastestFee.as_str().into(),
            provenance: "row-source".into(),
            accepted_at_unix: 10,
            live_max_age_secs: 120,
            last_known_good_max_age_secs: 900,
        };
        assert!(matches!(
            PersistedFeeObservation::try_from(wrong_source),
            Err(FeeObservationRepositoryError::InvalidStoredSource {
                rail: FeeRail::Bitcoin,
                source: FeeObservationSource::LiveLiquid,
            })
        ));

        let invalid_generation = FeeObservationRow {
            rail: "liquid".into(),
            generation: 0,
            rate_sat_per_vbyte: 0.5,
            observed_at_unix: 10,
            source: "liquid_live".into(),
            target: FeeQuoteTarget::LiquidConfirmationTargetOne.as_str().into(),
            provenance: "row-source".into(),
            accepted_at_unix: 10,
            live_max_age_secs: 120,
            last_known_good_max_age_secs: 900,
        };
        assert!(matches!(
            PersistedFeeObservation::try_from(invalid_generation),
            Err(FeeObservationRepositoryError::InvalidStoredInteger {
                field: "generation"
            })
        ));
    }

    #[test]
    fn lkg_decisions_cannot_be_persisted_again_to_extend_lifetime() {
        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .restore_bitcoin_last_known_good(BitcoinLastKnownGood::new(
                rate(2.0),
                10_000,
                provenance("restored"),
            ))
            .unwrap();
        let policy = BitcoinFeePolicy::default();
        let selected = snapshot.read_bitcoin(&policy, 10_100).unwrap();
        assert!(matches!(
            AcceptedFeeObservation::bitcoin(&selected, &policy, 10_100),
            Err(FeeObservationRepositoryError::NonLiveDecision {
                rail: FeeRail::Bitcoin,
                source: FeeObservationSource::BitcoinLastKnownGood,
            })
        ));
        assert!(snapshot
            .accepted_bitcoin_for_persistence(&policy, 10_100)
            .is_err());
    }
}
