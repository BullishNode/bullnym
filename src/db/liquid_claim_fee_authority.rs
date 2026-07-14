use std::error::Error;
use std::fmt;

use crate::fee_decision_record::{FeeConstructionPurpose, FEE_POLICY_VERSION};
use crate::fee_policy::{FeeObservationSource, FeeProvenance, FeeRail, SatPerVbyte};

/// Raw nullable schema-054 columns shared by reverse- and chain-claim row
/// projections. The outer records use SQLx's `flatten + try_from` boundary so a
/// partial or malformed authority packet cannot enter application state.
#[derive(Debug, Default, sqlx::FromRow)]
pub(crate) struct LiquidClaimFeeAuthorityRow {
    claim_actual_fee_sat: Option<i64>,
    claim_actual_fee_rate_sat_vb: Option<f64>,
    claim_fee_decision_purpose: Option<String>,
    claim_fee_decision_rail: Option<String>,
    claim_fee_decision_target: Option<String>,
    claim_fee_decision_source: Option<String>,
    claim_fee_decision_rate_sat_vb: Option<f64>,
    claim_fee_decision_quoted_at_unix: Option<i64>,
    claim_fee_decision_evaluated_at_unix: Option<i64>,
    claim_fee_decision_freshness_age_secs: Option<i64>,
    claim_fee_decision_freshness_max_age_secs: Option<i64>,
    claim_fee_decision_provenance: Option<String>,
    claim_fee_decision_policy_floor_sat_vb: Option<f64>,
    claim_fee_decision_policy_cap_sat_vb: Option<f64>,
    claim_fee_decision_policy_version: Option<String>,
}

/// Typed nullable authority stored beside one Liquid claim journal.
///
/// All-null is the only representation available to an unjournaled row and to
/// immutable claims written before schema 054. Once claim bytes exist, callers
/// interpret this variant as an explicitly accepted legacy journal. Every
/// schema-054 claim instead decodes to one validated complete record.
#[derive(Debug, Clone, PartialEq)]
pub enum LiquidClaimFeeAuthority {
    Legacy,
    Complete(LiquidClaimFeeAuthorityRecord),
}

#[derive(Debug, Clone, PartialEq)]
pub struct LiquidClaimFeeAuthorityRecord {
    purpose: FeeConstructionPurpose,
    actual_fee_sat: u64,
    actual_fee_rate: SatPerVbyte,
    source: FeeObservationSource,
    decision_rate: SatPerVbyte,
    quoted_at_unix: u64,
    evaluated_at_unix: u64,
    freshness_age_secs: u64,
    freshness_max_age_secs: u64,
    provenance: FeeProvenance,
    policy_floor: SatPerVbyte,
    policy_cap: SatPerVbyte,
}

impl LiquidClaimFeeAuthority {
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }

    /// Validate the values rederived from the exact persisted transaction.
    /// Legacy journals deliberately bypass schema-054 authority checks; their
    /// absent construction evidence must not be fabricated after the fact.
    pub fn validate_replayed_claim(
        &self,
        expected_purpose: FeeConstructionPurpose,
        derived_actual_fee_sat: i64,
        derived_actual_fee_rate_sat_vb: f64,
        derived_discounted_vbytes: u64,
    ) -> Result<(), LiquidClaimFeeAuthorityError> {
        let Self::Complete(record) = self else {
            return Ok(());
        };
        if expected_purpose.rail() != FeeRail::Liquid || record.purpose != expected_purpose {
            return Err(LiquidClaimFeeAuthorityError::ReplayMetadataMismatch);
        }
        let Ok(derived_actual_fee_sat) = u64::try_from(derived_actual_fee_sat) else {
            return Err(LiquidClaimFeeAuthorityError::ActualFeeAmountMismatch);
        };
        if record.actual_fee_sat != derived_actual_fee_sat {
            return Err(LiquidClaimFeeAuthorityError::ActualFeeAmountMismatch);
        }
        let derived_actual_fee_rate = SatPerVbyte::try_from(derived_actual_fee_rate_sat_vb)
            .map_err(|_| LiquidClaimFeeAuthorityError::ActualFeeRateMismatch)?;
        if record.actual_fee_rate.as_f64().to_bits() != derived_actual_fee_rate.as_f64().to_bits() {
            return Err(LiquidClaimFeeAuthorityError::ActualFeeRateMismatch);
        }
        let expected_actual_fee_sat = record
            .decision_rate
            .checked_fee_for_vbytes(derived_discounted_vbytes)
            .map_err(|_| LiquidClaimFeeAuthorityError::DecisionFeeAmountMismatch)?;
        if record.actual_fee_sat != expected_actual_fee_sat {
            return Err(LiquidClaimFeeAuthorityError::DecisionFeeAmountMismatch);
        }
        Ok(())
    }
}

impl TryFrom<LiquidClaimFeeAuthorityRow> for LiquidClaimFeeAuthority {
    type Error = LiquidClaimFeeAuthorityError;

    fn try_from(row: LiquidClaimFeeAuthorityRow) -> Result<Self, Self::Error> {
        let present = [
            row.claim_actual_fee_sat.is_some(),
            row.claim_actual_fee_rate_sat_vb.is_some(),
            row.claim_fee_decision_purpose.is_some(),
            row.claim_fee_decision_rail.is_some(),
            row.claim_fee_decision_target.is_some(),
            row.claim_fee_decision_source.is_some(),
            row.claim_fee_decision_rate_sat_vb.is_some(),
            row.claim_fee_decision_quoted_at_unix.is_some(),
            row.claim_fee_decision_evaluated_at_unix.is_some(),
            row.claim_fee_decision_freshness_age_secs.is_some(),
            row.claim_fee_decision_freshness_max_age_secs.is_some(),
            row.claim_fee_decision_provenance.is_some(),
            row.claim_fee_decision_policy_floor_sat_vb.is_some(),
            row.claim_fee_decision_policy_cap_sat_vb.is_some(),
            row.claim_fee_decision_policy_version.is_some(),
        ]
        .into_iter()
        .filter(|is_present| *is_present)
        .count();
        if present == 0 {
            return Ok(Self::Legacy);
        }
        if present != 15 {
            return Err(LiquidClaimFeeAuthorityError::PartialPacket { present });
        }

        let actual_fee_sat = positive_u64(
            required(row.claim_actual_fee_sat, "claim_actual_fee_sat")?,
            "claim_actual_fee_sat",
        )?;
        let actual_fee_rate = rate(
            required(
                row.claim_actual_fee_rate_sat_vb,
                "claim_actual_fee_rate_sat_vb",
            )?,
            "claim_actual_fee_rate_sat_vb",
        )?;
        let purpose = parse_purpose(required(
            row.claim_fee_decision_purpose,
            "claim_fee_decision_purpose",
        )?)?;
        expect_text(
            required(row.claim_fee_decision_rail, "claim_fee_decision_rail")?,
            "liquid",
            "claim_fee_decision_rail",
        )?;
        expect_text(
            required(row.claim_fee_decision_target, "claim_fee_decision_target")?,
            "1",
            "claim_fee_decision_target",
        )?;
        let source = parse_source(required(
            row.claim_fee_decision_source,
            "claim_fee_decision_source",
        )?)?;
        let decision_rate = rate(
            required(
                row.claim_fee_decision_rate_sat_vb,
                "claim_fee_decision_rate_sat_vb",
            )?,
            "claim_fee_decision_rate_sat_vb",
        )?;
        let quoted_at_unix = nonnegative_u64(
            required(
                row.claim_fee_decision_quoted_at_unix,
                "claim_fee_decision_quoted_at_unix",
            )?,
            "claim_fee_decision_quoted_at_unix",
        )?;
        let evaluated_at_unix = nonnegative_u64(
            required(
                row.claim_fee_decision_evaluated_at_unix,
                "claim_fee_decision_evaluated_at_unix",
            )?,
            "claim_fee_decision_evaluated_at_unix",
        )?;
        let freshness_age_secs = nonnegative_u64(
            required(
                row.claim_fee_decision_freshness_age_secs,
                "claim_fee_decision_freshness_age_secs",
            )?,
            "claim_fee_decision_freshness_age_secs",
        )?;
        let freshness_max_age_secs = positive_u64(
            required(
                row.claim_fee_decision_freshness_max_age_secs,
                "claim_fee_decision_freshness_max_age_secs",
            )?,
            "claim_fee_decision_freshness_max_age_secs",
        )?;
        if evaluated_at_unix.checked_sub(quoted_at_unix) != Some(freshness_age_secs)
            || freshness_age_secs > freshness_max_age_secs
        {
            return Err(LiquidClaimFeeAuthorityError::InvalidField {
                field: "claim_fee_decision_freshness",
            });
        }
        let provenance = FeeProvenance::new(required(
            row.claim_fee_decision_provenance,
            "claim_fee_decision_provenance",
        )?)
        .map_err(|_| LiquidClaimFeeAuthorityError::InvalidField {
            field: "claim_fee_decision_provenance",
        })?;
        let policy_floor = rate(
            required(
                row.claim_fee_decision_policy_floor_sat_vb,
                "claim_fee_decision_policy_floor_sat_vb",
            )?,
            "claim_fee_decision_policy_floor_sat_vb",
        )?;
        let policy_cap = rate(
            required(
                row.claim_fee_decision_policy_cap_sat_vb,
                "claim_fee_decision_policy_cap_sat_vb",
            )?,
            "claim_fee_decision_policy_cap_sat_vb",
        )?;
        if policy_cap < policy_floor || decision_rate < policy_floor || decision_rate > policy_cap {
            return Err(LiquidClaimFeeAuthorityError::InvalidField {
                field: "claim_fee_decision_policy_bounds",
            });
        }
        expect_text(
            required(
                row.claim_fee_decision_policy_version,
                "claim_fee_decision_policy_version",
            )?,
            FEE_POLICY_VERSION,
            "claim_fee_decision_policy_version",
        )?;

        Ok(Self::Complete(LiquidClaimFeeAuthorityRecord {
            purpose,
            actual_fee_sat,
            actual_fee_rate,
            source,
            decision_rate,
            quoted_at_unix,
            evaluated_at_unix,
            freshness_age_secs,
            freshness_max_age_secs,
            provenance,
            policy_floor,
            policy_cap,
        }))
    }
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, LiquidClaimFeeAuthorityError> {
    value.ok_or(LiquidClaimFeeAuthorityError::InvalidField { field })
}

fn nonnegative_u64(value: i64, field: &'static str) -> Result<u64, LiquidClaimFeeAuthorityError> {
    u64::try_from(value).map_err(|_| LiquidClaimFeeAuthorityError::InvalidField { field })
}

fn positive_u64(value: i64, field: &'static str) -> Result<u64, LiquidClaimFeeAuthorityError> {
    if value <= 0 {
        return Err(LiquidClaimFeeAuthorityError::InvalidField { field });
    }
    nonnegative_u64(value, field)
}

fn rate(value: f64, field: &'static str) -> Result<SatPerVbyte, LiquidClaimFeeAuthorityError> {
    SatPerVbyte::try_from(value).map_err(|_| LiquidClaimFeeAuthorityError::InvalidField { field })
}

fn parse_purpose(value: String) -> Result<FeeConstructionPurpose, LiquidClaimFeeAuthorityError> {
    match value.as_str() {
        "reverse_liquid_claim" => Ok(FeeConstructionPurpose::ReverseLiquidClaim),
        "chain_liquid_claim" => Ok(FeeConstructionPurpose::ChainLiquidClaim),
        _ => Err(LiquidClaimFeeAuthorityError::InvalidField {
            field: "claim_fee_decision_purpose",
        }),
    }
}

fn parse_source(value: String) -> Result<FeeObservationSource, LiquidClaimFeeAuthorityError> {
    match value.as_str() {
        "liquid_live" => Ok(FeeObservationSource::LiveLiquid),
        "liquid_last_known_good" => Ok(FeeObservationSource::LiquidLastKnownGood),
        _ => Err(LiquidClaimFeeAuthorityError::InvalidField {
            field: "claim_fee_decision_source",
        }),
    }
}

fn expect_text(
    value: String,
    expected: &str,
    field: &'static str,
) -> Result<(), LiquidClaimFeeAuthorityError> {
    if value == expected {
        Ok(())
    } else {
        Err(LiquidClaimFeeAuthorityError::InvalidField { field })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidClaimFeeAuthorityError {
    PartialPacket { present: usize },
    InvalidField { field: &'static str },
    ReplayMetadataMismatch,
    ActualFeeAmountMismatch,
    ActualFeeRateMismatch,
    DecisionFeeAmountMismatch,
}

impl fmt::Display for LiquidClaimFeeAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialPacket { present } => write!(
                formatter,
                "Liquid claim fee authority is partial ({present}/15 fields)"
            ),
            Self::InvalidField { field } => {
                write!(formatter, "Liquid claim fee authority has invalid {field}")
            }
            Self::ReplayMetadataMismatch => {
                formatter.write_str("Liquid claim fee authority does not match replay purpose")
            }
            Self::ActualFeeAmountMismatch => formatter
                .write_str("Liquid claim actual fee does not match the journaled transaction"),
            Self::ActualFeeRateMismatch => formatter
                .write_str("Liquid claim actual fee rate does not match the journaled transaction"),
            Self::DecisionFeeAmountMismatch => formatter
                .write_str("Liquid claim actual fee does not match the journaled fee decision"),
        }
    }
}

impl Error for LiquidClaimFeeAuthorityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_row(purpose: &str) -> LiquidClaimFeeAuthorityRow {
        LiquidClaimFeeAuthorityRow {
            claim_actual_fee_sat: Some(210),
            claim_actual_fee_rate_sat_vb: Some(1.5),
            claim_fee_decision_purpose: Some(purpose.into()),
            claim_fee_decision_rail: Some("liquid".into()),
            claim_fee_decision_target: Some("1".into()),
            claim_fee_decision_source: Some("liquid_live".into()),
            claim_fee_decision_rate_sat_vb: Some(1.5),
            claim_fee_decision_quoted_at_unix: Some(1_000),
            claim_fee_decision_evaluated_at_unix: Some(1_005),
            claim_fee_decision_freshness_age_secs: Some(5),
            claim_fee_decision_freshness_max_age_secs: Some(60),
            claim_fee_decision_provenance: Some("unit-liquid-live".into()),
            claim_fee_decision_policy_floor_sat_vb: Some(0.1),
            claim_fee_decision_policy_cap_sat_vb: Some(10.0),
            claim_fee_decision_policy_version: Some(FEE_POLICY_VERSION.into()),
        }
    }

    #[test]
    fn complete_reverse_and_chain_packets_decode_and_validate() {
        for (text, purpose, source_text, expected_source) in [
            (
                "reverse_liquid_claim",
                FeeConstructionPurpose::ReverseLiquidClaim,
                "liquid_live",
                FeeObservationSource::LiveLiquid,
            ),
            (
                "chain_liquid_claim",
                FeeConstructionPurpose::ChainLiquidClaim,
                "liquid_last_known_good",
                FeeObservationSource::LiquidLastKnownGood,
            ),
        ] {
            let mut row = complete_row(text);
            row.claim_fee_decision_source = Some(source_text.into());
            let authority = LiquidClaimFeeAuthority::try_from(row).unwrap();
            let LiquidClaimFeeAuthority::Complete(record) = &authority else {
                panic!("complete fixture decoded as legacy")
            };
            assert_eq!(record.purpose, purpose);
            assert_eq!(record.source, expected_source);
            assert_eq!(record.actual_fee_sat, 210);
            assert_eq!(record.actual_fee_rate.as_f64(), 1.5);
            assert_eq!(record.decision_rate.as_f64(), 1.5);
            assert_eq!(record.quoted_at_unix, 1_000);
            assert_eq!(record.evaluated_at_unix, 1_005);
            assert_eq!(record.freshness_age_secs, 5);
            assert_eq!(record.freshness_max_age_secs, 60);
            assert_eq!(
                record.provenance.expose_for_persistence(),
                "unit-liquid-live"
            );
            assert_eq!(record.policy_floor.as_f64(), 0.1);
            assert_eq!(record.policy_cap.as_f64(), 10.0);
            authority
                .validate_replayed_claim(purpose, 210, 1.5, 140)
                .unwrap();
        }
    }

    #[test]
    fn partial_packet_is_rejected() {
        let row = LiquidClaimFeeAuthorityRow {
            claim_fee_decision_purpose: Some("reverse_liquid_claim".into()),
            ..LiquidClaimFeeAuthorityRow::default()
        };
        assert_eq!(
            LiquidClaimFeeAuthority::try_from(row),
            Err(LiquidClaimFeeAuthorityError::PartialPacket { present: 1 })
        );
    }

    #[test]
    fn metadata_mismatch_is_rejected_at_decode_or_replay() {
        let mut wrong_target = complete_row("reverse_liquid_claim");
        wrong_target.claim_fee_decision_target = Some("fastestFee".into());
        assert_eq!(
            LiquidClaimFeeAuthority::try_from(wrong_target),
            Err(LiquidClaimFeeAuthorityError::InvalidField {
                field: "claim_fee_decision_target"
            })
        );

        let chain = LiquidClaimFeeAuthority::try_from(complete_row("chain_liquid_claim")).unwrap();
        assert_eq!(
            chain.validate_replayed_claim(
                FeeConstructionPurpose::ReverseLiquidClaim,
                210,
                1.5,
                140
            ),
            Err(LiquidClaimFeeAuthorityError::ReplayMetadataMismatch)
        );
    }

    #[test]
    fn actual_fee_mismatch_is_rejected() {
        let authority =
            LiquidClaimFeeAuthority::try_from(complete_row("reverse_liquid_claim")).unwrap();
        assert_eq!(
            authority.validate_replayed_claim(
                FeeConstructionPurpose::ReverseLiquidClaim,
                211,
                1.5,
                140
            ),
            Err(LiquidClaimFeeAuthorityError::ActualFeeAmountMismatch)
        );
        assert_eq!(
            authority.validate_replayed_claim(
                FeeConstructionPurpose::ReverseLiquidClaim,
                210,
                1.500_000_000_000_000_2,
                140
            ),
            Err(LiquidClaimFeeAuthorityError::ActualFeeRateMismatch)
        );
    }

    #[test]
    fn actual_fee_must_equal_the_decision_rate_ceil_rule() {
        let mut rounded_row = complete_row("reverse_liquid_claim");
        rounded_row.claim_actual_fee_sat = Some(209);
        rounded_row.claim_actual_fee_rate_sat_vb = Some(209.0 / 139.0);
        let rounded_authority = LiquidClaimFeeAuthority::try_from(rounded_row).unwrap();
        rounded_authority
            .validate_replayed_claim(
                FeeConstructionPurpose::ReverseLiquidClaim,
                209,
                209.0 / 139.0,
                139,
            )
            .unwrap();

        for actual_fee_sat in [208, 210] {
            let mut row = complete_row("reverse_liquid_claim");
            row.claim_actual_fee_sat = Some(actual_fee_sat);
            row.claim_actual_fee_rate_sat_vb = Some(actual_fee_sat as f64 / 139.0);
            let authority = LiquidClaimFeeAuthority::try_from(row).unwrap();
            assert_eq!(
                authority.validate_replayed_claim(
                    FeeConstructionPurpose::ReverseLiquidClaim,
                    actual_fee_sat,
                    actual_fee_sat as f64 / 139.0,
                    139
                ),
                Err(LiquidClaimFeeAuthorityError::DecisionFeeAmountMismatch)
            );
        }
    }

    #[test]
    fn all_null_packet_is_accepted_as_legacy() {
        let authority =
            LiquidClaimFeeAuthority::try_from(LiquidClaimFeeAuthorityRow::default()).unwrap();
        assert!(authority.is_legacy());
        assert!(authority
            .validate_replayed_claim(FeeConstructionPurpose::ReverseLiquidClaim, 0, f64::NAN, 0)
            .is_ok());
    }
}
