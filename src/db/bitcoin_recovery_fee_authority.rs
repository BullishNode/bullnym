use std::error::Error;
use std::fmt;

use crate::fee_decision_record::{FeeConstructionPurpose, FEE_POLICY_VERSION};
use crate::fee_policy::{FeeObservationSource, FeeProvenance, FeeRail, SatPerVbyte};

/// Raw nullable schema-054 decision columns for one Bitcoin recovery attempt.
/// SQLx decodes this shape first, then the outer attempt's `flatten + try_from`
/// boundary rejects every representation except all-null legacy or all-13
/// validated authority.
#[derive(Debug, Default, sqlx::FromRow)]
pub(crate) struct BitcoinRecoveryFeeAuthorityRow {
    fee_decision_purpose: Option<String>,
    fee_decision_rail: Option<String>,
    fee_decision_target: Option<String>,
    fee_decision_source: Option<String>,
    fee_decision_rate_sat_vb: Option<f64>,
    fee_decision_quoted_at_unix: Option<i64>,
    fee_decision_evaluated_at_unix: Option<i64>,
    fee_decision_freshness_age_secs: Option<i64>,
    fee_decision_freshness_max_age_secs: Option<i64>,
    fee_decision_provenance: Option<String>,
    fee_decision_policy_floor_sat_vb: Option<f64>,
    fee_decision_policy_cap_sat_vb: Option<f64>,
    fee_decision_policy_version: Option<String>,
}

/// Typed fee-decision authority stored with immutable Bitcoin recovery bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum BitcoinRecoveryFeeAuthority {
    /// Attempts journaled before schema 054 have no decision packet. Their
    /// raw fee amount and effective rate remain independently validated.
    Legacy,
    Complete(BitcoinRecoveryFeeAuthorityRecord),
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinRecoveryFeeAuthorityRecord {
    purpose: FeeConstructionPurpose,
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

impl BitcoinRecoveryFeeAuthority {
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }

    /// Bind complete schema-054 authority to the fee paid by the exact final
    /// bytes. Boltz constructs relative-fee Bitcoin transactions with
    /// `ceil(rate * final_vbytes)`; replay must enforce that same rule.
    pub fn validate_replayed_fee(
        &self,
        derived_fee_amount_sat: u64,
        final_vbytes: u64,
    ) -> Result<(), BitcoinRecoveryFeeAuthorityError> {
        let Self::Complete(record) = self else {
            return Ok(());
        };
        if record.purpose != FeeConstructionPurpose::BitcoinRecovery
            || record.purpose.rail() != FeeRail::Bitcoin
        {
            return Err(BitcoinRecoveryFeeAuthorityError::ReplayMetadataMismatch);
        }
        let expected_fee_amount_sat = record
            .decision_rate
            .checked_fee_for_vbytes(final_vbytes)
            .map_err(|_| BitcoinRecoveryFeeAuthorityError::DecisionFeeAmountMismatch)?;
        if derived_fee_amount_sat != expected_fee_amount_sat {
            return Err(BitcoinRecoveryFeeAuthorityError::DecisionFeeAmountMismatch);
        }
        Ok(())
    }
}

impl TryFrom<BitcoinRecoveryFeeAuthorityRow> for BitcoinRecoveryFeeAuthority {
    type Error = BitcoinRecoveryFeeAuthorityError;

    fn try_from(row: BitcoinRecoveryFeeAuthorityRow) -> Result<Self, Self::Error> {
        let present = [
            row.fee_decision_purpose.is_some(),
            row.fee_decision_rail.is_some(),
            row.fee_decision_target.is_some(),
            row.fee_decision_source.is_some(),
            row.fee_decision_rate_sat_vb.is_some(),
            row.fee_decision_quoted_at_unix.is_some(),
            row.fee_decision_evaluated_at_unix.is_some(),
            row.fee_decision_freshness_age_secs.is_some(),
            row.fee_decision_freshness_max_age_secs.is_some(),
            row.fee_decision_provenance.is_some(),
            row.fee_decision_policy_floor_sat_vb.is_some(),
            row.fee_decision_policy_cap_sat_vb.is_some(),
            row.fee_decision_policy_version.is_some(),
        ]
        .into_iter()
        .filter(|is_present| *is_present)
        .count();
        if present == 0 {
            return Ok(Self::Legacy);
        }
        if present != 13 {
            return Err(BitcoinRecoveryFeeAuthorityError::PartialPacket { present });
        }

        let purpose = parse_purpose(required(row.fee_decision_purpose, "fee_decision_purpose")?)?;
        expect_text(
            required(row.fee_decision_rail, "fee_decision_rail")?,
            "bitcoin",
            "fee_decision_rail",
        )?;
        expect_text(
            required(row.fee_decision_target, "fee_decision_target")?,
            "fastestFee",
            "fee_decision_target",
        )?;
        let source = parse_source(required(row.fee_decision_source, "fee_decision_source")?)?;
        let decision_rate = rate(
            required(row.fee_decision_rate_sat_vb, "fee_decision_rate_sat_vb")?,
            "fee_decision_rate_sat_vb",
        )?;
        let quoted_at_unix = nonnegative_u64(
            required(
                row.fee_decision_quoted_at_unix,
                "fee_decision_quoted_at_unix",
            )?,
            "fee_decision_quoted_at_unix",
        )?;
        let evaluated_at_unix = nonnegative_u64(
            required(
                row.fee_decision_evaluated_at_unix,
                "fee_decision_evaluated_at_unix",
            )?,
            "fee_decision_evaluated_at_unix",
        )?;
        let freshness_age_secs = nonnegative_u64(
            required(
                row.fee_decision_freshness_age_secs,
                "fee_decision_freshness_age_secs",
            )?,
            "fee_decision_freshness_age_secs",
        )?;
        let freshness_max_age_secs = positive_u64(
            required(
                row.fee_decision_freshness_max_age_secs,
                "fee_decision_freshness_max_age_secs",
            )?,
            "fee_decision_freshness_max_age_secs",
        )?;
        if evaluated_at_unix.checked_sub(quoted_at_unix) != Some(freshness_age_secs)
            || freshness_age_secs > freshness_max_age_secs
        {
            return Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_freshness",
            });
        }
        let provenance = FeeProvenance::new(required(
            row.fee_decision_provenance,
            "fee_decision_provenance",
        )?)
        .map_err(|_| BitcoinRecoveryFeeAuthorityError::InvalidField {
            field: "fee_decision_provenance",
        })?;
        let policy_floor = rate(
            required(
                row.fee_decision_policy_floor_sat_vb,
                "fee_decision_policy_floor_sat_vb",
            )?,
            "fee_decision_policy_floor_sat_vb",
        )?;
        let policy_cap = rate(
            required(
                row.fee_decision_policy_cap_sat_vb,
                "fee_decision_policy_cap_sat_vb",
            )?,
            "fee_decision_policy_cap_sat_vb",
        )?;
        if policy_cap < policy_floor || decision_rate < policy_floor || decision_rate > policy_cap {
            return Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_policy_bounds",
            });
        }
        expect_text(
            required(
                row.fee_decision_policy_version,
                "fee_decision_policy_version",
            )?,
            FEE_POLICY_VERSION,
            "fee_decision_policy_version",
        )?;

        Ok(Self::Complete(BitcoinRecoveryFeeAuthorityRecord {
            purpose,
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

fn required<T>(
    value: Option<T>,
    field: &'static str,
) -> Result<T, BitcoinRecoveryFeeAuthorityError> {
    value.ok_or(BitcoinRecoveryFeeAuthorityError::InvalidField { field })
}

fn nonnegative_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, BitcoinRecoveryFeeAuthorityError> {
    u64::try_from(value).map_err(|_| BitcoinRecoveryFeeAuthorityError::InvalidField { field })
}

fn positive_u64(value: i64, field: &'static str) -> Result<u64, BitcoinRecoveryFeeAuthorityError> {
    if value <= 0 {
        return Err(BitcoinRecoveryFeeAuthorityError::InvalidField { field });
    }
    nonnegative_u64(value, field)
}

fn rate(value: f64, field: &'static str) -> Result<SatPerVbyte, BitcoinRecoveryFeeAuthorityError> {
    SatPerVbyte::try_from(value)
        .map_err(|_| BitcoinRecoveryFeeAuthorityError::InvalidField { field })
}

fn parse_purpose(
    value: String,
) -> Result<FeeConstructionPurpose, BitcoinRecoveryFeeAuthorityError> {
    match value.as_str() {
        "bitcoin_recovery" => Ok(FeeConstructionPurpose::BitcoinRecovery),
        _ => Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
            field: "fee_decision_purpose",
        }),
    }
}

fn parse_source(value: String) -> Result<FeeObservationSource, BitcoinRecoveryFeeAuthorityError> {
    match value.as_str() {
        "bitcoin_live" => Ok(FeeObservationSource::LiveBitcoin),
        "bitcoin_last_known_good" => Ok(FeeObservationSource::BitcoinLastKnownGood),
        _ => Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
            field: "fee_decision_source",
        }),
    }
}

fn expect_text(
    value: String,
    expected: &str,
    field: &'static str,
) -> Result<(), BitcoinRecoveryFeeAuthorityError> {
    if value == expected {
        Ok(())
    } else {
        Err(BitcoinRecoveryFeeAuthorityError::InvalidField { field })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinRecoveryFeeAuthorityError {
    PartialPacket { present: usize },
    InvalidField { field: &'static str },
    ReplayMetadataMismatch,
    DecisionFeeAmountMismatch,
}

impl fmt::Display for BitcoinRecoveryFeeAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialPacket { present } => write!(
                formatter,
                "Bitcoin recovery fee authority is partial ({present}/13 fields)"
            ),
            Self::InvalidField { field } => {
                write!(
                    formatter,
                    "Bitcoin recovery fee authority has invalid {field}"
                )
            }
            Self::ReplayMetadataMismatch => {
                formatter.write_str("Bitcoin recovery fee authority does not match replay purpose")
            }
            Self::DecisionFeeAmountMismatch => formatter
                .write_str("Bitcoin recovery fee does not match the journaled fee decision"),
        }
    }
}

impl Error for BitcoinRecoveryFeeAuthorityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_row() -> BitcoinRecoveryFeeAuthorityRow {
        BitcoinRecoveryFeeAuthorityRow {
            fee_decision_purpose: Some("bitcoin_recovery".into()),
            fee_decision_rail: Some("bitcoin".into()),
            fee_decision_target: Some("fastestFee".into()),
            fee_decision_source: Some("bitcoin_live".into()),
            fee_decision_rate_sat_vb: Some(2.5),
            fee_decision_quoted_at_unix: Some(1_000),
            fee_decision_evaluated_at_unix: Some(1_005),
            fee_decision_freshness_age_secs: Some(5),
            fee_decision_freshness_max_age_secs: Some(120),
            fee_decision_provenance: Some("unit-bitcoin-live".into()),
            fee_decision_policy_floor_sat_vb: Some(1.0),
            fee_decision_policy_cap_sat_vb: Some(500.0),
            fee_decision_policy_version: Some(FEE_POLICY_VERSION.into()),
        }
    }

    #[test]
    fn complete_live_and_lkg_packets_decode_and_validate() {
        for (source_text, expected_source) in [
            ("bitcoin_live", FeeObservationSource::LiveBitcoin),
            (
                "bitcoin_last_known_good",
                FeeObservationSource::BitcoinLastKnownGood,
            ),
        ] {
            let mut row = complete_row();
            row.fee_decision_source = Some(source_text.into());
            let authority = BitcoinRecoveryFeeAuthority::try_from(row).unwrap();
            let BitcoinRecoveryFeeAuthority::Complete(record) = &authority else {
                panic!("complete fixture decoded as legacy")
            };
            assert_eq!(record.purpose, FeeConstructionPurpose::BitcoinRecovery);
            assert_eq!(record.source, expected_source);
            assert_eq!(record.decision_rate.as_f64(), 2.5);
            assert_eq!(record.quoted_at_unix, 1_000);
            assert_eq!(record.evaluated_at_unix, 1_005);
            assert_eq!(record.freshness_age_secs, 5);
            assert_eq!(record.freshness_max_age_secs, 120);
            assert_eq!(
                record.provenance.expose_for_persistence(),
                "unit-bitcoin-live"
            );
            assert_eq!(record.policy_floor.as_f64(), 1.0);
            assert_eq!(record.policy_cap.as_f64(), 500.0);
            authority.validate_replayed_fee(353, 141).unwrap();
        }
    }

    #[test]
    fn partial_packet_is_rejected() {
        let row = BitcoinRecoveryFeeAuthorityRow {
            fee_decision_purpose: Some("bitcoin_recovery".into()),
            ..BitcoinRecoveryFeeAuthorityRow::default()
        };
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(row),
            Err(BitcoinRecoveryFeeAuthorityError::PartialPacket { present: 1 })
        );
    }

    #[test]
    fn malformed_metadata_clock_bounds_and_version_are_rejected() {
        let mut wrong_purpose = complete_row();
        wrong_purpose.fee_decision_purpose = Some("chain_liquid_claim".into());
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(wrong_purpose),
            Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_purpose"
            })
        );

        let mut wrong_rail = complete_row();
        wrong_rail.fee_decision_rail = Some("liquid".into());
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(wrong_rail),
            Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_rail"
            })
        );

        let mut wrong_target = complete_row();
        wrong_target.fee_decision_target = Some("1".into());
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(wrong_target),
            Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_target"
            })
        );

        let mut wrong_source = complete_row();
        wrong_source.fee_decision_source = Some("liquid_live".into());
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(wrong_source),
            Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_source"
            })
        );

        let mut wrong_clock = complete_row();
        wrong_clock.fee_decision_evaluated_at_unix = Some(1_006);
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(wrong_clock),
            Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_freshness"
            })
        );

        let mut wrong_bounds = complete_row();
        wrong_bounds.fee_decision_policy_cap_sat_vb = Some(2.0);
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(wrong_bounds),
            Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_policy_bounds"
            })
        );

        let mut wrong_version = complete_row();
        wrong_version.fee_decision_policy_version = Some("unknown".into());
        assert_eq!(
            BitcoinRecoveryFeeAuthority::try_from(wrong_version),
            Err(BitcoinRecoveryFeeAuthorityError::InvalidField {
                field: "fee_decision_policy_version"
            })
        );
    }

    #[test]
    fn replay_requires_the_exact_fractional_ceil_amount() {
        let authority = BitcoinRecoveryFeeAuthority::try_from(complete_row()).unwrap();
        authority.validate_replayed_fee(353, 141).unwrap();
        for wrong_fee in [352, 354] {
            assert_eq!(
                authority.validate_replayed_fee(wrong_fee, 141),
                Err(BitcoinRecoveryFeeAuthorityError::DecisionFeeAmountMismatch)
            );
        }
    }

    #[test]
    fn all_null_packet_is_explicit_legacy() {
        let authority =
            BitcoinRecoveryFeeAuthority::try_from(BitcoinRecoveryFeeAuthorityRow::default())
                .unwrap();
        assert!(authority.is_legacy());
        assert!(authority.validate_replayed_fee(0, 0).is_ok());
    }
}
