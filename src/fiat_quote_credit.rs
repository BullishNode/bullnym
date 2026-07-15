//! Pure cumulative fiat-credit accounting for one immutable quote version.
//!
//! Policy C credits only merchant-side satoshis that the caller has already
//! classified as eligible and on time for this exact quote. This module does
//! not decide eligibility, quote attribution, expiry, finality, or persistence.
//! It converts two monotonic cumulative satoshi totals into the corresponding
//! cumulative fiat credit and the non-negative delta for the new event.

use std::fmt;

const SATOSHIS_PER_BTC: i128 = 100_000_000;

/// Durable policy identifier written beside credited payment evidence.
pub const FIAT_QUOTE_CREDIT_POLICY: &str = "quote_cumulative_saturation_v1";

/// Complete Policy C input for one canonical accounting-sequence step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiatQuoteCreditInput {
    /// Immutable fiat face value of the quote, in its currency's minor unit.
    pub fiat_target_minor: i64,
    /// Immutable quote rate in fiat minor units per BTC.
    pub rate_minor_per_btc: i64,
    /// Immutable merchant-side satoshi target stored by the quote.
    pub merchant_amount_sat: i64,
    /// Eligible, on-time merchant satoshis before the new event.
    pub prior_cumulative_eligible_merchant_sat: i64,
    /// Eligible, on-time merchant satoshis including the new event.
    pub cumulative_eligible_merchant_sat: i64,
}

/// Policy C credit after applying one canonical accounting-sequence step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiatQuoteCreditOutcome {
    /// Total fiat minor units credited for this quote after the new event.
    pub cumulative_credit_minor: i64,
    /// Fiat minor units attributable to this event alone.
    pub event_credit_delta_minor: i64,
}

/// Invalid quote terms or cumulative accounting input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiatQuoteCreditError {
    NonPositiveFiatTarget,
    NonPositiveRate,
    NonPositiveMerchantAmount,
    NegativePriorCumulative,
    NegativeCumulative,
    CumulativeRegression { prior: i64, cumulative: i64 },
    MerchantAmountMismatch { expected: i64, actual: i64 },
    ArithmeticOverflow,
}

impl fmt::Display for FiatQuoteCreditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPositiveFiatTarget => formatter.write_str("fiat target must be positive"),
            Self::NonPositiveRate => formatter.write_str("fiat rate must be positive"),
            Self::NonPositiveMerchantAmount => {
                formatter.write_str("merchant satoshi target must be positive")
            }
            Self::NegativePriorCumulative => {
                formatter.write_str("prior cumulative eligible satoshis cannot be negative")
            }
            Self::NegativeCumulative => {
                formatter.write_str("cumulative eligible satoshis cannot be negative")
            }
            Self::CumulativeRegression { prior, cumulative } => write!(
                formatter,
                "cumulative eligible satoshis regressed from {prior} to {cumulative}"
            ),
            Self::MerchantAmountMismatch { expected, actual } => write!(
                formatter,
                "merchant satoshi target mismatch: expected {expected}, got {actual}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("fiat quote credit arithmetic overflow")
            }
        }
    }
}

impl std::error::Error for FiatQuoteCreditError {}

/// Calculate cumulative Policy C credit and this event's delta.
///
/// The cumulative inputs must follow the canonical accounting sequence. A
/// duplicate therefore has equal prior and new totals and produces a zero
/// delta; a lower new total is rejected rather than recording negative credit.
pub fn calculate_fiat_quote_credit(
    input: FiatQuoteCreditInput,
) -> Result<FiatQuoteCreditOutcome, FiatQuoteCreditError> {
    validate_quote_terms(
        input.fiat_target_minor,
        input.rate_minor_per_btc,
        input.merchant_amount_sat,
    )?;
    if input.prior_cumulative_eligible_merchant_sat < 0 {
        return Err(FiatQuoteCreditError::NegativePriorCumulative);
    }
    if input.cumulative_eligible_merchant_sat < 0 {
        return Err(FiatQuoteCreditError::NegativeCumulative);
    }
    if input.cumulative_eligible_merchant_sat < input.prior_cumulative_eligible_merchant_sat {
        return Err(FiatQuoteCreditError::CumulativeRegression {
            prior: input.prior_cumulative_eligible_merchant_sat,
            cumulative: input.cumulative_eligible_merchant_sat,
        });
    }

    let prior_credit_minor = project_validated_credit(
        input.fiat_target_minor,
        input.rate_minor_per_btc,
        input.merchant_amount_sat,
        input.prior_cumulative_eligible_merchant_sat,
    )?;
    let cumulative_credit_minor = project_validated_credit(
        input.fiat_target_minor,
        input.rate_minor_per_btc,
        input.merchant_amount_sat,
        input.cumulative_eligible_merchant_sat,
    )?;
    let event_credit_delta_minor = cumulative_credit_minor
        .checked_sub(prior_credit_minor)
        .ok_or(FiatQuoteCreditError::ArithmeticOverflow)?;

    Ok(FiatQuoteCreditOutcome {
        cumulative_credit_minor,
        event_credit_delta_minor,
    })
}

/// Project fiat credit from the currently active eligible satoshi total.
///
/// Unlike [`calculate_fiat_quote_credit`], this helper has no monotonicity
/// requirement. A caller can therefore recompute an active projection after a
/// deactivation or reactivation without this module assuming persistence or
/// emitting a negative accounting event.
pub fn project_fiat_quote_credit_minor(
    fiat_target_minor: i64,
    rate_minor_per_btc: i64,
    merchant_amount_sat: i64,
    cumulative_eligible_merchant_sat: i64,
) -> Result<i64, FiatQuoteCreditError> {
    validate_quote_terms(fiat_target_minor, rate_minor_per_btc, merchant_amount_sat)?;
    if cumulative_eligible_merchant_sat < 0 {
        return Err(FiatQuoteCreditError::NegativeCumulative);
    }
    project_validated_credit(
        fiat_target_minor,
        rate_minor_per_btc,
        merchant_amount_sat,
        cumulative_eligible_merchant_sat,
    )
}

fn validate_quote_terms(
    fiat_target_minor: i64,
    rate_minor_per_btc: i64,
    merchant_amount_sat: i64,
) -> Result<(), FiatQuoteCreditError> {
    if fiat_target_minor <= 0 {
        return Err(FiatQuoteCreditError::NonPositiveFiatTarget);
    }
    if rate_minor_per_btc <= 0 {
        return Err(FiatQuoteCreditError::NonPositiveRate);
    }
    if merchant_amount_sat <= 0 {
        return Err(FiatQuoteCreditError::NonPositiveMerchantAmount);
    }

    let fiat_scaled = i128::from(fiat_target_minor)
        .checked_mul(SATOSHIS_PER_BTC)
        .ok_or(FiatQuoteCreditError::ArithmeticOverflow)?;
    let expected = fiat_scaled
        .checked_div(i128::from(rate_minor_per_btc))
        .ok_or(FiatQuoteCreditError::ArithmeticOverflow)?;
    let expected = i64::try_from(expected).map_err(|_| FiatQuoteCreditError::ArithmeticOverflow)?;
    if expected <= 0 {
        return Err(FiatQuoteCreditError::NonPositiveMerchantAmount);
    }
    if merchant_amount_sat != expected {
        return Err(FiatQuoteCreditError::MerchantAmountMismatch {
            expected,
            actual: merchant_amount_sat,
        });
    }
    Ok(())
}

fn project_validated_credit(
    fiat_target_minor: i64,
    rate_minor_per_btc: i64,
    merchant_amount_sat: i64,
    cumulative_eligible_merchant_sat: i64,
) -> Result<i64, FiatQuoteCreditError> {
    if cumulative_eligible_merchant_sat >= merchant_amount_sat {
        return Ok(fiat_target_minor);
    }

    let converted = i128::from(cumulative_eligible_merchant_sat)
        .checked_mul(i128::from(rate_minor_per_btc))
        .ok_or(FiatQuoteCreditError::ArithmeticOverflow)?
        .checked_div(SATOSHIS_PER_BTC)
        .ok_or(FiatQuoteCreditError::ArithmeticOverflow)?;
    let capped = converted.min(i128::from(fiat_target_minor));
    i64::try_from(capped).map_err(|_| FiatQuoteCreditError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: i64 = 1_000;
    const RATE: i64 = 10_000_000;
    const MERCHANT_SAT: i64 = 10_000;

    fn input(prior: i64, cumulative: i64) -> FiatQuoteCreditInput {
        FiatQuoteCreditInput {
            fiat_target_minor: TARGET,
            rate_minor_per_btc: RATE,
            merchant_amount_sat: MERCHANT_SAT,
            prior_cumulative_eligible_merchant_sat: prior,
            cumulative_eligible_merchant_sat: cumulative,
        }
    }

    fn apply_sequence(parts: &[i64]) -> (i64, i64) {
        let mut cumulative_sat = 0_i64;
        let mut credited_minor = 0_i64;
        for part in parts {
            let prior = cumulative_sat;
            cumulative_sat = cumulative_sat.checked_add(*part).unwrap();
            let outcome = calculate_fiat_quote_credit(input(prior, cumulative_sat)).unwrap();
            credited_minor = credited_minor
                .checked_add(outcome.event_credit_delta_minor)
                .unwrap();
            assert_eq!(outcome.cumulative_credit_minor, credited_minor);
        }
        (cumulative_sat, credited_minor)
    }

    #[test]
    fn split_and_order_are_invariant_under_canonical_sequence() {
        let first = apply_sequence(&[1_234, 2_345, 6_421]);
        let reordered = apply_sequence(&[6_421, 1_234, 2_345]);
        let unsplit = apply_sequence(&[10_000]);
        assert_eq!(first, (MERCHANT_SAT, TARGET));
        assert_eq!(reordered, first);
        assert_eq!(unsplit, first);
    }

    #[test]
    fn exact_merchant_target_saturates_rounding_remainder() {
        let just_below = calculate_fiat_quote_credit(FiatQuoteCreditInput {
            fiat_target_minor: 1_000,
            rate_minor_per_btc: 30_000_000,
            merchant_amount_sat: 3_333,
            prior_cumulative_eligible_merchant_sat: 0,
            cumulative_eligible_merchant_sat: 3_332,
        })
        .unwrap();
        assert_eq!(just_below.cumulative_credit_minor, 999);

        let at_target = calculate_fiat_quote_credit(FiatQuoteCreditInput {
            fiat_target_minor: 1_000,
            rate_minor_per_btc: 30_000_000,
            merchant_amount_sat: 3_333,
            prior_cumulative_eligible_merchant_sat: 3_332,
            cumulative_eligible_merchant_sat: 3_333,
        })
        .unwrap();
        assert_eq!(at_target.cumulative_credit_minor, 1_000);
        assert_eq!(at_target.event_credit_delta_minor, 1);
    }

    #[test]
    fn underpayment_uses_floor_conversion() {
        assert_eq!(
            calculate_fiat_quote_credit(input(0, 1)).unwrap(),
            FiatQuoteCreditOutcome {
                cumulative_credit_minor: 0,
                event_credit_delta_minor: 0,
            }
        );
        assert_eq!(
            calculate_fiat_quote_credit(input(1, 1_999)).unwrap(),
            FiatQuoteCreditOutcome {
                cumulative_credit_minor: 199,
                event_credit_delta_minor: 199,
            }
        );
    }

    #[test]
    fn overpayment_is_capped_at_fiat_target() {
        let outcome = calculate_fiat_quote_credit(input(9_999, 50_000)).unwrap();
        assert_eq!(outcome.cumulative_credit_minor, TARGET);
        assert_eq!(outcome.event_credit_delta_minor, 1);
    }

    #[test]
    fn duplicate_cumulative_total_has_zero_delta() {
        assert_eq!(
            calculate_fiat_quote_credit(input(4_321, 4_321)).unwrap(),
            FiatQuoteCreditOutcome {
                cumulative_credit_minor: 432,
                event_credit_delta_minor: 0,
            }
        );
        assert_eq!(
            calculate_fiat_quote_credit(input(12_000, 12_000)).unwrap(),
            FiatQuoteCreditOutcome {
                cumulative_credit_minor: TARGET,
                event_credit_delta_minor: 0,
            }
        );
    }

    #[test]
    fn cumulative_regression_and_invalid_terms_are_rejected() {
        assert_eq!(
            calculate_fiat_quote_credit(input(500, 499)),
            Err(FiatQuoteCreditError::CumulativeRegression {
                prior: 500,
                cumulative: 499,
            })
        );
        assert_eq!(
            calculate_fiat_quote_credit(FiatQuoteCreditInput {
                merchant_amount_sat: MERCHANT_SAT + 1,
                ..input(0, 1)
            }),
            Err(FiatQuoteCreditError::MerchantAmountMismatch {
                expected: MERCHANT_SAT,
                actual: MERCHANT_SAT + 1,
            })
        );
        assert_eq!(
            calculate_fiat_quote_credit(FiatQuoteCreditInput {
                fiat_target_minor: 0,
                ..input(0, 1)
            }),
            Err(FiatQuoteCreditError::NonPositiveFiatTarget)
        );
    }

    #[test]
    fn checked_i128_intermediate_handles_i64_product_boundary() {
        let target = i64::MAX;
        let rate = i64::MAX;
        let merchant_sat = 100_000_000;
        let outcome = calculate_fiat_quote_credit(FiatQuoteCreditInput {
            fiat_target_minor: target,
            rate_minor_per_btc: rate,
            merchant_amount_sat: merchant_sat,
            prior_cumulative_eligible_merchant_sat: 0,
            cumulative_eligible_merchant_sat: merchant_sat - 1,
        })
        .unwrap();
        assert!(outcome.cumulative_credit_minor < target);
        assert_eq!(
            outcome.event_credit_delta_minor,
            outcome.cumulative_credit_minor
        );
    }

    #[test]
    fn unrepresentable_merchant_target_is_reported_as_overflow() {
        assert_eq!(
            calculate_fiat_quote_credit(FiatQuoteCreditInput {
                fiat_target_minor: i64::MAX,
                rate_minor_per_btc: 1,
                merchant_amount_sat: i64::MAX,
                prior_cumulative_eligible_merchant_sat: 0,
                cumulative_eligible_merchant_sat: 0,
            }),
            Err(FiatQuoteCreditError::ArithmeticOverflow)
        );
    }

    #[test]
    fn deactivate_and_reactivate_recompute_the_same_active_projection() {
        let active = project_fiat_quote_credit_minor(TARGET, RATE, MERCHANT_SAT, 6_000).unwrap();
        let deactivated =
            project_fiat_quote_credit_minor(TARGET, RATE, MERCHANT_SAT, 3_000).unwrap();
        let reactivated =
            project_fiat_quote_credit_minor(TARGET, RATE, MERCHANT_SAT, 6_000).unwrap();
        let canonical_retry = calculate_fiat_quote_credit(input(6_000, 6_000)).unwrap();
        assert_eq!(active, 600);
        assert_eq!(deactivated, 300);
        assert_eq!(reactivated, active);
        assert_eq!(canonical_retry.cumulative_credit_minor, active);
        assert_eq!(canonical_retry.event_credit_delta_minor, 0);
    }
}
