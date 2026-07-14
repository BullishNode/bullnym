//! Construction-boundary adapters for fee-policy decisions.
//!
//! The public conversion path accepts only the rail-specific decisions from
//! [`crate::fee_policy`]. Builders intentionally retain only the selected rate;
//! the caller keeps provenance/freshness metadata for persistence once the
//! corresponding attempt schemas exist.

use crate::fee_policy::{BitcoinFeeDecision, LiquidFeeDecision, SatPerVbyte};

/// The Liquid rate portion of an upstream policy decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LiquidBuilderFeeDecision(SatPerVbyte);

impl LiquidBuilderFeeDecision {
    pub fn rate(self) -> SatPerVbyte {
        self.0
    }
}

impl From<&LiquidFeeDecision> for LiquidBuilderFeeDecision {
    fn from(decision: &LiquidFeeDecision) -> Self {
        Self(decision.rate())
    }
}

/// The Bitcoin rate portion of an upstream policy decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BitcoinBuilderFeeDecision(SatPerVbyte);

impl BitcoinBuilderFeeDecision {
    pub fn rate(self) -> SatPerVbyte {
        self.0
    }
}

impl From<&BitcoinFeeDecision> for BitcoinBuilderFeeDecision {
    fn from(decision: &BitcoinFeeDecision) -> Self {
        Self(decision.rate())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_policy::{
        BitcoinFeePolicy, FeeProvenance, LiquidFeePolicy, LiveBitcoin, LiveLiquid,
    };

    #[test]
    fn only_policy_decisions_cross_each_rail_boundary_without_rate_drift() {
        for rate in [0.1, 2.0, 10.0] {
            let live = LiveLiquid::new(
                SatPerVbyte::try_from(rate).unwrap(),
                1_000,
                FeeProvenance::new("live-liquid").unwrap(),
            );
            let decision = LiquidFeePolicy::default()
                .decide_typed(Some(&live), None, 1_000)
                .unwrap();
            assert_eq!(
                LiquidBuilderFeeDecision::from(&decision).rate().as_f64(),
                rate
            );
        }

        for rate in [1.0, 2.0, 500.0] {
            let live = LiveBitcoin::new(
                SatPerVbyte::try_from(rate).unwrap(),
                1_000,
                FeeProvenance::new("live-bitcoin").unwrap(),
            );
            let decision = BitcoinFeePolicy::default()
                .decide_typed(Some(&live), None, 1_000)
                .unwrap();
            assert_eq!(
                BitcoinBuilderFeeDecision::from(&decision).rate().as_f64(),
                rate
            );
        }
    }
}
