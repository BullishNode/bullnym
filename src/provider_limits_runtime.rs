//! One process-local cache for the exact BTC -> L-BTC reverse-pair limits.
//!
//! Only the periodic refresh path performs provider I/O. Metadata and callback
//! readers clone one small validated state under a standard-library read lock.

use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use boltz_client::swaps::boltz::ReversePair;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use crate::provider_limits::{
    effective_lightning_address_range, fixed_checkout_reverse_quote,
    revalidate_lightning_address_creation, EffectiveLightningAddressRange,
    FixedCheckoutReverseQuote, FixedCheckoutReverseQuoteError, LightningAddressCreationError,
    LightningAddressUnavailable, ProviderAsset, ProviderLimitMode, ProviderZeroConfLimit,
    ReversePairObservation, ReversePairSnapshotState, ReversePairSource,
    ReversePairValidationError,
};

pub const PROVIDER_LIMIT_REFRESH_CADENCE: Duration = Duration::from_secs(30);
pub const PROVIDER_LIMIT_MAXIMUM_AGE: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLimitRefreshOutcome {
    Updated,
    Invalid(ReversePairValidationError),
    FetchFailed,
}

/// Shared, cheap-to-read state for Lightning Address limit decisions.
#[derive(Debug, Clone, Default)]
pub struct ProviderLimitsRuntime {
    state: Arc<RwLock<ReversePairSnapshotState>>,
}

impl ProviderLimitsRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clone the current safe value without provider or other external I/O.
    pub fn snapshot(&self) -> ReversePairSnapshotState {
        match self.state.read() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Record completion of a successful reverse-pairs response.
    ///
    /// `None` means the authoritative response omitted the exact BTC -> L-BTC
    /// pair and immediately replaces prior state with a typed invalid value.
    pub fn record_successful_refresh(
        &self,
        pair: Option<ReversePair>,
        completed_at: Instant,
    ) -> ProviderLimitRefreshOutcome {
        let state = match pair {
            Some(pair) => ReversePairSnapshotState::from_observation(ReversePairObservation::new(
                ProviderAsset::Bitcoin,
                ProviderAsset::LiquidBitcoin,
                pair,
                ProviderZeroConfLimit::NotReportedByReversePairContract,
                ReversePairSource::BoltzV2ReversePairs,
                completed_at,
            )),
            None => ReversePairSnapshotState::Invalid(ReversePairValidationError::ExactPairMissing),
        };
        let outcome = match &state {
            ReversePairSnapshotState::Available(_) => ProviderLimitRefreshOutcome::Updated,
            ReversePairSnapshotState::Invalid(error) => {
                ProviderLimitRefreshOutcome::Invalid(*error)
            }
            ReversePairSnapshotState::Missing => {
                unreachable!("refresh never creates missing state")
            }
        };
        self.replace(state);
        outcome
    }

    /// Effective standard reverse-offer range using one current cached value.
    pub fn lightning_address_range(
        &self,
        product_minimum_msat: u64,
        product_maximum_msat: u64,
    ) -> Result<EffectiveLightningAddressRange, LightningAddressUnavailable> {
        self.lightning_address_range_at(product_minimum_msat, product_maximum_msat, Instant::now())
    }

    /// Revalidate immediately before allocation/provider mutation.
    pub fn revalidate_lightning_address_creation(
        &self,
        product_minimum_msat: u64,
        product_maximum_msat: u64,
        amount_msat: u64,
    ) -> Result<(u64, EffectiveLightningAddressRange), LightningAddressCreationError> {
        self.revalidate_lightning_address_creation_at(
            product_minimum_msat,
            product_maximum_msat,
            amount_msat,
            Instant::now(),
        )
    }

    /// Exact payer-pays quote for a fixed-price checkout. Unlike Lightning
    /// Address range reads, this includes the validated reverse-pair fee packet
    /// and fails closed when that packet is missing or stale.
    pub fn fixed_checkout_reverse_quote(
        &self,
        merchant_amount_sat: u64,
    ) -> Result<FixedCheckoutReverseQuote, FixedCheckoutReverseQuoteError> {
        fixed_checkout_reverse_quote(
            &self.snapshot(),
            merchant_amount_sat,
            Instant::now(),
            PROVIDER_LIMIT_MAXIMUM_AGE,
        )
    }

    fn lightning_address_range_at(
        &self,
        product_minimum_msat: u64,
        product_maximum_msat: u64,
        now: Instant,
    ) -> Result<EffectiveLightningAddressRange, LightningAddressUnavailable> {
        effective_lightning_address_range(
            &self.snapshot(),
            product_minimum_msat,
            product_maximum_msat,
            ProviderLimitMode::Standard,
            now,
            PROVIDER_LIMIT_MAXIMUM_AGE,
        )
    }

    fn revalidate_lightning_address_creation_at(
        &self,
        product_minimum_msat: u64,
        product_maximum_msat: u64,
        amount_msat: u64,
        now: Instant,
    ) -> Result<(u64, EffectiveLightningAddressRange), LightningAddressCreationError> {
        revalidate_lightning_address_creation(
            &self.snapshot(),
            product_minimum_msat,
            product_maximum_msat,
            ProviderLimitMode::Standard,
            amount_msat,
            now,
            PROVIDER_LIMIT_MAXIMUM_AGE,
        )
    }

    fn replace(&self, replacement: ReversePairSnapshotState) {
        match self.state.write() {
            Ok(mut state) => *state = replacement,
            Err(poisoned) => *poisoned.into_inner() = replacement,
        }
    }

    pub(crate) fn record_fetch_result(
        &self,
        result: Result<Option<ReversePair>, ()>,
        completed_at: Instant,
    ) -> ProviderLimitRefreshOutcome {
        match result {
            Ok(pair) => self.record_successful_refresh(pair, completed_at),
            Err(()) => ProviderLimitRefreshOutcome::FetchFailed,
        }
    }
}

/// Run the single fixed-cadence refresh loop. The fetch future itself is
/// cancellable, and the completion clock is sampled only after it resolves.
pub(crate) async fn run_periodic_refresh<F, Fut, C>(
    runtime: ProviderLimitsRuntime,
    cancel: CancellationToken,
    mut fetch: F,
    completed_at: C,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<ReversePair>, ()>>,
    C: Fn() -> Instant,
{
    let mut tick = tokio::time::interval(PROVIDER_LIMIT_REFRESH_CADENCE);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }

        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            result = fetch() => result,
        };
        match runtime.record_fetch_result(result, completed_at()) {
            ProviderLimitRefreshOutcome::Updated => {
                tracing::debug!(event = "provider_limits_refresh_updated");
            }
            ProviderLimitRefreshOutcome::Invalid(error) => {
                tracing::error!(
                    event = "provider_limits_refresh_invalid",
                    reason = %error,
                    "Lightning Address provider-limit snapshot closed"
                );
            }
            ProviderLimitRefreshOutcome::FetchFailed => {
                tracing::warn!(
                    event = "provider_limits_refresh_failed",
                    "retaining the last provider-limit snapshot until its fixed freshness limit"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use boltz_client::swaps::boltz::{PairMinerFees, ReverseFees, ReverseLimits};

    use super::*;

    const HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn pair(minimum_sat: u64, maximum_sat: u64) -> ReversePair {
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

    #[test]
    fn cadence_and_freshness_are_one_fixed_contract() {
        assert_eq!(PROVIDER_LIMIT_REFRESH_CADENCE, Duration::from_secs(30));
        assert_eq!(
            PROVIDER_LIMIT_MAXIMUM_AGE,
            PROVIDER_LIMIT_REFRESH_CADENCE * 3
        );
    }

    #[test]
    fn valid_success_replaces_state_and_reads_are_lock_only() {
        let runtime = ProviderLimitsRuntime::new();
        let completed_at = Instant::now();
        assert_eq!(
            runtime.record_successful_refresh(Some(pair(100, 1_000)), completed_at),
            ProviderLimitRefreshOutcome::Updated
        );

        for _ in 0..100 {
            let range = runtime
                .lightning_address_range_at(50_000, 2_000_000, completed_at)
                .unwrap();
            assert_eq!(range.limits_msat(), (100_000, 1_000_000));
            assert_eq!(range.snapshot_evidence().2, completed_at);
        }
    }

    #[test]
    fn missing_or_invalid_success_closes_immediately_and_replaces_good_state() {
        let runtime = ProviderLimitsRuntime::new();
        let now = Instant::now();
        runtime.record_successful_refresh(Some(pair(100, 1_000)), now);
        assert_eq!(
            runtime.record_successful_refresh(None, now),
            ProviderLimitRefreshOutcome::Invalid(ReversePairValidationError::ExactPairMissing)
        );
        assert!(matches!(
            runtime.snapshot(),
            ReversePairSnapshotState::Invalid(ReversePairValidationError::ExactPairMissing)
        ));

        let mut malformed = pair(100, 1_000);
        malformed.rate = 0.999;
        assert_eq!(
            runtime.record_successful_refresh(Some(malformed), now),
            ProviderLimitRefreshOutcome::Invalid(ReversePairValidationError::InvalidPairRate)
        );
        assert_eq!(
            runtime
                .lightning_address_range_at(100_000, 1_000_000, now)
                .unwrap_err(),
            LightningAddressUnavailable::SnapshotInvalid(
                ReversePairValidationError::InvalidPairRate
            )
        );
    }

    #[test]
    fn transient_failure_retains_last_good_only_until_exact_staleness_boundary() {
        let runtime = ProviderLimitsRuntime::new();
        let observed_at = Instant::now();
        runtime.record_successful_refresh(Some(pair(100, 1_000)), observed_at);
        assert_eq!(
            runtime.record_fetch_result(Err(()), observed_at + Duration::from_secs(20)),
            ProviderLimitRefreshOutcome::FetchFailed
        );

        let at_boundary = observed_at + PROVIDER_LIMIT_MAXIMUM_AGE;
        assert!(runtime
            .lightning_address_range_at(100_000, 1_000_000, at_boundary)
            .is_ok());
        assert_eq!(
            runtime
                .lightning_address_range_at(
                    100_000,
                    1_000_000,
                    at_boundary + Duration::from_nanos(1),
                )
                .unwrap_err(),
            LightningAddressUnavailable::SnapshotStale
        );
    }

    #[test]
    fn newer_valid_success_uses_its_completion_time_and_limits() {
        let runtime = ProviderLimitsRuntime::new();
        let first = Instant::now();
        let second = first + Duration::from_secs(30);
        runtime.record_successful_refresh(Some(pair(100, 1_000)), first);
        runtime.record_successful_refresh(Some(pair(250, 800)), second);

        let range = runtime
            .lightning_address_range_at(100_000, 1_000_000, second)
            .unwrap();
        assert_eq!(range.limits_msat(), (250_000, 800_000));
        assert_eq!(range.snapshot_evidence().2, second);
    }

    #[test]
    fn invalid_display_is_finite_and_redacted() {
        let text = LightningAddressUnavailable::SnapshotInvalid(
            ReversePairValidationError::MaximumBelowMinimum,
        )
        .to_string();
        assert_eq!(
            text,
            "lightning address temporarily unavailable: snapshot_invalid"
        );
        assert!(!text.contains("maximum_below_minimum"));
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_loop_waits_one_cadence_samples_completion_and_cancels() {
        let runtime = ProviderLimitsRuntime::new();
        let cancel = CancellationToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch_completed = Arc::new(AtomicBool::new(false));
        let completion = Instant::now();
        let times = Arc::new(Mutex::new(VecDeque::from([completion])));

        let task = tokio::spawn(run_periodic_refresh(
            runtime.clone(),
            cancel.clone(),
            {
                let calls = calls.clone();
                let fetch_completed = fetch_completed.clone();
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    fetch_completed.store(true, Ordering::SeqCst);
                    std::future::ready(Ok(Some(pair(100, 1_000))))
                }
            },
            {
                let fetch_completed = fetch_completed.clone();
                let times = times.clone();
                let cancel = cancel.clone();
                move || {
                    assert!(fetch_completed.load(Ordering::SeqCst));
                    cancel.cancel();
                    times.lock().unwrap().pop_front().unwrap()
                }
            },
        ));

        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        tokio::time::advance(PROVIDER_LIMIT_REFRESH_CADENCE - Duration::from_nanos(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_nanos(1)).await;
        task.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime
                .lightning_address_range_at(100_000, 1_000_000, completion)
                .unwrap()
                .snapshot_evidence()
                .2,
            completion
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_an_in_flight_fetch_without_state_change() {
        let runtime = ProviderLimitsRuntime::new();
        let cancel = CancellationToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_periodic_refresh(
            runtime.clone(),
            cancel.clone(),
            {
                let calls = calls.clone();
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<Result<Option<ReversePair>, ()>>()
                }
            },
            Instant::now,
        ));

        tokio::task::yield_now().await;
        tokio::time::advance(PROVIDER_LIMIT_REFRESH_CADENCE).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        cancel.cancel();
        task.await.unwrap();
        assert!(matches!(
            runtime.snapshot(),
            ReversePairSnapshotState::Missing
        ));
    }
}
