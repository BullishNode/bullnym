use std::future::pending;
use std::time::Duration;

use crate::db::WatcherLane;

pub(crate) const EPOCH_RESUME_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeWait {
    Disabled,
    After(Duration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeIntent {
    None,
    ContinueSoon,
    DeferToCadence,
}

impl ResumeIntent {
    pub(crate) const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::ContinueSoon, _) | (_, Self::ContinueSoon) => Self::ContinueSoon,
            (Self::DeferToCadence, _) | (_, Self::DeferToCadence) => Self::DeferToCadence,
            (Self::None, Self::None) => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WatcherTurn<T> {
    pub(crate) outcome: T,
    pub(crate) resume: ResumeIntent,
}

impl<T> WatcherTurn<T> {
    pub(crate) const fn complete(outcome: T) -> Self {
        Self {
            outcome,
            resume: ResumeIntent::None,
        }
    }

    pub(crate) const fn continue_soon(outcome: T) -> Self {
        Self {
            outcome,
            resume: ResumeIntent::ContinueSoon,
        }
    }

    pub(crate) const fn defer_to_cadence(outcome: T) -> Self {
        Self {
            outcome,
            resume: ResumeIntent::DeferToCadence,
        }
    }
}

/// Tracks only unfinished, already-started watcher epochs. Normal cadence
/// ticks remain the sole way to start a fresh epoch; this schedule only keeps
/// a bounded traversal moving after a page boundary or token exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EpochResumeSchedule {
    recent_pending: bool,
    historical_pending: bool,
    next_shared: WatcherLane,
}

impl Default for EpochResumeSchedule {
    fn default() -> Self {
        Self {
            recent_pending: false,
            historical_pending: false,
            next_shared: WatcherLane::Recent,
        }
    }
}

impl EpochResumeSchedule {
    pub(crate) fn observe(&mut self, lane: WatcherLane, intent: ResumeIntent) {
        let incomplete = intent == ResumeIntent::ContinueSoon;
        let pending = match lane {
            WatcherLane::Recent => &mut self.recent_pending,
            WatcherLane::Historical => &mut self.historical_pending,
        };
        let newly_pending = incomplete && !*pending;
        *pending = incomplete;

        // A normal recent cadence tick that starts more work preempts the next
        // shared continuation. Thereafter both pending lanes alternate.
        if lane == WatcherLane::Recent && newly_pending {
            self.next_shared = WatcherLane::Recent;
        }
    }

    pub(crate) const fn wait(&self) -> ResumeWait {
        if self.recent_pending || self.historical_pending {
            ResumeWait::After(EPOCH_RESUME_INTERVAL)
        } else {
            ResumeWait::Disabled
        }
    }

    pub(crate) fn take_next(&mut self) -> Option<WatcherLane> {
        match (self.recent_pending, self.historical_pending) {
            (false, false) => None,
            (true, false) => Some(WatcherLane::Recent),
            (false, true) => Some(WatcherLane::Historical),
            (true, true) => {
                let next = self.next_shared;
                self.next_shared = match next {
                    WatcherLane::Recent => WatcherLane::Historical,
                    WatcherLane::Historical => WatcherLane::Recent,
                };
                Some(next)
            }
        }
    }
}

pub(crate) async fn wait_for_epoch_resume(wait: ResumeWait) {
    match wait {
        ResumeWait::Disabled => pending::<()>().await,
        ResumeWait::After(delay) => tokio::time::sleep(delay).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn startup_incomplete_prefers_recent_then_alternates() {
        let mut schedule = EpochResumeSchedule::default();
        schedule.observe(WatcherLane::Recent, ResumeIntent::ContinueSoon);
        schedule.observe(WatcherLane::Historical, ResumeIntent::ContinueSoon);

        assert_eq!(schedule.wait(), ResumeWait::After(Duration::from_secs(1)));
        assert_eq!(schedule.take_next(), Some(WatcherLane::Recent));
        assert_eq!(schedule.take_next(), Some(WatcherLane::Historical));
        assert_eq!(schedule.take_next(), Some(WatcherLane::Recent));
    }

    #[test]
    fn newly_pending_recent_preempts_an_incomplete_historical_epoch() {
        let mut schedule = EpochResumeSchedule::default();
        schedule.observe(WatcherLane::Historical, ResumeIntent::ContinueSoon);
        assert_eq!(schedule.take_next(), Some(WatcherLane::Historical));

        schedule.observe(WatcherLane::Recent, ResumeIntent::ContinueSoon);
        assert_eq!(schedule.take_next(), Some(WatcherLane::Recent));
        assert_eq!(schedule.take_next(), Some(WatcherLane::Historical));
    }

    #[test]
    fn completed_or_failed_epochs_do_not_create_an_idle_resume_loop() {
        let mut schedule = EpochResumeSchedule::default();
        assert_eq!(schedule.wait(), ResumeWait::Disabled);
        assert_eq!(schedule.take_next(), None);

        schedule.observe(WatcherLane::Recent, ResumeIntent::ContinueSoon);
        schedule.observe(WatcherLane::Recent, ResumeIntent::None);
        schedule.observe(WatcherLane::Historical, ResumeIntent::DeferToCadence);
        assert_eq!(schedule.wait(), ResumeWait::Disabled);
        assert_eq!(schedule.take_next(), None);
    }

    #[test]
    fn advancing_phase_dominates_an_independent_cadence_deferral() {
        assert_eq!(
            ResumeIntent::DeferToCadence.combine(ResumeIntent::ContinueSoon),
            ResumeIntent::ContinueSoon
        );
        assert_eq!(
            ResumeIntent::ContinueSoon.combine(ResumeIntent::DeferToCadence),
            ResumeIntent::ContinueSoon
        );
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_resume_wait_yields_immediately_to_cancellation() {
        let disabled = wait_for_epoch_resume(ResumeWait::Disabled);
        tokio::pin!(disabled);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut disabled)
                .await
                .is_err(),
            "a disabled resume wait must remain pending"
        );

        let cancel = CancellationToken::new();
        cancel.cancel();

        tokio::select! {
            biased;
            _ = cancel.cancelled() => {}
            _ = &mut disabled => {
                panic!("a disabled resume wait must remain pending")
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_recent_interval_cannot_burst_starve_historical_resume() {
        let mut recent_tick = tokio::time::interval(Duration::from_secs(30));
        recent_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        recent_tick.tick().await;

        // Model a recent turn that ran past its next normal deadline. Consuming
        // that one delayed cadence tick schedules the following tick from now,
        // rather than leaving a burst immediately ready ahead of continuation.
        // Move past two 30-second deadlines. With Burst, consuming just one
        // leaves the second tick immediately ready and the biased recent branch
        // below wins. Delay schedules the next deadline from the current time.
        tokio::time::advance(Duration::from_secs(61)).await;
        recent_tick.tick().await;

        let mut schedule = EpochResumeSchedule::default();
        schedule.observe(WatcherLane::Historical, ResumeIntent::ContinueSoon);
        let waiting_since = tokio::time::Instant::now();
        let selected = tokio::select! {
            biased;
            _ = recent_tick.tick() => WatcherLane::Recent,
            _ = wait_for_epoch_resume(schedule.wait()) => {
                schedule.take_next().expect("historical continuation")
            }
        };

        assert_eq!(selected, WatcherLane::Historical);
        assert_eq!(
            tokio::time::Instant::now().duration_since(waiting_since),
            EPOCH_RESUME_INTERVAL
        );
    }
}
