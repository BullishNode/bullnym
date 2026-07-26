//! Bounded, coalesced handoff from active payer status reads to direct-chain
//! watchers. A wake is only a scheduling hint: the watcher still re-queries
//! its authoritative backend and applies evidence through the normal reducer.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeWaitOutcome {
    Completed,
    TimedOut,
    Unavailable,
}

#[derive(Debug, Default)]
pub struct WatcherWakeup {
    requested_generation: AtomicU64,
    completed_generation: AtomicU64,
    registered: AtomicBool,
    wake: Notify,
    completion: Notify,
}

impl WatcherWakeup {
    /// Register the one worker that consumes this wake channel. Status reads
    /// never wait when the corresponding worker is disabled or unavailable.
    pub fn register(self: &Arc<Self>) -> WatcherWakeupRegistration {
        let was_registered = self.registered.swap(true, Ordering::AcqRel);
        assert!(!was_registered, "a direct watcher wakeup has two consumers");
        WatcherWakeupRegistration {
            wakeup: Arc::clone(self),
        }
    }

    pub async fn request_and_wait(&self, max_wait: Duration) -> WakeWaitOutcome {
        if !self.registered.load(Ordering::Acquire) {
            return WakeWaitOutcome::Unavailable;
        }
        let target = self.requested_generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.wake.notify_one();
        let wait = async {
            loop {
                if self.completed_generation.load(Ordering::Acquire) >= target {
                    return WakeWaitOutcome::Completed;
                }
                if !self.registered.load(Ordering::Acquire) {
                    return WakeWaitOutcome::Unavailable;
                }
                let notified = self.completion.notified();
                if self.completed_generation.load(Ordering::Acquire) >= target {
                    return WakeWaitOutcome::Completed;
                }
                notified.await;
            }
        };
        tokio::time::timeout(max_wait, wait)
            .await
            .unwrap_or(WakeWaitOutcome::TimedOut)
    }

    /// Wait for at least one request and return the newest coalesced
    /// generation. Requests that arrive before this snapshot share one scan.
    pub async fn wait_for_request(&self) -> u64 {
        loop {
            let requested = self.requested_generation.load(Ordering::Acquire);
            if requested > self.completed_generation.load(Ordering::Acquire) {
                return requested;
            }
            let notified = self.wake.notified();
            let requested = self.requested_generation.load(Ordering::Acquire);
            if requested > self.completed_generation.load(Ordering::Acquire) {
                return requested;
            }
            notified.await;
        }
    }

    pub fn complete_through(&self, generation: u64) {
        self.completed_generation
            .fetch_max(generation, Ordering::AcqRel);
        self.completion.notify_waiters();
    }
}

pub struct WatcherWakeupRegistration {
    wakeup: Arc<WatcherWakeup>,
}

impl Drop for WatcherWakeupRegistration {
    fn drop(&mut self) {
        self.wakeup.registered.store(false, Ordering::Release);
        self.wakeup.completion.notify_waiters();
    }
}

#[derive(Debug, Default)]
pub struct DirectWatcherWakeups {
    pub bitcoin: Arc<WatcherWakeup>,
    pub liquid: Arc<WatcherWakeup>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_worker_never_delays_a_status_read() {
        let wakeup = WatcherWakeup::default();
        assert_eq!(
            wakeup.request_and_wait(Duration::from_secs(1)).await,
            WakeWaitOutcome::Unavailable
        );
    }

    #[tokio::test]
    async fn concurrent_requests_coalesce_into_one_completed_generation() {
        let wakeup = Arc::new(WatcherWakeup::default());
        let _registration = wakeup.register();
        let first = wakeup.request_and_wait(Duration::from_secs(1));
        let second = wakeup.request_and_wait(Duration::from_secs(1));
        let worker = async {
            tokio::task::yield_now().await;
            let generation = wakeup.wait_for_request().await;
            assert_eq!(generation, 2);
            wakeup.complete_through(generation);
        };
        let (first, second, ()) = tokio::join!(first, second, worker);
        assert_eq!(first, WakeWaitOutcome::Completed);
        assert_eq!(second, WakeWaitOutcome::Completed);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_wait_times_out_without_claiming_authority_success() {
        let wakeup = Arc::new(WatcherWakeup::default());
        let _registration = wakeup.register();
        assert_eq!(
            wakeup.request_and_wait(Duration::from_secs(2)).await,
            WakeWaitOutcome::TimedOut
        );
    }
}
