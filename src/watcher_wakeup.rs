//! Bounded, coalesced handoff from active payer status reads to direct-chain
//! watchers. A wake is only a scheduling hint: the watcher still re-queries
//! its authoritative backend and applies evidence through the normal reducer.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;
use uuid::Uuid;

/// Includes queued and currently executing Liquid targets. Keeping this bound
/// process-local and non-configurable prevents public invoice polling from
/// turning configuration drift into unbounded watcher work.
pub const TARGETED_LIQUID_WAKE_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeWaitOutcome {
    Completed,
    TimedOut,
    Unavailable,
    Backpressured,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TargetedEntryState {
    Pending = 0,
    Completed = 1,
    Unavailable = 2,
}

impl TargetedEntryState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Completed,
            2 => Self::Unavailable,
            _ => unreachable!("targeted watcher entry has an invalid state"),
        }
    }
}

#[derive(Debug)]
struct TargetedWakeEntry {
    generation: u64,
    request_count: AtomicU64,
    state: AtomicU8,
    completion: Notify,
}

impl TargetedWakeEntry {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            request_count: AtomicU64::new(1),
            state: AtomicU8::new(TargetedEntryState::Pending as u8),
            completion: Notify::new(),
        }
    }

    fn state(&self) -> TargetedEntryState {
        TargetedEntryState::from_u8(self.state.load(Ordering::Acquire))
    }

    fn finish(&self, state: TargetedEntryState) {
        self.state.store(state as u8, Ordering::Release);
        self.completion.notify_waiters();
    }
}

#[derive(Debug, Default)]
struct TargetedQueueState {
    registered: bool,
    next_generation: u64,
    queue: VecDeque<Uuid>,
    entries: HashMap<Uuid, Arc<TargetedWakeEntry>>,
}

/// Result returned to one invoice-status waiter. Queue measurements are
/// snapshots taken when the request was accepted; the authoritative result is
/// always the refreshed database projection, never wake completion itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetedWakeWait {
    pub outcome: WakeWaitOutcome,
    pub generation: Option<u64>,
    pub coalesced: bool,
    pub queue_depth: usize,
    pub outstanding: usize,
}

impl TargetedWakeWait {
    pub const fn unavailable() -> Self {
        Self {
            outcome: WakeWaitOutcome::Unavailable,
            generation: None,
            coalesced: false,
            queue_depth: 0,
            outstanding: 0,
        }
    }
}

#[derive(Debug)]
pub struct TargetedWakeRequest {
    pub invoice_id: Uuid,
    pub generation: u64,
    pub queue_depth_after_dequeue: usize,
    entry: Arc<TargetedWakeEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetedWakeCompletion {
    pub request_count: u64,
    pub queue_depth: usize,
    pub outstanding: usize,
}

/// Fixed-capacity, invoice-keyed handoff for Liquid status refreshes. One map
/// entry covers both queued and in-flight work, so polls arriving during a
/// scan coalesce with the same generation instead of scheduling a second one.
#[derive(Debug)]
pub struct TargetedWatcherWakeup {
    capacity: usize,
    state: Mutex<TargetedQueueState>,
    wake: Notify,
}

impl Default for TargetedWatcherWakeup {
    fn default() -> Self {
        Self::new(TARGETED_LIQUID_WAKE_CAPACITY)
    }
}

impl TargetedWatcherWakeup {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "targeted watcher capacity must be non-zero");
        Self {
            capacity,
            state: Mutex::new(TargetedQueueState::default()),
            wake: Notify::new(),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, TargetedQueueState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn register(self: &Arc<Self>) -> TargetedWatcherWakeupRegistration {
        let mut state = self.lock_state();
        assert!(
            !state.registered,
            "a targeted watcher wakeup has two consumers"
        );
        state.registered = true;
        drop(state);
        TargetedWatcherWakeupRegistration {
            wakeup: Arc::clone(self),
        }
    }

    pub async fn request_and_wait(&self, invoice_id: Uuid, max_wait: Duration) -> TargetedWakeWait {
        let (entry, coalesced, queue_depth, outstanding, should_notify) = {
            let mut state = self.lock_state();
            if !state.registered {
                return TargetedWakeWait::unavailable();
            }
            if let Some(entry) = state.entries.get(&invoice_id).cloned() {
                entry.request_count.fetch_add(1, Ordering::AcqRel);
                (entry, true, state.queue.len(), state.entries.len(), false)
            } else {
                if state.entries.len() >= self.capacity {
                    return TargetedWakeWait {
                        outcome: WakeWaitOutcome::Backpressured,
                        generation: None,
                        coalesced: false,
                        queue_depth: state.queue.len(),
                        outstanding: state.entries.len(),
                    };
                }
                state.next_generation = state.next_generation.wrapping_add(1).max(1);
                let entry = Arc::new(TargetedWakeEntry::new(state.next_generation));
                state.entries.insert(invoice_id, Arc::clone(&entry));
                state.queue.push_back(invoice_id);
                (entry, false, state.queue.len(), state.entries.len(), true)
            }
        };
        if should_notify {
            self.wake.notify_one();
        }

        let wait = async {
            loop {
                match entry.state() {
                    TargetedEntryState::Completed => return WakeWaitOutcome::Completed,
                    TargetedEntryState::Unavailable => return WakeWaitOutcome::Unavailable,
                    TargetedEntryState::Pending => {}
                }
                let notified = entry.completion.notified();
                match entry.state() {
                    TargetedEntryState::Completed => return WakeWaitOutcome::Completed,
                    TargetedEntryState::Unavailable => return WakeWaitOutcome::Unavailable,
                    TargetedEntryState::Pending => notified.await,
                }
            }
        };
        let outcome = tokio::time::timeout(max_wait, wait)
            .await
            .unwrap_or(WakeWaitOutcome::TimedOut);
        TargetedWakeWait {
            outcome,
            generation: Some(entry.generation),
            coalesced,
            queue_depth,
            outstanding,
        }
    }

    pub async fn wait_for_request(&self) -> TargetedWakeRequest {
        loop {
            if let Some(request) = self.take_request() {
                return request;
            }
            let notified = self.wake.notified();
            if let Some(request) = self.take_request() {
                return request;
            }
            notified.await;
        }
    }

    fn take_request(&self) -> Option<TargetedWakeRequest> {
        let mut state = self.lock_state();
        let invoice_id = state.queue.pop_front()?;
        let entry = state
            .entries
            .get(&invoice_id)
            .cloned()
            .expect("queued targeted wake must retain its entry");
        Some(TargetedWakeRequest {
            invoice_id,
            generation: entry.generation,
            queue_depth_after_dequeue: state.queue.len(),
            entry,
        })
    }

    pub fn complete(&self, request: TargetedWakeRequest) -> TargetedWakeCompletion {
        let (queue_depth, outstanding) = {
            let mut state = self.lock_state();
            let matches_current = state.entries.get(&request.invoice_id).is_some_and(|entry| {
                Arc::ptr_eq(entry, &request.entry) && entry.generation == request.generation
            });
            if matches_current {
                state.entries.remove(&request.invoice_id);
            }
            (state.queue.len(), state.entries.len())
        };
        request.entry.finish(TargetedEntryState::Completed);
        TargetedWakeCompletion {
            request_count: request.entry.request_count.load(Ordering::Acquire),
            queue_depth,
            outstanding,
        }
    }
}

pub struct TargetedWatcherWakeupRegistration {
    wakeup: Arc<TargetedWatcherWakeup>,
}

impl Drop for TargetedWatcherWakeupRegistration {
    fn drop(&mut self) {
        let entries = {
            let mut state = self.wakeup.lock_state();
            state.registered = false;
            state.queue.clear();
            state
                .entries
                .drain()
                .map(|(_, entry)| entry)
                .collect::<Vec<_>>()
        };
        for entry in entries {
            entry.finish(TargetedEntryState::Unavailable);
        }
    }
}

#[derive(Debug)]
pub struct DirectWatcherWakeups {
    pub bitcoin: Arc<WatcherWakeup>,
    pub liquid: Arc<TargetedWatcherWakeup>,
}

impl Default for DirectWatcherWakeups {
    fn default() -> Self {
        Self {
            bitcoin: Arc::new(WatcherWakeup::default()),
            liquid: Arc::new(TargetedWatcherWakeup::default()),
        }
    }
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

    #[tokio::test]
    async fn targeted_duplicate_requests_share_one_inflight_scan() {
        let wakeup = Arc::new(TargetedWatcherWakeup::new(4));
        let _registration = wakeup.register();
        let invoice_id = Uuid::new_v4();
        let first_wakeup = Arc::clone(&wakeup);
        let first = tokio::spawn(async move {
            first_wakeup
                .request_and_wait(invoice_id, Duration::from_secs(1))
                .await
        });
        while wakeup.lock_state().entries.is_empty() {
            tokio::task::yield_now().await;
        }
        let request = wakeup.wait_for_request().await;
        assert_eq!(request.invoice_id, invoice_id);
        assert_eq!(request.queue_depth_after_dequeue, 0);

        let second_wakeup = Arc::clone(&wakeup);
        let second = tokio::spawn(async move {
            second_wakeup
                .request_and_wait(invoice_id, Duration::from_secs(1))
                .await
        });
        while request.entry.request_count.load(Ordering::Acquire) < 2 {
            tokio::task::yield_now().await;
        }
        let completion = wakeup.complete(request);
        assert_eq!(completion.request_count, 2);
        assert_eq!(completion.outstanding, 0);

        let first = first.await.unwrap();
        let second = second.await.unwrap();
        assert_eq!(first.outcome, WakeWaitOutcome::Completed);
        assert!(!first.coalesced);
        assert_eq!(second.outcome, WakeWaitOutcome::Completed);
        assert!(second.coalesced);
        assert_eq!(first.generation, second.generation);
    }

    #[tokio::test]
    async fn targeted_distinct_requests_are_strictly_bounded() {
        let wakeup = Arc::new(TargetedWatcherWakeup::new(2));
        let _registration = wakeup.register();
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first_wakeup = Arc::clone(&wakeup);
        let first = tokio::spawn(async move {
            first_wakeup
                .request_and_wait(first_id, Duration::from_secs(1))
                .await
        });
        let second_wakeup = Arc::clone(&wakeup);
        let second = tokio::spawn(async move {
            second_wakeup
                .request_and_wait(second_id, Duration::from_secs(1))
                .await
        });
        while wakeup.lock_state().entries.len() < 2 {
            tokio::task::yield_now().await;
        }

        let rejected = wakeup
            .request_and_wait(Uuid::new_v4(), Duration::from_secs(1))
            .await;
        assert_eq!(rejected.outcome, WakeWaitOutcome::Backpressured);
        assert_eq!(rejected.outstanding, 2);

        let mut accepted = std::collections::HashSet::new();
        for _ in 0..2 {
            let request = wakeup.wait_for_request().await;
            accepted.insert(request.invoice_id);
            wakeup.complete(request);
        }
        assert_eq!(accepted, [first_id, second_id].into_iter().collect());
        assert_eq!(first.await.unwrap().outcome, WakeWaitOutcome::Completed);
        assert_eq!(second.await.unwrap().outcome, WakeWaitOutcome::Completed);
    }

    #[tokio::test(start_paused = true)]
    async fn targeted_wait_timeout_does_not_enqueue_duplicate_work() {
        let wakeup = Arc::new(TargetedWatcherWakeup::new(2));
        let _registration = wakeup.register();
        let invoice_id = Uuid::new_v4();
        let timed_out = wakeup
            .request_and_wait(invoice_id, Duration::from_secs(2))
            .await;
        assert_eq!(timed_out.outcome, WakeWaitOutcome::TimedOut);

        let retry = wakeup.request_and_wait(invoice_id, Duration::from_secs(1));
        let worker = async {
            let request = wakeup.wait_for_request().await;
            let completion = wakeup.complete(request);
            assert_eq!(completion.request_count, 2);
        };
        let (retry, ()) = tokio::join!(retry, worker);
        assert_eq!(retry.outcome, WakeWaitOutcome::Completed);
        assert!(retry.coalesced);
        assert_eq!(retry.generation, timed_out.generation);
    }

    #[tokio::test]
    async fn targeted_worker_restart_releases_waiters_and_accepts_new_work() {
        let wakeup = Arc::new(TargetedWatcherWakeup::new(2));
        let registration = wakeup.register();
        let old_id = Uuid::new_v4();
        let old_wakeup = Arc::clone(&wakeup);
        let old_waiter = tokio::spawn(async move {
            old_wakeup
                .request_and_wait(old_id, Duration::from_secs(1))
                .await
        });
        tokio::task::yield_now().await;
        drop(registration);
        assert_eq!(
            old_waiter.await.unwrap().outcome,
            WakeWaitOutcome::Unavailable
        );

        let _replacement = wakeup.register();
        let new_id = Uuid::new_v4();
        let waiter = wakeup.request_and_wait(new_id, Duration::from_secs(1));
        let worker = async {
            let request = wakeup.wait_for_request().await;
            assert_eq!(request.invoice_id, new_id);
            wakeup.complete(request);
        };
        let (waiter, ()) = tokio::join!(waiter, worker);
        assert_eq!(waiter.outcome, WakeWaitOutcome::Completed);
    }
}
