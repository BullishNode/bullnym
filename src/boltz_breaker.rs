//! A small circuit breaker for the user-facing Boltz creation paths.
//!
//! During a Boltz outage every swap-creation call otherwise stalls to the full
//! 10s client timeout before erroring, and a payer redirected to Lightning has
//! no fast signal that Boltz is down. The breaker trips after N consecutive
//! transport-class failures (connect/timeout/5xx — never a 4xx business error)
//! and fast-fails subsequent calls for a short window, then half-opens to probe
//! recovery. See issue #31.
//!
//! Only the user-facing creation methods on `BoltzService` consult it. The
//! claimer/reconciler polling paths deliberately do NOT — they have their own
//! retry/backoff budgets and must keep hammering Boltz during recovery.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default consecutive transport failures before the breaker opens.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
/// Default fail-fast window once open.
pub const DEFAULT_OPEN_FOR: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Proceed with the Boltz call.
    Allow,
    /// Breaker is open — fail fast without calling Boltz.
    Reject,
}

#[derive(Debug)]
struct Inner {
    /// Consecutive transport failures while closed.
    consecutive_failures: u32,
    /// When `Some`, the breaker is open until this instant.
    open_until: Option<Instant>,
    /// True after an open window elapses and a single probe has been allowed
    /// through; the probe's outcome decides whether we re-open or close.
    half_open: bool,
}

pub struct BoltzBreaker {
    inner: Mutex<Inner>,
    threshold: u32,
    open_for: Duration,
}

impl BoltzBreaker {
    pub fn new(threshold: u32, open_for: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                consecutive_failures: 0,
                open_until: None,
                half_open: false,
            }),
            threshold,
            open_for,
        }
    }

    /// Decide whether a call may proceed. `Instant`-injected for tests.
    fn gate_at(&self, now: Instant) -> Gate {
        let mut g = self.inner.lock().expect("breaker mutex poisoned");
        match g.open_until {
            // Still inside the open window: fail fast.
            Some(until) if now < until => Gate::Reject,
            // Window elapsed: allow a single probe (half-open).
            Some(_) => {
                g.open_until = None;
                g.half_open = true;
                Gate::Allow
            }
            None => Gate::Allow,
        }
    }

    /// Record a call outcome. `transport_failure` must be true ONLY for
    /// connect/timeout/5xx-class failures — a 4xx business rejection means
    /// Boltz is reachable and healthy, so it resets the breaker like a success.
    fn record_at(&self, now: Instant, transport_failure: bool) {
        let mut g = self.inner.lock().expect("breaker mutex poisoned");
        if transport_failure {
            g.consecutive_failures = g.consecutive_failures.saturating_add(1);
            // A failed half-open probe, or crossing the threshold, (re)opens.
            if g.half_open || g.consecutive_failures >= self.threshold {
                g.open_until = Some(now + self.open_for);
                g.half_open = false;
            }
        } else {
            // Reachable: close and reset.
            g.consecutive_failures = 0;
            g.half_open = false;
            g.open_until = None;
        }
    }

    pub fn gate(&self) -> Gate {
        self.gate_at(Instant::now())
    }

    pub fn record(&self, transport_failure: bool) {
        self.record_at(Instant::now(), transport_failure);
    }
}

impl Default for BoltzBreaker {
    fn default() -> Self {
        Self::new(DEFAULT_FAILURE_THRESHOLD, DEFAULT_OPEN_FOR)
    }
}

/// Classify an `AppError` from a Boltz call as transport-class (breaker should
/// count it) vs business/other (breaker should treat as reachable). Biased
/// toward NOT tripping: only clear transport signatures count, so a burst of
/// legitimate 4xx business errors can never open the breaker.
pub fn is_transport_failure(err: &crate::error::AppError) -> bool {
    let s = err.to_string().to_lowercase();
    s.contains("timed out")
        || s.contains("timeout")
        || s.contains("error sending request")
        || s.contains("connection refused")
        || s.contains("connection reset")
        || s.contains("connection closed")
        || s.contains("dns error")
        || s.contains("tcp connect")
        || s.contains("502")
        || s.contains("503")
        || s.contains("504")
        || s.contains("bad gateway")
        || s.contains("gateway timeout")
        || s.contains("service unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn stays_closed_below_threshold() {
        let b = BoltzBreaker::new(3, Duration::from_secs(30));
        let now = t0();
        b.record_at(now, true);
        b.record_at(now, true);
        assert_eq!(b.gate_at(now), Gate::Allow, "2 < threshold 3 stays closed");
    }

    #[test]
    fn opens_at_threshold_and_fast_fails() {
        let b = BoltzBreaker::new(3, Duration::from_secs(30));
        let now = t0();
        b.record_at(now, true);
        b.record_at(now, true);
        b.record_at(now, true);
        assert_eq!(b.gate_at(now), Gate::Reject, "threshold reached -> open");
        // Still open just before the window elapses.
        assert_eq!(b.gate_at(now + Duration::from_secs(29)), Gate::Reject);
    }

    #[test]
    fn half_opens_after_window_then_closes_on_success() {
        let b = BoltzBreaker::new(2, Duration::from_secs(30));
        let now = t0();
        b.record_at(now, true);
        b.record_at(now, true);
        assert_eq!(b.gate_at(now), Gate::Reject);
        // After the window, a single probe is allowed (half-open).
        let later = now + Duration::from_secs(31);
        assert_eq!(b.gate_at(later), Gate::Allow);
        // Probe succeeds -> closed, counter reset.
        b.record_at(later, false);
        assert_eq!(b.gate_at(later), Gate::Allow);
    }

    #[test]
    fn half_open_probe_failure_reopens_immediately() {
        let b = BoltzBreaker::new(2, Duration::from_secs(30));
        let now = t0();
        b.record_at(now, true);
        b.record_at(now, true);
        let later = now + Duration::from_secs(31);
        assert_eq!(b.gate_at(later), Gate::Allow, "half-open probe");
        // Probe fails (single failure in half-open) -> reopen.
        b.record_at(later, true);
        assert_eq!(b.gate_at(later), Gate::Reject);
        assert_eq!(b.gate_at(later + Duration::from_secs(31)), Gate::Allow);
    }

    #[test]
    fn business_error_does_not_trip() {
        let b = BoltzBreaker::new(2, Duration::from_secs(30));
        let now = t0();
        // Non-transport failures reset the counter each time.
        b.record_at(now, false);
        b.record_at(now, false);
        b.record_at(now, false);
        assert_eq!(b.gate_at(now), Gate::Allow);
    }

    #[test]
    fn success_resets_partial_failure_streak() {
        let b = BoltzBreaker::new(3, Duration::from_secs(30));
        let now = t0();
        b.record_at(now, true);
        b.record_at(now, true);
        b.record_at(now, false); // reachable again
        b.record_at(now, true); // streak restarts at 1
        assert_eq!(b.gate_at(now), Gate::Allow);
    }

    #[test]
    fn transport_classifier_matches_transport_only() {
        use crate::error::AppError;
        assert!(is_transport_failure(&AppError::BoltzError(
            "error sending request for url".into()
        )));
        assert!(is_transport_failure(&AppError::BoltzError(
            "operation timed out".into()
        )));
        assert!(is_transport_failure(&AppError::BoltzError(
            "502 Bad Gateway".into()
        )));
        // Business errors must NOT count.
        assert!(!is_transport_failure(&AppError::BoltzError(
            "amount 1000 below minimum 25000".into()
        )));
        assert!(!is_transport_failure(&AppError::BoltzError(
            "no invoice returned".into()
        )));
    }
}
