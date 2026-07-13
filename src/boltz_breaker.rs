//! A small circuit breaker for the user-facing Boltz creation paths.
//!
//! During a Boltz outage every swap-creation call otherwise stalls to the full
//! 10s client timeout before erroring, and a payer redirected to Lightning has
//! no fast signal that Boltz is down. The breaker trips after N consecutive
//! qualified failures (transport/HTTP 429/5xx — never a 4xx business error)
//! and fast-fails subsequent calls for a short window, then half-opens to probe
//! recovery. See issue #31.
//!
//! Only the user-facing creation methods on `BoltzService` consult it. The
//! claimer/reconciler polling paths deliberately do NOT — they have their own
//! retry/backoff budgets and must keep hammering Boltz during recovery.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default consecutive qualified failures before the breaker opens.
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

/// Operator-facing state of the process-local provider-creation circuit.
///
/// These are deliberately finite, low-cardinality values. The snapshot never
/// carries a provider URL/body, endpoint, payment identity, key, or raw error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationCircuitState {
    Closed,
    Suspect,
    Open,
    HalfOpen,
}

impl CreationCircuitState {
    #[cfg(test)]
    const ALL: [Self; 4] = [Self::Closed, Self::Suspect, Self::Open, Self::HalfOpen];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Suspect => "suspect",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// Finite reason for a creation-circuit state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreationCircuitTransitionReason {
    QualifiedFailure,
    FailureThresholdReached,
    CooldownElapsed,
    ProbeSucceeded,
    ProbeFailed,
    Reachable,
}

impl CreationCircuitTransitionReason {
    #[cfg(test)]
    const ALL: [Self; 6] = [
        Self::QualifiedFailure,
        Self::FailureThresholdReached,
        Self::CooldownElapsed,
        Self::ProbeSucceeded,
        Self::ProbeFailed,
        Self::Reachable,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::QualifiedFailure => "qualified_failure",
            Self::FailureThresholdReached => "failure_threshold_reached",
            Self::CooldownElapsed => "cooldown_elapsed",
            Self::ProbeSucceeded => "probe_succeeded",
            Self::ProbeFailed => "probe_failed",
            Self::Reachable => "reachable",
        }
    }
}

/// Current low-cardinality circuit snapshot consumed by #68 operations
/// readiness. It is not serialized into the public `/ready` response and does
/// not participate in a second admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreationCircuitSnapshot {
    pub state: CreationCircuitState,
    pub consecutive_qualified_failures: u32,
    pub transition_count: u64,
}

impl Default for CreationCircuitSnapshot {
    fn default() -> Self {
        Self {
            state: CreationCircuitState::Closed,
            consecutive_qualified_failures: 0,
            transition_count: 0,
        }
    }
}

/// One low-cardinality transition. `count` is monotonic for the process and
/// lets a metrics/log consumer detect missed transitions without adding a
/// high-cardinality label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreationCircuitTransition {
    pub(crate) from: CreationCircuitState,
    pub(crate) to: CreationCircuitState,
    pub(crate) reason: CreationCircuitTransitionReason,
    pub(crate) count: u64,
}

#[derive(Debug)]
struct Inner {
    /// Consecutive qualified failures while closed/suspect.
    consecutive_failures: u32,
    /// When `Some`, the breaker is open until this instant.
    open_until: Option<Instant>,
    /// True after an open window elapses and a single probe has been allowed
    /// through; the probe's outcome decides whether we re-open or close.
    half_open: bool,
    /// Monotonic count of state changes for low-cardinality operations
    /// telemetry. Repeated failures within one state do not increment it.
    transition_count: u64,
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
                transition_count: 0,
            }),
            threshold,
            open_for,
        }
    }

    /// Decide whether a call may proceed. `Instant`-injected for tests.
    fn gate_at(&self, now: Instant) -> Gate {
        let (gate, transition) = {
            let mut g = self.inner.lock().expect("breaker mutex poisoned");
            let before = circuit_state(&g);
            let (gate, reason) = match g.open_until {
                // Still inside the open window: fail fast.
                Some(until) if now < until => (Gate::Reject, None),
                // Window elapsed: allow exactly one probe (half-open).
                Some(_) => {
                    g.open_until = None;
                    g.half_open = true;
                    (
                        Gate::Allow,
                        Some(CreationCircuitTransitionReason::CooldownElapsed),
                    )
                }
                // A probe is already in flight. Concurrent callers fail fast.
                None if g.half_open => (Gate::Reject, None),
                None => (Gate::Allow, None),
            };
            let transition = reason.and_then(|reason| record_transition(&mut g, before, reason));
            (gate, transition)
        };
        if let Some(transition) = transition {
            crate::admission::emit_creation_circuit_transition(transition);
        }
        gate
    }

    /// Record a call outcome. `qualified_failure` must be true ONLY for
    /// connect/DNS/timeout, HTTP 429, or HTTP 5xx failures. A 4xx business
    /// rejection means Boltz is reachable and healthy, so it resets the
    /// breaker like a success. Local failures after the provider call are not
    /// recorded here at all.
    fn record_at(&self, now: Instant, qualified_failure: bool) {
        let transition = {
            let mut g = self.inner.lock().expect("breaker mutex poisoned");
            let before = circuit_state(&g);
            if qualified_failure {
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

            let after = circuit_state(&g);
            let reason = match (qualified_failure, before, after) {
                (true, CreationCircuitState::HalfOpen, CreationCircuitState::Open) => {
                    CreationCircuitTransitionReason::ProbeFailed
                }
                (false, CreationCircuitState::HalfOpen, CreationCircuitState::Closed) => {
                    CreationCircuitTransitionReason::ProbeSucceeded
                }
                (true, _, CreationCircuitState::Open) => {
                    CreationCircuitTransitionReason::FailureThresholdReached
                }
                (true, _, CreationCircuitState::Suspect) => {
                    CreationCircuitTransitionReason::QualifiedFailure
                }
                (false, _, CreationCircuitState::Closed) => {
                    CreationCircuitTransitionReason::Reachable
                }
                _ => CreationCircuitTransitionReason::QualifiedFailure,
            };
            record_transition(&mut g, before, reason)
        };
        if let Some(transition) = transition {
            crate::admission::emit_creation_circuit_transition(transition);
        }
    }

    pub fn gate(&self) -> Gate {
        self.gate_at(Instant::now())
    }

    pub fn record(&self, qualified_failure: bool) {
        self.record_at(Instant::now(), qualified_failure);
    }

    pub fn snapshot(&self) -> CreationCircuitSnapshot {
        let inner = self.inner.lock().expect("breaker mutex poisoned");
        snapshot_from_inner(&inner)
    }
}

fn circuit_state(inner: &Inner) -> CreationCircuitState {
    if inner.half_open {
        CreationCircuitState::HalfOpen
    } else if inner.open_until.is_some() {
        CreationCircuitState::Open
    } else if inner.consecutive_failures > 0 {
        CreationCircuitState::Suspect
    } else {
        CreationCircuitState::Closed
    }
}

fn snapshot_from_inner(inner: &Inner) -> CreationCircuitSnapshot {
    CreationCircuitSnapshot {
        state: circuit_state(inner),
        consecutive_qualified_failures: inner.consecutive_failures,
        transition_count: inner.transition_count,
    }
}

fn record_transition(
    inner: &mut Inner,
    from: CreationCircuitState,
    reason: CreationCircuitTransitionReason,
) -> Option<CreationCircuitTransition> {
    let to = circuit_state(inner);
    if from == to {
        return None;
    }
    inner.transition_count = inner.transition_count.saturating_add(1);
    Some(CreationCircuitTransition {
        from,
        to,
        reason,
        count: inner.transition_count,
    })
}

impl Default for BoltzBreaker {
    fn default() -> Self {
        Self::new(DEFAULT_FAILURE_THRESHOLD, DEFAULT_OPEN_FOR)
    }
}

/// Classify the pinned Boltz client's typed error before it is converted to an
/// application error. HTTP 429 and every 5xx status qualify; other typed and
/// business errors do not.
pub(crate) fn is_qualified_boltz_failure(err: &boltz_client::error::Error) -> bool {
    match err {
        boltz_client::error::Error::HTTPStatusNotSuccess(status, _) => {
            qualified_http_status(status.as_u16())
        }
        // The pinned client's creation POST helper currently uses this variant
        // for both reqwest transport failures and non-success response text.
        // Keep the fallback intentionally narrow until the client preserves a
        // typed status for these calls.
        boltz_client::error::Error::HTTP(message) => qualified_failure_message(message),
        _ => false,
    }
}

fn qualified_failure_message(message: &str) -> bool {
    let s = message.to_lowercase();
    s.contains("timed out")
        || s.contains("timeout")
        || s.contains("error sending request")
        || s.contains("connection refused")
        || s.contains("connection reset")
        || s.contains("connection closed")
        || s.contains("dns error")
        || s.contains("tcp connect")
        // Preserve the landed compatibility signatures while typed status
        // handling covers 429 and the full 5xx range when available.
        || s.contains("502")
        || s.contains("503")
        || s.contains("504")
        || contains_qualified_http_status(&s)
        || s.contains("too many requests")
        || s.contains("internal server error")
        || s.contains("not implemented")
        || s.contains("bad gateway")
        || s.contains("gateway timeout")
        || s.contains("service unavailable")
}

fn contains_qualified_http_status(message: &str) -> bool {
    const MARKERS: [&str; 5] = ["http status", "http", "status code", "status:", "status"];

    MARKERS.iter().any(|marker| {
        message.match_indices(marker).any(|(index, _)| {
            let tail = &message[index + marker.len()..];
            let tail = tail.trim_start_matches(|character: char| {
                character.is_ascii_whitespace() || character == ':' || character == '='
            });
            let digits: String = tail
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .take(4)
                .collect();
            digits.len() == 3 && digits.parse::<u16>().is_ok_and(qualified_http_status)
        })
    })
}

const fn qualified_http_status(status: u16) -> bool {
    status == 429 || (status >= 500 && status <= 599)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn default_contract_is_five_failures_and_thirty_seconds() {
        assert_eq!(DEFAULT_FAILURE_THRESHOLD, 5);
        assert_eq!(DEFAULT_OPEN_FOR, Duration::from_secs(30));

        let breaker = BoltzBreaker::default();
        assert_eq!(breaker.threshold, DEFAULT_FAILURE_THRESHOLD);
        assert_eq!(breaker.open_for, DEFAULT_OPEN_FOR);
    }

    #[test]
    fn exactly_one_concurrent_half_open_probe_is_allowed() {
        const CALLERS: usize = 32;
        let breaker = Arc::new(BoltzBreaker::new(2, Duration::from_secs(30)));
        let now = t0();
        breaker.record_at(now, true);
        breaker.record_at(now, true);
        let later = now + Duration::from_secs(30);
        let barrier = Arc::new(std::sync::Barrier::new(CALLERS));

        let gates: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..CALLERS)
                .map(|_| {
                    let breaker = breaker.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        breaker.gate_at(later)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("gate thread panicked"))
                .collect()
        });

        assert_eq!(gates.iter().filter(|gate| **gate == Gate::Allow).count(), 1);
        assert_eq!(
            gates.iter().filter(|gate| **gate == Gate::Reject).count(),
            CALLERS - 1
        );
        assert_eq!(breaker.snapshot().state, CreationCircuitState::HalfOpen);
    }

    #[test]
    fn snapshots_and_transition_counts_cover_the_complete_state_machine() {
        let breaker = BoltzBreaker::default();
        let now = t0();

        assert_eq!(breaker.snapshot().state, CreationCircuitState::Closed);
        breaker.record_at(now, true);
        assert_eq!(
            breaker.snapshot(),
            CreationCircuitSnapshot {
                state: CreationCircuitState::Suspect,
                consecutive_qualified_failures: 1,
                transition_count: 1,
            }
        );
        assert_eq!(breaker.gate_at(now), Gate::Allow);

        for _ in 1..DEFAULT_FAILURE_THRESHOLD {
            breaker.record_at(now, true);
        }
        assert_eq!(breaker.snapshot().state, CreationCircuitState::Open);
        assert_eq!(breaker.snapshot().transition_count, 2);
        let provider_calls = std::sync::atomic::AtomicUsize::new(0);
        if breaker.gate_at(now) == Gate::Allow {
            provider_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        assert_eq!(
            provider_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "open circuit must fail before provider work"
        );
        assert_eq!(
            breaker.gate_at(now + DEFAULT_OPEN_FOR - Duration::from_nanos(1)),
            Gate::Reject
        );

        let later = now + DEFAULT_OPEN_FOR;
        assert_eq!(breaker.gate_at(later), Gate::Allow);
        assert_eq!(breaker.snapshot().state, CreationCircuitState::HalfOpen);
        assert_eq!(breaker.gate_at(later), Gate::Reject);
        assert_eq!(breaker.snapshot().transition_count, 3);
        breaker.record_at(later, true);
        assert_eq!(breaker.snapshot().state, CreationCircuitState::Open);
        assert_eq!(breaker.snapshot().transition_count, 4);

        let retry = later + DEFAULT_OPEN_FOR;
        assert_eq!(breaker.gate_at(retry), Gate::Allow);
        breaker.record_at(retry, false);
        assert_eq!(breaker.snapshot().state, CreationCircuitState::Closed);
        assert_eq!(breaker.snapshot().consecutive_qualified_failures, 0);
        assert_eq!(breaker.snapshot().transition_count, 6);
    }

    #[test]
    fn classifier_counts_transport_429_and_every_5xx_but_not_business_or_local_failures() {
        assert!(qualified_http_status(429));
        assert!((500..=599).all(qualified_http_status));
        assert!(!qualified_http_status(422));

        for message in [
            "error sending request for url",
            "operation timed out",
            "502 Bad Gateway",
            "Too many requests",
            "Internal Server Error",
            "Service Unavailable",
            "HTTP 429 Too Many Requests",
            "HTTP status: 500",
            "status code 501",
            "HTTP 507 Insufficient Storage",
            "HTTP 599 provider extension",
        ] {
            assert!(
                is_qualified_boltz_failure(&boltz_client::error::Error::HTTP(message.into())),
                "did not qualify {message}"
            );
        }
        for message in [
            "amount 1000 below minimum 25000",
            "no invoice returned",
            "HTTP 422 amount is outside pair limits",
        ] {
            assert!(!is_qualified_boltz_failure(
                &boltz_client::error::Error::HTTP(message.into())
            ));
        }

        // Typed-status branch coverage is intentionally unit-level: pinned
        // c205 creation POSTs collapse non-success responses into `HTTP(body)`.
        let too_many = boltz_client::error::Error::HTTPStatusNotSuccess(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            serde_json::Value::String("sensitive provider body".into()),
        );
        let server = boltz_client::error::Error::HTTPStatusNotSuccess(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::Value::Null,
        );
        let business = boltz_client::error::Error::HTTPStatusNotSuccess(
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::Value::Null,
        );
        assert!(is_qualified_boltz_failure(&too_many));
        assert!(is_qualified_boltz_failure(&server));
        assert!(!is_qualified_boltz_failure(&business));
        assert!(!is_qualified_boltz_failure(
            &boltz_client::error::Error::Protocol(
                "local validation timed out after HTTP 503".into()
            )
        ));

        let breaker = BoltzBreaker::default();
        let now = t0();
        breaker.record_at(now, true);
        breaker.record_at(now, false); // reachable business response
        assert_eq!(breaker.snapshot().state, CreationCircuitState::Closed);
        assert_eq!(breaker.snapshot().consecutive_qualified_failures, 0);
    }

    #[test]
    fn operator_state_and_reason_labels_are_finite_and_redacted() {
        assert_eq!(
            CreationCircuitState::ALL.map(CreationCircuitState::as_str),
            ["closed", "suspect", "open", "half_open"]
        );
        assert_eq!(
            CreationCircuitTransitionReason::ALL.map(CreationCircuitTransitionReason::as_str),
            [
                "qualified_failure",
                "failure_threshold_reached",
                "cooldown_elapsed",
                "probe_succeeded",
                "probe_failed",
                "reachable",
            ]
        );
        assert_eq!(
            format!("{:?}", CreationCircuitSnapshot::default()),
            "CreationCircuitSnapshot { state: Closed, consecutive_qualified_failures: 0, transition_count: 0 }"
        );
    }
}
