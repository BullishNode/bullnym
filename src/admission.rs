//! In-process, rail-specific admission safety for new monetary obligations.
//!
//! This state is deliberately process-local. A new process starts closed and
//! must observe its own workers completing successful cycles before it can
//! expose new payer instructions. Existing instructions, status, webhooks,
//! claiming, reconciliation, and recovery do not consult this component.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FAILURES_TO_CLOSE: u8 = 3;
const SUCCESSES_TO_REOPEN: u8 = 2;
const STALE_CADENCES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rail {
    DirectLiquid,
    DirectBitcoin,
    LightningReverse,
    BitcoinChain,
}

impl Rail {
    pub const ALL: [Self; 4] = [
        Self::DirectLiquid,
        Self::DirectBitcoin,
        Self::LightningReverse,
        Self::BitcoinChain,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectLiquid => "direct_liquid",
            Self::DirectBitcoin => "direct_bitcoin",
            Self::LightningReverse => "lightning_reverse",
            Self::BitcoinChain => "bitcoin_chain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Worker {
    LiquidWatcher,
    BitcoinWatcher,
    ReverseClaimer,
    ChainClaimer,
    ReverseReconciler,
    ChainReconciler,
    AutomaticFallback,
    SettlementRepair,
    SlowRecovery,
}

impl Worker {
    pub const ALL: [Self; 9] = [
        Self::LiquidWatcher,
        Self::BitcoinWatcher,
        Self::ReverseClaimer,
        Self::ChainClaimer,
        Self::ReverseReconciler,
        Self::ChainReconciler,
        Self::AutomaticFallback,
        Self::SettlementRepair,
        Self::SlowRecovery,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LiquidWatcher => "liquid_watcher",
            Self::BitcoinWatcher => "bitcoin_watcher",
            Self::ReverseClaimer => "reverse_claimer",
            Self::ChainClaimer => "chain_claimer",
            Self::ReverseReconciler => "reverse_reconciler",
            Self::ChainReconciler => "chain_reconciler",
            Self::AutomaticFallback => "automatic_fallback",
            Self::SettlementRepair => "settlement_repair",
            Self::SlowRecovery => "slow_recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dependency {
    Workers,
    Schema,
    DirectLiquidBackend,
    DirectBitcoinWatcher,
    LiquidClaimClient,
    BitcoinEvidenceClient,
    BoltzClient,
    SwapKeyLineage,
    RecoveryJournal,
    ProviderRecoveryConsistency,
    FeePolicy,
    RecoveryCommitment,
    Worker(Worker),
}

impl Dependency {
    fn as_str(self) -> &'static str {
        match self {
            Self::Workers => "workers",
            Self::Schema => "schema",
            Self::DirectLiquidBackend => "direct_liquid_backend",
            Self::DirectBitcoinWatcher => "direct_bitcoin_watcher",
            Self::LiquidClaimClient => "liquid_claim_client",
            Self::BitcoinEvidenceClient => "bitcoin_evidence_client",
            Self::BoltzClient => "boltz_client",
            Self::SwapKeyLineage => "swap_key_lineage",
            Self::RecoveryJournal => "recovery_journal",
            Self::ProviderRecoveryConsistency => "provider_recovery_consistency",
            Self::FeePolicy => "fee_policy",
            Self::RecoveryCommitment => "recovery_commitment",
            Self::Worker(worker) => worker.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReasonCode {
    Disabled,
    Unavailable,
    Unsafe,
    StartupPending,
    TaskStopped,
    WorkerStale,
    WorkerDegraded,
    WorkerSuspect,
}

impl ReasonCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Unavailable => "unavailable",
            Self::Unsafe => "unsafe",
            Self::StartupPending => "startup_pending",
            Self::TaskStopped => "task_stopped",
            Self::WorkerStale => "worker_stale",
            Self::WorkerDegraded => "worker_degraded",
            Self::WorkerSuspect => "worker_suspect",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdmissionReason {
    pub dependency: Dependency,
    pub code: ReasonCode,
}

impl AdmissionReason {
    fn operator_code(self) -> String {
        format!("{}:{}", self.dependency.as_str(), self.code.as_str())
    }

    fn closes_admission(self) -> bool {
        self.code != ReasonCode::WorkerSuspect
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionState {
    Open,
    Suspect,
    Closed,
}

impl AdmissionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Suspect => "suspect",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDecision {
    pub rail: Rail,
    pub state: AdmissionState,
    pub reasons: Vec<AdmissionReason>,
}

impl AdmissionDecision {
    pub fn allowed(&self) -> bool {
        self.state != AdmissionState::Closed
    }
}

/// Private in-process operations view: #68's rail decisions plus the landed
/// provider-creation circuit. This type is intentionally not serializable and
/// is not part of public `/ready`; existing-obligation availability is not
/// derived from the creation circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationsSnapshot {
    pub money_admission: [AdmissionDecision; 4],
    pub provider_creation_circuit: crate::boltz_breaker::CreationCircuitSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionDenied {
    pub rail: Rail,
}

/// Result of applying one authenticated provider-recovery reconciliation to
/// new-chain admission. This is deliberately finite and identity-free: source
/// errors and recovery evidence remain at the reconciliation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRecoveryConsistencyTransitionV1 {
    Safe,
    Unsafe,
}

impl ProviderRecoveryConsistencyTransitionV1 {
    pub const fn safe(self) -> bool {
        matches!(self, Self::Safe)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FoundationFacts {
    pub workers_enabled: bool,
    pub schema_ready: bool,
    pub direct_liquid_backend_ready: bool,
    pub direct_bitcoin_watcher_ready: bool,
    pub liquid_claim_client_ready: bool,
    pub bitcoin_evidence_client_ready: bool,
    pub boltz_client_ready: bool,
    pub swap_key_lineage_safe: bool,
    pub recovery_journal_ready: bool,
    /// Exact startup agreement between the provider restore snapshot, the
    /// authenticated manifest witness, and local PostgreSQL recovery evidence.
    pub provider_recovery_consistent: bool,
    /// Remains false until issue #64 supplies a persisted live decision.
    pub fee_policy_ready: bool,
    /// Global capability only. Issue #84 must additionally bind the exact
    /// merchant-specific commitment before a chain offer is created.
    pub recovery_commitment_ready: bool,
}

#[derive(Debug, Clone)]
pub struct WorkerCadences {
    values: BTreeMap<Worker, Duration>,
}

impl WorkerCadences {
    pub fn from_runtime(
        reconciler: Duration,
        slow_recovery: Duration,
        liquid_watcher: Duration,
        bitcoin_watcher: Duration,
    ) -> Self {
        let mut values = BTreeMap::new();
        values.insert(Worker::LiquidWatcher, liquid_watcher);
        values.insert(Worker::BitcoinWatcher, bitcoin_watcher);
        values.insert(Worker::ReverseClaimer, Duration::from_secs(10));
        values.insert(Worker::ChainClaimer, Duration::from_secs(10));
        values.insert(Worker::ReverseReconciler, reconciler);
        values.insert(Worker::ChainReconciler, reconciler);
        values.insert(Worker::AutomaticFallback, reconciler);
        values.insert(Worker::SettlementRepair, reconciler);
        values.insert(Worker::SlowRecovery, slow_recovery);
        Self { values }
    }

    fn cadence(&self, worker: Worker) -> Duration {
        self.values
            .get(&worker)
            .copied()
            .unwrap_or(Duration::from_secs(1))
    }

    fn long_for_tests() -> Self {
        let day = Duration::from_secs(24 * 60 * 60);
        Self::from_runtime(day, day, day, day)
    }
}

#[derive(Debug, Clone, Default)]
struct WorkerState {
    started: bool,
    stopped: bool,
    startup_complete: bool,
    last_progress: Option<Instant>,
    consecutive_failures: u8,
    recovery_successes: u8,
    closed_by_failures: bool,
    closed_by_stale: bool,
}

#[derive(Debug)]
struct State {
    facts: FoundationFacts,
    workers: BTreeMap<Worker, WorkerState>,
    cadences: WorkerCadences,
    last_emitted: BTreeMap<Rail, AdmissionDecision>,
}

type Clock = dyn Fn() -> Instant + Send + Sync;

#[derive(Clone)]
pub struct MoneyAdmission {
    inner: Arc<Mutex<State>>,
    clock: Arc<Clock>,
}

impl MoneyAdmission {
    pub fn new(facts: FoundationFacts, cadences: WorkerCadences) -> Self {
        Self::with_clock(facts, cadences, Arc::new(Instant::now))
    }

    fn with_clock(facts: FoundationFacts, cadences: WorkerCadences, clock: Arc<Clock>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                facts,
                workers: Worker::ALL
                    .into_iter()
                    .map(|worker| (worker, WorkerState::default()))
                    .collect(),
                cadences,
                last_emitted: BTreeMap::new(),
            })),
            clock,
        }
    }

    /// Preserve the existing integration-test behavior while individual tests
    /// explicitly replace facts/reporters to exercise closed states.
    #[doc(hidden)]
    pub fn healthy_test_fixture() -> Self {
        let now = Instant::now();
        let admission = Self::new(
            FoundationFacts {
                workers_enabled: true,
                schema_ready: true,
                direct_liquid_backend_ready: true,
                direct_bitcoin_watcher_ready: true,
                liquid_claim_client_ready: true,
                bitcoin_evidence_client_ready: true,
                boltz_client_ready: true,
                swap_key_lineage_safe: true,
                recovery_journal_ready: true,
                provider_recovery_consistent: true,
                fee_policy_ready: true,
                recovery_commitment_ready: true,
            },
            WorkerCadences::long_for_tests(),
        );
        {
            let mut state = admission.inner.lock().expect("admission mutex poisoned");
            for worker in Worker::ALL {
                state.workers.insert(
                    worker,
                    WorkerState {
                        started: true,
                        stopped: false,
                        startup_complete: true,
                        last_progress: Some(now),
                        consecutive_failures: 0,
                        recovery_successes: 0,
                        closed_by_failures: false,
                        closed_by_stale: false,
                    },
                );
            }
        }
        admission
    }

    pub fn reporter(&self, worker: Worker) -> WorkerReporter {
        let reporter = WorkerReporter {
            admission: self.clone(),
            worker,
            active: true,
        };
        self.mutate(|state, now| {
            state.workers.insert(
                worker,
                WorkerState {
                    started: true,
                    stopped: false,
                    startup_complete: false,
                    last_progress: Some(now),
                    consecutive_failures: 0,
                    recovery_successes: 0,
                    closed_by_failures: false,
                    closed_by_stale: false,
                },
            );
        });
        reporter
    }

    /// Guard the periodic swap-key lineage monitor. If that task exits without
    /// first declaring intentional shutdown, swap admission fails closed.
    pub fn swap_key_lineage_reporter(&self) -> SwapKeyLineageReporter {
        SwapKeyLineageReporter {
            admission: self.clone(),
            active: true,
        }
    }

    pub fn decision(&self, rail: Rail) -> AdmissionDecision {
        let now = (self.clock)();
        let mut state = self.inner.lock().expect("admission mutex poisoned");
        refresh_stale_workers(&mut state, now);
        let decision = decide(&state, rail, now);
        emit_if_changed(&mut state, decision.clone());
        decision
    }

    /// Combine the existing #68 readiness view with the creation breaker's
    /// immutable snapshot for an in-process operations consumer. This is
    /// telemetry only: it does not add another admission decision or gate.
    pub fn operations_snapshot(
        &self,
        provider_creation_circuit: crate::boltz_breaker::CreationCircuitSnapshot,
    ) -> OperationsSnapshot {
        let now = (self.clock)();
        let mut state = self.inner.lock().expect("admission mutex poisoned");
        refresh_stale_workers(&mut state, now);
        let money_admission = Rail::ALL.map(|rail| decide(&state, rail, now));
        for decision in &money_admission {
            emit_if_changed(&mut state, decision.clone());
        }
        OperationsSnapshot {
            money_admission,
            provider_creation_circuit,
        }
    }

    pub fn enforce(&self, rail: Rail) -> Result<(), AdmissionDenied> {
        if self.decision(rail).allowed() {
            Ok(())
        } else {
            Err(AdmissionDenied { rail })
        }
    }

    pub fn set_workers_enabled(&self, ready: bool) {
        self.mutate(|state, _| state.facts.workers_enabled = ready);
    }

    pub fn set_schema_ready(&self, ready: bool) {
        self.mutate(|state, _| state.facts.schema_ready = ready);
    }

    pub fn set_swap_key_lineage_safe(&self, ready: bool) {
        self.mutate(|state, _| state.facts.swap_key_lineage_safe = ready);
    }

    pub fn set_fee_policy_ready(&self, ready: bool) {
        self.mutate(|state, _| state.facts.fee_policy_ready = ready);
    }

    pub fn set_recovery_commitment_ready(&self, ready: bool) {
        self.mutate(|state, _| state.facts.recovery_commitment_ready = ready);
    }

    /// Apply one complete authenticated provider/local/witness reconciliation
    /// to the provider-recovery admission fact.
    ///
    /// Callers cannot supply a bare boolean or a freely constructed report:
    /// the accepted fact has private fields and is produced only after the
    /// bounded startup reconciliation has validated all three recovery
    /// sources and the Bitcoin lockup witness. Any source failure or any
    /// classified disagreement closes the fact synchronously.
    pub fn apply_provider_recovery_reconciliation_v1(
        &self,
        result: Result<
            crate::startup_provider_reconciliation::StartupProviderReconciliationFactV1,
            crate::startup_provider_reconciliation::StartupProviderReconciliationErrorV1,
        >,
    ) -> ProviderRecoveryConsistencyTransitionV1 {
        let transition = match result {
            Ok(fact) if fact.exact_agreement() => ProviderRecoveryConsistencyTransitionV1::Safe,
            Ok(_) | Err(_) => ProviderRecoveryConsistencyTransitionV1::Unsafe,
        };
        self.mutate(|state, _| {
            state.facts.provider_recovery_consistent = transition.safe();
        });
        transition
    }

    fn mutate(&self, f: impl FnOnce(&mut State, Instant)) {
        let now = (self.clock)();
        let mut state = self.inner.lock().expect("admission mutex poisoned");
        // A late event must not erase evidence that the worker already missed
        // its deadline. Latch staleness against the previous progress time,
        // then apply the event. A late success therefore counts as only the
        // first of the two successes required to reopen.
        refresh_stale_workers(&mut state, now);
        f(&mut state, now);
        refresh_stale_workers(&mut state, now);
        for rail in Rail::ALL {
            let decision = decide(&state, rail, now);
            emit_if_changed(&mut state, decision);
        }
    }

    fn worker_progress(&self, worker: Worker) {
        self.mutate(|state, now| {
            if let Some(worker) = state.workers.get_mut(&worker) {
                worker.last_progress = Some(now);
            }
        });
    }

    fn worker_success(&self, worker: Worker) {
        self.mutate(|state, now| {
            let worker = state.workers.entry(worker).or_default();
            worker.started = true;
            worker.stopped = false;
            worker.startup_complete = true;
            worker.last_progress = Some(now);
            worker.consecutive_failures = 0;
            if worker.closed_by_failures || worker.closed_by_stale {
                worker.recovery_successes = worker.recovery_successes.saturating_add(1);
                if worker.recovery_successes >= SUCCESSES_TO_REOPEN {
                    worker.closed_by_failures = false;
                    worker.closed_by_stale = false;
                    worker.recovery_successes = 0;
                }
            } else {
                worker.recovery_successes = 0;
            }
        });
    }

    fn worker_failure(&self, worker: Worker) {
        self.mutate(|state, now| {
            let worker = state.workers.entry(worker).or_default();
            worker.started = true;
            worker.stopped = false;
            worker.last_progress = Some(now);
            worker.recovery_successes = 0;
            worker.consecutive_failures = worker.consecutive_failures.saturating_add(1);
            if worker.consecutive_failures >= FAILURES_TO_CLOSE {
                worker.closed_by_failures = true;
            }
        });
    }

    fn worker_stopped(&self, worker: Worker) {
        self.mutate(|state, _| {
            let worker = state.workers.entry(worker).or_default();
            worker.started = true;
            worker.stopped = true;
        });
    }
}

pub struct WorkerReporter {
    admission: MoneyAdmission,
    worker: Worker,
    active: bool,
}

impl WorkerReporter {
    pub fn progress(&self) {
        self.admission.worker_progress(self.worker);
    }

    pub fn cycle_succeeded(&self) {
        self.admission.worker_success(self.worker);
    }

    pub fn cycle_failed(&self) {
        self.admission.worker_failure(self.worker);
    }

    /// Suppress the task-stopped transition during whole-process cancellation.
    pub fn intentional_shutdown(&mut self) {
        self.active = false;
    }
}

impl Drop for WorkerReporter {
    fn drop(&mut self) {
        if self.active {
            self.admission.worker_stopped(self.worker);
        }
    }
}

pub struct SwapKeyLineageReporter {
    admission: MoneyAdmission,
    active: bool,
}

impl SwapKeyLineageReporter {
    pub fn observed_safe(&self, safe: bool) {
        self.admission.set_swap_key_lineage_safe(safe);
    }

    /// Suppress fail-closed reporting while the whole process is shutting down.
    pub fn intentional_shutdown(&mut self) {
        self.active = false;
    }
}

impl Drop for SwapKeyLineageReporter {
    fn drop(&mut self) {
        if self.active {
            self.admission.set_swap_key_lineage_safe(false);
        }
    }
}

fn required_workers(rail: Rail) -> &'static [Worker] {
    match rail {
        Rail::DirectLiquid => &[Worker::LiquidWatcher],
        Rail::DirectBitcoin => &[Worker::BitcoinWatcher],
        Rail::LightningReverse => &[
            Worker::ReverseClaimer,
            Worker::ReverseReconciler,
            Worker::SettlementRepair,
            Worker::SlowRecovery,
        ],
        Rail::BitcoinChain => &[
            Worker::ChainClaimer,
            Worker::ChainReconciler,
            Worker::AutomaticFallback,
            Worker::SettlementRepair,
            Worker::SlowRecovery,
        ],
    }
}

fn refresh_stale_workers(state: &mut State, now: Instant) {
    for worker in Worker::ALL {
        let stale_after = state
            .cadences
            .cadence(worker)
            .saturating_mul(STALE_CADENCES);
        let Some(worker_state) = state.workers.get_mut(&worker) else {
            continue;
        };
        if worker_state.started
            && worker_state.startup_complete
            && !worker_state.stopped
            && worker_state
                .last_progress
                .is_none_or(|last| now.saturating_duration_since(last) >= stale_after)
        {
            worker_state.closed_by_stale = true;
            worker_state.recovery_successes = 0;
        }
    }
}

fn decide(state: &State, rail: Rail, now: Instant) -> AdmissionDecision {
    let mut reasons = BTreeSet::new();
    let facts = state.facts;

    if !facts.workers_enabled {
        reasons.insert(AdmissionReason {
            dependency: Dependency::Workers,
            code: ReasonCode::Disabled,
        });
    }
    if !facts.schema_ready {
        reasons.insert(AdmissionReason {
            dependency: Dependency::Schema,
            code: ReasonCode::Unavailable,
        });
    }

    match rail {
        Rail::DirectLiquid => {
            add_unavailable(
                &mut reasons,
                facts.direct_liquid_backend_ready,
                Dependency::DirectLiquidBackend,
            );
        }
        Rail::DirectBitcoin => {
            add_unavailable(
                &mut reasons,
                facts.direct_bitcoin_watcher_ready,
                Dependency::DirectBitcoinWatcher,
            );
        }
        Rail::LightningReverse => {
            add_unavailable(
                &mut reasons,
                facts.liquid_claim_client_ready,
                Dependency::LiquidClaimClient,
            );
            add_unavailable(
                &mut reasons,
                facts.boltz_client_ready,
                Dependency::BoltzClient,
            );
            add_unsafe(
                &mut reasons,
                facts.swap_key_lineage_safe,
                Dependency::SwapKeyLineage,
            );
            add_unavailable(&mut reasons, facts.fee_policy_ready, Dependency::FeePolicy);
        }
        Rail::BitcoinChain => {
            add_unavailable(
                &mut reasons,
                facts.liquid_claim_client_ready,
                Dependency::LiquidClaimClient,
            );
            add_unavailable(
                &mut reasons,
                facts.bitcoin_evidence_client_ready,
                Dependency::BitcoinEvidenceClient,
            );
            add_unavailable(
                &mut reasons,
                facts.boltz_client_ready,
                Dependency::BoltzClient,
            );
            add_unsafe(
                &mut reasons,
                facts.swap_key_lineage_safe,
                Dependency::SwapKeyLineage,
            );
            add_unavailable(
                &mut reasons,
                facts.recovery_journal_ready,
                Dependency::RecoveryJournal,
            );
            add_unsafe(
                &mut reasons,
                facts.provider_recovery_consistent,
                Dependency::ProviderRecoveryConsistency,
            );
            add_unavailable(&mut reasons, facts.fee_policy_ready, Dependency::FeePolicy);
            add_unavailable(
                &mut reasons,
                facts.recovery_commitment_ready,
                Dependency::RecoveryCommitment,
            );
        }
    }

    for worker in required_workers(rail) {
        let dependency = Dependency::Worker(*worker);
        let worker_state = state.workers.get(worker);
        match worker_state {
            None | Some(WorkerState { started: false, .. }) => {
                reasons.insert(AdmissionReason {
                    dependency,
                    code: ReasonCode::StartupPending,
                });
            }
            Some(worker_state) if worker_state.stopped => {
                reasons.insert(AdmissionReason {
                    dependency,
                    code: ReasonCode::TaskStopped,
                });
            }
            Some(worker_state) if !worker_state.startup_complete => {
                reasons.insert(AdmissionReason {
                    dependency,
                    code: ReasonCode::StartupPending,
                });
            }
            Some(worker_state) => {
                let stale_after = state
                    .cadences
                    .cadence(*worker)
                    .saturating_mul(STALE_CADENCES);
                if worker_state.closed_by_stale
                    || worker_state
                        .last_progress
                        .is_none_or(|last| now.saturating_duration_since(last) >= stale_after)
                {
                    reasons.insert(AdmissionReason {
                        dependency,
                        code: ReasonCode::WorkerStale,
                    });
                } else if worker_state.closed_by_failures {
                    reasons.insert(AdmissionReason {
                        dependency,
                        code: ReasonCode::WorkerDegraded,
                    });
                } else if worker_state.consecutive_failures > 0 {
                    reasons.insert(AdmissionReason {
                        dependency,
                        code: ReasonCode::WorkerSuspect,
                    });
                }
            }
        }
    }

    let reasons: Vec<_> = reasons.into_iter().collect();
    let state = if reasons.iter().any(|reason| reason.closes_admission()) {
        AdmissionState::Closed
    } else if reasons.is_empty() {
        AdmissionState::Open
    } else {
        AdmissionState::Suspect
    };

    AdmissionDecision {
        rail,
        state,
        reasons,
    }
}

fn add_unavailable(reasons: &mut BTreeSet<AdmissionReason>, ready: bool, dependency: Dependency) {
    if !ready {
        reasons.insert(AdmissionReason {
            dependency,
            code: ReasonCode::Unavailable,
        });
    }
}

fn add_unsafe(reasons: &mut BTreeSet<AdmissionReason>, safe: bool, dependency: Dependency) {
    if !safe {
        reasons.insert(AdmissionReason {
            dependency,
            code: ReasonCode::Unsafe,
        });
    }
}

fn emit_if_changed(state: &mut State, decision: AdmissionDecision) {
    let changed = state.last_emitted.get(&decision.rail) != Some(&decision);
    if !changed {
        return;
    }
    let reason_codes: Vec<String> = decision
        .reasons
        .iter()
        .map(|reason| reason.operator_code())
        .collect();
    tracing::warn!(
        event = "money_admission_changed",
        rail = decision.rail.as_str(),
        state = decision.state.as_str(),
        reason_codes = ?reason_codes,
        "money admission state changed"
    );
    state.last_emitted.insert(decision.rail, decision);
}

/// Emit creation-circuit transitions using #68's private, low-cardinality
/// operations-telemetry convention. The finite transition type makes it
/// impossible to attach a URL, endpoint, provider body, payment identity, key,
/// or raw error to these fields.
pub(crate) fn emit_creation_circuit_transition(
    transition: crate::boltz_breaker::CreationCircuitTransition,
) {
    tracing::warn!(
        event = "money_admission_creation_circuit_changed",
        operation = "provider_offer_creation",
        previous_state = transition.from.as_str(),
        state = transition.to.as_str(),
        reason_code = transition.reason.as_str(),
        transition_count = transition.count,
        "provider creation circuit state changed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_facts() -> FoundationFacts {
        FoundationFacts {
            workers_enabled: true,
            schema_ready: true,
            direct_liquid_backend_ready: true,
            direct_bitcoin_watcher_ready: true,
            liquid_claim_client_ready: true,
            bitcoin_evidence_client_ready: true,
            boltz_client_ready: true,
            swap_key_lineage_safe: true,
            recovery_journal_ready: true,
            provider_recovery_consistent: true,
            fee_policy_ready: true,
            recovery_commitment_ready: true,
        }
    }

    fn clocked() -> (MoneyAdmission, Arc<Mutex<Instant>>) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let clock_now = now.clone();
        let admission = MoneyAdmission::with_clock(
            healthy_facts(),
            WorkerCadences::from_runtime(
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(10),
            ),
            Arc::new(move || *clock_now.lock().expect("clock mutex poisoned")),
        );
        (admission, now)
    }

    fn make_rail_healthy(admission: &MoneyAdmission, rail: Rail) -> Vec<WorkerReporter> {
        required_workers(rail)
            .iter()
            .map(|worker| {
                let reporter = admission.reporter(*worker);
                reporter.cycle_succeeded();
                reporter
            })
            .collect()
    }

    fn assert_foundation_matrix(
        change: impl FnOnce(&mut FoundationFacts),
        expected_closed: &[Rail],
    ) {
        let admission = MoneyAdmission::healthy_test_fixture();
        admission.mutate(|state, _| change(&mut state.facts));

        for rail in Rail::ALL {
            assert_eq!(
                !admission.decision(rail).allowed(),
                expected_closed.contains(&rail),
                "unexpected result for {rail:?}"
            );
        }
    }

    #[test]
    fn current_process_startup_success_is_required() {
        let (admission, _clock) = clocked();
        let decision = admission.decision(Rail::LightningReverse);
        assert_eq!(decision.state, AdmissionState::Closed);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::StartupPending));

        let _reporters = make_rail_healthy(&admission, Rail::LightningReverse);
        assert_eq!(
            admission.decision(Rail::LightningReverse).state,
            AdmissionState::Open
        );
    }

    #[test]
    fn prior_process_success_cannot_open_a_fresh_instance() {
        let (prior_process, _prior_clock) = clocked();
        let _prior_reporters = make_rail_healthy(&prior_process, Rail::LightningReverse);
        assert!(prior_process.decision(Rail::LightningReverse).allowed());

        let (fresh_process, _fresh_clock) = clocked();
        let decision = fresh_process.decision(Rail::LightningReverse);
        assert_eq!(decision.state, AdmissionState::Closed);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.code == ReasonCode::StartupPending));
    }

    #[test]
    fn dependency_matrix_is_rail_specific() {
        let admission = MoneyAdmission::healthy_test_fixture();
        admission.set_swap_key_lineage_safe(false);

        assert!(admission.decision(Rail::DirectLiquid).allowed());
        assert!(admission.decision(Rail::DirectBitcoin).allowed());
        assert!(!admission.decision(Rail::LightningReverse).allowed());
        assert!(!admission.decision(Rail::BitcoinChain).allowed());
    }

    #[test]
    fn every_foundation_fact_closes_exactly_its_dependent_rails() {
        assert_foundation_matrix(
            |facts| facts.workers_enabled = false,
            &[
                Rail::DirectLiquid,
                Rail::DirectBitcoin,
                Rail::LightningReverse,
                Rail::BitcoinChain,
            ],
        );
        assert_foundation_matrix(
            |facts| facts.schema_ready = false,
            &[
                Rail::DirectLiquid,
                Rail::DirectBitcoin,
                Rail::LightningReverse,
                Rail::BitcoinChain,
            ],
        );
        assert_foundation_matrix(
            |facts| facts.direct_liquid_backend_ready = false,
            &[Rail::DirectLiquid],
        );
        assert_foundation_matrix(
            |facts| facts.direct_bitcoin_watcher_ready = false,
            &[Rail::DirectBitcoin],
        );
        assert_foundation_matrix(
            |facts| facts.liquid_claim_client_ready = false,
            &[Rail::LightningReverse, Rail::BitcoinChain],
        );
        assert_foundation_matrix(
            |facts| facts.bitcoin_evidence_client_ready = false,
            &[Rail::BitcoinChain],
        );
        assert_foundation_matrix(
            |facts| facts.boltz_client_ready = false,
            &[Rail::LightningReverse, Rail::BitcoinChain],
        );
        assert_foundation_matrix(
            |facts| facts.swap_key_lineage_safe = false,
            &[Rail::LightningReverse, Rail::BitcoinChain],
        );
        assert_foundation_matrix(
            |facts| facts.recovery_journal_ready = false,
            &[Rail::BitcoinChain],
        );
        assert_foundation_matrix(
            |facts| facts.provider_recovery_consistent = false,
            &[Rail::BitcoinChain],
        );
        assert_foundation_matrix(
            |facts| facts.fee_policy_ready = false,
            &[Rail::LightningReverse, Rail::BitcoinChain],
        );
        assert_foundation_matrix(
            |facts| facts.recovery_commitment_ready = false,
            &[Rail::BitcoinChain],
        );
    }

    #[test]
    fn workers_disabled_closes_every_money_rail() {
        let admission = MoneyAdmission::healthy_test_fixture();
        admission.set_workers_enabled(false);
        for rail in Rail::ALL {
            assert!(!admission.decision(rail).allowed(), "{rail:?} stayed open");
        }
    }

    #[test]
    fn fee_and_recovery_facts_fail_closed_without_invention() {
        let admission = MoneyAdmission::healthy_test_fixture();
        admission.set_fee_policy_ready(false);
        admission.set_recovery_commitment_ready(false);

        assert!(admission.decision(Rail::DirectLiquid).allowed());
        assert!(admission.decision(Rail::DirectBitcoin).allowed());
        assert!(!admission.decision(Rail::LightningReverse).allowed());
        let chain = admission.decision(Rail::BitcoinChain);
        assert!(!chain.allowed());
        assert!(chain.reasons.iter().any(|reason| {
            reason.dependency == Dependency::RecoveryCommitment
                && reason.code == ReasonCode::Unavailable
        }));
    }

    #[test]
    fn provider_recovery_disagreement_closes_only_new_chain_swaps() {
        let mut facts = healthy_facts();
        facts.provider_recovery_consistent = false;
        let admission = MoneyAdmission::new(facts, WorkerCadences::long_for_tests());
        let _reporters = make_rail_healthy(&admission, Rail::BitcoinChain);
        let _reverse_reporters = make_rail_healthy(&admission, Rail::LightningReverse);
        let _liquid_reporters = make_rail_healthy(&admission, Rail::DirectLiquid);
        let _bitcoin_reporters = make_rail_healthy(&admission, Rail::DirectBitcoin);

        assert!(admission.decision(Rail::DirectLiquid).allowed());
        assert!(admission.decision(Rail::DirectBitcoin).allowed());
        assert!(admission.decision(Rail::LightningReverse).allowed());
        let chain = admission.decision(Rail::BitcoinChain);
        assert!(!chain.allowed());
        assert!(chain.reasons.iter().any(|reason| {
            reason.dependency == Dependency::ProviderRecoveryConsistency
                && reason.code == ReasonCode::Unsafe
        }));
    }

    #[test]
    fn transient_failures_close_at_three_and_reopen_after_two_successes() {
        let admission = MoneyAdmission::healthy_test_fixture();
        let reporter = admission.reporter(Worker::ReverseReconciler);
        reporter.cycle_succeeded();

        reporter.cycle_failed();
        reporter.cycle_failed();
        assert_eq!(
            admission.decision(Rail::LightningReverse).state,
            AdmissionState::Suspect
        );
        reporter.cycle_failed();
        assert_eq!(
            admission.decision(Rail::LightningReverse).state,
            AdmissionState::Closed
        );

        reporter.cycle_succeeded();
        assert_eq!(
            admission.decision(Rail::LightningReverse).state,
            AdmissionState::Closed
        );
        reporter.cycle_succeeded();
        assert_eq!(
            admission.decision(Rail::LightningReverse).state,
            AdmissionState::Open
        );
    }

    #[test]
    fn worker_stales_at_exactly_three_cadences() {
        let (admission, now) = clocked();
        let _reporters = make_rail_healthy(&admission, Rail::DirectLiquid);
        assert!(admission.decision(Rail::DirectLiquid).allowed());

        *now.lock().expect("clock mutex poisoned") += Duration::from_secs(30);
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn first_late_progress_latches_staleness_without_counting_as_recovery() {
        let (admission, now) = clocked();
        let reporters = make_rail_healthy(&admission, Rail::DirectLiquid);

        *now.lock().expect("clock mutex poisoned") += Duration::from_secs(30);
        reporters[0].progress();
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
        reporters[0].cycle_succeeded();
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
        reporters[0].cycle_succeeded();
        assert!(admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn first_late_success_latches_staleness_and_counts_as_one_recovery() {
        let (admission, now) = clocked();
        let reporters = make_rail_healthy(&admission, Rail::DirectLiquid);

        *now.lock().expect("clock mutex poisoned") += Duration::from_secs(30);
        reporters[0].cycle_succeeded();
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
        reporters[0].cycle_succeeded();
        assert!(admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn first_late_failure_latches_staleness_before_failure_hysteresis() {
        let (admission, now) = clocked();
        let reporters = make_rail_healthy(&admission, Rail::DirectLiquid);

        *now.lock().expect("clock mutex poisoned") += Duration::from_secs(30);
        reporters[0].cycle_failed();
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
        reporters[0].cycle_succeeded();
        assert!(!admission.decision(Rail::DirectLiquid).allowed());
        reporters[0].cycle_succeeded();
        assert!(admission.decision(Rail::DirectLiquid).allowed());
    }

    #[test]
    fn unexpected_task_drop_closes_immediately() {
        let admission = MoneyAdmission::healthy_test_fixture();
        let reporter = admission.reporter(Worker::BitcoinWatcher);
        reporter.cycle_succeeded();
        assert!(admission.decision(Rail::DirectBitcoin).allowed());
        drop(reporter);
        assert!(!admission.decision(Rail::DirectBitcoin).allowed());
    }

    #[tokio::test]
    async fn panicking_tokio_task_closes_its_worker_immediately() {
        let admission = MoneyAdmission::healthy_test_fixture();
        let reporter = admission.reporter(Worker::BitcoinWatcher);
        reporter.cycle_succeeded();
        assert!(admission.decision(Rail::DirectBitcoin).allowed());

        let task = tokio::spawn(async move {
            let _reporter = reporter;
            panic!("scripted worker panic");
        });
        let error = task.await.expect_err("worker task must panic");
        assert!(error.is_panic());
        assert!(!admission.decision(Rail::DirectBitcoin).allowed());
    }

    #[test]
    fn lineage_reporter_fails_swap_rails_closed_on_unexpected_drop() {
        let admission = MoneyAdmission::healthy_test_fixture();
        drop(admission.swap_key_lineage_reporter());

        assert!(admission.decision(Rail::DirectLiquid).allowed());
        assert!(admission.decision(Rail::DirectBitcoin).allowed());
        assert!(!admission.decision(Rail::LightningReverse).allowed());
        assert!(!admission.decision(Rail::BitcoinChain).allowed());
    }

    #[test]
    fn lineage_reporter_suppresses_drop_during_intentional_shutdown() {
        let admission = MoneyAdmission::healthy_test_fixture();
        let mut reporter = admission.swap_key_lineage_reporter();
        reporter.intentional_shutdown();
        drop(reporter);

        assert!(admission.decision(Rail::LightningReverse).allowed());
        assert!(admission.decision(Rail::BitcoinChain).allowed());
    }

    #[test]
    fn worker_failure_closes_only_dependent_rails() {
        let admission = MoneyAdmission::healthy_test_fixture();
        let reverse = admission.reporter(Worker::ReverseReconciler);
        reverse.cycle_succeeded();
        drop(reverse);

        assert!(!admission.decision(Rail::LightningReverse).allowed());
        assert!(admission.decision(Rail::BitcoinChain).allowed());
        assert!(admission.decision(Rail::DirectLiquid).allowed());
        assert!(admission.decision(Rail::DirectBitcoin).allowed());
    }

    #[test]
    fn every_stopped_worker_closes_exactly_its_dependent_rails() {
        for worker in Worker::ALL {
            let admission = MoneyAdmission::healthy_test_fixture();
            let reporter = admission.reporter(worker);
            reporter.cycle_succeeded();
            drop(reporter);

            for rail in Rail::ALL {
                assert_eq!(
                    !admission.decision(rail).allowed(),
                    required_workers(rail).contains(&worker),
                    "unexpected rail result for stopped {worker:?} on {rail:?}"
                );
            }
        }
    }

    #[test]
    fn reasons_are_stable_sorted_and_deduplicated() {
        let (admission, _clock) = clocked();
        admission.set_workers_enabled(false);
        admission.set_schema_ready(false);
        let decision = admission.decision(Rail::BitcoinChain);
        let mut sorted = decision.reasons.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(decision.reasons, sorted);
    }

    #[test]
    fn operations_snapshot_observes_creation_circuit_without_becoming_a_gate() {
        let admission = MoneyAdmission::healthy_test_fixture();
        let before = Rail::ALL.map(|rail| admission.decision(rail));
        let breaker = crate::boltz_breaker::BoltzBreaker::default();
        for _ in 0..crate::boltz_breaker::DEFAULT_FAILURE_THRESHOLD {
            breaker.record(true);
        }

        let operations = admission.operations_snapshot(breaker.snapshot());
        assert_eq!(operations.money_admission, before);
        assert!(operations
            .money_admission
            .iter()
            .all(AdmissionDecision::allowed));
        assert_eq!(
            operations.provider_creation_circuit.state,
            crate::boltz_breaker::CreationCircuitState::Open
        );
        assert_eq!(operations.provider_creation_circuit.transition_count, 2);
    }
}
