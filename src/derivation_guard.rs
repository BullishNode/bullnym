//! Startup detection of a rewound swap-key sequence.
//!
//! Swap keys are derived at monotonically increasing indices handed out by
//! `swap_key_seq`. If a database backup is restored that predates some already
//! issued indices, `nextval` will re-hand-out indices that were previously used
//! to sign live swaps, silently reusing key material for new swaps. Migration
//! 050 reserves each key in a durable global registry before the provider call,
//! including keys whose provider request or swap-row write later fails. At
//! startup and every 30 seconds, admission compares the value the sequence
//! would issue NEXT against both those active-generation allocations and
//! migration-044 legacy evidence, including the immutable high-water ledger
//! that survives signed user purge. A next value at or below any maximum closes
//! new swap admission while existing-obligation recovery remains live.

use crate::db;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug)]
struct DerivationGuardIntegrationTestHookState {
    fingerprint: String,
    key_epoch: i32,
    derivation_scheme_version: i32,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

static DERIVATION_GUARD_INTEGRATION_TEST_HOOK_ACTIVE: AtomicBool = AtomicBool::new(false);
static DERIVATION_GUARD_INTEGRATION_TEST_HOOK: OnceLock<
    Mutex<Option<Arc<DerivationGuardIntegrationTestHookState>>>,
> = OnceLock::new();

fn derivation_guard_integration_test_hook_slot(
) -> &'static Mutex<Option<Arc<DerivationGuardIntegrationTestHookState>>> {
    DERIVATION_GUARD_INTEGRATION_TEST_HOOK.get_or_init(|| Mutex::new(None))
}

/// One-shot synchronization seam proving sequence-read ordering under a real
/// concurrent allocation. It is inert unless an integration test installs it
/// for the exact root/epoch/scheme tuple being checked.
#[doc(hidden)]
pub struct DerivationGuardIntegrationTestHook {
    state: Arc<DerivationGuardIntegrationTestHookState>,
}

impl DerivationGuardIntegrationTestHook {
    pub async fn wait_until_reached(&self) {
        self.state.reached.notified().await;
    }

    pub fn release(&self) {
        self.state.release.notify_one();
    }
}

impl Drop for DerivationGuardIntegrationTestHook {
    fn drop(&mut self) {
        self.state.release.notify_one();
        let mut slot = derivation_guard_integration_test_hook_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.state))
        {
            slot.take();
            DERIVATION_GUARD_INTEGRATION_TEST_HOOK_ACTIVE.store(false, Ordering::Release);
        }
    }
}

#[doc(hidden)]
pub fn install_derivation_guard_integration_test_hook(
    fingerprint: &str,
    key_epoch: i32,
    derivation_scheme_version: i32,
) -> DerivationGuardIntegrationTestHook {
    let state = Arc::new(DerivationGuardIntegrationTestHookState {
        fingerprint: fingerprint.to_string(),
        key_epoch,
        derivation_scheme_version,
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let mut slot = derivation_guard_integration_test_hook_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        slot.is_none(),
        "a derivation-guard integration-test hook is already installed"
    );
    *slot = Some(state.clone());
    DERIVATION_GUARD_INTEGRATION_TEST_HOOK_ACTIVE.store(true, Ordering::Release);
    DerivationGuardIntegrationTestHook { state }
}

async fn pause_before_sequence_read_for_integration_test(
    fingerprint: &str,
    key_epoch: i32,
    derivation_scheme_version: i32,
) {
    if !DERIVATION_GUARD_INTEGRATION_TEST_HOOK_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let state = {
        let mut slot = derivation_guard_integration_test_hook_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !slot.as_ref().is_some_and(|installed| {
            installed.fingerprint == fingerprint
                && installed.key_epoch == key_epoch
                && installed.derivation_scheme_version == derivation_scheme_version
        }) {
            return;
        }
        DERIVATION_GUARD_INTEGRATION_TEST_HOOK_ACTIVE.store(false, Ordering::Release);
        slot.take()
    };
    if let Some(state) = state {
        state.reached.notify_one();
        state.release.notified().await;
    }
}

/// True when the NEXT value the sequence will issue is at or below the highest
/// index already persisted for the seed — i.e. the next allocation would reuse
/// an index. The comparand must be the next-to-issue value, NOT the raw
/// `last_value`: after normal operation `last_value` equals the most recently
/// persisted index (nextval returns the value that becomes `last_value`), so
/// comparing `last_value` would flag every healthy restart.
/// `max_persisted == None` (no post-migration rows yet) is always safe: a fresh
/// deploy or a pre-migration history has nothing to collide with.
///
/// Pure so the boundary condition is unit-testable without a database.
pub fn rollback_detected(seq_next_value: i64, max_persisted_index: Option<i64>) -> bool {
    match max_persisted_index {
        Some(max) => seq_next_value <= max,
        None => false,
    }
}

/// Query the sequence's next-to-issue value, the active root/epoch/scheme's
/// durable allocation maximum, the live legacy swap-row maximum, and the
/// purge-stable migration-044 high-water maximum for this root, then evaluate
/// [`rollback_detected`].
///
/// Errors (including missing migration-050 allocation metadata)
/// are surfaced to the caller, which treats them as non-fatal: readiness gating
/// already blocks traffic until the schema marker is present.
pub async fn check_rollback(
    pool: &PgPool,
    fingerprint: &str,
    key_epoch: i32,
    derivation_scheme_version: i32,
) -> Result<bool, sqlx::Error> {
    // Allocation consumes the sequence before it commits either the registry
    // row or a legacy swap row. Read every monotonic durable maximum first and
    // the sequence last: if allocation races this check, the final sequence
    // read is therefore already ahead of the newly visible maximum. Reversing
    // this order can compare a stale next value N with a concurrently committed
    // allocation N and falsely close admission.
    let reverse_max = db::max_persisted_reverse_key_index(pool, fingerprint).await?;
    let chain_max = db::max_persisted_chain_key_index(pool, fingerprint).await?;
    let allocation_max =
        db::max_reserved_swap_key_index(pool, fingerprint, key_epoch, derivation_scheme_version)
            .await?;
    let legacy_high_water = db::max_legacy_swap_key_index(pool, fingerprint).await?;
    pause_before_sequence_read_for_integration_test(
        fingerprint,
        key_epoch,
        derivation_scheme_version,
    )
    .await;
    let seq_next_value = db::swap_key_seq_next_value(pool).await?;
    let max_persisted = [reverse_max, chain_max, allocation_max, legacy_high_water]
        .into_iter()
        .flatten()
        .max();
    Ok(rollback_detected(seq_next_value, max_persisted))
}

#[cfg(test)]
mod tests {
    use super::rollback_detected;

    #[test]
    fn no_persisted_rows_is_never_a_rollback() {
        // Fresh deploy: sequence has advanced but nothing recorded yet.
        assert!(!rollback_detected(100, None));
        assert!(!rollback_detected(0, None));
    }

    #[test]
    fn healthy_steady_state_restart_is_safe() {
        // The last issued index (150) was persisted, so last_value = 150 with
        // is_called = true and the NEXT issue is 151. A restart in this state
        // must NOT alert — this is the exact false positive the next-to-issue
        // comparison exists to avoid.
        assert!(!rollback_detected(151, Some(150)));
        assert!(!rollback_detected(1_000, Some(100)));
    }

    #[test]
    fn next_issue_at_or_behind_max_is_a_rollback() {
        // Restore rewound the sequence so its next issue would repeat an
        // already-persisted index: collision.
        assert!(rollback_detected(150, Some(150)));
        assert!(rollback_detected(100, Some(149)));
        assert!(rollback_detected(0, Some(0)));
    }
}
