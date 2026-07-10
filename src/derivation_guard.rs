//! Startup detection of a rewound swap-key sequence.
//!
//! Swap keys are derived at monotonically increasing indices handed out by
//! `swap_key_seq`. If a database backup is restored that predates some already
//! issued indices, `nextval` will re-hand-out indices that were previously used
//! to sign live swaps, silently reusing key material for new swaps. Each swap
//! now records `(root_fingerprint, index)` (migration 044); at startup we
//! compare the value the sequence would issue NEXT against the maximum index
//! we have persisted for this seed. If the next issue would not exceed that
//! maximum, the next allocation would collide with an existing index — a
//! rewind. (Note: in healthy steady state `last_value` EQUALS the max persisted
//! index, so the comparison is on next-to-issue, never on raw `last_value`.)
//!
//! This phase only *detects and alerts* (loud `ERROR` log + `/version`
//! surfacing). Fail-closed admission gating of the swap-creation path is a
//! deliberate follow-up: it sits on the payment hot path and warrants live
//! validation that this deployment cannot yet perform.

use crate::db;
use sqlx::PgPool;

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

/// Query the sequence's next-to-issue value and the max persisted index across
/// both swap tables for `fingerprint`, then evaluate [`rollback_detected`].
///
/// Errors (including "column does not exist" before migration 044 is applied)
/// are surfaced to the caller, which treats them as non-fatal: readiness gating
/// already blocks traffic until the schema marker is present.
pub async fn check_rollback(pool: &PgPool, fingerprint: &str) -> Result<bool, sqlx::Error> {
    let seq_next_value = db::swap_key_seq_next_value(pool).await?;
    let reverse_max = db::max_persisted_reverse_key_index(pool, fingerprint).await?;
    let chain_max = db::max_persisted_chain_key_index(pool, fingerprint).await?;
    let max_persisted = match (reverse_max, chain_max) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
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
