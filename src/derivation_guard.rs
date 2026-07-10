//! Startup detection of a rewound swap-key sequence.
//!
//! Swap keys are derived at monotonically increasing indices handed out by
//! `swap_key_seq`. If a database backup is restored that predates some already
//! issued indices, `nextval` will re-hand-out indices that were previously used
//! to sign live swaps, silently reusing key material for new swaps. Each swap
//! now records `(root_fingerprint, index)` (migration 044); at startup we
//! compare the sequence's high-water mark against the maximum index we have
//! persisted for this seed. If the sequence is not strictly ahead, the next
//! allocation would collide with an existing index — a rewind.
//!
//! This phase only *detects and alerts* (loud `ERROR` log + `/version`
//! surfacing). Fail-closed admission gating of the swap-creation path is a
//! deliberate follow-up: it sits on the payment hot path and warrants live
//! validation that this deployment cannot yet perform.

use crate::db;
use sqlx::PgPool;

/// True when the sequence high-water mark is not strictly ahead of the highest
/// index already persisted for the seed — i.e. the next allocation would reuse
/// an index. `max_persisted == None` (no post-migration rows yet) is always
/// safe: a fresh deploy or a pre-migration history has nothing to collide with.
///
/// Pure so the boundary condition is unit-testable without a database.
pub fn rollback_detected(seq_last_value: i64, max_persisted_index: Option<i64>) -> bool {
    match max_persisted_index {
        Some(max) => seq_last_value <= max,
        None => false,
    }
}

/// Query the sequence and the max persisted index across both swap tables for
/// `fingerprint`, then evaluate [`rollback_detected`].
///
/// Errors (including "column does not exist" before migration 044 is applied)
/// are surfaced to the caller, which treats them as non-fatal: readiness gating
/// already blocks traffic until the schema marker is present.
pub async fn check_rollback(pool: &PgPool, fingerprint: &str) -> Result<bool, sqlx::Error> {
    let seq_last_value = db::swap_key_seq_last_value(pool).await?;
    let reverse_max = db::max_persisted_reverse_key_index(pool, fingerprint).await?;
    let chain_max = db::max_persisted_chain_key_index(pool, fingerprint).await?;
    let max_persisted = match (reverse_max, chain_max) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    Ok(rollback_detected(seq_last_value, max_persisted))
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
    fn sequence_ahead_of_max_is_safe() {
        // Normal steady state: nextval always allocated before use, so the
        // sequence's last_value is strictly greater than any persisted index.
        assert!(!rollback_detected(150, Some(149)));
        assert!(!rollback_detected(1_000, Some(100)));
    }

    #[test]
    fn sequence_at_or_behind_max_is_a_rollback() {
        // Restore rewound the sequence to/behind an already-issued index: the
        // next allocation would collide.
        assert!(rollback_detected(149, Some(149)));
        assert!(rollback_detected(100, Some(149)));
        assert!(rollback_detected(0, Some(0)));
    }
}
