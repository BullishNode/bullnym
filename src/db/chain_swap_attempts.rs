use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::fee_decision_record::FeeDecisionRecord;

/// Complete previous-output evidence for one Bitcoin recovery input.  Keeping
/// the amount and script with the outpoint makes the journal independently
/// auditable and supplies the exact material a later explicit replacement
/// implementation would need without rescanning an already-spent UTXO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySourcePrevout {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug)]
pub struct NewBitcoinRecoveryAttempt<'a> {
    pub chain_swap_id: Uuid,
    pub raw_tx_hex: &'a str,
    pub txid: &'a str,
    pub source_prevouts: &'a [RecoverySourcePrevout],
    pub destination_address: &'a str,
    pub destination_script_hex: &'a str,
    pub destination_vout: i32,
    pub destination_amount_sat: i64,
    pub fee_amount_sat: i64,
    pub fee_rate_sat_vb: f64,
    pub fee_decision: &'a FeeDecisionRecord,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChainSwapTxAttempt {
    pub id: Uuid,
    pub chain_swap_id: Uuid,
    pub purpose: String,
    pub raw_tx_hex: String,
    pub txid: String,
    pub source_prevouts: sqlx::types::Json<Vec<RecoverySourcePrevout>>,
    pub destination_address: String,
    pub destination_script_hex: String,
    pub destination_vout: i32,
    pub destination_amount_sat: i64,
    pub fee_amount_sat: i64,
    pub fee_rate_sat_vb: f64,
    pub fee_decision_purpose: String,
    pub fee_decision_rail: String,
    pub fee_decision_target: String,
    pub fee_decision_source: String,
    pub fee_decision_rate_sat_vb: f64,
    pub fee_decision_quoted_at_unix: i64,
    pub fee_decision_evaluated_at_unix: i64,
    pub fee_decision_freshness_age_secs: i64,
    pub fee_decision_freshness_max_age_secs: i64,
    pub fee_decision_provenance: String,
    pub fee_decision_policy_floor_sat_vb: f64,
    pub fee_decision_policy_cap_sat_vb: f64,
    pub fee_decision_policy_version: String,
    pub status: String,
    pub broadcast_attempts: i32,
    pub last_broadcast_result: Option<String>,
    pub integrity_reason: Option<String>,
    pub constructed_at_unix: i64,
    pub first_broadcast_attempt_at_unix: Option<i64>,
    pub last_broadcast_attempt_at_unix: Option<i64>,
    pub broadcast_at_unix: Option<i64>,
    pub confirmed_at_unix: Option<i64>,
    pub finalized_at_unix: Option<i64>,
    pub integrity_hold_at_unix: Option<i64>,
    pub updated_at_unix: i64,
}

const ATTEMPT_COLUMNS: &str = "id, chain_swap_id, purpose, raw_tx_hex, txid, source_prevouts, \
     destination_address, destination_script_hex, destination_vout, \
     destination_amount_sat, fee_amount_sat, fee_rate_sat_vb, \
     fee_decision_purpose, fee_decision_rail, fee_decision_target, \
     fee_decision_source, fee_decision_rate_sat_vb, \
     fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
     fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
     fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
     fee_decision_policy_cap_sat_vb, fee_decision_policy_version, status, \
     broadcast_attempts, last_broadcast_result, integrity_reason, \
     EXTRACT(EPOCH FROM constructed_at)::BIGINT AS constructed_at_unix, \
     EXTRACT(EPOCH FROM first_broadcast_attempt_at)::BIGINT \
         AS first_broadcast_attempt_at_unix, \
     EXTRACT(EPOCH FROM last_broadcast_attempt_at)::BIGINT \
         AS last_broadcast_attempt_at_unix, \
     EXTRACT(EPOCH FROM broadcast_at)::BIGINT AS broadcast_at_unix, \
     EXTRACT(EPOCH FROM confirmed_at)::BIGINT AS confirmed_at_unix, \
     EXTRACT(EPOCH FROM finalized_at)::BIGINT AS finalized_at_unix, \
     EXTRACT(EPOCH FROM integrity_hold_at)::BIGINT AS integrity_hold_at_unix, \
     EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at_unix";

/// Insert the immutable recovery intent inside the caller's advisory-locked
/// transaction.  A unique `(chain_swap_id, purpose)` constraint makes a second
/// set of bytes fail closed.
pub async fn insert_bitcoin_recovery_attempt(
    conn: &mut PgConnection,
    attempt: &NewBitcoinRecoveryAttempt<'_>,
) -> Result<ChainSwapTxAttempt, sqlx::Error> {
    let source_prevouts = sqlx::types::Json(attempt.source_prevouts);
    let decision = attempt.fee_decision;
    let quoted_at = checked_fee_unix("fee_decision_quoted_at_unix", decision.quoted_at_unix())?;
    let evaluated_at = checked_fee_unix(
        "fee_decision_evaluated_at_unix",
        decision.evaluated_at_unix(),
    )?;
    let freshness_age = checked_fee_unix(
        "fee_decision_freshness_age_secs",
        decision.freshness_age_secs(),
    )?;
    let freshness_max_age = checked_fee_unix(
        "fee_decision_freshness_max_age_secs",
        decision.freshness_max_age_secs(),
    )?;
    sqlx::query_as::<_, ChainSwapTxAttempt>(&format!(
        "INSERT INTO chain_swap_tx_attempts \
             (chain_swap_id, purpose, raw_tx_hex, txid, source_prevouts, \
              destination_address, destination_script_hex, destination_vout, \
              destination_amount_sat, fee_amount_sat, fee_rate_sat_vb, \
              fee_decision_purpose, fee_decision_rail, fee_decision_target, \
              fee_decision_source, fee_decision_rate_sat_vb, \
              fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
              fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
              fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
              fee_decision_policy_cap_sat_vb, fee_decision_policy_version) \
         VALUES ($1, 'btc_recovery', $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                 $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23) \
         RETURNING {ATTEMPT_COLUMNS}"
    ))
    .bind(attempt.chain_swap_id)
    .bind(attempt.raw_tx_hex)
    .bind(attempt.txid)
    .bind(source_prevouts)
    .bind(attempt.destination_address)
    .bind(attempt.destination_script_hex)
    .bind(attempt.destination_vout)
    .bind(attempt.destination_amount_sat)
    .bind(attempt.fee_amount_sat)
    .bind(attempt.fee_rate_sat_vb)
    .bind(decision.purpose().as_str())
    .bind(decision.rail().as_str())
    .bind(decision.target().as_str())
    .bind(decision.source().as_str())
    .bind(decision.rate().as_f64())
    .bind(quoted_at)
    .bind(evaluated_at)
    .bind(freshness_age)
    .bind(freshness_max_age)
    .bind(decision.provenance_for_persistence())
    .bind(decision.policy_floor().as_f64())
    .bind(decision.policy_cap().as_f64())
    .bind(decision.policy_version())
    .fetch_one(conn)
    .await
}

fn checked_fee_unix(field: &'static str, value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value)
        .map_err(|_| sqlx::Error::Protocol(format!("{field} exceeds BIGINT storage")))
}

pub async fn get_bitcoin_recovery_attempt(
    pool: &PgPool,
    chain_swap_id: Uuid,
) -> Result<Option<ChainSwapTxAttempt>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapTxAttempt>(&format!(
        "SELECT {ATTEMPT_COLUMNS} \
           FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND purpose = 'btc_recovery'"
    ))
    .bind(chain_swap_id)
    .fetch_optional(pool)
    .await
}

pub async fn get_bitcoin_recovery_attempt_for_update(
    conn: &mut PgConnection,
    chain_swap_id: Uuid,
) -> Result<Option<ChainSwapTxAttempt>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapTxAttempt>(&format!(
        "SELECT {ATTEMPT_COLUMNS} \
           FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND purpose = 'btc_recovery' \
          FOR UPDATE"
    ))
    .bind(chain_swap_id)
    .fetch_optional(conn)
    .await
}

/// Durably record that a broadcast call is about to happen.  A process death
/// after this commit is deliberately ambiguous, and restart reconciliation
/// must inspect the expected txid/source outpoints before replaying the same
/// bytes.
pub async fn mark_recovery_broadcast_started(
    pool: &PgPool,
    attempt_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let chain_swap_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE chain_swap_tx_attempts \
            SET broadcast_attempts = broadcast_attempts + 1, \
                first_broadcast_attempt_at = \
                    COALESCE(first_broadcast_attempt_at, NOW()), \
                last_broadcast_attempt_at = NOW(), \
                last_broadcast_result = 'attempt started', \
                updated_at = NOW() \
          WHERE id = $1 \
            AND status IN ('constructed', 'broadcast_ambiguous') \
          RETURNING chain_swap_id",
    )
    .bind(attempt_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(chain_swap_id) = chain_swap_id {
        // The stale-recovery worker keys off the parent timestamp. Delay its
        // next pass after every real broadcast call instead of hot-looping an
        // old `refunding` row once it crosses the age threshold.
        sqlx::query("UPDATE chain_swap_records SET updated_at = NOW() WHERE id = $1")
            .bind(chain_swap_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(1)
    } else {
        tx.rollback().await?;
        Ok(0)
    }
}

pub async fn mark_recovery_broadcast_ambiguous(
    pool: &PgPool,
    attempt_id: Uuid,
    result: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_tx_attempts \
            SET status = 'broadcast_ambiguous', \
                last_broadcast_result = $2, \
                updated_at = NOW() \
          WHERE id = $1 \
            AND status IN ('constructed', 'broadcast_ambiguous')",
    )
    .bind(attempt_id)
    .bind(result)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn mark_recovery_integrity_hold(
    pool: &PgPool,
    attempt_id: Uuid,
    reason: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_tx_attempts \
            SET status = 'integrity_hold', \
                integrity_reason = $2, \
                integrity_hold_at = COALESCE(integrity_hold_at, NOW()), \
                updated_at = NOW() \
          WHERE id = $1 \
            AND status NOT IN ('confirmed', 'finalized')",
    )
    .bind(attempt_id)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Atomically record a known broadcast transaction and mirror it to the
/// compatibility chain-swap columns.  The destination equality predicate is
/// the final database-side guard against redirecting a committed attempt.
pub async fn complete_recovery_broadcast(
    pool: &PgPool,
    attempt_id: Uuid,
    chain_swap_id: Uuid,
    expected_txid: &str,
    result_text: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    let attempt_rows = sqlx::query(
        "UPDATE chain_swap_tx_attempts \
            SET status = CASE \
                    WHEN status IN ('confirmed', 'finalized') THEN status \
                    ELSE 'broadcast' END, \
                broadcast_at = COALESCE(broadcast_at, NOW()), \
                last_broadcast_result = $4, \
                updated_at = NOW() \
          WHERE id = $1 AND chain_swap_id = $2 AND txid = $3 \
            AND status <> 'integrity_hold'",
    )
    .bind(attempt_id)
    .bind(chain_swap_id)
    .bind(expected_txid)
    .bind(result_text)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if attempt_rows != 1 {
        return Err(sqlx::Error::Protocol(
            "recovery attempt was missing, mismatched, or held".into(),
        ));
    }

    let swap_rows = sqlx::query(
        "UPDATE chain_swap_records cs \
            SET status = 'refunded', refund_txid = $3, updated_at = NOW() \
          FROM chain_swap_tx_attempts a \
         WHERE cs.id = $2 \
           AND a.id = $1 \
           AND a.chain_swap_id = cs.id \
           AND a.txid = $3 \
           AND cs.refund_address = a.destination_address \
           AND (cs.status = 'refunding' \
                OR (cs.status = 'refunded' AND cs.refund_txid = $3))",
    )
    .bind(attempt_id)
    .bind(chain_swap_id)
    .bind(expected_txid)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if swap_rows != 1 {
        return Err(sqlx::Error::Protocol(
            "chain swap no longer matches its committed recovery attempt".into(),
        ));
    }

    tx.commit().await
}
