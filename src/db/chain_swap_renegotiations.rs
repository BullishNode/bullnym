use std::fmt;
use std::str::FromStr;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::chain_swap_renegotiation::{
    ChainSwapRenegotiationOperation, ChangedQuoteRedrive, RenegotiationDomainError,
    RenegotiationErrorClass, RenegotiationIdentity, RenegotiationState, RenegotiationTransition,
    RenegotiationTransitionKind, TransitionDisposition, VerifiedRenegotiationAcceptance,
};

const OPERATION_COLUMNS: &str = "chain_swap_id, state, quoted_actual_amount_sat, \
    quote_response_digest, EXTRACT(EPOCH FROM quote_observed_at)::BIGINT \
        AS quote_observed_at_unix, \
    policy_version, policy_evidence_digest, \
    EXTRACT(EPOCH FROM policy_validated_at)::BIGINT AS policy_validated_at_unix, \
    accept_attempt_count, last_error_class, version, \
    EXTRACT(EPOCH FROM accept_requested_at)::BIGINT AS accept_requested_at_unix, \
    EXTRACT(EPOCH FROM ambiguous_at)::BIGINT AS ambiguous_at_unix, \
    terminal_response_digest, \
    EXTRACT(EPOCH FROM terminal_observed_at)::BIGINT AS terminal_observed_at_unix, \
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix, \
    EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at_unix";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenegotiationTransitionOutcome {
    pub operation: ChainSwapRenegotiationOperation,
    pub disposition: TransitionDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordAcceptedRenegotiationOutcome {
    Applied(ChainSwapRenegotiationOperation),
    ExactRetry(ChainSwapRenegotiationOperation),
    RepairedParent(ChainSwapRenegotiationOperation),
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordDeclinedRenegotiationOutcome {
    Applied(ChainSwapRenegotiationOperation),
    ExactRetry(ChainSwapRenegotiationOperation),
    Busy,
    LiquidPathActive,
}

pub enum ChainSwapRenegotiationStoreError {
    Database(sqlx::Error),
    Domain(RenegotiationDomainError),
    NotFound { chain_swap_id: Uuid },
    IdentityConflict { chain_swap_id: Uuid },
    CasMiss { chain_swap_id: Uuid },
    Busy { chain_swap_id: Uuid },
    ParentAmountConflict { chain_swap_id: Uuid },
    ParentUpdateLost { chain_swap_id: Uuid },
}

impl fmt::Debug for ChainSwapRenegotiationStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => f.write_str("Database(<redacted>)"),
            Self::Domain(error) => f.debug_tuple("Domain").field(error).finish(),
            Self::NotFound { chain_swap_id } => f
                .debug_struct("NotFound")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::IdentityConflict { chain_swap_id } => f
                .debug_struct("IdentityConflict")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::CasMiss { chain_swap_id } => f
                .debug_struct("CasMiss")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::Busy { chain_swap_id } => f
                .debug_struct("Busy")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::ParentAmountConflict { chain_swap_id } => f
                .debug_struct("ParentAmountConflict")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::ParentUpdateLost { chain_swap_id } => f
                .debug_struct("ParentUpdateLost")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
        }
    }
}

impl fmt::Display for ChainSwapRenegotiationStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => f.write_str("renegotiation operation database request failed"),
            Self::Domain(error) => error.fmt(f),
            Self::NotFound { .. } => f.write_str("renegotiation operation was not found"),
            Self::IdentityConflict { .. } => {
                f.write_str("chain swap already has a different renegotiation quote policy")
            }
            Self::CasMiss { .. } => {
                f.write_str("renegotiation operation changed during compare-and-swap")
            }
            Self::Busy { .. } => {
                f.write_str("renegotiation finalization is serialized by another swap worker")
            }
            Self::ParentAmountConflict { .. } => {
                f.write_str("chain swap has conflicting accepted renegotiation amount")
            }
            Self::ParentUpdateLost { .. } => {
                f.write_str("chain swap changed during accepted renegotiation commit")
            }
        }
    }
}

impl std::error::Error for ChainSwapRenegotiationStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Domain(error) => Some(error),
            // PostgreSQL diagnostics may contain quote evidence. Do not expose
            // raw database errors through a chained generic reporter.
            Self::Database(_)
            | Self::NotFound { .. }
            | Self::IdentityConflict { .. }
            | Self::CasMiss { .. }
            | Self::Busy { .. }
            | Self::ParentAmountConflict { .. }
            | Self::ParentUpdateLost { .. } => None,
        }
    }
}

impl From<sqlx::Error> for ChainSwapRenegotiationStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<RenegotiationDomainError> for ChainSwapRenegotiationStoreError {
    fn from(error: RenegotiationDomainError) -> Self {
        Self::Domain(error)
    }
}

#[derive(sqlx::FromRow)]
struct RenegotiationOperationDbRow {
    chain_swap_id: Uuid,
    state: String,
    quoted_actual_amount_sat: i64,
    quote_response_digest: String,
    quote_observed_at_unix: i64,
    policy_version: String,
    policy_evidence_digest: String,
    policy_validated_at_unix: i64,
    accept_attempt_count: i32,
    last_error_class: Option<String>,
    version: i64,
    accept_requested_at_unix: Option<i64>,
    ambiguous_at_unix: Option<i64>,
    terminal_response_digest: Option<String>,
    terminal_observed_at_unix: Option<i64>,
    created_at_unix: i64,
    updated_at_unix: i64,
}

#[derive(sqlx::FromRow)]
struct RenegotiationParentDbRow {
    status: String,
    renegotiated_server_lock_amount_sat: Option<i64>,
}

impl TryFrom<RenegotiationOperationDbRow> for ChainSwapRenegotiationOperation {
    type Error = RenegotiationDomainError;

    fn try_from(row: RenegotiationOperationDbRow) -> Result<Self, Self::Error> {
        let quoted_actual_amount_sat =
            u64::try_from(row.quoted_actual_amount_sat).map_err(|_| {
                RenegotiationDomainError::InvalidIdentity {
                    field: "quoted_actual_amount_sat",
                }
            })?;
        let identity = RenegotiationIdentity::new(
            row.chain_swap_id,
            quoted_actual_amount_sat,
            row.quote_response_digest,
            row.quote_observed_at_unix,
            row.policy_version,
            row.policy_evidence_digest,
            row.policy_validated_at_unix,
        )?;
        let state = RenegotiationState::from_str(&row.state)?;
        let accept_attempt_count = u32::try_from(row.accept_attempt_count)
            .map_err(|_| RenegotiationDomainError::InvalidStoredAttemptCount)?;
        let version = u64::try_from(row.version)
            .map_err(|_| RenegotiationDomainError::InvalidStoredVersion)?;
        let last_error_class = row
            .last_error_class
            .as_deref()
            .map(RenegotiationErrorClass::from_str)
            .transpose()?;

        ChainSwapRenegotiationOperation::from_persisted_parts(
            identity,
            state,
            accept_attempt_count,
            last_error_class,
            version,
            row.accept_requested_at_unix,
            row.ambiguous_at_unix,
            row.terminal_response_digest,
            row.terminal_observed_at_unix,
            row.created_at_unix,
            row.updated_at_unix,
        )
    }
}

/// Persist the exact quote and policy evidence in the initial `quoted` state.
/// A retry with identical immutable evidence returns the current operation;
/// different evidence for the same swap is rejected.
pub async fn persist_quoted_chain_swap_renegotiation(
    pool: &PgPool,
    identity: &RenegotiationIdentity,
) -> Result<ChainSwapRenegotiationOperation, ChainSwapRenegotiationStoreError> {
    identity.validate()?;
    let quoted_actual_amount_sat =
        i64::try_from(identity.quoted_actual_amount_sat).map_err(|_| {
            RenegotiationDomainError::InvalidIdentity {
                field: "quoted_actual_amount_sat",
            }
        })?;

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO chain_swap_renegotiation_operations ( \
             chain_swap_id, state, quoted_actual_amount_sat, quote_response_digest, \
             quote_observed_at, policy_version, policy_evidence_digest, \
             policy_validated_at, accept_attempt_count, version \
         ) VALUES ( \
             $1, 'quoted', $2, $3, to_timestamp($4::double precision), \
             $5, $6, to_timestamp($7::double precision), 0, 1 \
         ) ON CONFLICT (chain_swap_id) DO NOTHING",
    )
    .bind(identity.chain_swap_id)
    .bind(quoted_actual_amount_sat)
    .bind(identity.quote_response_digest())
    .bind(identity.quote_observed_at_unix)
    .bind(identity.policy_version())
    .bind(identity.policy_evidence_digest())
    .bind(identity.policy_validated_at_unix)
    .execute(&mut *tx)
    .await?;

    let operation = load_operation_for_update(&mut tx, identity.chain_swap_id).await?;
    if operation.identity != *identity {
        return Err(ChainSwapRenegotiationStoreError::IdentityConflict {
            chain_swap_id: identity.chain_swap_id,
        });
    }
    tx.commit().await?;
    Ok(operation)
}

pub async fn get_chain_swap_renegotiation(
    pool: &PgPool,
    chain_swap_id: Uuid,
) -> Result<Option<ChainSwapRenegotiationOperation>, ChainSwapRenegotiationStoreError> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} \
           FROM chain_swap_renegotiation_operations \
          WHERE chain_swap_id = $1"
    );
    let row = sqlx::query_as::<_, RenegotiationOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .fetch_optional(pool)
        .await?;
    row.map(TryInto::try_into).transpose().map_err(Into::into)
}

/// Commit `accept_requested` before returning to the caller.
///
/// A caller may mutate Boltz only after this function returns `Ok`. This
/// function and the generic transition adapter perform no network I/O and hold
/// the row lock only for the database compare-and-swap transaction.
pub async fn request_chain_swap_renegotiation_accept(
    pool: &PgPool,
    identity: &RenegotiationIdentity,
    expected_version: u64,
) -> Result<RenegotiationTransitionOutcome, ChainSwapRenegotiationStoreError> {
    let transition = RenegotiationTransition::new(
        identity.clone(),
        expected_version,
        RenegotiationTransitionKind::RequestAccept,
    )?;
    transition_chain_swap_renegotiation(pool, &transition).await
}

/// Atomically replace an ambiguous quote+policy identity with independently
/// revalidated evidence and commit the next `accept_requested` CAS before the
/// caller may submit the changed quote to Boltz.
pub async fn request_changed_chain_swap_renegotiation_accept(
    pool: &PgPool,
    redrive: &ChangedQuoteRedrive,
) -> Result<RenegotiationTransitionOutcome, ChainSwapRenegotiationStoreError> {
    let quoted_actual_amount_sat =
        i64::try_from(redrive.replacement_identity.quoted_actual_amount_sat).map_err(|_| {
            RenegotiationDomainError::InvalidIdentity {
                field: "quoted_actual_amount_sat",
            }
        })?;
    let expected_version = i64::try_from(redrive.expected_version)
        .map_err(|_| RenegotiationDomainError::InvalidExpectedVersion)?;

    let mut tx = pool.begin().await?;
    let current =
        load_operation_for_update(&mut tx, redrive.current_identity.chain_swap_id).await?;
    let disposition = redrive.plan(&current)?;
    if disposition == TransitionDisposition::ExactRetry {
        tx.commit().await?;
        return Ok(RenegotiationTransitionOutcome {
            operation: current,
            disposition,
        });
    }

    let sql = format!(
        "UPDATE chain_swap_renegotiation_operations \
            SET quoted_actual_amount_sat = $3, \
                quote_response_digest = $4, \
                quote_observed_at = to_timestamp($5::double precision), \
                policy_version = $6, \
                policy_evidence_digest = $7, \
                policy_validated_at = to_timestamp($8::double precision), \
                state = 'accept_requested', \
                accept_attempt_count = accept_attempt_count + 1, \
                accept_requested_at = clock_timestamp(), \
                version = version + 1, \
                updated_at = clock_timestamp() \
          WHERE chain_swap_id = $1 AND version = $2 \
        RETURNING {OPERATION_COLUMNS}"
    );
    let row = sqlx::query_as::<_, RenegotiationOperationDbRow>(&sql)
        .bind(redrive.current_identity.chain_swap_id)
        .bind(expected_version)
        .bind(quoted_actual_amount_sat)
        .bind(redrive.replacement_identity.quote_response_digest())
        .bind(redrive.replacement_identity.quote_observed_at_unix)
        .bind(redrive.replacement_identity.policy_version())
        .bind(redrive.replacement_identity.policy_evidence_digest())
        .bind(redrive.replacement_identity.policy_validated_at_unix)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ChainSwapRenegotiationStoreError::CasMiss {
            chain_swap_id: redrive.current_identity.chain_swap_id,
        })?;
    let operation = ChainSwapRenegotiationOperation::try_from(row)?;
    tx.commit().await?;
    Ok(RenegotiationTransitionOutcome {
        operation,
        disposition,
    })
}

pub async fn mark_chain_swap_renegotiation_ambiguous(
    pool: &PgPool,
    identity: &RenegotiationIdentity,
    expected_version: u64,
    error_class: RenegotiationErrorClass,
) -> Result<RenegotiationTransitionOutcome, ChainSwapRenegotiationStoreError> {
    let transition = RenegotiationTransition::new(
        identity.clone(),
        expected_version,
        RenegotiationTransitionKind::MarkAmbiguous { error_class },
    )?;
    transition_chain_swap_renegotiation(pool, &transition).await
}

/// Commit independently verified acceptance and the legacy parent operational
/// amount in one short transaction. The per-swap advisory lock and both row
/// locks are released before this function returns; it performs no network I/O.
pub async fn record_accepted_chain_swap_renegotiation(
    pool: &PgPool,
    evidence: &VerifiedRenegotiationAcceptance,
    expected_version: u64,
) -> Result<RecordAcceptedRenegotiationOutcome, ChainSwapRenegotiationStoreError> {
    let identity = evidence.identity();
    let transition = RenegotiationTransition::new(
        identity.clone(),
        expected_version,
        RenegotiationTransitionKind::MarkAccepted {
            terminal_response_digest: evidence.terminal_response_digest().to_owned(),
        },
    )?;
    let accepted_amount = i64::try_from(evidence.accepted_actual_amount_sat()).map_err(|_| {
        RenegotiationDomainError::InvalidIdentity {
            field: "accepted_actual_amount_sat",
        }
    })?;

    let mut tx = pool.begin().await?;
    let lock_key = format!("chain-claim:{}", identity.chain_swap_id);
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await?;
    if !got_lock {
        tx.rollback().await?;
        return Ok(RecordAcceptedRenegotiationOutcome::Busy);
    }

    let parent = sqlx::query_as::<_, RenegotiationParentDbRow>(
        "SELECT status, renegotiated_server_lock_amount_sat \
           FROM chain_swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(identity.chain_swap_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ChainSwapRenegotiationStoreError::NotFound {
        chain_swap_id: identity.chain_swap_id,
    })?;
    let current = load_operation_for_update(&mut tx, identity.chain_swap_id).await?;
    let disposition = current.plan_transition(&transition)?;

    if parent
        .renegotiated_server_lock_amount_sat
        .is_some_and(|amount| amount != accepted_amount)
    {
        return Err(ChainSwapRenegotiationStoreError::ParentAmountConflict {
            chain_swap_id: identity.chain_swap_id,
        });
    }
    let parent_needs_update = parent.renegotiated_server_lock_amount_sat.is_none();
    if parent_needs_update {
        let updated = sqlx::query(
            "UPDATE chain_swap_records \
                SET renegotiated_server_lock_amount_sat = $2, \
                    renegotiated_at = clock_timestamp(), \
                    status = CASE \
                        WHEN status IN ('user_lock_mempool', 'user_lock_confirmed') \
                        THEN 'user_lock_confirmed' ELSE status END, \
                    updated_at = clock_timestamp() \
              WHERE id = $1 AND renegotiated_server_lock_amount_sat IS NULL",
        )
        .bind(identity.chain_swap_id)
        .bind(accepted_amount)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(ChainSwapRenegotiationStoreError::ParentUpdateLost {
                chain_swap_id: identity.chain_swap_id,
            });
        }
    }

    let operation = if disposition == TransitionDisposition::Apply {
        execute_transition_update(&mut tx, &transition).await?
    } else {
        current
    };
    tx.commit().await?;

    Ok(match (disposition, parent_needs_update) {
        (TransitionDisposition::Apply, _) => RecordAcceptedRenegotiationOutcome::Applied(operation),
        (TransitionDisposition::ExactRetry, true) => {
            RecordAcceptedRenegotiationOutcome::RepairedParent(operation)
        }
        (TransitionDisposition::ExactRetry, false) => {
            RecordAcceptedRenegotiationOutcome::ExactRetry(operation)
        }
    })
}

/// Compatibility adapter for callers that already hold exact accepted quote
/// identity. Acceptance still goes through the atomic journal+parent commit;
/// this wrapper never exposes the former journal-only transition.
pub async fn mark_chain_swap_renegotiation_accepted(
    pool: &PgPool,
    identity: &RenegotiationIdentity,
    expected_version: u64,
    terminal_response_digest: impl Into<String>,
) -> Result<RenegotiationTransitionOutcome, ChainSwapRenegotiationStoreError> {
    let evidence = VerifiedRenegotiationAcceptance::new(
        identity.clone(),
        identity.quoted_actual_amount_sat,
        identity.quote_response_digest(),
        terminal_response_digest,
    )?;
    match record_accepted_chain_swap_renegotiation(pool, &evidence, expected_version).await? {
        RecordAcceptedRenegotiationOutcome::Applied(operation) => {
            Ok(RenegotiationTransitionOutcome {
                operation,
                disposition: TransitionDisposition::Apply,
            })
        }
        RecordAcceptedRenegotiationOutcome::ExactRetry(operation)
        | RecordAcceptedRenegotiationOutcome::RepairedParent(operation) => {
            Ok(RenegotiationTransitionOutcome {
                operation,
                disposition: TransitionDisposition::ExactRetry,
            })
        }
        RecordAcceptedRenegotiationOutcome::Busy => Err(ChainSwapRenegotiationStoreError::Busy {
            chain_swap_id: identity.chain_swap_id,
        }),
    }
}

pub async fn mark_chain_swap_renegotiation_declined(
    pool: &PgPool,
    identity: &RenegotiationIdentity,
    expected_version: u64,
    terminal_response_digest: impl Into<String>,
) -> Result<RenegotiationTransitionOutcome, ChainSwapRenegotiationStoreError> {
    let transition = RenegotiationTransition::new(
        identity.clone(),
        expected_version,
        RenegotiationTransitionKind::MarkDeclined {
            terminal_response_digest: terminal_response_digest.into(),
        },
    )?;
    transition_chain_swap_renegotiation(pool, &transition).await
}

/// Serialize a positively decoded provider refusal against a late Liquid lock
/// or claim. The caller must classify the provider response before entering;
/// ambiguous outcomes are not accepted by the domain transition.
pub async fn record_definite_declined_chain_swap_renegotiation(
    pool: &PgPool,
    identity: &RenegotiationIdentity,
    expected_version: u64,
    terminal_response_digest: impl Into<String>,
) -> Result<RecordDeclinedRenegotiationOutcome, ChainSwapRenegotiationStoreError> {
    let transition = RenegotiationTransition::new(
        identity.clone(),
        expected_version,
        RenegotiationTransitionKind::MarkDeclined {
            terminal_response_digest: terminal_response_digest.into(),
        },
    )?;
    let mut tx = pool.begin().await?;
    let lock_key = format!("chain-claim:{}", identity.chain_swap_id);
    let got_lock: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .fetch_one(&mut *tx)
            .await?;
    if !got_lock {
        tx.rollback().await?;
        return Ok(RecordDeclinedRenegotiationOutcome::Busy);
    }

    let parent = sqlx::query_as::<_, RenegotiationParentDbRow>(
        "SELECT status, renegotiated_server_lock_amount_sat \
           FROM chain_swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(identity.chain_swap_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ChainSwapRenegotiationStoreError::NotFound {
        chain_swap_id: identity.chain_swap_id,
    })?;
    let current = load_operation_for_update(&mut tx, identity.chain_swap_id).await?;

    if parent.renegotiated_server_lock_amount_sat.is_some() || liquid_path_is_active(&parent.status)
    {
        tx.commit().await?;
        return Ok(RecordDeclinedRenegotiationOutcome::LiquidPathActive);
    }

    let disposition = current.plan_transition(&transition)?;
    let operation = if disposition == TransitionDisposition::Apply {
        execute_transition_update(&mut tx, &transition).await?
    } else {
        current
    };
    tx.commit().await?;
    Ok(match disposition {
        TransitionDisposition::Apply => RecordDeclinedRenegotiationOutcome::Applied(operation),
        TransitionDisposition::ExactRetry => {
            RecordDeclinedRenegotiationOutcome::ExactRetry(operation)
        }
    })
}

pub(crate) async fn transition_chain_swap_renegotiation(
    pool: &PgPool,
    transition: &RenegotiationTransition,
) -> Result<RenegotiationTransitionOutcome, ChainSwapRenegotiationStoreError> {
    let mut tx = pool.begin().await?;
    let current = load_operation_for_update(&mut tx, transition.identity.chain_swap_id).await?;
    let disposition = current.plan_transition(transition)?;
    if disposition == TransitionDisposition::ExactRetry {
        tx.commit().await?;
        return Ok(RenegotiationTransitionOutcome {
            operation: current,
            disposition,
        });
    }

    let operation = execute_transition_update(&mut tx, transition).await?;
    tx.commit().await?;
    Ok(RenegotiationTransitionOutcome {
        operation,
        disposition,
    })
}

async fn execute_transition_update(
    tx: &mut Transaction<'_, Postgres>,
    transition: &RenegotiationTransition,
) -> Result<ChainSwapRenegotiationOperation, ChainSwapRenegotiationStoreError> {
    let sql = transition_update_sql(&transition.kind);
    let mut query = sqlx::query_as::<_, RenegotiationOperationDbRow>(&sql)
        .bind(transition.identity.chain_swap_id)
        .bind(
            i64::try_from(transition.expected_version)
                .map_err(|_| RenegotiationDomainError::InvalidExpectedVersion)?,
        );
    query = match &transition.kind {
        RenegotiationTransitionKind::RequestAccept => query,
        RenegotiationTransitionKind::MarkAmbiguous { error_class } => {
            query.bind(error_class.as_str())
        }
        RenegotiationTransitionKind::MarkAccepted {
            terminal_response_digest,
        }
        | RenegotiationTransitionKind::MarkDeclined {
            terminal_response_digest,
        } => query.bind(terminal_response_digest),
    };
    let row = query.fetch_optional(&mut **tx).await?.ok_or(
        ChainSwapRenegotiationStoreError::CasMiss {
            chain_swap_id: transition.identity.chain_swap_id,
        },
    )?;
    ChainSwapRenegotiationOperation::try_from(row).map_err(Into::into)
}

async fn load_operation_for_update(
    tx: &mut Transaction<'_, Postgres>,
    chain_swap_id: Uuid,
) -> Result<ChainSwapRenegotiationOperation, ChainSwapRenegotiationStoreError> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} \
           FROM chain_swap_renegotiation_operations \
          WHERE chain_swap_id = $1 \
          FOR UPDATE"
    );
    let row = sqlx::query_as::<_, RenegotiationOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ChainSwapRenegotiationStoreError::NotFound { chain_swap_id })?;
    row.try_into().map_err(Into::into)
}

fn transition_update_sql(kind: &RenegotiationTransitionKind) -> String {
    let mutation = match kind {
        RenegotiationTransitionKind::RequestAccept => {
            "state = 'accept_requested', \
             accept_attempt_count = accept_attempt_count + 1, \
             accept_requested_at = clock_timestamp()"
        }
        RenegotiationTransitionKind::MarkAmbiguous { .. } => {
            "state = 'ambiguous', \
             last_error_class = $3, \
             ambiguous_at = clock_timestamp()"
        }
        RenegotiationTransitionKind::MarkAccepted { .. } => {
            "state = 'accepted', \
             terminal_response_digest = $3, \
             terminal_observed_at = clock_timestamp()"
        }
        RenegotiationTransitionKind::MarkDeclined { .. } => {
            "state = 'declined', \
             terminal_response_digest = $3, \
             terminal_observed_at = clock_timestamp()"
        }
    };
    format!(
        "UPDATE chain_swap_renegotiation_operations \
            SET {mutation}, \
                version = version + 1, \
                updated_at = clock_timestamp() \
          WHERE chain_swap_id = $1 \
            AND version = $2 \
        RETURNING {OPERATION_COLUMNS}"
    )
}

fn liquid_path_is_active(status: &str) -> bool {
    matches!(
        status,
        "server_lock_mempool"
            | "server_lock_confirmed"
            | "claiming"
            | "claimed"
            | "claim_failed"
            | "claim_stuck"
    )
}

#[cfg(test)]
mod tests {
    use super::liquid_path_is_active;

    #[test]
    fn definite_decline_is_blocked_by_exact_liquid_progress_statuses() {
        for status in [
            "server_lock_mempool",
            "server_lock_confirmed",
            "claiming",
            "claimed",
            "claim_failed",
            "claim_stuck",
        ] {
            assert!(
                liquid_path_is_active(status),
                "{status} must keep the Liquid branch authoritative"
            );
        }
    }

    #[test]
    fn definite_decline_does_not_invent_liquid_progress() {
        for status in [
            "pending",
            "user_lock_mempool",
            "user_lock_confirmed",
            "refund_due",
            "refunding",
            "refunded",
            "expired",
            "lockup_failed",
        ] {
            assert!(
                !liquid_path_is_active(status),
                "{status} is not independently observed Liquid progression"
            );
        }
    }
}
