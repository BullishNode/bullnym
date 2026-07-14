use axum::http::StatusCode;
use axum::{response::IntoResponse, Json};
use serde::Serialize;
use std::time::Duration;
use tokio::time::timeout;

use crate::version::EXPECTED_SCHEMA_MARKER;
use crate::AppState;

const READINESS_DB_TIMEOUT: Duration = Duration::from_secs(2);

const MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL: &str =
    "SELECT NOT EXISTS ( \
         SELECT 1 \
           FROM (VALUES \
             ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_require_review25_fee_authority', 'require_review25_bitcoin_attempt_fee_authority', 7), \
             ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_immutable', 'guard_chain_swap_tx_attempt_immutable', 19), \
             ('chain_swap_tx_attempts', 'chain_swap_tx_attempts_validate_replacement', 'enforce_liquid_claim_replacement_lineage', 7), \
             ('invoice_payment_events', 'invoice_payment_event_evidence_guard', 'guard_invoice_payment_event_evidence', 19), \
             ('invoice_payment_events', 'invoice_payment_event_reject_merchant_settlement_delete', 'reject_merchant_settlement_event_delete', 11), \
             ('merchant_settlement_checkpoints', 'merchant_settlement_checkpoint_validate_write', 'enforce_merchant_settlement_checkpoint_write', 23), \
             ('merchant_settlement_checkpoints', 'merchant_settlement_checkpoint_reject_delete', 'reject_merchant_settlement_delete', 11), \
             ('merchant_settlement_retained_outputs', 'merchant_settlement_retained_validate_update', 'enforce_merchant_settlement_retained_update', 23), \
             ('merchant_settlement_retained_outputs', 'merchant_settlement_retained_reject_delete', 'reject_merchant_settlement_delete', 11) \
           ) required(table_name, trigger_name, function_name, trigger_type) \
          WHERE NOT EXISTS ( \
              SELECT 1 \
                FROM pg_trigger trigger_info \
                JOIN pg_class relation ON relation.oid = trigger_info.tgrelid \
                JOIN pg_namespace relation_namespace \
                  ON relation_namespace.oid = relation.relnamespace \
                JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid \
                JOIN pg_namespace function_namespace \
                  ON function_namespace.oid = function_info.pronamespace \
               WHERE relation_namespace.nspname = 'public' \
                 AND function_namespace.nspname = 'public' \
                 AND relation.relname = required.table_name \
                 AND relation.relkind = 'r' \
                 AND trigger_info.tgname = required.trigger_name \
                 AND function_info.proname = required.function_name \
                 AND function_info.pronargs = 0 \
                 AND trigger_info.tgtype = required.trigger_type::SMALLINT \
                 AND NOT trigger_info.tgisinternal \
                 AND trigger_info.tgenabled IN ('O', 'A') \
          ) \
    )";

const MERCHANT_SETTLEMENT_PRIVILEGES_SQL: &str =
    "WITH required_tables(table_name) AS (VALUES \
         ('chain_swap_tx_attempts'), \
         ('invoice_payment_events'), \
         ('merchant_settlement_checkpoints'), \
         ('merchant_settlement_retained_outputs') \
     ), required_functions(function_name) AS (VALUES \
         ('guard_chain_swap_tx_attempt_immutable'), \
         ('require_review25_bitcoin_attempt_fee_authority'), \
         ('enforce_liquid_claim_replacement_lineage'), \
         ('guard_invoice_payment_event_evidence'), \
         ('reject_merchant_settlement_event_delete'), \
         ('enforce_merchant_settlement_checkpoint_write'), \
         ('enforce_merchant_settlement_retained_update'), \
         ('reject_merchant_settlement_delete') \
     ) \
     SELECT NOT EXISTS ( \
         SELECT 1 FROM required_tables required \
          WHERE NOT EXISTS ( \
              SELECT 1 \
                FROM pg_class relation \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
               WHERE namespace.nspname = 'public' \
                 AND relation.relname = required.table_name \
                 AND relation.relkind = 'r' \
                 AND pg_get_userbyid(relation.relowner) <> current_user \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(relation.relowner), 'USAGE') \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(relation.relowner), 'SET') \
                 AND has_table_privilege(current_user, relation.oid, 'SELECT') \
                 AND has_table_privilege(current_user, relation.oid, 'INSERT') \
                 AND has_table_privilege(current_user, relation.oid, 'UPDATE') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'DELETE') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                 AND NOT has_table_privilege(current_user, relation.oid, 'TRIGGER') \
          ) \
     ) \
     AND NOT EXISTS ( \
         SELECT 1 \
           FROM pg_class relation \
           JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
           CROSS JOIN LATERAL aclexplode(COALESCE( \
               relation.relacl, acldefault('r', relation.relowner) \
           )) acl \
          WHERE namespace.nspname = 'public' \
            AND relation.relname IN (SELECT table_name FROM required_tables) \
            AND acl.grantee = 0 \
     ) \
     AND NOT EXISTS ( \
         SELECT 1 FROM required_functions required \
          WHERE NOT EXISTS ( \
              SELECT 1 \
                FROM pg_proc function_info \
                JOIN pg_namespace namespace \
                  ON namespace.oid = function_info.pronamespace \
               WHERE namespace.nspname = 'public' \
                 AND function_info.proname = required.function_name \
                 AND function_info.pronargs = 0 \
                 AND pg_get_userbyid(function_info.proowner) <> current_user \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(function_info.proowner), 'USAGE') \
                 AND NOT pg_has_role(current_user, pg_get_userbyid(function_info.proowner), 'SET') \
          ) \
     ) \
     AND EXISTS ( \
         SELECT 1 \
           FROM pg_class sequence_info \
           JOIN pg_namespace namespace ON namespace.oid = sequence_info.relnamespace \
          WHERE namespace.nspname = 'public' \
            AND sequence_info.relname = 'invoice_payment_events_accounting_sequence_seq' \
            AND sequence_info.relkind = 'S' \
            AND pg_get_userbyid(sequence_info.relowner) <> current_user \
            AND NOT pg_has_role(current_user, pg_get_userbyid(sequence_info.relowner), 'USAGE') \
            AND NOT pg_has_role(current_user, pg_get_userbyid(sequence_info.relowner), 'SET') \
            AND has_sequence_privilege(current_user, sequence_info.oid, 'USAGE') \
            AND NOT has_sequence_privilege(current_user, sequence_info.oid, 'SELECT') \
            AND NOT has_sequence_privilege(current_user, sequence_info.oid, 'UPDATE') \
            AND NOT EXISTS ( \
                SELECT 1 \
                  FROM aclexplode(COALESCE( \
                      sequence_info.relacl, acldefault('S', sequence_info.relowner) \
                  )) acl \
                 WHERE acl.grantee = 0 \
            ) \
     )";

type DirectLifecyclePrivileges = (
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
);

type WatcherLanePrivileges = (Option<bool>, Option<bool>, Option<bool>);
type SwapKeyLineagePrivileges = (Option<bool>, Option<bool>, Option<bool>);
type ChainSwapRecordPrivileges = (Option<bool>, Option<bool>, Option<bool>);
type RecoveryCommitmentPrivileges = (
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
);

#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub service: &'static str,
    pub ready: bool,
    pub expected_schema_marker: &'static str,
    pub database: ComponentStatus,
    pub schema: ComponentStatus,
}

#[derive(Debug, Serialize)]
pub struct ComponentStatus {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ComponentStatus {
    fn ok() -> Self {
        Self {
            ok: true,
            detail: None,
        }
    }

    fn error(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: Some(detail.into()),
        }
    }
}

pub async fn ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> impl IntoResponse {
    let database = check_database(&state.db).await;
    let schema = if database.ok {
        check_schema(&state.db).await
    } else {
        ComponentStatus::error("database unavailable")
    };
    let ready = database.ok && schema.ok;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadinessResponse {
            service: "pay-service",
            ready,
            expected_schema_marker: EXPECTED_SCHEMA_MARKER,
            database,
            schema,
        }),
    )
}

async fn check_database(pool: &sqlx::PgPool) -> ComponentStatus {
    match timeout(
        READINESS_DB_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool),
    )
    .await
    {
        Ok(Ok(1)) => ComponentStatus::ok(),
        Ok(Ok(_)) => ComponentStatus::error("unexpected database probe result"),
        Ok(Err(e)) => {
            tracing::warn!("readiness database probe failed: {e}");
            ComponentStatus::error("database probe failed")
        }
        Err(_) => ComponentStatus::error("database probe timed out"),
    }
}

async fn check_schema(pool: &sqlx::PgPool) -> ComponentStatus {
    match timeout(READINESS_DB_TIMEOUT, schema_and_journal_ready(pool)).await {
        Ok(Ok(true)) => ComponentStatus::ok(),
        Ok(Ok(false)) => ComponentStatus::error(format!(
            "expected schema marker {EXPECTED_SCHEMA_MARKER} is not present or a required durable journal is not writable"
        )),
        Ok(Err(e)) => {
            tracing::warn!("readiness schema probe failed: {e}");
            ComponentStatus::error("schema probe failed")
        }
        Err(_) => ComponentStatus::error("schema probe timed out"),
    }
}

/// Verify the complete current schema marker and the write privilege required
/// by the recovery journal. Normal startup treats this as a foundation; the
/// HTTP readiness endpoint reuses the same predicate so deploy and runtime
/// checks cannot drift.
pub async fn schema_and_journal_ready(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    if !schema_marker_present(pool).await?
        || !swap_key_lineage_invariants_present(pool).await?
        || !merchant_settlement_trigger_invariants_present(pool).await?
        || !merchant_settlement_privileges_present(pool).await?
    {
        return Ok(false);
    }

    let privileges = sqlx::query_as::<_, (Option<bool>, Option<bool>, Option<bool>)>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_tx_attempts'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_tx_attempts'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_tx_attempts'), \
                'UPDATE' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let direct_lifecycle_privileges = sqlx::query_as::<_, DirectLifecyclePrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_scan_heads'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_scan_heads'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_scan_heads'), \
                'UPDATE' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_payment_transitions'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.invoice_direct_payment_transitions'), \
                'INSERT' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let watcher_lane_privileges = sqlx::query_as::<_, WatcherLanePrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.watcher_lane_progress'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.watcher_lane_progress'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.watcher_lane_progress'), \
                'UPDATE' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let swap_key_lineage_privileges = sqlx::query_as::<_, SwapKeyLineagePrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.swap_key_allocations'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.swap_key_allocations'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.swap_key_legacy_high_water'), \
                'SELECT' \
            )",
    )
    .fetch_one(pool)
    .await?;

    let chain_swap_record_privileges = sqlx::query_as::<_, ChainSwapRecordPrivileges>(
        "SELECT \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_records'), \
                'SELECT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_records'), \
                'INSERT' \
            ), \
            has_table_privilege( \
                current_user, \
                to_regclass('public.chain_swap_records'), \
                'UPDATE' \
            )",
    )
    .fetch_one(pool)
    .await?;

    Ok(journal_privileges_ready(privileges)
        && direct_lifecycle_privileges_ready(direct_lifecycle_privileges)
        && watcher_lane_privileges_ready(watcher_lane_privileges)
        && swap_key_lineage_privileges_ready(swap_key_lineage_privileges)
        && chain_swap_record_privileges_ready(chain_swap_record_privileges))
}

async fn merchant_settlement_privileges_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(MERCHANT_SETTLEMENT_PRIVILEGES_SQL)
        .fetch_one(pool)
        .await
}

async fn merchant_settlement_trigger_invariants_present(
    pool: &sqlx::PgPool,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL)
        .fetch_one(pool)
        .await
}

/// Global #84 capability boundary. This does not assert that any particular
/// merchant has registered a policy; creation performs that separate lookup.
/// It proves that the current runtime role has append/read-only ledger rights,
/// PUBLIC has no table ACL, and PostgreSQL will bind every new chain swap to
/// one immutable ID/address pair.
pub async fn recovery_commitment_ready(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    if !recovery_commitment_invariants_present(pool).await? {
        return Ok(false);
    }

    let privileges = sqlx::query_as::<_, RecoveryCommitmentPrivileges>(
        "SELECT \
            (SELECT pg_get_userbyid(relation.relowner) <> current_user \
               FROM pg_class relation \
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
              WHERE namespace.nspname = 'public' \
                AND relation.relname = 'recovery_address_commitments'), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'SELECT' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'INSERT' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'UPDATE' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'DELETE' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'TRUNCATE' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'REFERENCES' \
            ), \
            has_table_privilege( \
                current_user, to_regclass('public.recovery_address_commitments'), 'TRIGGER' \
            )",
    )
    .fetch_one(pool)
    .await?;

    Ok(recovery_commitment_privileges_ready(privileges))
}

/// Inspect the exact migration-053 contract rather than trusting a table-name
/// marker. Column types/nullability, constraints, ordered FK columns, actions,
/// trigger functions/events, and PUBLIC ACL state all fail closed.
async fn recovery_commitment_invariants_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('recovery_address_commitments', 'commitment_id', 'uuid', FALSE), \
                    ('recovery_address_commitments', 'npub', 'text', FALSE), \
                    ('recovery_address_commitments', 'contract_format_version', 'int2', FALSE), \
                    ('recovery_address_commitments', 'commitment_version', 'int8', FALSE), \
                    ('recovery_address_commitments', 'canonical_btc_address', 'text', FALSE), \
                    ('recovery_address_commitments', 'original_signature', 'text', FALSE), \
                    ('recovery_address_commitments', 'signed_at_unix', 'int8', FALSE), \
                    ('recovery_address_commitments', 'registered_at', 'timestamptz', FALSE), \
                    ('chain_swap_records', 'recovery_address_commitment_id', 'uuid', TRUE), \
                    ('chain_swap_records', 'merchant_emergency_btc_address', 'text', TRUE) \
                ) AS required(table_name, column_name, type_name, is_nullable) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_attribute attribute \
                    JOIN pg_class relation ON relation.oid = attribute.attrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    JOIN pg_type column_type ON column_type.oid = attribute.atttypid \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND attribute.attname = required.column_name \
                      AND column_type.typname = required.type_name \
                      AND NOT attribute.attisdropped \
                      AND attribute.attnum > 0 \
                      AND (NOT attribute.attnotnull) = required.is_nullable \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('recovery_address_commitments', 'recovery_address_commitments_pkey', 'p'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_id_non_nil_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_npub_shape_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_contract_version_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_version_positive_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_address_shape_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_signature_shape_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_signed_at_check', 'c'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_npub_version_key', 'u'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_signature_once_key', 'u'), \
                    ('recovery_address_commitments', 'recovery_address_commitment_id_address_key', 'u'), \
                    ('chain_swap_records', 'chain_swap_records_recovery_commitment_pair_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_recovery_commitment_fkey', 'f') \
                ) AS required(table_name, constraint_name, constraint_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_constraint constraint_info \
                    JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND constraint_info.conname = required.constraint_name \
                      AND constraint_info.contype::TEXT = required.constraint_type \
                      AND constraint_info.convalidated \
                ) \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint pair_constraint \
                JOIN pg_class relation ON relation.oid = pair_constraint.conrelid \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                WHERE namespace.nspname = 'public' \
                  AND relation.relname = 'chain_swap_records' \
                  AND pair_constraint.conname = 'chain_swap_records_recovery_commitment_pair_check' \
                  AND pair_constraint.contype = 'c' \
                  AND pair_constraint.convalidated \
                  AND pg_get_expr( \
                      pair_constraint.conbin, \
                      pair_constraint.conrelid, \
                      TRUE \
                  ) = '(recovery_address_commitment_id IS NULL) = (merchant_emergency_btc_address IS NULL)' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint unique_constraint \
                JOIN pg_class relation ON relation.oid = unique_constraint.conrelid \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                WHERE namespace.nspname = 'public' \
                  AND relation.relname = 'recovery_address_commitments' \
                  AND unique_constraint.conname = 'recovery_address_commitment_id_address_key' \
                  AND unique_constraint.contype = 'u' \
                  AND unique_constraint.convalidated \
                  AND ( \
                      SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality) \
                      FROM unnest(unique_constraint.conkey) WITH ORDINALITY \
                           AS key_column(attnum, ordinality) \
                      JOIN pg_attribute attribute \
                        ON attribute.attrelid = relation.oid \
                       AND attribute.attnum = key_column.attnum \
                  ) = ARRAY['commitment_id', 'canonical_btc_address']::TEXT[] \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint foreign_key \
                JOIN pg_class source_relation ON source_relation.oid = foreign_key.conrelid \
                JOIN pg_namespace source_namespace ON source_namespace.oid = source_relation.relnamespace \
                JOIN pg_class target_relation ON target_relation.oid = foreign_key.confrelid \
                JOIN pg_namespace target_namespace ON target_namespace.oid = target_relation.relnamespace \
                WHERE source_namespace.nspname = 'public' \
                  AND source_relation.relname = 'chain_swap_records' \
                  AND target_namespace.nspname = 'public' \
                  AND target_relation.relname = 'recovery_address_commitments' \
                  AND foreign_key.conname = 'chain_swap_records_recovery_commitment_fkey' \
                  AND foreign_key.contype = 'f' \
                  AND foreign_key.convalidated \
                  AND NOT foreign_key.condeferrable \
                  AND NOT foreign_key.condeferred \
                  AND foreign_key.confupdtype = 'r' \
                  AND foreign_key.confdeltype = 'r' \
                  AND foreign_key.confmatchtype = 's' \
                  AND ( \
                      SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality) \
                      FROM unnest(foreign_key.conkey) WITH ORDINALITY \
                           AS key_column(attnum, ordinality) \
                      JOIN pg_attribute attribute \
                        ON attribute.attrelid = source_relation.oid \
                       AND attribute.attnum = key_column.attnum \
                  ) = ARRAY['recovery_address_commitment_id', 'merchant_emergency_btc_address']::TEXT[] \
                  AND ( \
                      SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality) \
                      FROM unnest(foreign_key.confkey) WITH ORDINALITY \
                           AS key_column(attnum, ordinality) \
                      JOIN pg_attribute attribute \
                        ON attribute.attrelid = target_relation.oid \
                       AND attribute.attnum = key_column.attnum \
                  ) = ARRAY['commitment_id', 'canonical_btc_address']::TEXT[] \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('recovery_address_commitments', 'recovery_address_commitment_validate_insert', 'enforce_recovery_address_commitment_insert', 7), \
                    ('recovery_address_commitments', 'recovery_address_commitment_reject_update', 'reject_recovery_address_commitment_update', 19), \
                    ('recovery_address_commitments', 'recovery_address_commitment_reject_delete', 'reject_recovery_address_commitment_delete', 11), \
                    ('chain_swap_records', 'chain_swap_records_require_recovery_commitment', 'require_chain_swap_recovery_commitment', 7), \
                    ('chain_swap_records', 'chain_swap_records_reject_recovery_commitment_update', 'reject_chain_swap_recovery_commitment_mutation', 19) \
                ) AS required(table_name, trigger_name, function_name, trigger_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_trigger trigger_info \
                    JOIN pg_class relation ON relation.oid = trigger_info.tgrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND trigger_info.tgname = required.trigger_name \
                      AND function_info.proname = required.function_name \
                      AND trigger_info.tgtype = required.trigger_type::SMALLINT \
                      AND NOT trigger_info.tgisinternal \
                      AND trigger_info.tgenabled IN ('O', 'A') \
                      AND ( \
                          required.trigger_name <> 'chain_swap_records_reject_recovery_commitment_update' \
                          OR cardinality(trigger_info.tgattr::SMALLINT[]) = 0 \
                          OR ( \
                              SELECT array_agg(attribute.attname::TEXT) \
                              FROM unnest(trigger_info.tgattr::SMALLINT[]) attribute_number \
                              JOIN pg_attribute attribute \
                                ON attribute.attrelid = relation.oid \
                               AND attribute.attnum = attribute_number \
                          ) @> ARRAY[ \
                              'recovery_address_commitment_id', \
                              'merchant_emergency_btc_address' \
                          ]::TEXT[] \
                      ) \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM pg_class relation \
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                CROSS JOIN LATERAL aclexplode( \
                    COALESCE(relation.relacl, acldefault('r', relation.relowner)) \
                ) acl \
                WHERE namespace.nspname = 'public' \
                  AND relation.relname = 'recovery_address_commitments' \
                  AND acl.grantee = 0 \
            )",
    )
    .fetch_one(pool)
    .await
}

/// Migration 050 is a safety boundary, not merely an additive table marker.
/// Verify every database invariant that prevents swap-key reuse or mutable
/// lineage. Trigger checks include the owning table, function, timing, event,
/// row scope, and enabled state via PostgreSQL's exact `tgtype` bitmask.
async fn swap_key_lineage_invariants_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('swap_key_allocations', 'swap_key_allocations_root_fingerprint_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_key_epoch_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_scheme_version_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_child_index_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_purpose_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_public_key_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_preimage_hash_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_preimage_purpose_check', 'c'), \
                    ('swap_key_allocations', 'swap_key_allocations_derivation_identity_key', 'u'), \
                    ('swap_key_allocations', 'swap_key_allocations_public_key_key', 'u'), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_pkey', 'p'), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_root_fingerprint_check', 'c'), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_max_child_index_check', 'c'), \
                    ('swap_records', 'swap_records_key_allocation_id_fkey', 'f'), \
                    ('swap_records', 'swap_records_lineage_shape_check', 'c'), \
                    ('swap_records', 'swap_records_lineage_epoch_check', 'c'), \
                    ('swap_records', 'swap_records_lineage_scheme_check', 'c'), \
                    ('swap_records', 'swap_records_claim_public_key_check', 'c'), \
                    ('swap_records', 'swap_records_preimage_hash_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_claim_key_allocation_id_fkey', 'f'), \
                    ('chain_swap_records', 'chain_swap_records_refund_key_allocation_id_fkey', 'f'), \
                    ('chain_swap_records', 'chain_swap_records_lineage_shape_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_lineage_epoch_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_lineage_scheme_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_claim_public_key_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_refund_public_key_check', 'c'), \
                    ('chain_swap_records', 'chain_swap_records_preimage_hash_check', 'c') \
                ) AS required(table_name, constraint_name, constraint_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_constraint c \
                    JOIN pg_class relation ON relation.oid = c.conrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND c.conname = required.constraint_name \
                      AND c.contype::TEXT = required.constraint_type \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('swap_key_allocations', 'swap_key_allocations_preimage_hash_key'), \
                    ('swap_records', 'swap_records_key_allocation_id_key'), \
                    ('chain_swap_records', 'chain_swap_records_claim_key_allocation_id_key'), \
                    ('chain_swap_records', 'chain_swap_records_refund_key_allocation_id_key'), \
                    ('swap_records', 'swap_records_fingerprint_key_index_key'), \
                    ('chain_swap_records', 'chain_swap_records_fingerprint_claim_index_key'), \
                    ('chain_swap_records', 'chain_swap_records_fingerprint_refund_index_key') \
                ) AS required(table_name, index_name) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_index i \
                    JOIN pg_class index_relation ON index_relation.oid = i.indexrelid \
                    JOIN pg_class table_relation ON table_relation.oid = i.indrelid \
                    JOIN pg_namespace namespace ON namespace.oid = table_relation.relnamespace \
                    WHERE namespace.nspname = 'public' \
                      AND table_relation.relname = required.table_name \
                      AND index_relation.relname = required.index_name \
                      AND i.indisunique \
                      AND i.indisvalid \
                      AND i.indpred IS NOT NULL \
                ) \
            ) \
            AND NOT EXISTS ( \
                SELECT 1 \
                FROM (VALUES \
                    ('swap_key_allocations', 'swap_key_allocations_validate_legacy_high_water', 'validate_swap_key_allocation_against_legacy', 7), \
                    ('swap_key_allocations', 'swap_key_allocations_reject_update', 'reject_swap_key_allocation_mutation', 19), \
                    ('swap_key_allocations', 'swap_key_allocations_reject_delete', 'reject_swap_key_allocation_mutation', 11), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_reject_update', 'reject_swap_key_legacy_high_water_mutation', 19), \
                    ('swap_key_legacy_high_water', 'swap_key_legacy_high_water_reject_delete', 'reject_swap_key_legacy_high_water_mutation', 11), \
                    ('swap_records', 'swap_records_validate_lineage', 'validate_reverse_swap_key_lineage', 23), \
                    ('chain_swap_records', 'chain_swap_records_validate_lineage', 'validate_chain_swap_key_lineage', 23), \
                    ('swap_records', 'swap_records_reject_lineage_update', 'reject_swap_record_lineage_mutation', 19), \
                    ('chain_swap_records', 'chain_swap_records_reject_lineage_update', 'reject_chain_swap_record_lineage_mutation', 19) \
                ) AS required(table_name, trigger_name, function_name, trigger_type) \
                WHERE NOT EXISTS ( \
                    SELECT 1 \
                    FROM pg_trigger trg \
                    JOIN pg_class relation ON relation.oid = trg.tgrelid \
                    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                    JOIN pg_proc proc ON proc.oid = trg.tgfoid \
                    WHERE namespace.nspname = 'public' \
                      AND relation.relname = required.table_name \
                      AND trg.tgname = required.trigger_name \
                      AND proc.proname = required.function_name \
                      AND trg.tgtype = required.trigger_type::SMALLINT \
                      AND NOT trg.tgisinternal \
                      AND trg.tgenabled IN ('O', 'A') \
                ) \
            )",
    )
    .fetch_one(pool)
    .await
}

fn journal_privileges_ready(
    (select, insert, update): (Option<bool>, Option<bool>, Option<bool>),
) -> bool {
    matches!(
        (select, insert, update),
        (Some(true), Some(true), Some(true))
    )
}

fn direct_lifecycle_privileges_ready(
    (scan_select, scan_insert, scan_update, transition_select, transition_insert): DirectLifecyclePrivileges,
) -> bool {
    matches!(
        (
            scan_select,
            scan_insert,
            scan_update,
            transition_select,
            transition_insert,
        ),
        (Some(true), Some(true), Some(true), Some(true), Some(true),)
    )
}

fn watcher_lane_privileges_ready((select, insert, update): WatcherLanePrivileges) -> bool {
    matches!(
        (select, insert, update),
        (Some(true), Some(true), Some(true))
    )
}

fn swap_key_lineage_privileges_ready(
    (allocation_select, allocation_insert, high_water_select): SwapKeyLineagePrivileges,
) -> bool {
    matches!(
        (allocation_select, allocation_insert, high_water_select),
        (Some(true), Some(true), Some(true))
    )
}

fn chain_swap_record_privileges_ready((select, insert, update): ChainSwapRecordPrivileges) -> bool {
    matches!(
        (select, insert, update),
        (Some(true), Some(true), Some(true))
    )
}

fn recovery_commitment_privileges_ready(
    (
        distinct_owner,
        select,
        insert,
        update,
        delete,
        truncate,
        references,
        trigger,
    ): RecoveryCommitmentPrivileges,
) -> bool {
    matches!(
        (
            distinct_owner,
            select,
            insert,
            update,
            delete,
            truncate,
            references,
            trigger,
        ),
        (
            Some(true),
            Some(true),
            Some(true),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
        )
    )
}

async fn schema_marker_present(pool: &sqlx::PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT \
            EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'users' \
                  AND column_name = 'verification_npub' \
                  AND is_nullable = 'YES' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'ct_descriptor' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'next_addr_idx' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'kind' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'donation_pages' \
                  AND c.contype = 'p' \
                  AND ( \
                      SELECT array_agg(a.attname::text ORDER BY k.ord) \
                      FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) \
                      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum \
                  ) = ARRAY['nym', 'kind']::text[] \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'cooperative_refused' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint \
                WHERE conname = 'chain_swap_records_status_check' \
                  AND pg_get_constraintdef(oid) LIKE '%refund_due%' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'renegotiated_server_lock_amount_sat' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'refund_address' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'last_reconciled_at' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'alias' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoices' \
                  AND column_name = 'public_slug' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_indexes \
                WHERE schemaname = 'public' \
                  AND tablename = 'swap_records' \
                  AND indexname = 'swap_records_boltz_swap_id_key' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'next_slow_attempt_at' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'next_slow_attempt_at' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'key_index' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'root_fingerprint' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'claim_key_index' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_key' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_template_version' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_failure_count' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'donation_pages' \
                  AND column_name = 'generated_og_retry_after' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_tx_attempts' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoices' \
                  AND column_name = 'presentation_status' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'invoices' \
                  AND c.conname = 'invoices_paid_via_or_closed_chk' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'watcher_lane_progress' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_pkey' \
                  AND c.contype = 'p' \
                  AND ( \
                      SELECT array_agg(a.attname::text ORDER BY k.ord) \
                      FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) \
                      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum \
                  ) = ARRAY['worker', 'lane']::text[] \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_worker_check' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_lane_check' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'watcher_lane_progress' \
                  AND c.conname = 'watcher_lane_progress_cursor_shape_check' \
                  AND c.contype = 'c' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoice_payment_events' \
                  AND column_name = 'accounting_state' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoice_direct_scan_heads' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'invoice_direct_payment_transitions' \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'invoice_direct_payment_transitions' \
                  AND t.tgname = 'invoice_direct_payment_transition_history_guard' \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) \
            AND EXISTS ( \
                SELECT 1 \
                FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'invoice_payment_events' \
                  AND t.tgname = 'invoice_payment_event_compatibility_insert_classifier' \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_key_allocations' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'swap_key_allocations' \
                  AND c.conname = 'swap_key_allocations_derivation_identity_key' \
                  AND c.contype = 'u' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'swap_records' \
                  AND column_name = 'key_allocation_id' \
                  AND is_nullable = 'YES' \
            ) \
            AND EXISTS ( \
                SELECT 1 FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name = 'refund_key_allocation_id' \
                  AND is_nullable = 'YES' \
            ) \
            AND ( \
                SELECT COUNT(*) FROM pg_indexes \
                WHERE schemaname = 'public' \
                  AND indexname IN ( \
                      'swap_records_key_allocation_id_key', \
                      'chain_swap_records_claim_key_allocation_id_key', \
                      'chain_swap_records_refund_key_allocation_id_key' \
                  ) \
            ) = 3 \
            AND ( \
                SELECT COUNT(*) FROM pg_indexes \
                WHERE schemaname = 'public' \
                  AND indexname IN ( \
                      'swap_records_fingerprint_key_index_key', \
                      'chain_swap_records_fingerprint_claim_index_key', \
                      'chain_swap_records_fingerprint_refund_index_key' \
                  ) \
            ) = 3 \
            AND EXISTS ( \
                SELECT 1 FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'swap_key_allocations' \
                  AND t.tgname = 'swap_key_allocations_reject_update' \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) \
            AND ( \
                SELECT COUNT(*) FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND table_name = 'chain_swap_records' \
                  AND column_name IN ( \
                      'pinned_pair_hash', \
                      'canonical_pair_quote_json', \
                      'creation_response_sha256', \
                      'btc_claim_script_sha256', \
                      'btc_refund_script_sha256', \
                      'liquid_claim_script_sha256', \
                      'liquid_refund_script_sha256', \
                      'btc_timeout_height', \
                      'liquid_timeout_height', \
                      'btc_network', \
                      'liquid_network', \
                      'liquid_asset_id', \
                      'merchant_liquid_destination', \
                      'merchant_emergency_btc_address' \
                  ) \
            ) = 14 \
            AND ( \
                SELECT COUNT(*) FROM pg_constraint c \
                JOIN pg_class t ON t.oid = c.conrelid \
                JOIN pg_namespace n ON n.oid = t.relnamespace \
                WHERE n.nspname = 'public' \
                  AND t.relname = 'chain_swap_records' \
                  AND c.conname IN ( \
                      'chain_swap_records_creation_terms_shape_check', \
                      'chain_swap_records_pinned_pair_hash_check', \
                      'chain_swap_records_pair_quote_json_check', \
                      'chain_swap_records_creation_response_sha256_check', \
                      'chain_swap_records_btc_claim_script_sha256_check', \
                      'chain_swap_records_btc_refund_script_sha256_check', \
                      'chain_swap_records_liquid_claim_script_sha256_check', \
                      'chain_swap_records_liquid_refund_script_sha256_check', \
                      'chain_swap_records_btc_timeout_height_check', \
                      'chain_swap_records_liquid_timeout_height_check', \
                      'chain_swap_records_btc_network_check', \
                      'chain_swap_records_liquid_network_check', \
                      'chain_swap_records_liquid_asset_id_check', \
                      'chain_swap_records_merchant_liquid_destination_check', \
                      'chain_swap_records_merchant_emergency_btc_address_check' \
                  ) \
                  AND c.contype = 'c' \
                  AND c.convalidated \
            ) = 15 \
            AND ( \
                SELECT COUNT(*) FROM pg_trigger t \
                JOIN pg_class c ON c.oid = t.tgrelid \
                JOIN pg_namespace n ON n.oid = c.relnamespace \
                WHERE n.nspname = 'public' \
                  AND c.relname = 'chain_swap_records' \
                  AND t.tgname IN ( \
                      'chain_swap_records_require_creation_terms', \
                      'chain_swap_records_reject_creation_terms_update' \
                  ) \
                  AND NOT t.tgisinternal \
                  AND t.tgenabled IN ('O', 'A') \
            ) = 2 \
            AND ( \
                SELECT COUNT(*) FROM information_schema.columns \
                WHERE table_schema = 'public' \
                  AND (table_name, column_name) IN ( \
                      ('chain_swap_tx_attempts', 'replaces_txid'), \
                      ('chain_swap_tx_attempts', 'destination_asset_id'), \
                      ('chain_swap_tx_attempts', 'liquid_blinding_key_hex'), \
                      ('invoice_payment_events', 'merchant_settlement_family_key'), \
                      ('invoice_payment_events', 'merchant_chain_swap_id'), \
                      ('invoice_payment_events', 'merchant_settlement_finalized') \
                  ) \
            ) = 6 \
            AND ( \
                SELECT COUNT(*) FROM information_schema.tables \
                WHERE table_schema = 'public' \
                  AND table_name IN ( \
                      'merchant_settlement_checkpoints', \
                      'merchant_settlement_retained_outputs' \
                  ) \
            ) = 2 \
            AND ( \
                SELECT COUNT(*) \
                  FROM pg_constraint constraint_info \
                  JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
                  JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                 WHERE namespace.nspname = 'public' \
                   AND constraint_info.convalidated \
                   AND constraint_info.conname IN ( \
                       'chain_swap_tx_attempts_replaces_fkey', \
                       'invoice_payment_events_merchant_chain_swap_fkey', \
                       'merchant_settlement_checkpoint_journal_fkey', \
                       'merchant_settlement_retained_event_fkey', \
                       'merchant_settlement_retained_journal_fkey', \
                       'merchant_settlement_retained_checkpoint_fkey' \
                   ) \
            ) = 6",
    )
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        chain_swap_record_privileges_ready, direct_lifecycle_privileges_ready,
        journal_privileges_ready, recovery_commitment_privileges_ready,
        swap_key_lineage_privileges_ready, watcher_lane_privileges_ready,
        MERCHANT_SETTLEMENT_PRIVILEGES_SQL, MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL,
    };

    #[test]
    fn merchant_settlement_readiness_matches_deploy_boundary() {
        for (table, trigger, function, trigger_type) in [
            (
                "chain_swap_tx_attempts",
                "chain_swap_tx_attempts_require_review25_fee_authority",
                "require_review25_bitcoin_attempt_fee_authority",
                7,
            ),
            (
                "chain_swap_tx_attempts",
                "chain_swap_tx_attempts_immutable",
                "guard_chain_swap_tx_attempt_immutable",
                19,
            ),
            (
                "chain_swap_tx_attempts",
                "chain_swap_tx_attempts_validate_replacement",
                "enforce_liquid_claim_replacement_lineage",
                7,
            ),
            (
                "invoice_payment_events",
                "invoice_payment_event_evidence_guard",
                "guard_invoice_payment_event_evidence",
                19,
            ),
            (
                "invoice_payment_events",
                "invoice_payment_event_reject_merchant_settlement_delete",
                "reject_merchant_settlement_event_delete",
                11,
            ),
            (
                "merchant_settlement_checkpoints",
                "merchant_settlement_checkpoint_validate_write",
                "enforce_merchant_settlement_checkpoint_write",
                23,
            ),
            (
                "merchant_settlement_checkpoints",
                "merchant_settlement_checkpoint_reject_delete",
                "reject_merchant_settlement_delete",
                11,
            ),
            (
                "merchant_settlement_retained_outputs",
                "merchant_settlement_retained_validate_update",
                "enforce_merchant_settlement_retained_update",
                23,
            ),
            (
                "merchant_settlement_retained_outputs",
                "merchant_settlement_retained_reject_delete",
                "reject_merchant_settlement_delete",
                11,
            ),
        ] {
            let binding = format!("('{table}', '{trigger}', '{function}', {trigger_type})");
            assert!(
                MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL.contains(&binding),
                "missing exact trigger binding: {binding}"
            );
        }
        for exact_catalog_guard in [
            "relation_namespace.nspname = 'public'",
            "function_namespace.nspname = 'public'",
            "function_info.pronargs = 0",
            "trigger_info.tgtype = required.trigger_type::SMALLINT",
            "NOT trigger_info.tgisinternal",
            "trigger_info.tgenabled IN ('O', 'A')",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_TRIGGER_INVARIANTS_SQL.contains(exact_catalog_guard),
                "missing trigger catalog guard: {exact_catalog_guard}"
            );
        }

        for table in [
            "chain_swap_tx_attempts",
            "invoice_payment_events",
            "merchant_settlement_checkpoints",
            "merchant_settlement_retained_outputs",
        ] {
            assert!(MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains(&format!("('{table}')")));
        }
        for function in [
            "guard_chain_swap_tx_attempt_immutable",
            "require_review25_bitcoin_attempt_fee_authority",
            "enforce_liquid_claim_replacement_lineage",
            "guard_invoice_payment_event_evidence",
            "reject_merchant_settlement_event_delete",
            "enforce_merchant_settlement_checkpoint_write",
            "enforce_merchant_settlement_retained_update",
            "reject_merchant_settlement_delete",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains(&format!("('{function}')")),
                "missing function owner guard: {function}"
            );
        }
        for owner_guard in [
            "relation.relowner) <> current_user",
            "function_info.proowner) <> current_user",
            "sequence_info.relowner) <> current_user",
            "relation.relowner), 'USAGE'",
            "relation.relowner), 'SET'",
            "function_info.proowner), 'USAGE'",
            "function_info.proowner), 'SET'",
            "sequence_info.relowner), 'USAGE'",
            "sequence_info.relowner), 'SET'",
            "invoice_payment_events_accounting_sequence_seq",
        ] {
            assert!(
                MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains(owner_guard),
                "missing owner capability guard: {owner_guard}"
            );
        }
        assert!(!MERCHANT_SETTLEMENT_PRIVILEGES_SQL.contains("'MEMBER'"));
    }

    #[test]
    fn recovery_journal_requires_every_privilege() {
        assert!(journal_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));

        for privileges in [
            (Some(false), Some(true), Some(true)),
            (Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true)),
            (Some(true), None, Some(true)),
            (Some(true), Some(true), None),
        ] {
            assert!(!journal_privileges_ready(privileges));
        }
    }

    #[test]
    fn recovery_commitment_requires_private_append_only_runtime_acl() {
        assert!(recovery_commitment_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
        )));

        for privileges in [
            (
                Some(false),
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(false),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(true),
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
            (
                Some(true),
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(true),
            ),
            (
                None,
                Some(true),
                Some(true),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
        ] {
            assert!(!recovery_commitment_privileges_ready(privileges));
        }
    }

    #[test]
    fn direct_lifecycle_requires_scan_and_transition_privileges() {
        assert!(direct_lifecycle_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
            Some(true),
            Some(true),
        )));

        for privileges in [
            (Some(false), Some(true), Some(true), Some(true), Some(true)),
            (Some(true), Some(false), Some(true), Some(true), Some(true)),
            (Some(true), Some(true), Some(false), Some(true), Some(true)),
            (Some(true), Some(true), Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true), Some(true), Some(true)),
        ] {
            assert!(!direct_lifecycle_privileges_ready(privileges));
        }
    }

    #[test]
    fn watcher_lane_progress_requires_read_write_privileges() {
        assert!(watcher_lane_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));

        for privileges in [
            (Some(false), Some(true), Some(true)),
            (Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true)),
            (Some(true), None, Some(true)),
            (Some(true), Some(true), None),
        ] {
            assert!(!watcher_lane_privileges_ready(privileges));
        }
    }

    #[test]
    fn swap_key_lineage_requires_allocation_write_and_high_water_read_privileges() {
        assert!(swap_key_lineage_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            Some(false),
            Some(true),
            Some(true),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            Some(true),
            Some(false),
            Some(true),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            Some(true),
            Some(true),
            Some(false),
        )));
        assert!(!swap_key_lineage_privileges_ready((
            None,
            Some(true),
            Some(true),
        )));
    }

    #[test]
    fn chain_swap_creation_requires_record_read_write_privileges() {
        assert!(chain_swap_record_privileges_ready((
            Some(true),
            Some(true),
            Some(true),
        )));
        for privileges in [
            (Some(false), Some(true), Some(true)),
            (Some(true), Some(false), Some(true)),
            (Some(true), Some(true), Some(false)),
            (None, Some(true), Some(true)),
            (Some(true), None, Some(true)),
            (Some(true), Some(true), None),
        ] {
            assert!(!chain_swap_record_privileges_ready(privileges));
        }
    }
}
