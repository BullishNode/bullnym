use axum::http::StatusCode;
use axum::{response::IntoResponse, Json};
use serde::Serialize;
use std::time::Duration;
use tokio::time::timeout;

use crate::version::EXPECTED_SCHEMA_MARKER;
use crate::AppState;

const READINESS_DB_TIMEOUT: Duration = Duration::from_secs(2);

type DirectLifecyclePrivileges = (
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
);

type WatcherLanePrivileges = (Option<bool>, Option<bool>, Option<bool>);
type SwapKeyLineagePrivileges = (Option<bool>, Option<bool>, Option<bool>);

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
    if !schema_marker_present(pool).await? || !swap_key_lineage_invariants_present(pool).await? {
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

    Ok(journal_privileges_ready(privileges)
        && direct_lifecycle_privileges_ready(direct_lifecycle_privileges)
        && watcher_lane_privileges_ready(watcher_lane_privileges)
        && swap_key_lineage_privileges_ready(swap_key_lineage_privileges))
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
            ) = 2",
    )
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        direct_lifecycle_privileges_ready, journal_privileges_ready,
        swap_key_lineage_privileges_ready, watcher_lane_privileges_ready,
    };

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
}
