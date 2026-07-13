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
    if !schema_marker_present(pool).await? {
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

    Ok(journal_privileges_ready(privileges)
        && direct_lifecycle_privileges_ready(direct_lifecycle_privileges))
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
            )",
    )
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::{direct_lifecycle_privileges_ready, journal_privileges_ready};

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
}
