use axum::http::StatusCode;
use axum::{response::IntoResponse, Json};
use serde::Serialize;
use std::time::Duration;
use tokio::time::timeout;

use crate::version::EXPECTED_SCHEMA_MARKER;
use crate::AppState;

const READINESS_DB_TIMEOUT: Duration = Duration::from_secs(2);

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
    match timeout(READINESS_DB_TIMEOUT, schema_marker_present(pool)).await {
        Ok(Ok(true)) => ComponentStatus::ok(),
        Ok(Ok(false)) => ComponentStatus::error(format!(
            "expected schema marker {EXPECTED_SCHEMA_MARKER} is not present"
        )),
        Ok(Err(e)) => {
            tracing::warn!("readiness schema probe failed: {e}");
            ComponentStatus::error("schema probe failed")
        }
        Err(_) => ComponentStatus::error("schema probe timed out"),
    }
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
            )",
    )
    .fetch_one(pool)
    .await
}
