use std::net::SocketAddr;
use std::str::FromStr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth;
use crate::certification::{self, CertificationScope};
use crate::db::{
    self, GetPaidTransaction, GetPaidTransactionCursor, MAX_GET_PAID_TRANSACTION_PAGE_SIZE,
};
use crate::error::AppError;
use crate::ip_whitelist;
use crate::AppState;

pub const ACTION_GET_PAID_TRANSACTION_LIST: &str = "get-paid-transaction-list";
const CURSOR_VERSION: u8 = 1;
const MAX_CURSOR_BYTES: usize = 256;

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetPaidTransactionHistoryQuery {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
    #[serde(default)]
    pub cursor: String,
    pub limit: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct GetPaidTransactionHistoryItem {
    pub transaction_id: Uuid,
    pub source: String,
    pub invoice_id: Option<Uuid>,
    pub amount_sat: u64,
    pub received_at_unix: i64,
    pub rail: String,
    pub settlement_state: String,
    pub late: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct GetPaidTransactionHistoryResponse {
    pub transactions: Vec<GetPaidTransactionHistoryItem>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CursorWire {
    v: u8,
    received_at_unix_micros: i64,
    source_rank: i16,
    transaction_id: Uuid,
}

pub async fn list_signed(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<GetPaidTransactionHistoryQuery>,
) -> Result<Response, AppError> {
    let peer = peer_opt.map(|ConnectInfo(address)| address);
    let ip = ip_whitelist::caller_ip(peer, &headers, state.config.rate_limit.trust_forwarded_for);
    let is_whitelisted = ip
        .map(|address| state.ip_whitelist.contains(address))
        .unwrap_or(false);
    let is_certification_allowed = certification::allows_scope(
        &state,
        CertificationScope::MetadataLookup,
        peer,
        &headers,
        "signed_get_paid_transaction_history",
        Some(&query.npub),
    );
    if !is_whitelisted && !is_certification_allowed {
        if let Some(address) = ip {
            state.rate_limiter.check_api_per_ip(address).await?;
        }
    }

    validate_canonical_npub(&query.npub)?;
    let limit = validate_limit(query.limit)?;
    let cursor = decode_cursor(&query.cursor)?;
    let limit_text = limit.to_string();
    auth::verify_la_v2(
        ACTION_GET_PAID_TRANSACTION_LIST,
        &query.npub,
        "",
        &[query.cursor.as_str(), limit_text.as_str()],
        query.timestamp,
        &query.signature,
    )?;

    let page = db::list_get_paid_transactions(&state.db, &query.npub, cursor, limit)
        .await
        .map_err(|_| AppError::DbError("Get Paid transaction history query failed".into()))?;
    let next_cursor = if page.has_more {
        page.transactions.last().map(encode_cursor).transpose()?
    } else {
        None
    };
    let transactions = page
        .transactions
        .into_iter()
        .map(project_transaction)
        .collect::<Result<Vec<_>, _>>()?;
    let mut response = Json(GetPaidTransactionHistoryResponse {
        transactions,
        next_cursor,
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}

pub fn build_get_paid_transaction_history_message(
    npub: &str,
    cursor: &str,
    limit: i64,
    timestamp: u64,
) -> Result<Vec<u8>, AppError> {
    validate_canonical_npub(npub)?;
    let limit = validate_limit(limit)?;
    decode_cursor(cursor)?;
    let limit_text = limit.to_string();
    Ok(auth::build_la_v2_message(
        ACTION_GET_PAID_TRANSACTION_LIST,
        npub,
        "",
        &[cursor, limit_text.as_str()],
        timestamp,
    ))
}

fn validate_limit(limit: i64) -> Result<u16, AppError> {
    u16::try_from(limit)
        .ok()
        .filter(|value| (1..=MAX_GET_PAID_TRANSACTION_PAGE_SIZE).contains(value))
        .ok_or_else(|| {
            AppError::InvalidAmount(format!(
                "limit must be between 1 and {MAX_GET_PAID_TRANSACTION_PAGE_SIZE}"
            ))
        })
}

fn validate_canonical_npub(npub: &str) -> Result<(), AppError> {
    let parsed = XOnlyPublicKey::from_str(npub)
        .map_err(|_| AppError::AuthError("invalid Get Paid history npub".into()))?;
    if parsed.to_string() != npub {
        return Err(AppError::AuthError(
            "Get Paid history npub must be canonical lowercase hex".into(),
        ));
    }
    Ok(())
}

fn encode_cursor(transaction: &GetPaidTransaction) -> Result<String, AppError> {
    let wire = CursorWire {
        v: CURSOR_VERSION,
        received_at_unix_micros: transaction.received_at_unix_micros,
        source_rank: transaction.source_rank,
        transaction_id: transaction.transaction_id,
    };
    serde_json::to_vec(&wire)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| AppError::DbError("Get Paid transaction cursor encoding failed".into()))
}

fn decode_cursor(value: &str) -> Result<Option<GetPaidTransactionCursor>, AppError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_CURSOR_BYTES {
        return Err(AppError::InvalidAmount(
            "invalid Get Paid history cursor".into(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::InvalidAmount("invalid Get Paid history cursor".into()))?;
    let wire: CursorWire = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::InvalidAmount("invalid Get Paid history cursor".into()))?;
    if wire.v != CURSOR_VERSION
        || wire.received_at_unix_micros <= 0
        || !(1..=4).contains(&wire.source_rank)
        || URL_SAFE_NO_PAD.encode(&bytes) != value
    {
        return Err(AppError::InvalidAmount(
            "invalid Get Paid history cursor".into(),
        ));
    }
    Ok(Some(GetPaidTransactionCursor {
        received_at_unix_micros: wire.received_at_unix_micros,
        source_rank: wire.source_rank,
        transaction_id: wire.transaction_id,
    }))
}

fn project_transaction(
    transaction: GetPaidTransaction,
) -> Result<GetPaidTransactionHistoryItem, AppError> {
    if !matches!(
        transaction.source.as_str(),
        "lightning_address" | "invoice" | "payment_page" | "point_of_sale"
    ) || !matches!(
        transaction.rail.as_str(),
        "lightning" | "liquid" | "bitcoin"
    ) || !matches!(
        transaction.settlement_state.as_str(),
        "pending" | "settled" | "problem"
    ) || transaction.amount_sat <= 0
        || transaction.received_at_unix_micros <= 0
    {
        return Err(AppError::DbError(
            "Get Paid transaction history projection failed".into(),
        ));
    }
    Ok(GetPaidTransactionHistoryItem {
        transaction_id: transaction.transaction_id,
        source: transaction.source,
        invoice_id: transaction.invoice_id,
        amount_sat: u64::try_from(transaction.amount_sat).map_err(|_| {
            AppError::DbError("Get Paid transaction history projection failed".into())
        })?,
        received_at_unix: transaction.received_at_unix_micros / 1_000_000,
        rail: transaction.rail,
        settlement_state: transaction.settlement_state,
        late: transaction.late,
        comment: transaction.comment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPUB: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn signing_message_binds_empty_cursor_and_limit() {
        let actual = build_get_paid_transaction_history_message(NPUB, "", 50, 7).unwrap();
        let expected =
            auth::build_la_v2_message(ACTION_GET_PAID_TRANSACTION_LIST, NPUB, "", &["", "50"], 7);
        assert_eq!(actual, expected);
    }

    #[test]
    fn cursor_round_trips_and_rejects_malformed_or_future_versions() {
        let transaction = GetPaidTransaction {
            transaction_id: Uuid::from_u128(42),
            source: "invoice".into(),
            source_rank: 3,
            invoice_id: Some(Uuid::from_u128(7)),
            amount_sat: 1,
            received_at_unix_micros: 1_700_000_000_000_001,
            rail: "liquid".into(),
            settlement_state: "settled".into(),
            late: false,
            comment: None,
        };
        let encoded = encode_cursor(&transaction).unwrap();
        assert_eq!(
            decode_cursor(&encoded).unwrap(),
            Some(GetPaidTransactionCursor::from(&transaction))
        );
        assert!(decode_cursor("not-base64!").is_err());
        let future = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&CursorWire {
                v: 2,
                received_at_unix_micros: 1,
                source_rank: 3,
                transaction_id: Uuid::nil(),
            })
            .unwrap(),
        );
        assert!(decode_cursor(&future).is_err());
    }

    #[test]
    fn projection_accepts_only_bounded_wire_values() {
        let valid = GetPaidTransaction {
            transaction_id: Uuid::from_u128(42),
            source: "invoice".into(),
            source_rank: 3,
            invoice_id: Some(Uuid::from_u128(7)),
            amount_sat: 21_000,
            received_at_unix_micros: 1_700_000_000_000_001,
            rail: "bitcoin".into(),
            settlement_state: "problem".into(),
            late: true,
            comment: Some("private text".into()),
        };
        let projected = project_transaction(valid.clone()).unwrap();
        assert_eq!(projected.amount_sat, 21_000);
        assert!(projected.late);

        let mut invalid_source = valid.clone();
        invalid_source.source = "unknown".into();
        assert!(project_transaction(invalid_source).is_err());

        let mut invalid_rail = valid.clone();
        invalid_rail.rail = "unknown".into();
        assert!(project_transaction(invalid_rail).is_err());

        let mut invalid_state = valid.clone();
        invalid_state.settlement_state = "unknown".into();
        assert!(project_transaction(invalid_state).is_err());

        let mut invalid_amount = valid.clone();
        invalid_amount.amount_sat = 0;
        assert!(project_transaction(invalid_amount).is_err());

        let mut invalid_time = valid;
        invalid_time.received_at_unix_micros = 0;
        assert!(project_transaction(invalid_time).is_err());
    }
}
