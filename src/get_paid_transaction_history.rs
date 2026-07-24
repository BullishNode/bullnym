use std::net::SocketAddr;
use std::str::FromStr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue};
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
    pub settlement_kind: GetPaidSettlementKind,
    pub late: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_details: Option<GetPaidSettlementDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fiat_conversion: Option<GetPaidFiatConversionOverride>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GetPaidSettlementKind {
    Bitcoin,
    Fiat,
    Mixed,
    Unavailable,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct GetPaidFiatSettlementLeg {
    pub amount_minor: Option<i64>,
    pub quoted_amount_minor: Option<i64>,
    pub currency: String,
    pub order_id: Uuid,
    pub status: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct GetPaidBitcoinSettlementLeg {
    pub amount_sat: i64,
    pub network: &'static str,
    pub status: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GetPaidSettlementDetails {
    Fiat {
        fiat_percentage: Option<i16>,
        fiat: Vec<GetPaidFiatSettlementLeg>,
    },
    Mixed {
        fiat_percentage: Option<i16>,
        bitcoin: Vec<GetPaidBitcoinSettlementLeg>,
        fiat: Vec<GetPaidFiatSettlementLeg>,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct GetPaidFiatConversionOverride {
    pub status: &'static str,
    pub reason: &'static str,
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
    response.headers_mut().insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
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
    let (settlement_kind, settlement_details, fiat_conversion) =
        project_merchant_settlement(&transaction);
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
        settlement_kind,
        late: transaction.late,
        comment: transaction.comment,
        settlement_details,
        fiat_conversion,
    })
}

fn project_merchant_settlement(
    transaction: &GetPaidTransaction,
) -> (
    GetPaidSettlementKind,
    Option<GetPaidSettlementDetails>,
    Option<GetPaidFiatConversionOverride>,
) {
    if !transaction.settlement_present {
        let kind = if transaction.fiat_policy_present {
            GetPaidSettlementKind::Unavailable
        } else {
            GetPaidSettlementKind::Bitcoin
        };
        return (kind, None, None);
    }

    if transaction.settlement_funding_route.as_deref() == Some("bitcoin_fallback") {
        let reason = match transaction.settlement_fallback_category.as_deref() {
            Some("below_minimum") => "below_minimum",
            Some("invalid_split") => "invalid_split",
            Some("conversion_unavailable" | "ambiguous_create") | None => "conversion_unavailable",
            Some(_) => "conversion_unavailable",
        };
        return (
            GetPaidSettlementKind::Bitcoin,
            None,
            Some(GetPaidFiatConversionOverride {
                status: "overridden",
                reason,
            }),
        );
    }

    if transaction.settlement_funding_route.as_deref() != Some("bull_bitcoin") {
        return (GetPaidSettlementKind::Unavailable, None, None);
    }

    let Some(order_id) = transaction
        .settlement_order_id
        .filter(|order_id| !order_id.is_nil())
    else {
        return (GetPaidSettlementKind::Unavailable, None, None);
    };
    let Some(currency) = transaction
        .settlement_currency
        .as_deref()
        .filter(|currency| {
            matches!(
                *currency,
                "ARS" | "CAD" | "COP" | "CRC" | "EUR" | "MXN" | "USD"
            )
        })
    else {
        return (GetPaidSettlementKind::Unavailable, None, None);
    };
    let Some(status) = transaction
        .settlement_status_detail
        .as_deref()
        .and_then(normalize_fiat_status)
    else {
        return (GetPaidSettlementKind::Unavailable, None, None);
    };
    let amount_minor = match status {
        "settled" => match transaction
            .settlement_credited_fiat_minor
            .filter(|amount| *amount > 0)
        {
            Some(amount) => Some(amount),
            None => return (GetPaidSettlementKind::Unavailable, None, None),
        },
        // A non-final provider observation may already include an amount.
        // It is not merchant-authoritative until settlement is final.
        "pending" | "unavailable" => None,
        _ => return (GetPaidSettlementKind::Unavailable, None, None),
    };
    // The locked quote is shown while pending and after settlement alike. It is
    // never fabricated: a missing or nonpositive stored value collapses to null
    // rather than to a guessed amount.
    let quoted_amount_minor = transaction
        .settlement_quoted_fiat_minor
        .filter(|amount| *amount > 0);
    // The split percentage captured at payment time. Out-of-range values are
    // treated as unknown (null); the current product config is never consulted.
    let fiat_percentage = transaction
        .settlement_fiat_percentage
        .filter(|percentage| (1..=100).contains(percentage));
    let fiat = GetPaidFiatSettlementLeg {
        amount_minor,
        quoted_amount_minor,
        currency: currency.to_owned(),
        order_id,
        status: status.to_owned(),
    };

    match transaction.settlement_purpose.as_deref() {
        Some("fiat_only") => (
            GetPaidSettlementKind::Fiat,
            Some(GetPaidSettlementDetails::Fiat {
                fiat_percentage,
                fiat: vec![fiat],
            }),
            None,
        ),
        Some("mixed") => {
            let Some(amount_sat) = transaction
                .settlement_bitcoin_amount_sat
                .filter(|amount| *amount > 0)
            else {
                return (GetPaidSettlementKind::Unavailable, None, None);
            };
            let Some(bitcoin_status) = transaction
                .settlement_bitcoin_status
                .as_deref()
                .filter(|status| matches!(*status, "pending" | "settled" | "problem"))
            else {
                return (GetPaidSettlementKind::Unavailable, None, None);
            };
            (
                GetPaidSettlementKind::Mixed,
                Some(GetPaidSettlementDetails::Mixed {
                    fiat_percentage,
                    bitcoin: vec![GetPaidBitcoinSettlementLeg {
                        amount_sat,
                        network: "liquid",
                        status: bitcoin_status.to_owned(),
                    }],
                    fiat: vec![fiat],
                }),
                None,
            )
        }
        _ => (GetPaidSettlementKind::Unavailable, None, None),
    }
}

fn normalize_fiat_status(value: &str) -> Option<&'static str> {
    match value {
        "pending" => Some("pending"),
        "settled" => Some("settled"),
        "unavailable" | "integrity_error" => Some("unavailable"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const NPUB: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn settlement_transaction() -> GetPaidTransaction {
        GetPaidTransaction {
            transaction_id: Uuid::from_u128(42),
            source: "invoice".into(),
            source_rank: 3,
            invoice_id: Some(Uuid::from_u128(7)),
            amount_sat: 100_000,
            received_at_unix_micros: 1_700_000_000_000_001,
            rail: "lightning".into(),
            settlement_state: "settled".into(),
            late: false,
            comment: None,
            settlement_present: true,
            fiat_policy_present: true,
            settlement_purpose: Some("fiat_only".into()),
            settlement_order_id: Some(Uuid::from_u128(9)),
            settlement_currency: Some("CAD".into()),
            settlement_status_detail: Some("settled".into()),
            settlement_credited_fiat_minor: Some(12_345),
            settlement_quoted_fiat_minor: Some(12_345),
            settlement_fiat_percentage: Some(100),
            settlement_funding_route: Some("bull_bitcoin".into()),
            settlement_fallback_category: None,
            settlement_bitcoin_amount_sat: None,
            settlement_bitcoin_status: None,
        }
    }

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
            settlement_present: false,
            fiat_policy_present: false,
            settlement_purpose: None,
            settlement_order_id: None,
            settlement_currency: None,
            settlement_status_detail: None,
            settlement_credited_fiat_minor: None,
            settlement_quoted_fiat_minor: None,
            settlement_fiat_percentage: None,
            settlement_funding_route: None,
            settlement_fallback_category: None,
            settlement_bitcoin_amount_sat: None,
            settlement_bitcoin_status: None,
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
            settlement_present: false,
            fiat_policy_present: false,
            settlement_purpose: None,
            settlement_order_id: None,
            settlement_currency: None,
            settlement_status_detail: None,
            settlement_credited_fiat_minor: None,
            settlement_quoted_fiat_minor: None,
            settlement_fiat_percentage: None,
            settlement_funding_route: None,
            settlement_fallback_category: None,
            settlement_bitcoin_amount_sat: None,
            settlement_bitcoin_status: None,
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

    #[test]
    fn projection_emits_explicit_bitcoin_and_fallback_contracts() {
        let mut ordinary = settlement_transaction();
        ordinary.settlement_present = false;
        ordinary.fiat_policy_present = false;
        let ordinary = serde_json::to_value(project_transaction(ordinary).unwrap()).unwrap();
        assert_eq!(ordinary["settlement_kind"], "bitcoin");
        assert!(ordinary.get("settlement_details").is_none());
        assert!(ordinary.get("fiat_conversion").is_none());

        let mut fallback = settlement_transaction();
        fallback.settlement_funding_route = Some("bitcoin_fallback".into());
        fallback.settlement_fallback_category = Some("below_minimum".into());
        fallback.settlement_status_detail = Some("none".into());
        fallback.settlement_credited_fiat_minor = None;
        let fallback = serde_json::to_value(project_transaction(fallback).unwrap()).unwrap();
        assert_eq!(fallback["settlement_kind"], "bitcoin");
        assert_eq!(
            fallback["fiat_conversion"],
            json!({"status": "overridden", "reason": "below_minimum"})
        );
        assert!(fallback.get("settlement_details").is_none());
    }

    #[test]
    fn captured_fiat_policy_without_a_settlement_fails_closed() {
        let mut pending = settlement_transaction();
        pending.settlement_present = false;
        pending.fiat_policy_present = true;
        pending.settlement_purpose = None;
        pending.settlement_order_id = None;
        pending.settlement_currency = None;
        pending.settlement_status_detail = None;
        pending.settlement_credited_fiat_minor = None;
        pending.settlement_funding_route = None;

        let pending = serde_json::to_value(project_transaction(pending).unwrap()).unwrap();
        assert_eq!(pending["settlement_kind"], "unavailable");
        assert!(pending.get("settlement_details").is_none());
        assert!(pending.get("fiat_conversion").is_none());
    }

    #[test]
    fn projection_emits_strict_fiat_and_mixed_contracts() {
        let fiat = serde_json::to_value(
            project_transaction(settlement_transaction()).expect("valid fiat projection"),
        )
        .unwrap();
        assert_eq!(fiat["settlement_kind"], "fiat");
        assert_eq!(fiat["settlement_details"]["kind"], "fiat");
        assert_eq!(
            fiat["settlement_details"]["fiat"][0]["amount_minor"],
            12_345
        );
        assert_eq!(
            fiat["settlement_details"]["fiat"][0]["quoted_amount_minor"],
            12_345
        );
        assert_eq!(fiat["settlement_details"]["fiat_percentage"], 100);

        let mut mixed = settlement_transaction();
        mixed.settlement_purpose = Some("mixed".into());
        mixed.settlement_fiat_percentage = Some(40);
        mixed.settlement_bitcoin_amount_sat = Some(60_000);
        mixed.settlement_bitcoin_status = Some("settled".into());
        let mixed = serde_json::to_value(project_transaction(mixed).unwrap()).unwrap();
        assert_eq!(mixed["settlement_kind"], "mixed");
        assert_eq!(mixed["settlement_details"]["kind"], "mixed");
        assert_eq!(mixed["settlement_details"]["fiat_percentage"], 40);
        assert_eq!(
            mixed["settlement_details"]["bitcoin"][0]["amount_sat"],
            60_000
        );
        assert_eq!(
            mixed["settlement_details"]["bitcoin"][0]["network"],
            "liquid"
        );
    }

    #[test]
    fn projection_fails_closed_without_partial_details() {
        let mut malformed = settlement_transaction();
        malformed.settlement_order_id = None;
        let malformed = serde_json::to_value(project_transaction(malformed).unwrap()).unwrap();
        assert_eq!(malformed["settlement_kind"], "unavailable");
        assert!(malformed.get("settlement_details").is_none());
        assert!(malformed.get("fiat_conversion").is_none());

        let mut pending_with_amount = settlement_transaction();
        pending_with_amount.settlement_status_detail = Some("pending".into());
        let pending =
            serde_json::to_value(project_transaction(pending_with_amount).unwrap()).unwrap();
        assert_eq!(pending["settlement_kind"], "fiat");
        // v2: the credited amount stays null while pending, but the locked quote
        // is exposed so the merchant sees the fiat value immediately.
        assert_eq!(
            pending["settlement_details"]["fiat"][0]["amount_minor"],
            Value::Null
        );
        assert_eq!(
            pending["settlement_details"]["fiat"][0]["quoted_amount_minor"],
            12_345
        );

        let mut mixed_without_bitcoin = settlement_transaction();
        mixed_without_bitcoin.settlement_purpose = Some("mixed".into());
        let mixed =
            serde_json::to_value(project_transaction(mixed_without_bitcoin).unwrap()).unwrap();
        assert_eq!(mixed["settlement_kind"], "unavailable");
    }

    #[test]
    fn projection_v2_nulls_missing_quote_and_percentage_without_fabricating() {
        // A legacy row predating the quote/percentage columns, or an anomalous
        // nonpositive/out-of-range stored value, projects JSON null rather than
        // a guessed amount or percentage.
        let mut legacy = settlement_transaction();
        legacy.settlement_quoted_fiat_minor = None;
        legacy.settlement_fiat_percentage = None;
        let legacy = serde_json::to_value(project_transaction(legacy).unwrap()).unwrap();
        assert_eq!(legacy["settlement_kind"], "fiat");
        assert_eq!(
            legacy["settlement_details"]["fiat"][0]["amount_minor"],
            12_345
        );
        assert_eq!(
            legacy["settlement_details"]["fiat"][0]["quoted_amount_minor"],
            Value::Null
        );
        assert_eq!(legacy["settlement_details"]["fiat_percentage"], Value::Null);

        let mut anomalous = settlement_transaction();
        anomalous.settlement_status_detail = Some("pending".into());
        anomalous.settlement_quoted_fiat_minor = Some(0);
        anomalous.settlement_fiat_percentage = Some(0);
        let anomalous = serde_json::to_value(project_transaction(anomalous).unwrap()).unwrap();
        assert_eq!(
            anomalous["settlement_details"]["fiat"][0]["quoted_amount_minor"],
            Value::Null
        );
        assert_eq!(
            anomalous["settlement_details"]["fiat_percentage"],
            Value::Null
        );
    }

    #[test]
    fn canonical_fixture_pins_all_version_two_shapes() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../docs/api/fixtures/get-paid-transactions-settlement-v2.json"
        ))
        .unwrap();
        let transactions = fixture["transactions"].as_array().unwrap();
        assert_eq!(transactions.len(), 7);
        assert_eq!(transactions[0]["settlement_kind"], "bitcoin");
        assert_eq!(transactions[1]["fiat_conversion"]["status"], "overridden");

        // Pending fiat leg: no credited amount yet, but the locked quote and the
        // captured split percentage are already exposed.
        let pending = &transactions[2]["settlement_details"];
        assert_eq!(pending["kind"], "fiat");
        assert_eq!(pending["fiat_percentage"], 100);
        assert_eq!(pending["fiat"][0]["amount_minor"], Value::Null);
        assert_eq!(pending["fiat"][0]["quoted_amount_minor"], 5000);

        // Settled fiat leg valued late: credited differs from the earlier quote.
        let settled = &transactions[3]["settlement_details"];
        assert_eq!(settled["kind"], "fiat");
        assert_eq!(settled["fiat"][0]["amount_minor"], 12345);
        assert_eq!(settled["fiat"][0]["quoted_amount_minor"], 12000);

        // Mixed settlement exposes the captured split at the details level.
        let mixed = &transactions[4]["settlement_details"];
        assert_eq!(mixed["kind"], "mixed");
        assert_eq!(mixed["fiat_percentage"], 40);
        assert_eq!(mixed["fiat"][0]["quoted_amount_minor"], 12345);

        // Legacy row predating the columns: quote and percentage are JSON null.
        let legacy = &transactions[5]["settlement_details"];
        assert_eq!(legacy["fiat_percentage"], Value::Null);
        assert_eq!(legacy["fiat"][0]["quoted_amount_minor"], Value::Null);
        assert_eq!(legacy["fiat"][0]["amount_minor"], 12345);

        assert_eq!(transactions[6]["settlement_kind"], "unavailable");
    }
}
