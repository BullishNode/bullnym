//! Merchant-authenticated history for private LNURL payer comments.
//!
//! This is the only HTTP projection of the private comment ledger. The route
//! is identity-wide and LA-v2 signed, selects only payment-evidenced intents,
//! and returns a deliberately narrow DTO. Public invoice, LNURL, Page/POS,
//! status, and rendering handlers do not import this module.

use std::net::SocketAddr;
use std::str::FromStr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth;
use crate::certification::{self, CertificationScope};
use crate::db::{
    self, LnurlCommentIntent, MAX_AUTHENTICATED_HISTORY_PAGE_NUMBER,
    MAX_AUTHENTICATED_HISTORY_PAGE_SIZE,
};
use crate::error::AppError;
use crate::ip_whitelist;
use crate::AppState;

/// LA-v2 action allocated to the private, identity-wide comment history.
pub const ACTION_LNURL_COMMENT_HISTORY: &str = "lnurl-comment-history";

/// Merchant-signed query. Pagination changes the returned private data and is
/// therefore part of the signed payload in exact `[page, pageSize]` order.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LnurlCommentHistoryQuery {
    pub npub: String,
    pub timestamp: u64,
    pub signature: String,
    pub page: i64,
    #[serde(rename = "pageSize")]
    pub page_size: i64,
}

/// Narrow authenticated projection of one evidenced payer comment.
///
/// It intentionally omits the merchant npub, intent digest, payment rail,
/// instruction/provider reference, payment-evidence reference, and pre-payment
/// creation timestamp. `comment` is copied byte-for-byte from the validated
/// stored UTF-8 string; JSON escaping changes representation, not its decoded
/// bytes.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct LnurlCommentHistoryItem {
    pub intent_id: Uuid,
    pub nym: String,
    pub amount_msat: u64,
    pub comment: String,
    pub received_at_unix: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct LnurlCommentHistoryResponse {
    pub comments: Vec<LnurlCommentHistoryItem>,
    pub page: u16,
    #[serde(rename = "pageSize")]
    pub page_size: u16,
    pub has_more: bool,
}

/// `GET /api/v1/lnurl/comments` — list only this authenticated merchant's
/// payment-evidenced comments in stable newest-first order.
///
/// The merchant need not remain active: immutable received-payment history
/// survives deactivation and restart. Authentication still proves possession
/// of the exact identity key on every request.
pub async fn list_signed(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<LnurlCommentHistoryQuery>,
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
        "signed_lnurl_comment_history",
        Some(&query.npub),
    );
    if !is_whitelisted && !is_certification_allowed {
        if let Some(address) = ip {
            state.rate_limiter.check_api_per_ip(address).await?;
        }
    }

    let (page, page_size) = validate_page(query.page, query.page_size)?;
    validate_canonical_npub(&query.npub)?;
    let page_text = page.to_string();
    let page_size_text = page_size.to_string();
    auth::verify_la_v2(
        ACTION_LNURL_COMMENT_HISTORY,
        &query.npub,
        "",
        &[&page_text, &page_size_text],
        query.timestamp,
        &query.signature,
    )?;

    let history = db::list_received_lnurl_comments_page_for_authenticated_merchant(
        &state.db,
        &query.npub,
        page,
        page_size,
    )
    .await
    .map_err(map_history_error)?;
    let comments = history
        .intents
        .into_iter()
        .map(project_evidenced_intent)
        .collect::<Result<Vec<_>, _>>()?;

    let mut response = Json(LnurlCommentHistoryResponse {
        comments,
        page,
        page_size,
        has_more: history.has_more,
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

/// Build the byte-exact message clients sign for one history page.
pub fn build_lnurl_comment_history_message(
    npub: &str,
    page: i64,
    page_size: i64,
    timestamp: u64,
) -> Result<Vec<u8>, AppError> {
    let (page, page_size) = validate_page(page, page_size)?;
    validate_canonical_npub(npub)?;
    let page_text = page.to_string();
    let page_size_text = page_size.to_string();
    Ok(auth::build_la_v2_message(
        ACTION_LNURL_COMMENT_HISTORY,
        npub,
        "",
        &[&page_text, &page_size_text],
        timestamp,
    ))
}

fn validate_page(page: i64, page_size: i64) -> Result<(u16, u16), AppError> {
    let page = u16::try_from(page)
        .ok()
        .filter(|value| (1..=MAX_AUTHENTICATED_HISTORY_PAGE_NUMBER).contains(value))
        .ok_or_else(|| {
            AppError::InvalidAmount(format!(
                "page must be between 1 and {MAX_AUTHENTICATED_HISTORY_PAGE_NUMBER}"
            ))
        })?;
    let page_size = u16::try_from(page_size)
        .ok()
        .filter(|value| (1..=MAX_AUTHENTICATED_HISTORY_PAGE_SIZE).contains(value))
        .ok_or_else(|| {
            AppError::InvalidAmount(format!(
                "pageSize must be between 1 and {MAX_AUTHENTICATED_HISTORY_PAGE_SIZE}"
            ))
        })?;
    Ok((page, page_size))
}

fn validate_canonical_npub(npub: &str) -> Result<(), AppError> {
    let parsed = XOnlyPublicKey::from_str(npub)
        .map_err(|_| AppError::AuthError("invalid LNURL comment history npub".into()))?;
    if parsed.to_string() != npub {
        return Err(AppError::AuthError(
            "LNURL comment history npub must be canonical lowercase hex".into(),
        ));
    }
    Ok(())
}

fn project_evidenced_intent(
    intent: LnurlCommentIntent,
) -> Result<LnurlCommentHistoryItem, AppError> {
    let received_at_unix = intent
        .payment_evidence
        .as_ref()
        .map(|evidence| evidence.evidenced_at_unix)
        .ok_or_else(|| {
            AppError::DbError("private LNURL comment history projection failed".into())
        })?;
    Ok(LnurlCommentHistoryItem {
        intent_id: intent.intent_id,
        nym: intent.nym().to_owned(),
        amount_msat: intent.amount_msat,
        comment: intent.comment().as_str().to_owned(),
        received_at_unix,
    })
}

fn map_history_error(_: db::LnurlCommentPersistenceError) -> AppError {
    // Raw SQL and stored-value errors can contain private comment text or
    // correlation references. Never move them into AppError or its logs.
    AppError::DbError("private LNURL comment history query failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_message_has_identity_wide_canonical_page_fields() {
        let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let timestamp = 1_700_000_000;
        let actual = build_lnurl_comment_history_message(npub, 2, 50, timestamp).unwrap();
        let expected = auth::build_la_v2_message(
            ACTION_LNURL_COMMENT_HISTORY,
            npub,
            "",
            &["2", "50"],
            timestamp,
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn signing_message_rejects_noncanonical_identity_and_unbounded_pages() {
        let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(build_lnurl_comment_history_message(&npub.to_uppercase(), 1, 10, 1).is_err());
        assert!(build_lnurl_comment_history_message(npub, 0, 10, 1).is_err());
        assert!(build_lnurl_comment_history_message(
            npub,
            1,
            i64::from(MAX_AUTHENTICATED_HISTORY_PAGE_SIZE) + 1,
            1,
        )
        .is_err());
    }
}
