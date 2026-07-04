use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::db;
use crate::error::AppError;
use crate::lnurl;
use crate::AppState;

#[derive(Deserialize)]
pub struct Nip05Query {
    pub name: String,
}

#[derive(Serialize)]
pub struct Nip05Response {
    pub names: HashMap<String, String>,
}

/// NIP-05: `GET /.well-known/nostr.json?name={nym}`
pub async fn nostr_json(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<Nip05Query>,
) -> Result<Json<Nip05Response>, AppError> {
    // Rate-limit the same way as `/.well-known/lnurlp/:nym`. Both
    // endpoints leak nym-existence the same way; share the bucket so an
    // attacker can't double their budget by alternating endpoints.
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    lnurl::gate_metadata_per_ip(&state, peer, &headers, Some(&query.name)).await?;

    let user = db::get_active_user_by_nym(&state.db, &query.name)
        .await?
        .ok_or_else(|| AppError::NymNotFound(query.name.clone()))?;

    // NIP-05 is opt-in: a nym that never registered a dedicated verification
    // key has no public NIP-05 record. Return 404 rather than falling back to
    // the auth key (`npub`), which would collapse ADR-004 role separation.
    let verification_npub = user
        .verification_npub
        .ok_or_else(|| AppError::NymNotFound(query.name.clone()))?;

    let mut names = HashMap::new();
    names.insert(user.nym, verification_npub);

    Ok(Json(Nip05Response { names }))
}
