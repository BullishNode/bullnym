use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::db;
use crate::error::AppError;
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
    Query(query): Query<Nip05Query>,
) -> Result<Json<Nip05Response>, AppError> {
    let user = db::get_user_by_nym(&state.db, &query.name)
        .await?
        .ok_or_else(|| AppError::NymNotFound(query.name.clone()))?;

    if !user.is_active {
        return Err(AppError::NymNotFound(query.name));
    }

    let mut names = HashMap::new();
    names.insert(user.nym, user.npub);

    Ok(Json(Nip05Response { names }))
}
