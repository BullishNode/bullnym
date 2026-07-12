//! Esplora (mempool.space-shape) REST helpers with multi-endpoint failover.
//!
//! bullnym's Bitcoin backend is a single esplora endpoint (`bitcoin_watcher
//! .endpoint`) used for the chain-refund broadcast + the recovery confirmation
//! gate. A real incident showed a single "up-but-broken" node (returned
//! `sendrawtransaction code -1` for every tx, incl. a valid confirmed one)
//! blocking all broadcast. These helpers try an ordered list of endpoints so a
//! single broken/down provider can't stall the operation. See issue #47.

use std::time::Duration;

use crate::error::AppError;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap_or_default()
}

/// Broadcast a raw transaction hex to `endpoints` in order until one accepts.
/// Returns the txid. Success is either a 2xx txid response OR an "already
/// known" rejection (the tx is already in a mempool/block — treat as success
/// and return `expected_txid`, since re-broadcasting an idempotent tx is fine).
/// Errors only if EVERY endpoint returns a genuine rejection, so one broken or
/// down node cannot block the broadcast.
pub async fn broadcast(
    endpoints: &[String],
    tx_hex: &str,
    expected_txid: &str,
) -> Result<String, AppError> {
    let client = http_client();
    let mut errors: Vec<String> = Vec::new();
    for ep in endpoints {
        let url = format!("{}/tx", ep.trim_end_matches('/'));
        match client.post(&url).body(tx_hex.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    if let Some(txid) = accepted_response_txid(&body, expected_txid) {
                        tracing::info!(event = "btc_esplora_broadcast_ok", endpoint = %ep, txid = %txid);
                        return Ok(txid);
                    }
                    let txid = body.trim().to_lowercase();
                    errors.push(format!(
                        "{ep}: 2xx but returned txid '{txid}', expected '{expected_txid}'"
                    ));
                } else if is_already_known(&body) {
                    tracing::info!(
                        event = "btc_esplora_broadcast_already_known",
                        endpoint = %ep,
                        "tx already known to node; treating as broadcast success"
                    );
                    return Ok(expected_txid.to_string());
                } else {
                    tracing::warn!(event = "btc_esplora_failover", op = "broadcast", endpoint = %ep, status = %status, err = %body);
                    errors.push(format!("{ep}: {status} {body}"));
                }
            }
            Err(e) => {
                tracing::warn!(event = "btc_esplora_failover", op = "broadcast", endpoint = %ep, err = %e);
                errors.push(format!("{ep}: {e}"));
            }
        }
    }
    tracing::error!(
        event = "btc_esplora_all_endpoints_failed",
        op = "broadcast",
        endpoints = endpoints.len(),
        "all esplora endpoints rejected the broadcast"
    );
    Err(AppError::ElectrumError(format!(
        "broadcast failed on all {} esplora endpoint(s): {}",
        endpoints.len(),
        errors.join(" | ")
    )))
}

fn accepted_response_txid(body: &str, expected_txid: &str) -> Option<String> {
    let returned = body.trim().to_lowercase();
    (returned == expected_txid.to_lowercase()).then_some(returned)
}

/// A `sendrawtransaction`/esplora rejection body indicating our tx is already
/// in a mempool or block — an idempotent-broadcast success, not a failure.
///
/// IMPORTANT: this must only match "the tx WE sent is already known", never
/// "these inputs are missing/spent". In particular `code -25`
/// (`bad-txns-inputs-missingorspent` / `missing-inputs`) is deliberately NOT
/// treated as success: a lagging failover node that hasn't indexed the lockup
/// would return -25, and mis-reading that as success would mark the swap
/// terminally `refunded`/`claimed` with a txid no node ever accepted (a phantom
/// terminal state, unrecoverable). `-27` and the "already in ..." phrasings are
/// safe — Core returns plain success for genuine mempool duplicates, so those
/// only surface for txs that really are known.
fn is_already_known(body: &str) -> bool {
    let b = body.to_lowercase();
    b.contains("already in utxo set")
        || b.contains("already in block chain")
        || b.contains("txn-already-known")
        || b.contains("already known")
        || b.contains("\"code\":-27")
        || b.contains("code: -27")
}

/// GET+decode JSON from the first `endpoints` entry that answers 2xx with a
/// parseable body. Returns `None` if every endpoint fails (caller decides the
/// fail-safe default).
pub async fn get_json<T: serde::de::DeserializeOwned>(
    endpoints: &[String],
    path: &str,
) -> Option<T> {
    let client = http_client();
    let path = path.trim_start_matches('/');
    for ep in endpoints {
        let url = format!("{}/{}", ep.trim_end_matches('/'), path);
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<T>().await {
                Ok(v) => return Some(v),
                Err(e) => {
                    tracing::warn!(event = "btc_esplora_failover", op = "get_json", endpoint = %ep, err = %e)
                }
            },
            Ok(resp) => {
                tracing::warn!(event = "btc_esplora_failover", op = "get_json", endpoint = %ep, status = %resp.status())
            }
            Err(e) => {
                tracing::warn!(event = "btc_esplora_failover", op = "get_json", endpoint = %ep, err = %e)
            }
        }
    }
    tracing::error!(
        event = "btc_esplora_all_endpoints_failed",
        op = "get_json",
        path = %path,
        endpoints = endpoints.len(),
        "all esplora endpoints failed a GET"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::{accepted_response_txid, is_already_known};

    #[test]
    fn successful_broadcast_body_must_match_locally_computed_txid() {
        let expected = "ab".repeat(32);
        assert_eq!(
            accepted_response_txid(&expected.to_uppercase(), &expected),
            Some(expected.clone())
        );
        assert_eq!(accepted_response_txid(&"cd".repeat(32), &expected), None);
        assert_eq!(accepted_response_txid("not-a-txid", &expected), None);
    }

    #[test]
    fn already_known_classifier_excludes_missing_inputs() {
        assert!(is_already_known("txn-already-known"));
        assert!(is_already_known(
            r#"{"code":-27,"message":"already in chain"}"#
        ));
        assert!(!is_already_known(
            r#"{"code":-25,"message":"bad-txns-inputs-missingorspent"}"#
        ));
    }
}
