use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post, put};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

use pay_service::boltz::BoltzService;
use pay_service::config::{
    BoltzConfig, Config, ElectrumConfig, LimitsConfig, ProofConfig, RateLimitConfig,
};
use pay_service::ip_whitelist::IpWhitelist;
use pay_service::rate_limit::RateLimiter;
use pay_service::{claimer, lnurl, nostr, registration, AppState};

use boltz_client::network::Network;
use boltz_client::util::secrets::SwapMasterKey;
use secp256k1::{Keypair, Message, Secp256k1};
use sha2::{Digest, Sha256};

// --- Test infrastructure ---

fn require_test_db() -> String {
    std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set to run integration tests")
}

async fn test_pool() -> PgPool {
    let url = require_test_db();
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("failed to connect to test database")
}

fn test_config() -> Config {
    Config {
        domain: "test.example.com".to_string(),
        listen: "127.0.0.1:0".to_string(),
        pool_size: 2,
        boltz: BoltzConfig {
            api_url: "http://127.0.0.1:1".to_string(),
            electrum_url: "blockstream.info:995".to_string(),
        },
        limits: LimitsConfig::default(),
        proof: ProofConfig::default(),
        rate_limit: RateLimitConfig::default(),
        electrum: ElectrumConfig::default(),
        database_url: String::new(),
        swap_mnemonic: String::new(),
    }
}

fn test_state(pool: PgPool) -> AppState {
    let swap_master_key = SwapMasterKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        Network::Mainnet,
    ).unwrap();

    let rate_limiter = Arc::new(RateLimiter::new(pool.clone(), RateLimitConfig::default()));

    AppState {
        db: pool,
        config: Arc::new(test_config()),
        boltz: Arc::new(BoltzService::new("http://127.0.0.1:1", swap_master_key, None)),
        ip_whitelist: Arc::new(IpWhitelist::default()),
        rate_limiter,
        utxo_backend: None,
    }
}

fn test_app(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/lnurlp/:nym", get(lnurl::metadata))
        .route("/.well-known/nostr.json", get(nostr::nostr_json))
        .route("/lnurlp/callback/:nym", get(lnurl::callback))
        .route("/register", post(registration::register))
        .route("/register", put(registration::update_registration))
        .route("/register", axum::routing::delete(registration::delete_registration))
        .route("/webhook/boltz", post(claimer::webhook))
        .with_state(state)
}

fn sign_registration(nym: &str, ct_descriptor: &str) -> (String, String) {
    let (npub, sig, _) = sign_registration_with_keypair(nym, ct_descriptor);
    (npub, sig)
}

fn sign_registration_with_keypair(nym: &str, ct_descriptor: &str) -> (String, String, Keypair) {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _) = keypair.x_only_public_key();
    let npub_hex = xonly.to_string();
    let message = format!("{}{}", nym, ct_descriptor);
    let digest = Sha256::digest(message.as_bytes());
    let msg = Message::from_digest(*digest.as_ref());
    let sig = secp.sign_schnorr(&msg, &keypair);
    (npub_hex, sig.to_string(), keypair)
}

fn sign_with_keypair(keypair: &Keypair, message: &[u8]) -> String {
    let secp = Secp256k1::new();
    let digest = Sha256::digest(message);
    let msg = Message::from_digest(*digest.as_ref());
    secp.sign_schnorr(&msg, keypair).to_string()
}

// Valid CT descriptor (lwk 0.14, h-notation)
const TEST_DESCRIPTOR: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";

async fn cleanup_db(pool: &PgPool) {
    sqlx::query("DELETE FROM swap_records").execute(pool).await.ok();
    sqlx::query("DELETE FROM users").execute(pool).await.ok();
}

async fn post_json(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn get_path(app: &Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

// --- Registration tests ---

#[tokio::test]
async fn register_and_resolve() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig) = sign_registration("alice", TEST_DESCRIPTOR);
    let (status, body) = post_json(&app, "/register", json!({
        "nym": "alice",
        "ct_descriptor": TEST_DESCRIPTOR,
        "npub": npub,
        "signature": sig,
    }))
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["nym"], "alice");
    assert_eq!(body["lightning_address"], "alice@test.example.com");
    assert_eq!(body["nip05"], "alice@test.example.com");

    // LNURL metadata resolves
    let (status, body) = get_path(&app, "/.well-known/lnurlp/alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tag"], "payRequest");
    assert!(body["callback"].as_str().unwrap().contains("alice"));

    // NIP-05 resolves
    let (status, body) = get_path(&app, "/.well-known/nostr.json?name=alice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["names"]["alice"], npub);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_duplicate_nym_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub1, sig1) = sign_registration("taken", TEST_DESCRIPTOR);
    post_json(&app, "/register", json!({
        "nym": "taken", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub1, "signature": sig1,
    })).await;

    let (npub2, sig2) = sign_registration("taken", TEST_DESCRIPTOR);
    let (status, body) = post_json(&app, "/register", json!({
        "nym": "taken", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "signature": sig2,
    })).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_bad_signature_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, _) = sign_registration("badsig", TEST_DESCRIPTOR);
    let (status, _) = post_json(&app, "/register", json!({
        "nym": "badsig", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": "aa".repeat(32),
    })).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_invalid_nym_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    for bad_nym in ["AB", "a", "-bad", "bad-", "has space", "has_under", "a@b"] {
        let (npub, sig) = sign_registration(bad_nym, TEST_DESCRIPTOR);
        let (_, body) = post_json(&app, "/register", json!({
            "nym": bad_nym, "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
        })).await;
        assert_eq!(body["status"], "ERROR", "nym '{bad_nym}' should be rejected");
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn unknown_nym_returns_lnurl_error() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (status, body) = get_path(&app, "/.well-known/lnurlp/nobody").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

// --- Address index allocation ---

#[tokio::test]
async fn address_indices_are_sequential() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let (npub, _) = sign_registration("idxuser", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "idxuser", &npub, TEST_DESCRIPTOR).await.unwrap();

    for expected in 0..5 {
        let idx = pay_service::db::allocate_address_index(&pool, "idxuser").await.unwrap().unwrap();
        assert_eq!(idx, expected);
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn concurrent_address_allocation_no_duplicates() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let (npub, _) = sign_registration("concuser", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "concuser", &npub, TEST_DESCRIPTOR).await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            pay_service::db::allocate_address_index(&pool, "concuser").await.unwrap().unwrap()
        }));
    }

    let mut indices: Vec<i32> = Vec::new();
    for h in handles {
        indices.push(h.await.unwrap());
    }
    indices.sort();

    let unique: std::collections::HashSet<i32> = indices.iter().cloned().collect();
    assert_eq!(unique.len(), 10, "all 10 indices must be unique");
    assert_eq!(*indices.first().unwrap(), 0);
    assert_eq!(*indices.last().unwrap(), 9);

    cleanup_db(&pool).await;
}

// --- Webhook parsing ---

#[tokio::test]
async fn webhook_parses_boltz_envelope() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    // Webhook for unknown swap returns error
    let (status, body) = post_json(&app, "/webhook/boltz", json!({
        "event": "swap.update",
        "data": {"id": "nonexistent", "status": "transaction.mempool"}
    })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn webhook_rejects_malformed_payload() {
    let pool = test_pool().await;
    let app = test_app(test_state(pool.clone()));

    // Missing data field
    let (status, body) = post_json(&app, "/webhook/boltz", json!({"id": "x", "status": "y"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");
}

#[tokio::test]
async fn webhook_skips_terminal_swaps() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    let app = test_app(state);

    // Create a user and a fake swap record in "claimed" state
    cleanup_db(&pool).await;
    let (npub, _) = sign_registration("webhookuser", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "webhookuser", &npub, TEST_DESCRIPTOR).await.unwrap();

    pay_service::db::record_swap(&pool, &pay_service::db::NewSwapRecord {
        nym: "webhookuser",
        boltz_swap_id: "FAKE_CLAIMED",
        address: "lq1qqtest",
        address_index: 0,
        amount_sat: 1000,
        invoice: "lnbc...",
        preimage_hex: "aa".repeat(32).as_str(),
        claim_key_hex: "bb".repeat(32).as_str(),
        boltz_response_json: "{}",
    }).await.unwrap();

    // Mark as claimed
    let swap = pay_service::db::get_swap_by_boltz_id(&pool, "FAKE_CLAIMED").await.unwrap().unwrap();
    pay_service::db::update_swap_status(&pool, swap.id, pay_service::db::SwapStatus::Claimed, Some("txid123")).await.unwrap();

    // Webhook should be silently accepted (not trigger a re-claim)
    let (status, _) = post_json(&app, "/webhook/boltz", json!({
        "event": "swap.update",
        "data": {"id": "FAKE_CLAIMED", "status": "transaction.confirmed"}
    })).await;
    assert_eq!(status, StatusCode::OK);

    // Status should still be claimed
    let swap = pay_service::db::get_swap_by_boltz_id(&pool, "FAKE_CLAIMED").await.unwrap().unwrap();
    assert_eq!(swap.status, "claimed");

    cleanup_db(&pool).await;
}

// --- LNURL callback validation ---

#[tokio::test]
async fn callback_rejects_invalid_amounts() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    let app = test_app(state);

    // Register a user first
    let (npub, sig) = sign_registration("amtuser", TEST_DESCRIPTOR);
    post_json(&app, "/register", json!({
        "nym": "amtuser", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;

    // Below minimum (default 100k msat = 100 sats)
    let (_, body) = get_path(&app, "/lnurlp/callback/amtuser?amount=1000").await;
    assert_eq!(body["status"], "ERROR");

    // Not divisible by 1000
    let (_, body) = get_path(&app, "/lnurlp/callback/amtuser?amount=100500").await;
    assert_eq!(body["status"], "ERROR");

    // Above maximum
    let (_, body) = get_path(&app, "/lnurlp/callback/amtuser?amount=99000000000000").await;
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

// --- Delete registration ---

#[tokio::test]
async fn delete_registration_deactivates_user() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _) = keypair.x_only_public_key();
    let npub_hex = xonly.to_string();

    // Register
    let message = format!("{}{}", "deluser", TEST_DESCRIPTOR);
    let digest = Sha256::digest(message.as_bytes());
    let msg = Message::from_digest(*digest.as_ref());
    let sig = secp.sign_schnorr(&msg, &keypair);

    post_json(&app, "/register", json!({
        "nym": "deluser", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub_hex, "signature": sig.to_string(),
    })).await;

    // Delete
    let del_digest = Sha256::digest(b"delete");
    let del_msg = Message::from_digest(*del_digest.as_ref());
    let del_sig = secp.sign_schnorr(&del_msg, &keypair);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(json!({"npub": npub_hex, "signature": del_sig.to_string()}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // LNURL should no longer resolve
    let (_, body) = get_path(&app, "/.well-known/lnurlp/deluser").await;
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

// --- Nym lifecycle tests ---

#[tokio::test]
async fn reregister_after_delete_succeeds() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("lifecycle1", TEST_DESCRIPTOR);

    // Register
    let (status, _) = post_json(&app, "/register", json!({
        "nym": "lifecycle1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;
    assert_eq!(status, StatusCode::CREATED);

    // Delete
    let del_sig = sign_with_keypair(&keypair, b"delete");
    let resp = app.clone().oneshot(
        Request::builder()
            .method("DELETE").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"npub": npub, "signature": del_sig}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Re-register with new nym, same npub
    let new_msg = format!("{}{}", "lifecycle2", TEST_DESCRIPTOR);
    let new_sig = sign_with_keypair(&keypair, new_msg.as_bytes());
    let (status, body) = post_json(&app, "/register", json!({
        "nym": "lifecycle2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": new_sig,
    })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["nym"], "lifecycle2");

    // New nym resolves
    let (_, body) = get_path(&app, "/.well-known/lnurlp/lifecycle2").await;
    assert_eq!(body["tag"], "payRequest");

    // Old nym does not resolve
    let (_, body) = get_path(&app, "/.well-known/lnurlp/lifecycle1").await;
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn reregister_same_nym_after_delete() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("samename", TEST_DESCRIPTOR);

    // Register
    post_json(&app, "/register", json!({
        "nym": "samename", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;

    // Delete
    let del_sig = sign_with_keypair(&keypair, b"delete");
    app.clone().oneshot(
        Request::builder()
            .method("DELETE").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"npub": npub, "signature": del_sig}).to_string()))
            .unwrap(),
    ).await.unwrap();

    // Re-register same nym — should reactivate
    let re_sig = sign_with_keypair(&keypair, format!("{}{}", "samename", TEST_DESCRIPTOR).as_bytes());
    let (status, body) = post_json(&app, "/register", json!({
        "nym": "samename", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": re_sig,
    })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["nym"], "samename");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_while_active_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("active1", TEST_DESCRIPTOR);

    // Register first nym
    let (status, _) = post_json(&app, "/register", json!({
        "nym": "active1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;
    assert_eq!(status, StatusCode::CREATED);

    // Try registering second nym with same npub while first is active
    let msg2 = format!("{}{}", "active2", TEST_DESCRIPTOR);
    let sig2 = sign_with_keypair(&keypair, msg2.as_bytes());
    let (status, body) = post_json(&app, "/register", json!({
        "nym": "active2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig2,
    })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn deleted_nym_reserved_from_others() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub1, sig1, keypair1) = sign_registration_with_keypair("reserved", TEST_DESCRIPTOR);

    // User 1 registers and deletes
    post_json(&app, "/register", json!({
        "nym": "reserved", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub1, "signature": sig1,
    })).await;

    let del_sig = sign_with_keypair(&keypair1, b"delete");
    app.clone().oneshot(
        Request::builder()
            .method("DELETE").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"npub": npub1, "signature": del_sig}).to_string()))
            .unwrap(),
    ).await.unwrap();

    // User 2 tries to claim the same nym — should fail
    let (npub2, sig2) = sign_registration("reserved", TEST_DESCRIPTOR);
    let (_, body) = post_json(&app, "/register", json!({
        "nym": "reserved", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "signature": sig2,
    })).await;
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

// --- Purge (destructive delete with reservation) ---

async fn delete_request(app: &Router, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn insert_swap(pool: &PgPool, nym: &str, status: &str, addr_idx: i32) {
    sqlx::query(
        "INSERT INTO swap_records \
         (nym, boltz_swap_id, address, address_index, amount_sat, invoice, \
          preimage_hex, claim_key_hex, boltz_response_json, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(nym)
    .bind(format!("boltz-{nym}-{addr_idx}"))
    .bind(format!("lq1addr{addr_idx}"))
    .bind(addr_idx)
    .bind(1000i64)
    .bind("lnbc10n1...")
    .bind("aa".repeat(32))
    .bind("bb".repeat(32))
    .bind("{}")
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn purge_with_no_swaps_scrubs_descriptor_and_keeps_nym_reserved() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("purger1", TEST_DESCRIPTOR);
    post_json(&app, "/register", json!({
        "nym": "purger1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;

    let purge_sig = sign_with_keypair(&keypair, b"purge");
    let (status, _) = delete_request(&app, json!({
        "npub": npub, "signature": purge_sig, "purge": true,
    })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // LNURL no longer resolves
    let (_, body) = get_path(&app, "/.well-known/lnurlp/purger1").await;
    assert_eq!(body["status"], "ERROR");

    // Row survives with scrubbed descriptor and is_active=false
    let row: (bool, String) = sqlx::query_as(
        "SELECT is_active, ct_descriptor FROM users WHERE nym = $1",
    )
    .bind("purger1")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!row.0);
    assert_eq!(row.1, "");

    // Another npub cannot claim the reserved nym
    let (npub2, sig2) = sign_registration("purger1", TEST_DESCRIPTOR);
    let (_, body) = post_json(&app, "/register", json!({
        "nym": "purger1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "signature": sig2,
    })).await;
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn purge_blocked_when_pending_swap_exists() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("purger2", TEST_DESCRIPTOR);
    post_json(&app, "/register", json!({
        "nym": "purger2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;
    insert_swap(&pool, "purger2", "pending", 0).await;
    insert_swap(&pool, "purger2", "lockup_confirmed", 1).await;

    let purge_sig = sign_with_keypair(&keypair, b"purge");
    let (_, body) = delete_request(&app, json!({
        "npub": npub, "signature": purge_sig, "purge": true,
    })).await;
    assert_eq!(body["code"], "PurgeBlocked");
    assert!(body["reason"].as_str().unwrap().contains("2"));

    // User still active, swaps untouched
    let active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE nym = 'purger2'")
        .fetch_one(&pool).await.unwrap();
    assert!(active);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = 'purger2'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn purge_drops_only_terminal_swap_history() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("purger3", TEST_DESCRIPTOR);
    post_json(&app, "/register", json!({
        "nym": "purger3", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;
    insert_swap(&pool, "purger3", "claimed", 0).await;
    insert_swap(&pool, "purger3", "expired", 1).await;

    let purge_sig = sign_with_keypair(&keypair, b"purge");
    let (status, _) = delete_request(&app, json!({
        "npub": npub, "signature": purge_sig, "purge": true,
    })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = 'purger3'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn delete_signature_does_not_authorize_purge() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("purger4", TEST_DESCRIPTOR);
    post_json(&app, "/register", json!({
        "nym": "purger4", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;
    insert_swap(&pool, "purger4", "claimed", 0).await;

    // Sign the soft-delete challenge but try to use it for purge
    let delete_sig = sign_with_keypair(&keypair, b"delete");
    let (status, _) = delete_request(&app, json!({
        "npub": npub, "signature": delete_sig, "purge": true,
    })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // User still active, swap_records intact
    let active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE nym = 'purger4'")
        .fetch_one(&pool).await.unwrap();
    assert!(active);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = 'purger4'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn purge_then_owner_reregisters_same_nym() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, keypair) = sign_registration_with_keypair("purger5", TEST_DESCRIPTOR);
    post_json(&app, "/register", json!({
        "nym": "purger5", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig,
    })).await;

    let purge_sig = sign_with_keypair(&keypair, b"purge");
    delete_request(&app, json!({
        "npub": npub, "signature": purge_sig, "purge": true,
    })).await;

    // Same owner re-registers same nym
    let re_sig = sign_with_keypair(&keypair, format!("{}{}", "purger5", TEST_DESCRIPTOR).as_bytes());
    let (status, body) = post_json(&app, "/register", json!({
        "nym": "purger5", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": re_sig,
    })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["nym"], "purger5");

    cleanup_db(&pool).await;
}

#[test]
fn schnorr_sign_verify_roundtrip() {
    // This tests the exact same flow the mobile app uses:
    // 1. Generate a keypair
    // 2. Sign SHA256(message) with schnorr
    // 3. Verify with our auth::verify_signature
    
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
    use sha2::{Digest, Sha256};
    
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _parity) = keypair.x_only_public_key();
    let npub_hex = xonly.to_string();
    
    let message = b"tester1ct(slip77(...),elwpkh(...))";
    let digest = Sha256::digest(message);
    let msg = secp256k1::Message::from_digest(*digest.as_ref());
    let sig = secp.sign_schnorr(&msg, &keypair);
    let sig_hex = sig.to_string();
    
    println!("npub: {npub_hex}");
    println!("sig:  {sig_hex}");
    println!("sig len: {}", sig_hex.len());
    
    // Verify using our auth module
    let result = pay_service::auth::verify_signature(&npub_hex, message, &sig_hex);
    assert!(result.is_ok(), "Signature verification failed: {:?}", result);
}
