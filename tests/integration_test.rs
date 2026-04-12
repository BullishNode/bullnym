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
use pay_service::config::{BoltzConfig, Config, LimitsConfig};
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

    AppState {
        db: pool,
        config: Arc::new(test_config()),
        boltz: Arc::new(BoltzService::new("http://127.0.0.1:1", swap_master_key, None)),
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
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _) = keypair.x_only_public_key();
    let npub_hex = xonly.to_string();
    let message = format!("{}{}", nym, ct_descriptor);
    let digest = Sha256::digest(message.as_bytes());
    let msg = Message::from_digest(*digest.as_ref());
    let sig = secp.sign_schnorr(&msg, &keypair);
    (npub_hex, sig.to_string())
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
