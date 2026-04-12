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
use pay_service::config::{BoltzConfig, Config, DnsConfig, LimitsConfig};
use pay_service::{claimer, lnurl, nostr, registration, AppState};

use boltz_client::network::Network;
use boltz_client::util::secrets::SwapMasterKey;
use secp256k1::{Keypair, Message, Secp256k1};
use sha2::{Digest, Sha256};

async fn get_test_pool() -> Option<PgPool> {
    let url = std::env::var("TEST_DATABASE_URL").ok()?;
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .ok()
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
        dns: DnsConfig::default(),
        database_url: String::new(),
        swap_mnemonic: String::new(),
        easydns_api_key: None,
        easydns_api_token: None,
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
        boltz: Arc::new(BoltzService::new("http://127.0.0.1:1", swap_master_key)),
        dns: None,
    }
}

fn test_app(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/lnurlp/{nym}", get(lnurl::metadata))
        .route("/.well-known/nostr.json", get(nostr::nostr_json))
        .route("/lnurlp/callback/{nym}", get(lnurl::callback))
        .route("/register", post(registration::register))
        .route("/register", put(registration::update_registration))
        .route("/webhook/boltz", post(claimer::webhook))
        .with_state(state)
}

fn generate_registration(nym: &str, ct_descriptor: &str) -> (String, String, String) {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _) = keypair.x_only_public_key();
    let npub_hex = xonly.to_string();

    let message = format!("{}{}", nym, ct_descriptor);
    let digest = Sha256::digest(message.as_bytes());
    let msg = Message::from_digest(*digest.as_ref());
    let sig = secp.sign_schnorr(&msg, &keypair);

    (npub_hex, sig.to_string(), keypair.display_secret().to_string())
}

// Static test descriptor from "abandon...about" mnemonic — same as in descriptor.rs tests
const TEST_DESCRIPTOR: &str = "ct(slip77(0371e66dde8ab1a8f4d4c7c891c6a207a11e1bbd392147ae3a35a4ca85e92a40),elwpkh([be81a2a4/84'/1776'/0']xpub6DJJiSbjNa7GBDMBuFPxqh2uMy2pUMFNSGSCL3oJVHTc8HdJnw6AVGinMBDHb64svphEpJLc9YzRMCFMd5jP5KaDPZQMegxW2eLBigC7bgJV/0/*))";

async fn cleanup_db(pool: &PgPool) {
    sqlx::query("DELETE FROM swap_records").execute(pool).await.ok();
    sqlx::query("DELETE FROM users").execute(pool).await.ok();
}

// -- Registration tests --

#[tokio::test]
async fn register_success() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let state = test_state(pool.clone());
    let app = test_app(state);

    let (npub, sig, _) = generate_registration("testuser", TEST_DESCRIPTOR);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "nym": "testuser",
                        "ct_descriptor": TEST_DESCRIPTOR,
                        "npub": npub,
                        "signature": sig,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let body: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    ).unwrap();
    eprintln!("register response: status={status} body={body}");
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["nym"], "testuser");
    assert!(body["lightning_address"].as_str().unwrap().contains("@test.example.com"));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_duplicate_nym_fails() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let state = test_state(pool.clone());
    let app = test_app(state);

    let (npub1, sig1, _) = generate_registration("dupnym", TEST_DESCRIPTOR);
    let (npub2, sig2, _) = generate_registration("dupnym", TEST_DESCRIPTOR);

    let resp1 = app.clone()
        .oneshot(Request::builder()
            .method("POST").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"nym":"dupnym","ct_descriptor":TEST_DESCRIPTOR,"npub":npub1,"signature":sig1}).to_string()))
            .unwrap())
        .await.unwrap();
    assert_eq!(resp1.status(), StatusCode::CREATED);

    let resp2 = app
        .oneshot(Request::builder()
            .method("POST").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"nym":"dupnym","ct_descriptor":TEST_DESCRIPTOR,"npub":npub2,"signature":sig2}).to_string()))
            .unwrap())
        .await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &resp2.into_body().collect().await.unwrap().to_bytes(),
    ).unwrap();
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_invalid_signature_fails() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let state = test_state(pool.clone());
    let app = test_app(state);

    let (npub, _, _) = generate_registration("badsig", TEST_DESCRIPTOR);

    let resp = app
        .oneshot(Request::builder()
            .method("POST").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({
                "nym":"badsig",
                "ct_descriptor":TEST_DESCRIPTOR,
                "npub":npub,
                "signature":"aa".repeat(32),
            }).to_string()))
            .unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_invalid_nym_fails() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let state = test_state(pool.clone());
    let app = test_app(state);

    let (npub, sig, _) = generate_registration("AB", TEST_DESCRIPTOR);

    let resp = app
        .oneshot(Request::builder()
            .method("POST").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"nym":"AB","ct_descriptor":TEST_DESCRIPTOR,"npub":npub,"signature":sig}).to_string()))
            .unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    ).unwrap();
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

// -- LNURL metadata tests --

#[tokio::test]
async fn lnurl_metadata_for_registered_user() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let state = test_state(pool.clone());
    let app = test_app(state);

    let (npub, sig, _) = generate_registration("lnurluser", TEST_DESCRIPTOR);
    app.clone()
        .oneshot(Request::builder()
            .method("POST").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"nym":"lnurluser","ct_descriptor":TEST_DESCRIPTOR,"npub":npub,"signature":sig}).to_string()))
            .unwrap())
        .await.unwrap();

    let resp = app
        .oneshot(Request::builder().uri("/.well-known/lnurlp/lnurluser").body(Body::empty()).unwrap())
        .await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    ).unwrap();
    assert_eq!(body["tag"], "payRequest");
    assert!(body["callback"].as_str().unwrap().contains("lnurluser"));
    assert!(body["metadata"].as_str().unwrap().contains("lnurluser@test.example.com"));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn lnurl_metadata_for_unknown_nym() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let state = test_state(pool.clone());
    let app = test_app(state);

    let resp = app
        .oneshot(Request::builder().uri("/.well-known/lnurlp/nonexistent").body(Body::empty()).unwrap())
        .await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    ).unwrap();
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

// -- NIP-05 tests --

#[tokio::test]
async fn nip05_for_registered_user() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let state = test_state(pool.clone());
    let app = test_app(state);

    let (npub, sig, _) = generate_registration("nostruser", TEST_DESCRIPTOR);
    app.clone()
        .oneshot(Request::builder()
            .method("POST").uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(json!({"nym":"nostruser","ct_descriptor":TEST_DESCRIPTOR,"npub":npub,"signature":sig}).to_string()))
            .unwrap())
        .await.unwrap();

    let resp = app
        .oneshot(Request::builder().uri("/.well-known/nostr.json?name=nostruser").body(Body::empty()).unwrap())
        .await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &resp.into_body().collect().await.unwrap().to_bytes(),
    ).unwrap();
    assert_eq!(body["names"]["nostruser"], npub);

    cleanup_db(&pool).await;
}

// -- Address index allocation tests --

#[tokio::test]
async fn address_indices_are_sequential() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let (npub, _sig, _) = generate_registration("idxuser", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "idxuser", &npub, TEST_DESCRIPTOR).await.unwrap();

    for expected in 0..5 {
        let idx = pay_service::db::allocate_address_index(&pool, "idxuser").await.unwrap().unwrap();
        assert_eq!(idx, expected);
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn concurrent_address_allocation_no_duplicates() {
    let Some(pool) = get_test_pool().await else { return };
    cleanup_db(&pool).await;

    let (npub, _sig, _) = generate_registration("concuser", TEST_DESCRIPTOR);
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
    assert_eq!(unique.len(), 10);
    assert_eq!(*indices.first().unwrap(), 0);
    assert_eq!(*indices.last().unwrap(), 9);

    cleanup_db(&pool).await;
}
