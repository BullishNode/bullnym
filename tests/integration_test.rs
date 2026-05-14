use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post, put};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

use pay_service::boltz::BoltzService;
use pay_service::config::{
    BitcoinWatcherConfig, BoltzConfig, ClaimConfig, Config, DonationConfig, ElectrumConfig,
    InvoiceAccountingConfig, LimitsConfig, PricerConfig, ProofConfig, RateLimitConfig,
    ReconcilerConfig,
};
use pay_service::ip_whitelist::IpWhitelist;
use pay_service::pricer::PricerClient;
use pay_service::rate_limit::RateLimiter;
use pay_service::{claimer, invoice, lnurl, nostr, registration, AppState};

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
        pricer: PricerConfig::default(),
        donation: DonationConfig::default(),
        limits: LimitsConfig::default(),
        proof: ProofConfig::default(),
        rate_limit: RateLimitConfig::default(),
        electrum: ElectrumConfig::default(),
        claim: ClaimConfig::default(),
        reconciler: ReconcilerConfig::default(),
        bitcoin_watcher: BitcoinWatcherConfig::default(),
        invoice_accounting: InvoiceAccountingConfig::default(),
        database_url: String::new(),
        swap_mnemonic: String::new(),
        boltz_webhook_url_secret: String::new(),
        boltz_webhook_url_secret_previous: String::new(),
    }
}

fn test_state(pool: PgPool) -> AppState {
    let swap_master_key = SwapMasterKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        Network::Mainnet,
    ).unwrap();

    let rate_limiter = Arc::new(RateLimiter::new(pool.clone(), RateLimitConfig::default()));
    let pricer = Arc::new(PricerClient::new(PricerConfig::default()).unwrap());

    AppState {
        db: pool,
        config: Arc::new(test_config()),
        boltz: Arc::new(BoltzService::new(
            "http://127.0.0.1:1",
            swap_master_key,
            None,
        )),
        ip_whitelist: Arc::new(IpWhitelist::default()),
        rate_limiter,
        utxo_backend: None,
        pricer,
    }
}

fn test_app(state: AppState) -> Router {
    Router::new()
        .route("/.well-known/lnurlp/:nym", get(lnurl::metadata))
        .route("/.well-known/nostr.json", get(nostr::nostr_json))
        .route("/lnurlp/callback/:nym", get(lnurl::callback))
        .route("/register", post(registration::register))
        .route("/register", put(registration::update_registration))
        .route(
            "/register",
            axum::routing::delete(registration::delete_registration),
        )
        .route("/api/v1/invoices", post(invoice::create_signed_unlinked))
        .route("/webhook/boltz", post(claimer::webhook_unauthenticated))
        .with_state(state)
}

fn auth_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_registration(nym: &str, ct_descriptor: &str) -> (String, String, u64) {
    let (npub, sig, timestamp, _) = sign_registration_with_keypair(nym, ct_descriptor);
    (npub, sig, timestamp)
}

fn sign_registration_with_keypair(
    nym: &str,
    ct_descriptor: &str,
) -> (String, String, u64, Keypair) {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _) = keypair.x_only_public_key();
    let npub_hex = xonly.to_string();
    let (sig, timestamp) = sign_register_with_keypair(&keypair, &npub_hex, nym, ct_descriptor);
    (npub_hex, sig, timestamp, keypair)
}

fn sign_with_keypair(keypair: &Keypair, message: &[u8]) -> String {
    let secp = Secp256k1::new();
    let digest = Sha256::digest(message);
    let msg = Message::from_digest(*digest.as_ref());
    secp.sign_schnorr(&msg, keypair).to_string()
}

fn sign_la_action_with_timestamp(
    keypair: &Keypair,
    action: &str,
    npub: &str,
    nym: &str,
    payload_fields: &[&str],
    timestamp: u64,
) -> String {
    let message =
        pay_service::auth::build_la_v2_message(action, npub, nym, payload_fields, timestamp);
    sign_with_keypair(keypair, &message)
}

fn sign_la_action(
    keypair: &Keypair,
    action: &str,
    npub: &str,
    nym: &str,
    payload_fields: &[&str],
) -> (String, u64) {
    let timestamp = auth_timestamp();
    let sig = sign_la_action_with_timestamp(keypair, action, npub, nym, payload_fields, timestamp);
    (sig, timestamp)
}

fn sign_register_with_keypair(
    keypair: &Keypair,
    npub: &str,
    nym: &str,
    ct_descriptor: &str,
) -> (String, u64) {
    sign_la_action(keypair, "register", npub, nym, &[ct_descriptor])
}

fn sign_delete_with_keypair(keypair: &Keypair, npub: &str, nym: &str) -> (String, u64) {
    sign_la_action(keypair, "delete", npub, nym, &[])
}

fn sign_purge_with_keypair(keypair: &Keypair, npub: &str, nym: &str) -> (String, u64) {
    sign_la_action(keypair, "purge", npub, nym, &[])
}

fn sign_invoice_create_with_keypair(
    keypair: &Keypair,
    npub: &str,
    bitcoin_address: &str,
    expires_at_unix: i64,
) -> (String, u64) {
    let amount_sat = "1000";
    let fiat_amount_minor = "";
    let fiat_currency = "";
    let public_description = "";
    let recipient_name = "";
    let invoice_number = "";
    let accept_btc = "true";
    let accept_ln = "false";
    let accept_liquid = "false";
    let liquid_address = "";
    let liquid_blinding_key_hex = "";
    let expires_at = expires_at_unix.to_string();
    sign_la_action(
        keypair,
        "invoice-create",
        npub,
        "",
        &[
            amount_sat,
            fiat_amount_minor,
            fiat_currency,
            public_description,
            recipient_name,
            invoice_number,
            accept_btc,
            accept_ln,
            accept_liquid,
            bitcoin_address,
            liquid_address,
            liquid_blinding_key_hex,
            &expires_at,
        ],
    )
}

fn sign_invoice_create_without_expiry_with_keypair(
    keypair: &Keypair,
    npub: &str,
    bitcoin_address: &str,
) -> (String, u64) {
    let amount_sat = "1000";
    let fiat_amount_minor = "";
    let fiat_currency = "";
    let public_description = "";
    let recipient_name = "";
    let invoice_number = "";
    let accept_btc = "true";
    let accept_ln = "false";
    let accept_liquid = "false";
    let liquid_address = "";
    let liquid_blinding_key_hex = "";
    let expires_at = "";
    sign_la_action(
        keypair,
        "invoice-create",
        npub,
        "",
        &[
            amount_sat,
            fiat_amount_minor,
            fiat_currency,
            public_description,
            recipient_name,
            invoice_number,
            accept_btc,
            accept_ln,
            accept_liquid,
            bitcoin_address,
            liquid_address,
            liquid_blinding_key_hex,
            expires_at,
        ],
    )
}

// Valid CT descriptor (lwk 0.14, h-notation)
const TEST_DESCRIPTOR: &str = "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl";

async fn cleanup_db(pool: &PgPool) {
    sqlx::query("DELETE FROM processed_webhook_events")
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM chain_swap_records")
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM swap_records")
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM invoices").execute(pool).await.ok();
    sqlx::query("DELETE FROM donation_pages")
        .execute(pool)
        .await
        .ok();
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

    let (npub, sig, timestamp) = sign_registration("alice", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "alice",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": npub,
            "signature": sig,
            "timestamp": timestamp,
        }),
    )
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

    let (npub1, sig1, timestamp1) = sign_registration("taken", TEST_DESCRIPTOR);
    post_json(
        &app,
        "/register",
        json!({
            "nym": "taken", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub1, "signature": sig1, "timestamp": timestamp1,
        }),
    )
    .await;

    let (npub2, sig2, timestamp2) = sign_registration("taken", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "taken", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "signature": sig2, "timestamp": timestamp2,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_bad_signature_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, _, timestamp) = sign_registration("badsig", TEST_DESCRIPTOR);
    let (status, _) = post_json(&app, "/register", json!({
        "nym": "badsig", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": "aa".repeat(32), "timestamp": timestamp,
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
        let (npub, sig, timestamp) = sign_registration(bad_nym, TEST_DESCRIPTOR);
        let (_, body) = post_json(
            &app,
            "/register",
            json!({
                "nym": bad_nym, "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
            }),
        )
        .await;
        assert_eq!(
            body["status"], "ERROR",
            "nym '{bad_nym}' should be rejected"
        );
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

    let (npub, _, _) = sign_registration("idxuser", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "idxuser", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    for expected in 0..5 {
        let idx = pay_service::db::allocate_address_index(&pool, "idxuser")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(idx, expected);
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn concurrent_address_allocation_no_duplicates() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let (npub, _, _) = sign_registration("concuser", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "concuser", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    let mut handles = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            pay_service::db::allocate_address_index(&pool, "concuser")
                .await
                .unwrap()
                .unwrap()
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

    // Webhook for unknown swap is acknowledged so Boltz does not retry a
    // swap we never created or already purged.
    let (status, body) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "nonexistent", "status": "transaction.mempool"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Value::Null);

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
    let (npub, _, _) = sign_registration("webhookuser", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "webhookuser", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("webhookuser"),
            boltz_swap_id: "FAKE_CLAIMED",
            address: Some("lq1qqtest"),
            address_index: Some(0),
            amount_sat: 1000,
            invoice: "lnbc...",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: None,
        },
    )
    .await
    .unwrap();

    // Mark as claimed
    let swap = pay_service::db::get_swap_by_boltz_id(&pool, "FAKE_CLAIMED")
        .await
        .unwrap()
        .unwrap();
    pay_service::db::update_swap_status(
        &pool,
        swap.id,
        pay_service::db::SwapStatus::Claimed,
        Some("txid123"),
    )
    .await
    .unwrap();

    // Webhook should be silently accepted (not trigger a re-claim)
    let (status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "FAKE_CLAIMED", "status": "transaction.confirmed"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Status should still be claimed
    let swap = pay_service::db::get_swap_by_boltz_id(&pool, "FAKE_CLAIMED")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.status, "claimed");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn webhook_advances_chain_swap_records() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    let app = test_app(state);

    let npub = create_test_user(&pool, "chainwebhook").await;
    let invoice = insert_test_invoice(&pool, "chainwebhook", &npub, "lq1chainwebhook", 60).await;
    pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some("chainwebhook"),
            boltz_swap_id: "CHAIN_WEBHOOK_1",
            lockup_address: "bc1qchainwebhooklockup",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"CHAIN_WEBHOOK_1\"}",
        },
    )
    .await
    .unwrap();

    let (status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "CHAIN_WEBHOOK_1", "status": "transaction.server.confirmed"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let row = pay_service::db::get_chain_swap_by_boltz_id(&pool, "CHAIN_WEBHOOK_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "server_lock_confirmed");
    let invoice_after = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invoice_after.status, "in_progress");
    assert_eq!(invoice_after.settlement_status, "pending");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn webhook_skips_terminal_chain_swap_records() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    let app = test_app(state);

    let npub = create_test_user(&pool, "chainterminal").await;
    let invoice = insert_test_invoice(&pool, "chainterminal", &npub, "lq1chainterminal", 60).await;
    let row = pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some("chainterminal"),
            boltz_swap_id: "CHAIN_TERMINAL_1",
            lockup_address: "bc1qchainterminallockup",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"CHAIN_TERMINAL_1\"}",
        },
    )
    .await
    .unwrap();
    pay_service::db::update_chain_swap_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapStatus::Claimed,
        Some("chain-claim-txid"),
    )
    .await
    .unwrap();

    let (status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "CHAIN_TERMINAL_1", "status": "transaction.refunded"}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let row = pay_service::db::get_chain_swap_by_boltz_id(&pool, "CHAIN_TERMINAL_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "claimed");
    assert_eq!(row.claim_txid.as_deref(), Some("chain-claim-txid"));

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
    let (npub, sig, timestamp) = sign_registration("amtuser", TEST_DESCRIPTOR);
    post_json(
        &app,
        "/register",
        json!({
            "nym": "amtuser", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;

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
    let (sig, timestamp) =
        sign_register_with_keypair(&keypair, &npub_hex, "deluser", TEST_DESCRIPTOR);

    post_json(&app, "/register", json!({
        "nym": "deluser", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub_hex, "signature": sig, "timestamp": timestamp,
    })).await;

    // Delete
    let (del_sig, del_timestamp) = sign_delete_with_keypair(&keypair, &npub_hex, "deluser");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"npub": npub_hex, "nym": "deluser", "signature": del_sig, "timestamp": del_timestamp}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

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

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("lifecycle1", TEST_DESCRIPTOR);

    // Register
    let (status, _) = post_json(
        &app,
        "/register",
        json!({
            "nym": "lifecycle1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Delete
    let (del_sig, del_timestamp) = sign_delete_with_keypair(&keypair, &npub, "lifecycle1");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"npub": npub, "nym": "lifecycle1", "signature": del_sig, "timestamp": del_timestamp}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Re-register with new nym, same npub
    let (new_sig, new_timestamp) =
        sign_register_with_keypair(&keypair, &npub, "lifecycle2", TEST_DESCRIPTOR);
    let (status, body) = post_json(&app, "/register", json!({
        "nym": "lifecycle2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": new_sig, "timestamp": new_timestamp,
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

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("samename", TEST_DESCRIPTOR);

    // Register
    post_json(
        &app,
        "/register",
        json!({
            "nym": "samename", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;

    // Delete
    let (del_sig, del_timestamp) = sign_delete_with_keypair(&keypair, &npub, "samename");
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"npub": npub, "nym": "samename", "signature": del_sig, "timestamp": del_timestamp}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Re-register same nym — should reactivate
    let (re_sig, re_timestamp) =
        sign_register_with_keypair(&keypair, &npub, "samename", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "samename", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": re_sig, "timestamp": re_timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["nym"], "samename");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_while_active_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("active1", TEST_DESCRIPTOR);

    // Register first nym
    let (status, _) = post_json(
        &app,
        "/register",
        json!({
            "nym": "active1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Try registering second nym with same npub while first is active
    let (sig2, timestamp2) =
        sign_register_with_keypair(&keypair, &npub, "active2", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "active2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig2, "timestamp": timestamp2,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn deleted_nym_reserved_from_others() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub1, sig1, timestamp1, keypair1) =
        sign_registration_with_keypair("reserved", TEST_DESCRIPTOR);

    // User 1 registers and deletes
    post_json(
        &app,
        "/register",
        json!({
            "nym": "reserved", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub1, "signature": sig1, "timestamp": timestamp1,
        }),
    )
    .await;

    let (del_sig, del_timestamp) = sign_delete_with_keypair(&keypair1, &npub1, "reserved");
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"npub": npub1, "nym": "reserved", "signature": del_sig, "timestamp": del_timestamp}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // User 2 tries to claim the same nym — should fail
    let (npub2, sig2, timestamp2) = sign_registration("reserved", TEST_DESCRIPTOR);
    let (_, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "reserved", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "signature": sig2, "timestamp": timestamp2,
        }),
    )
    .await;
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

async fn create_test_user(pool: &PgPool, nym: &str) -> String {
    let (npub, _, _) = sign_registration(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    npub
}

async fn insert_test_invoice(
    pool: &PgPool,
    nym: &str,
    npub: &str,
    liquid_address: &str,
    expires_in_secs: i64,
) -> pay_service::db::Invoice {
    pay_service::db::insert_invoice(
        pool,
        &pay_service::db::NewInvoice {
            nym_owner: Some(nym),
            npub_owner: npub,
            origin: "checkout",
            fiat_amount_minor: None,
            fiat_currency: None,
            amount_sat: 1_000,
            rate_minor_per_btc: None,
            rate_lock_secs: expires_in_secs,
            memo: None,
            recipient_label: None,
            public_description: None,
            invoice_number: None,
            accept_btc: false,
            accept_ln: false,
            accept_liquid: true,
            bitcoin_address: None,
            liquid_address: Some(liquid_address),
            liquid_blinding_key_hex: Some("11".repeat(32).as_str()),
            expires_in_secs,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn registration_lifecycle_keeps_address_index_monotonic() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (npub, _, _) = sign_registration("idxlife", TEST_DESCRIPTOR);

    pay_service::db::create_user(&pool, "idxlife", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET next_addr_idx = 4 WHERE npub = $1")
        .bind(&npub)
        .execute(&pool)
        .await
        .unwrap();

    let updated = pay_service::db::update_user_descriptor(&pool, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.next_addr_idx, 4);

    pay_service::db::deactivate_user(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    let reactivated =
        pay_service::db::register_user_atomic(&pool, &npub, "idxlife", TEST_DESCRIPTOR, 5)
            .await
            .unwrap();
    match reactivated {
        pay_service::db::RegisterOutcome::Reactivated(user) => {
            assert_eq!(user.next_addr_idx, 4);
        }
        _ => panic!("expected reactivation"),
    }

    let purged = pay_service::db::purge_user(&pool, &npub).await.unwrap();
    match purged {
        pay_service::db::PurgeOutcome::Purged(user) => {
            assert_eq!(user.next_addr_idx, 4);
        }
        _ => panic!("expected purge"),
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn cancel_invoice_returns_final_status_on_repeated_cancel() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "cancelidem").await;
    let invoice = insert_test_invoice(
        &pool,
        "cancelidem",
        &npub,
        "lq1qqvxk052kf3qtkxmrakx50a9gc3smqad2ync54hzntjt980kfej9kkfe0247rp5h4yzmdftsahhw64uy8pzfe7cpg4fgykm7cv",
        3_600,
    )
    .await;

    let first = pay_service::db::cancel_invoice(&pool, invoice.id)
        .await
        .unwrap();
    let second = pay_service::db::cancel_invoice(&pool, invoice.id)
        .await
        .unwrap();

    assert_eq!(first, (1, "cancelled".to_string()));
    assert_eq!(second, (0, "cancelled".to_string()));

    cleanup_db(&pool).await;
}

fn liquid_direct_evidence<'a>(
    event_key: &'a str,
    amount_sat: i64,
    txid: &'a str,
    vout: i32,
    address: &'a str,
) -> pay_service::db::InvoicePaymentEvidence<'a> {
    pay_service::db::InvoicePaymentEvidence {
        rail: "liquid",
        source: "liquid_direct",
        event_key,
        amount_sat,
        txid: Some(txid),
        vout: Some(vout),
        boltz_swap_id: None,
        address: Some(address),
    }
}

fn bitcoin_direct_evidence<'a>(
    event_key: &'a str,
    amount_sat: i64,
    txid: &'a str,
    vout: i32,
    address: &'a str,
) -> pay_service::db::InvoicePaymentEvidence<'a> {
    pay_service::db::InvoicePaymentEvidence {
        rail: "bitcoin",
        source: "bitcoin_direct",
        event_key,
        amount_sat,
        txid: Some(txid),
        vout: Some(vout),
        boltz_swap_id: None,
        address: Some(address),
    }
}

async fn insert_test_btc_invoice(
    pool: &PgPool,
    nym: &str,
    npub: &str,
    bitcoin_address: &str,
) -> Result<pay_service::db::Invoice, sqlx::Error> {
    pay_service::db::insert_invoice(
        pool,
        &pay_service::db::NewInvoice {
            nym_owner: Some(nym),
            npub_owner: npub,
            origin: "wallet",
            fiat_amount_minor: None,
            fiat_currency: None,
            amount_sat: 1_000,
            rate_minor_per_btc: None,
            rate_lock_secs: 3_600,
            memo: None,
            recipient_label: None,
            public_description: None,
            invoice_number: None,
            accept_btc: true,
            accept_ln: false,
            accept_liquid: false,
            bitcoin_address: Some(bitcoin_address),
            liquid_address: None,
            liquid_blinding_key_hex: None,
            expires_in_secs: 3_600,
        },
    )
    .await
}

#[tokio::test]
async fn invoice_insert_rejects_reused_bitcoin_address() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "btcreuse").await;
    let address = "bc1qreuseinvoiceaddress000000000000000000000000";

    let first = insert_test_btc_invoice(&pool, "btcreuse", &npub, address).await;
    assert!(first.is_ok());

    let err = insert_test_btc_invoice(&pool, "btcreuse", &npub, address)
        .await
        .unwrap_err();
    let app_error = pay_service::error::AppError::from(err);
    assert_eq!(app_error.code(), "BitcoinAddressAlreadyUsed");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE bitcoin_address = $1")
        .bind(address)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn signed_invoice_create_canonicalizes_bitcoin_address_before_reuse_check() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (npub, _, _, keypair) = sign_registration_with_keypair("invoicecase", TEST_DESCRIPTOR);
    let expires_at_unix = auth_timestamp() as i64 + 3_600;
    let lower = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let upper = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";

    let (sig_upper, ts_upper) =
        sign_invoice_create_with_keypair(&keypair, &npub, upper, expires_at_unix);
    let (status, body) = post_json(
        &app,
        "/api/v1/invoices",
        json!({
            "npub": npub,
            "amount_sat": 1000,
            "fiat_amount_minor": null,
            "fiat_currency": null,
            "public_description": null,
            "recipient_name": null,
            "invoice_number": null,
            "accept_btc": true,
            "accept_ln": false,
            "accept_liquid": false,
            "bitcoin_address": upper,
            "liquid_address": null,
            "liquid_blinding_key_hex": null,
            "expires_at_unix": expires_at_unix,
            "timestamp": ts_upper,
            "signature": sig_upper,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["invoice_id"].is_string(), "body: {body}");

    let stored: String =
        sqlx::query_scalar("SELECT bitcoin_address FROM invoices WHERE npub_owner = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, lower);

    let (sig_lower, ts_lower) =
        sign_invoice_create_with_keypair(&keypair, &npub, lower, expires_at_unix);
    let (status, body) = post_json(
        &app,
        "/api/v1/invoices",
        json!({
            "npub": npub,
            "amount_sat": 1000,
            "fiat_amount_minor": null,
            "fiat_currency": null,
            "public_description": null,
            "recipient_name": null,
            "invoice_number": null,
            "accept_btc": true,
            "accept_ln": false,
            "accept_liquid": false,
            "bitcoin_address": lower,
            "liquid_address": null,
            "liquid_blinding_key_hex": null,
            "expires_at_unix": expires_at_unix,
            "timestamp": ts_lower,
            "signature": sig_lower,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["status"], "ERROR");
    assert_eq!(body["code"], "BitcoinAddressAlreadyUsed");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn signed_invoice_create_defaults_expiry_when_omitted() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (npub, _, _, keypair) = sign_registration_with_keypair("invoicedefault", TEST_DESCRIPTOR);
    let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    let (sig, ts) = sign_invoice_create_without_expiry_with_keypair(&keypair, &npub, address);
    let before = auth_timestamp() as i64;
    let (status, body) = post_json(
        &app,
        "/api/v1/invoices",
        json!({
            "npub": npub,
            "amount_sat": 1000,
            "fiat_amount_minor": null,
            "fiat_currency": null,
            "public_description": null,
            "recipient_name": null,
            "invoice_number": null,
            "accept_btc": true,
            "bitcoin_address": address,
            "liquid_address": null,
            "liquid_blinding_key_hex": null,
            "timestamp": ts,
            "signature": sig,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["invoice_id"].is_string(), "body: {body}");
    let expires_at_unix: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM expires_at)::BIGINT FROM invoices WHERE npub_owner = $1",
    )
    .bind(&npub)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        expires_at_unix >= before + 7 * 24 * 60 * 60 - 2,
        "expires_at_unix={expires_at_unix}, before={before}"
    );
    assert!(
        expires_at_unix <= before + 7 * 24 * 60 * 60 + 2,
        "expires_at_unix={expires_at_unix}, before={before}"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_insert_rejects_reused_liquid_address() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "liqreuse").await;
    let address = "lq1qqreuseinvoiceaddress000000000000000000000000";

    let _ = insert_test_invoice(&pool, "liqreuse", &npub, address, 3_600).await;

    let err = pay_service::db::insert_invoice(
        &pool,
        &pay_service::db::NewInvoice {
            nym_owner: Some("liqreuse"),
            npub_owner: &npub,
            origin: "wallet",
            fiat_amount_minor: None,
            fiat_currency: None,
            amount_sat: 1_000,
            rate_minor_per_btc: None,
            rate_lock_secs: 3_600,
            memo: None,
            recipient_label: None,
            public_description: None,
            invoice_number: None,
            accept_btc: false,
            accept_ln: false,
            accept_liquid: true,
            bitcoin_address: None,
            liquid_address: Some(address),
            liquid_blinding_key_hex: Some("22".repeat(32).as_str()),
            expires_in_secs: 3_600,
        },
    )
    .await
    .unwrap_err();
    let app_error = pay_service::error::AppError::from(err);
    assert_eq!(app_error.code(), "LiquidAddressAlreadyUsed");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE liquid_address = $1")
        .bind(address)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn checkout_liquid_allocator_skips_addresses_already_assigned_to_invoices() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "allocskip").await;
    let reused = "lq1allocskipreused000000000000000000000000";
    let fresh = "lq1allocskipfresh0000000000000000000000000";

    let _ = insert_test_invoice(&pool, "allocskip", &npub, reused, 3_600).await;

    let allocated = pay_service::db::allocate_next_liquid_for_active_nym(
        &pool,
        "allocskip",
        |_descriptor, idx| match idx {
            0 => Ok(reused.to_string()),
            1 => Ok(fresh.to_string()),
            other => Err(sqlx::Error::Protocol(format!("unexpected index {other}"))),
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(allocated, (fresh.to_string(), 1));
    let next_idx: i32 = sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = $1")
        .bind("allocskip")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(next_idx, 2);

    cleanup_db(&pool).await;
}

// --- Invoice lifecycle / watcher database coverage ---

#[tokio::test]
async fn invoice_expiry_gc_marks_only_active_past_deadline_rows() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "invoicegc").await;

    let expired_unpaid =
        insert_test_invoice(&pool, "invoicegc", &npub, "lq1expiredunpaid", -10).await;
    let expired_in_progress =
        insert_test_invoice(&pool, "invoicegc", &npub, "lq1expiredinprogress", -10).await;
    let expired_paid = insert_test_invoice(&pool, "invoicegc", &npub, "lq1expiredpaid", -10).await;
    let fresh_unpaid = insert_test_invoice(&pool, "invoicegc", &npub, "lq1freshunpaid", 60).await;

    pay_service::db::mark_invoice_in_progress(&pool, expired_in_progress.id)
        .await
        .unwrap();
    pay_service::db::record_invoice_payment(
        &pool,
        expired_paid.id,
        liquid_direct_evidence(
            "liquid_direct:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0",
            1_000,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            0,
            "lq1expiredpaid",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();

    let expired_count = pay_service::db::expire_invoices_past_deadline(&pool)
        .await
        .unwrap();
    assert_eq!(expired_count, 2);

    let expired_unpaid = pay_service::db::get_invoice_by_id(&pool, expired_unpaid.id)
        .await
        .unwrap()
        .unwrap();
    let expired_in_progress = pay_service::db::get_invoice_by_id(&pool, expired_in_progress.id)
        .await
        .unwrap()
        .unwrap();
    let expired_paid = pay_service::db::get_invoice_by_id(&pool, expired_paid.id)
        .await
        .unwrap()
        .unwrap();
    let fresh_unpaid = pay_service::db::get_invoice_by_id(&pool, fresh_unpaid.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(expired_unpaid.status, "expired");
    assert_eq!(expired_in_progress.status, "expired");
    assert_eq!(expired_paid.status, "paid");
    assert_eq!(fresh_unpaid.status, "unpaid");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_payment_events_track_partial_completion_and_overpay() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "eventacct").await;
    let invoice = insert_test_invoice(&pool, "eventacct", &npub, "lq1eventacct", 60).await;
    let tolerances = pay_service::db::InvoiceAccountingTolerances {
        btc_sat: 300,
        liquid_sat: 60,
        lightning_sat: 1,
    };

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:0",
            400,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            0,
            "lq1eventacct",
        ),
        tolerances,
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    let partial = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(partial.status, "partially_paid");
    assert_eq!(partial.settlement_status, "none");
    assert_eq!(partial.paid_via.as_deref(), Some("liquid"));
    assert_eq!(partial.paid_amount_sat, Some(400));
    assert!(partial.paid_at_unix.is_none());

    let duplicate_rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:0",
            400,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            0,
            "lq1eventacct",
        ),
        tolerances,
    )
    .await
    .unwrap();
    assert_eq!(duplicate_rows, 0);

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        bitcoin_direct_evidence(
            "bitcoin_direct:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc:0",
            590,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            0,
            "bc1qeventacct",
        ),
        tolerances,
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    let paid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paid.status, "paid");
    assert_eq!(paid.settlement_status, "settled");
    assert_eq!(paid.paid_via.as_deref(), Some("mixed"));
    assert_eq!(paid.paid_amount_sat, Some(990));
    assert!(paid.paid_at_unix.is_some());

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        bitcoin_direct_evidence(
            "bitcoin_direct:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd:1",
            20,
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            1,
            "bc1qeventacct",
        ),
        tolerances,
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    let overpaid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(overpaid.status, "overpaid");
    assert_eq!(overpaid.settlement_status, "settled");
    assert_eq!(overpaid.paid_amount_sat, Some(1_010));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_status_surfaces_partial_payment_remaining_amount() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let npub = create_test_user(&pool, "partialstatus").await;
    let invoice = insert_test_invoice(&pool, "partialstatus", &npub, "lq1partialstatus", 60).await;

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:abababababababababababababababababababababababababababababababab:0",
            400,
            "abababababababababababababababababababababababababababababababab",
            0,
            "lq1partialstatus",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();

    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "partially_paid");
    assert_eq!(body["paid_amount_sat"], 400);
    assert_eq!(body["remaining_amount_sat"], 600);
    assert_eq!(body["settlement_status"], "none");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_payment_events_store_direct_and_boltz_evidence() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "eventevidence").await;
    let invoice = insert_test_invoice(&pool, "eventevidence", &npub, "lq1eventevidence", 60).await;
    let tolerances = pay_service::db::InvoiceAccountingTolerances::default();

    let _ = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1111111111111111111111111111111111111111111111111111111111111111:2",
            100,
            "1111111111111111111111111111111111111111111111111111111111111111",
            2,
            "lq1eventevidence",
        ),
        tolerances,
    )
    .await
    .unwrap();
    let direct: (String, String, String, i32, Option<String>, String, i64) = sqlx::query_as(
        "SELECT rail, source, txid, vout, boltz_swap_id, address, amount_sat \
         FROM invoice_payment_events WHERE event_key = $1",
    )
    .bind("liquid_direct:1111111111111111111111111111111111111111111111111111111111111111:2")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(direct.0, "liquid");
    assert_eq!(direct.1, "liquid_direct");
    assert_eq!(
        direct.2,
        "1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(direct.3, 2);
    assert!(direct.4.is_none());
    assert_eq!(direct.5, "lq1eventevidence");
    assert_eq!(direct.6, 100);

    invoice::flip_invoice_on_lightning_settlement(
        &pool,
        Some(invoice.id),
        100,
        "boltz-reverse-evidence",
        "2222222222222222222222222222222222222222222222222222222222222222",
        tolerances,
    )
    .await;
    let boltz: (String, String, String, Option<i32>, String, Option<String>) = sqlx::query_as(
        "SELECT rail, source, txid, vout, boltz_swap_id, address \
         FROM invoice_payment_events WHERE event_key = $1",
    )
    .bind("lightning_boltz_reverse:boltz-reverse-evidence")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(boltz.0, "lightning");
    assert_eq!(boltz.1, "lightning_boltz_reverse");
    assert_eq!(
        boltz.2,
        "2222222222222222222222222222222222222222222222222222222222222222"
    );
    assert!(boltz.3.is_none());
    assert_eq!(boltz.4, "boltz-reverse-evidence");
    assert!(boltz.5.is_none());

    invoice::flip_invoice_on_bitcoin_boltz_settlement(
        &pool,
        Some(invoice.id),
        100,
        "boltz-chain-evidence",
        "3333333333333333333333333333333333333333333333333333333333333333",
        tolerances,
    )
    .await;
    let chain: (String, String, String, Option<i32>, String, Option<String>) = sqlx::query_as(
        "SELECT rail, source, txid, vout, boltz_swap_id, address \
         FROM invoice_payment_events WHERE event_key = $1",
    )
    .bind("bitcoin_boltz_chain:boltz-chain-evidence")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(chain.0, "bitcoin");
    assert_eq!(chain.1, "bitcoin_boltz_chain");
    assert_eq!(
        chain.2,
        "3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert!(chain.3.is_none());
    assert_eq!(chain.4, "boltz-chain-evidence");
    assert!(chain.5.is_none());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_payment_event_constraints_reject_invalid_evidence() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "eventconstraints").await;
    let invoice =
        insert_test_invoice(&pool, "eventconstraints", &npub, "lq1eventconstraints", 60).await;

    let wrong_rail = sqlx::query(
        "INSERT INTO invoice_payment_events \
            (invoice_id, rail, source, event_key, amount_sat, txid, vout, address) \
         VALUES ($1, 'bitcoin', 'liquid_direct', $2, 1, $3, 0, 'lq1eventconstraints')",
    )
    .bind(invoice.id)
    .bind("liquid_direct:4444444444444444444444444444444444444444444444444444444444444444:0")
    .bind("4444444444444444444444444444444444444444444444444444444444444444")
    .execute(&pool)
    .await;
    assert!(wrong_rail.is_err());

    let missing_direct_address = sqlx::query(
        "INSERT INTO invoice_payment_events \
            (invoice_id, rail, source, event_key, amount_sat, txid, vout) \
         VALUES ($1, 'liquid', 'liquid_direct', $2, 1, $3, 0)",
    )
    .bind(invoice.id)
    .bind("liquid_direct:5555555555555555555555555555555555555555555555555555555555555555:0")
    .bind("5555555555555555555555555555555555555555555555555555555555555555")
    .execute(&pool)
    .await;
    assert!(missing_direct_address.is_err());

    let missing_boltz_txid = sqlx::query(
        "INSERT INTO invoice_payment_events \
            (invoice_id, rail, source, event_key, amount_sat, boltz_swap_id) \
         VALUES ($1, 'lightning', 'lightning_boltz_reverse', $2, 1, 'swap-without-txid')",
    )
    .bind(invoice.id)
    .bind("lightning_boltz_reverse:swap-without-txid")
    .execute(&pool)
    .await;
    assert!(missing_boltz_txid.is_err());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_only_lightning_swap_does_not_require_nym() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "invoiceonly").await;
    let invoice = insert_test_invoice(&pool, "invoiceonly", &npub, "lq1invoiceonly", 60).await;

    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: None,
            boltz_swap_id: "invoiceonly-swap",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-invoiceonly",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();

    let pr = pay_service::db::latest_lightning_pr_for_invoice(&pool, invoice.id)
        .await
        .unwrap();
    assert_eq!(
        pr.as_ref().map(|(bolt11, _)| bolt11.as_str()),
        Some("lnbc-invoiceonly")
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn settlement_status_tracks_pending_and_claim_incidents() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "settlementstate").await;
    let invoice =
        insert_test_invoice(&pool, "settlementstate", &npub, "lq1settlementstate", 60).await;

    pay_service::db::mark_invoice_in_progress(&pool, invoice.id)
        .await
        .unwrap();
    let pending = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.status, "in_progress");
    assert_eq!(pending.settlement_status, "pending");

    pay_service::db::mark_invoice_settlement_status(&pool, Some(invoice.id), "claim_stuck")
        .await
        .unwrap();
    let stuck = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stuck.settlement_status, "claim_stuck");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn expired_partial_payment_becomes_underpaid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "eventunderpaid").await;
    let invoice =
        insert_test_invoice(&pool, "eventunderpaid", &npub, "lq1eventunderpaid", -10).await;

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee:0",
            400,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            0,
            "lq1eventunderpaid",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();

    let underpaid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(underpaid.status, "underpaid");
    assert_eq!(underpaid.paid_amount_sat, Some(400));
    assert_eq!(underpaid.paid_via.as_deref(), Some("liquid"));
    assert!(underpaid.paid_at_unix.is_none());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn liquid_address_watcher_scan_excludes_expired_invoice_rows() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "liquidscan").await;

    let expired = insert_test_invoice(&pool, "liquidscan", &npub, "lq1scanexpired", -10).await;
    let fresh = insert_test_invoice(&pool, "liquidscan", &npub, "lq1scanfresh", 60).await;

    let rows = pay_service::db::list_unpaid_invoices_with_liquid_address(&pool)
        .await
        .unwrap();
    let invoice_ids: std::collections::HashSet<_> =
        rows.into_iter().map(|(id, _, _, _)| id).collect();

    assert!(!invoice_ids.contains(&expired.id));
    assert!(invoice_ids.contains(&fresh.id));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn latest_lightning_pr_for_invoice_uses_newest_swap_row() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "latestpr").await;
    let invoice = insert_test_invoice(&pool, "latestpr", &npub, "lq1latestpr", 60).await;

    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("latestpr"),
            boltz_swap_id: "latestpr-old",
            address: Some("lq1latestold"),
            address_index: Some(0),
            amount_sat: 1_000,
            invoice: "lnbc-old",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE swap_records SET created_at = NOW() - INTERVAL '1 minute' WHERE boltz_swap_id = 'latestpr-old'")
        .execute(&pool)
        .await
        .unwrap();

    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("latestpr"),
            boltz_swap_id: "latestpr-new",
            address: Some("lq1latestnew"),
            address_index: Some(1),
            amount_sat: 1_000,
            invoice: "lnbc-new",
            preimage_hex: "cc".repeat(32).as_str(),
            claim_key_hex: "dd".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();

    let pr = pay_service::db::latest_lightning_pr_for_invoice(&pool, invoice.id)
        .await
        .unwrap();
    assert_eq!(
        pr.as_ref().map(|(bolt11, _)| bolt11.as_str()),
        Some("lnbc-new")
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn chain_swap_records_are_invoice_scoped_and_retrievable() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "chainswaprec").await;
    let invoice = insert_test_invoice(&pool, "chainswaprec", &npub, "lq1chainswaprec", 60).await;

    let row = pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some("chainswaprec"),
            boltz_swap_id: "chain-swap-rec-1",
            lockup_address: "bc1qchainswaplockup",
            lockup_bip21: Some("bitcoin:bc1qchainswaplockup?amount=0.00001000"),
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"chain-swap-rec-1\"}",
        },
    )
    .await
    .unwrap();
    assert_eq!(row.status, "pending");
    assert_eq!(row.from_chain, "BTC");
    assert_eq!(row.to_chain, "L-BTC");
    assert_eq!(row.claim_tx_hex, None);
    assert_eq!(row.claim_attempts, 0);
    assert_eq!(row.last_claim_error, None);

    let latest = pay_service::db::latest_payable_chain_swap_for_invoice(&pool, invoice.id, 1_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.boltz_swap_id, "chain-swap-rec-1");
    assert_eq!(
        latest.lockup_bip21.as_deref(),
        Some("bitcoin:bc1qchainswaplockup?amount=0.00001000")
    );
    let wrong_amount =
        pay_service::db::latest_payable_chain_swap_for_invoice(&pool, invoice.id, 999)
            .await
            .unwrap();
    assert!(
        wrong_amount.is_none(),
        "chain-swap offers must match the invoice's current remaining amount"
    );
    pay_service::db::update_chain_swap_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapStatus::Expired,
        None,
    )
    .await
    .unwrap();
    let stale = pay_service::db::latest_payable_chain_swap_for_invoice(&pool, invoice.id, 1_000)
        .await
        .unwrap();
    assert!(
        stale.is_none(),
        "expired chain swaps must not be exposed as payable offers"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn ready_to_claim_chain_swaps_includes_retry_rows_with_claim_txid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "chainretry").await;
    let invoice = insert_test_invoice(&pool, "chainretry", &npub, "lq1chainretry", 60).await;

    let row = pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some("chainretry"),
            boltz_swap_id: "chainretry-swap",
            lockup_address: "bc1qchainretrylockup",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"chainretry-swap\"}",
        },
    )
    .await
    .unwrap();
    pay_service::db::update_chain_swap_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapStatus::ServerLockConfirmed,
        None,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'claiming', \
             claim_txid = 'chain-retry-claim-txid', \
             claim_tx_hex = 'deadbeef', \
             next_claim_attempt_at = NOW() - INTERVAL '1 second' \
         WHERE boltz_swap_id = 'chainretry-swap'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let ready = pay_service::db::get_ready_to_claim_chain_swaps(&pool)
        .await
        .unwrap();
    let retry = ready
        .iter()
        .find(|row| row.boltz_swap_id == "chainretry-swap")
        .expect("claiming chain swap with persisted claim tx must be retryable");

    assert_eq!(retry.claim_txid.as_deref(), Some("chain-retry-claim-txid"));
    assert_eq!(retry.claim_tx_hex.as_deref(), Some("deadbeef"));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn chain_swap_claim_failure_transitions_to_stuck_at_budget() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "chainfail").await;
    let invoice = insert_test_invoice(&pool, "chainfail", &npub, "lq1chainfail", 60).await;

    let row = pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some("chainfail"),
            boltz_swap_id: "chainfail-swap",
            lockup_address: "bc1qchainfaillockup",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"chainfail-swap\"}",
        },
    )
    .await
    .unwrap();
    pay_service::db::update_chain_swap_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapStatus::ServerLockConfirmed,
        None,
    )
    .await
    .unwrap();

    let outcome = pay_service::db::record_chain_swap_claim_failure(
        &pool,
        row.id,
        "synthetic claim failure",
        1,
    )
    .await
    .unwrap();
    assert_eq!(outcome, pay_service::db::ClaimFailureOutcome::Stuck);

    let row = pay_service::db::get_chain_swap_by_boltz_id(&pool, "chainfail-swap")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "claim_stuck");
    assert_eq!(row.claim_attempts, 1);
    assert_eq!(
        row.last_claim_error.as_deref(),
        Some("synthetic claim failure")
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn ready_to_claim_swaps_includes_retry_rows_with_claim_txid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "claimretry").await;
    let invoice = insert_test_invoice(&pool, "claimretry", &npub, "lq1claimretry", 60).await;

    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("claimretry"),
            boltz_swap_id: "claimretry-swap",
            address: Some("lq1claimretryaddr"),
            address_index: Some(0),
            amount_sat: 1_000,
            invoice: "lnbc-claimretry",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();

    sqlx::query(
        "UPDATE swap_records \
         SET status = 'claiming', \
             claim_txid = 'retry-claim-txid', \
             claim_tx_hex = 'deadbeef', \
             next_claim_attempt_at = NOW() - INTERVAL '1 second' \
         WHERE boltz_swap_id = 'claimretry-swap'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let ready = pay_service::db::get_ready_to_claim_swaps(&pool)
        .await
        .unwrap();
    let retry = ready
        .iter()
        .find(|row| row.boltz_swap_id == "claimretry-swap")
        .expect("claiming swap with persisted claim tx must be retryable");

    assert_eq!(retry.claim_txid.as_deref(), Some("retry-claim-txid"));
    assert_eq!(retry.claim_tx_hex.as_deref(), Some("deadbeef"));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn purge_with_no_swaps_scrubs_descriptor_and_keeps_nym_reserved() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("purger1", TEST_DESCRIPTOR);
    post_json(
        &app,
        "/register",
        json!({
            "nym": "purger1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;

    let (purge_sig, purge_timestamp) = sign_purge_with_keypair(&keypair, &npub, "purger1");
    let (status, _) = delete_request(
        &app,
        json!({
            "npub": npub, "nym": "purger1", "signature": purge_sig, "purge": true, "timestamp": purge_timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // LNURL no longer resolves
    let (_, body) = get_path(&app, "/.well-known/lnurlp/purger1").await;
    assert_eq!(body["status"], "ERROR");

    // Row survives with scrubbed descriptor and is_active=false
    let row: (bool, String) =
        sqlx::query_as("SELECT is_active, ct_descriptor FROM users WHERE nym = $1")
            .bind("purger1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!row.0);
    assert_eq!(row.1, "");

    // Another npub cannot claim the reserved nym
    let (npub2, sig2, timestamp2) = sign_registration("purger1", TEST_DESCRIPTOR);
    let (_, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "purger1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "signature": sig2, "timestamp": timestamp2,
        }),
    )
    .await;
    assert_eq!(body["status"], "ERROR");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn purge_blocked_when_pending_swap_exists() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("purger2", TEST_DESCRIPTOR);
    post_json(
        &app,
        "/register",
        json!({
            "nym": "purger2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;
    insert_swap(&pool, "purger2", "pending", 0).await;
    insert_swap(&pool, "purger2", "lockup_confirmed", 1).await;

    let (purge_sig, purge_timestamp) = sign_purge_with_keypair(&keypair, &npub, "purger2");
    let (_, body) = delete_request(
        &app,
        json!({
            "npub": npub, "nym": "purger2", "signature": purge_sig, "purge": true, "timestamp": purge_timestamp,
        }),
    )
    .await;
    assert_eq!(body["code"], "PurgeBlocked");
    assert!(body["reason"].as_str().unwrap().contains("2"));

    // User still active, swaps untouched
    let active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE nym = 'purger2'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(active);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = 'purger2'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn purge_drops_only_terminal_swap_history() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("purger3", TEST_DESCRIPTOR);
    post_json(
        &app,
        "/register",
        json!({
            "nym": "purger3", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;
    insert_swap(&pool, "purger3", "claimed", 0).await;
    insert_swap(&pool, "purger3", "expired", 1).await;

    let (purge_sig, purge_timestamp) = sign_purge_with_keypair(&keypair, &npub, "purger3");
    let (status, _) = delete_request(
        &app,
        json!({
            "npub": npub, "nym": "purger3", "signature": purge_sig, "purge": true, "timestamp": purge_timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = 'purger3'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn delete_signature_does_not_authorize_purge() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("purger4", TEST_DESCRIPTOR);
    post_json(
        &app,
        "/register",
        json!({
            "nym": "purger4", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;
    insert_swap(&pool, "purger4", "claimed", 0).await;

    // Sign the soft-delete challenge but try to use it for purge
    let (delete_sig, delete_timestamp) = sign_delete_with_keypair(&keypair, &npub, "purger4");
    let (status, _) = delete_request(
        &app,
        json!({
            "npub": npub, "nym": "purger4", "signature": delete_sig, "purge": true, "timestamp": delete_timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // User still active, swap_records intact
    let active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE nym = 'purger4'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(active);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = 'purger4'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn purge_then_owner_reregisters_same_nym() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, timestamp, keypair) =
        sign_registration_with_keypair("purger5", TEST_DESCRIPTOR);
    post_json(
        &app,
        "/register",
        json!({
            "nym": "purger5", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": sig, "timestamp": timestamp,
        }),
    )
    .await;

    let (purge_sig, purge_timestamp) = sign_purge_with_keypair(&keypair, &npub, "purger5");
    delete_request(
        &app,
        json!({
            "npub": npub, "nym": "purger5", "signature": purge_sig, "purge": true, "timestamp": purge_timestamp,
        }),
    )
    .await;

    // Same owner re-registers same nym
    let (re_sig, re_timestamp) =
        sign_register_with_keypair(&keypair, &npub, "purger5", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "purger5", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "signature": re_sig, "timestamp": re_timestamp,
        }),
    )
    .await;
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

    use secp256k1::{Keypair, Secp256k1};
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
    assert!(
        result.is_ok(),
        "Signature verification failed: {:?}",
        result
    );
}

/// Two concurrent registers from the same npub, when only one slot remains
/// under the lifetime cap, must result in exactly one Created and one
/// non-success response — never two Createds (which would overshoot the cap)
/// and never InternalError (the bug pre-advisory-lock).
#[tokio::test]
async fn register_concurrent_does_not_exceed_cap() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    // One keypair → one npub for all calls.
    let (npub_hex, _, _, kp) = sign_registration_with_keypair("filler-0", TEST_DESCRIPTOR);

    // Burn 2 of 3 lifetime slots (`LimitsConfig::default()` cap = 3) by
    // creating + deactivating filler rows. Goes through the atomic flow
    // sequentially so the partial unique on active-npub isn't violated.
    pay_service::db::register_user_atomic(&pool, &npub_hex, "filler-0", TEST_DESCRIPTOR, 3)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_active = FALSE WHERE nym = 'filler-0'")
        .execute(&pool)
        .await
        .unwrap();
    pay_service::db::register_user_atomic(&pool, &npub_hex, "filler-1", TEST_DESCRIPTOR, 3)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_active = FALSE WHERE nym = 'filler-1'")
        .execute(&pool)
        .await
        .unwrap();

    // Two concurrent register calls — only one slot remains. Without the
    // advisory lock, both would pass `used < cap` (read=2) and both would
    // INSERT, leaving 4 lifetime rows. With the lock, the loser sees either
    // the active nym created by the winner or the exhausted lifetime cap.
    let (sig_a, timestamp_a) =
        sign_register_with_keypair(&kp, &npub_hex, "conc-a", TEST_DESCRIPTOR);
    let (sig_b, timestamp_b) =
        sign_register_with_keypair(&kp, &npub_hex, "conc-b", TEST_DESCRIPTOR);

    let req_a = post_json(
        &app,
        "/register",
        json!({
            "nym": "conc-a",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": npub_hex,
            "signature": sig_a,
            "timestamp": timestamp_a,
        }),
    );
    let req_b = post_json(
        &app,
        "/register",
        json!({
            "nym": "conc-b",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": npub_hex,
            "signature": sig_b,
            "timestamp": timestamp_b,
        }),
    );
    let ((status_a, body_a), (status_b, body_b)) = tokio::join!(req_a, req_b);

    let success_count =
        (status_a == StatusCode::CREATED) as u32 + (status_b == StatusCode::CREATED) as u32;
    let guarded_reject_count = matches!(
        body_a["code"].as_str(),
        Some("NymQuotaExceeded" | "KeyAlreadyRegistered")
    ) as u32
        + matches!(
            body_b["code"].as_str(),
            Some("NymQuotaExceeded" | "KeyAlreadyRegistered")
        ) as u32;

    assert_eq!(
        success_count, 1,
        "exactly one register should succeed; got a=({status_a:?},{body_a}) b=({status_b:?},{body_b})"
    );
    assert_eq!(
        guarded_reject_count, 1,
        "the other should be rejected by the atomic registration guard; got a={body_a} b={body_b}"
    );
    // The bug we're guarding against: race-loser returning a generic
    // InternalError because the cap check happened outside the atomic tx.
    let codes = [body_a["code"].as_str(), body_b["code"].as_str()];
    assert!(
        !codes.contains(&Some("InternalError")),
        "must not return InternalError under contention; got {codes:?}"
    );

    // DB invariant: exactly cap rows under this npub.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE npub = $1")
        .bind(&npub_hex)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 3, "lifetime cap must hold under contention");

    cleanup_db(&pool).await;
}
