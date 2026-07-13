use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{get, post, put};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Barrier, Mutex};
use tower::ServiceExt;

use pay_service::boltz::BoltzService;
use pay_service::config::{
    BitcoinWatcherConfig, BoltzConfig, CertificationConfig, ClaimConfig, Config, DonationConfig,
    ElectrumConfig, FeaturesConfig, InvoiceAccountingConfig, LimitsConfig, LiquidWatcherConfig,
    PricerConfig, ProofConfig, PwaConfig, RateLimitConfig, ReconcilerConfig, WorkersConfig,
};
use pay_service::donation_render::PwaShells;
use pay_service::error::AppError;
use pay_service::ip_whitelist::IpWhitelist;
use pay_service::pricer::PricerClient;
use pay_service::rate_limit::RateLimiter;
use pay_service::{
    certification, claimer, donation_page, donation_render, invoice, lnurl, nostr, readiness,
    registration, AppState,
};

use bitcoin::hashes::Hash as BitcoinHash;
use boltz_client::network::Network;
use boltz_client::swaps::BtcLikeTransaction;
use boltz_client::util::secrets::SwapMasterKey;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
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

/// A separate lazy pool for claim-preparation progress proofs. Seeding and
/// assertions use `test_pool`; this pool exists only to make the number of
/// connections available to the production claim path exact.
fn constrained_test_pool(
    max_connections: u32,
    connect_barrier: Option<Arc<tokio::sync::Barrier>>,
) -> PgPool {
    let mut options = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(1));
    if let Some(barrier) = connect_barrier {
        let arrivals = Arc::new(AtomicUsize::new(0));
        options = options.after_connect(move |_connection, _metadata| {
            let barrier = barrier.clone();
            let arrivals = arrivals.clone();
            Box::pin(async move {
                // Rendezvous exactly the first pool-capacity connections. A
                // later reconnect must not wait forever for a partner that
                // will never exist after the initial proof has completed.
                if arrivals.fetch_add(1, Ordering::SeqCst) < max_connections as usize {
                    barrier.wait().await;
                }
                Ok(())
            })
        });
    }
    options
        .connect_lazy(&require_test_db())
        .expect("constrained test pool URL must parse")
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
        pwa: PwaConfig::default(),
        donation: DonationConfig::default(),
        limits: LimitsConfig::default(),
        proof: ProofConfig::default(),
        features: FeaturesConfig::default(),
        rate_limit: RateLimitConfig::default(),
        certification: CertificationConfig::default(),
        electrum: ElectrumConfig::default(),
        claim: ClaimConfig::default(),
        reconciler: ReconcilerConfig::default(),
        bitcoin_watcher: BitcoinWatcherConfig::default(),
        liquid_watcher: LiquidWatcherConfig::default(),
        workers: WorkersConfig::default(),
        invoice_accounting: InvoiceAccountingConfig::default(),
        database_url: String::new(),
        swap_mnemonic: String::new(),
        boltz_webhook_url_secret: String::new(),
        boltz_webhook_url_secret_previous: String::new(),
    }
}

fn test_state(pool: PgPool) -> AppState {
    test_state_with_config(pool, test_config())
}

fn test_state_with_config(pool: PgPool, config: Config) -> AppState {
    let swap_master_key = SwapMasterKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        Network::Mainnet,
    ).unwrap();

    let rate_limiter = Arc::new(RateLimiter::new(pool.clone(), RateLimitConfig::default()));
    let pricer = Arc::new(PricerClient::new(PricerConfig::default()).unwrap());
    let boltz_api_url = config.boltz.api_url.clone();
    let liquid_claim_client_factory = Arc::new(
        pay_service::claimer::LiquidClaimClientFactory::try_new(
            config.claim_liquid_electrum_urls(),
        )
        .unwrap(),
    );
    let bitcoin_recovery_backend = Arc::new(
        pay_service::chain_recovery::BitcoinRecoveryBackend::try_new(
            config.bitcoin_watcher.effective_endpoints(),
        )
        .unwrap(),
    );

    AppState {
        db: pool,
        config: Arc::new(config),
        admission: pay_service::admission::MoneyAdmission::healthy_test_fixture(),
        boltz: Arc::new(BoltzService::new(&boltz_api_url, swap_master_key, None)),
        ip_whitelist: Arc::new(IpWhitelist::default()),
        certification: Arc::new(certification::CertificationAllowlist::default()),
        rate_limiter,
        utxo_backend: None,
        liquid_claim_client_factory: Some(liquid_claim_client_factory),
        bitcoin_recovery_backend: Some(bitcoin_recovery_backend),
        pricer,
        pwa_shells: Arc::new(PwaShells::default()),
        swap_key_root_fingerprint: Arc::new("0000000000000000".to_string()),
    }
}

fn test_state_with_nip05(pool: PgPool) -> AppState {
    let mut config = test_config();
    config.features.nip05 = true;
    test_state_with_config(pool, config)
}

fn test_app(state: AppState) -> Router {
    Router::new()
        .route("/ready", get(readiness::ready))
        .route("/.well-known/lnurlp/:nym", get(lnurl::metadata))
        .route("/.well-known/nostr.json", get(nostr::nostr_json))
        .route("/lnurlp/callback/:nym", get(lnurl::callback))
        .route("/donation-page", put(donation_page::save))
        .route("/donation-page/:nym", get(donation_page::get))
        .route(
            "/donation-page",
            axum::routing::delete(donation_page::archive),
        )
        .route("/sw.js", get(donation_render::service_worker))
        .route("/:nym/manifest.webmanifest", get(donation_render::manifest))
        .route(
            "/:nym/pos/manifest.webmanifest",
            get(donation_render::manifest_pos),
        )
        .route("/:nym/pos", get(donation_render::render_pos))
        .route("/:nym/invoice", post(invoice::create_anonymous))
        .route("/:nym/pos/invoice", post(invoice::create_anonymous_pos))
        .route("/register", post(registration::register))
        .route("/register", put(registration::update_registration))
        .route(
            "/register",
            axum::routing::delete(registration::delete_registration),
        )
        .route("/api/v1/:nym/invoices", post(invoice::create_signed_linked))
        .route("/api/v1/invoices", post(invoice::create_signed_unlinked))
        .route("/api/v1/invoices", get(invoice::list_signed))
        .route(
            "/api/v1/invoices/:id/lightning",
            post(invoice::fetch_lightning_offer),
        )
        .route(
            "/api/v1/invoices/recoverable",
            get(invoice::list_recoverable_signed),
        )
        .route(
            "/api/v1/:nym/invoices/:id/recover",
            post(invoice::recover_chain_swap),
        )
        .route(
            "/api/v1/:nym/invoices/:id",
            axum::routing::delete(invoice::cancel_linked),
        )
        .route(
            "/api/v1/invoices/:id",
            axum::routing::delete(invoice::cancel_unlinked),
        )
        .route("/:nym/i/:id", get(invoice::render_payment))
        .route("/invoice/:id", get(invoice::render_unlinked_payment))
        .route("/api/v1/invoices/:id/status", get(invoice::status))
        .route("/certification/preflight", get(certification::preflight))
        .route("/webhook/boltz", post(claimer::webhook_unauthenticated))
        .with_state(state)
}

fn auth_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fresh_bolt11(amount_sat: u64) -> String {
    let private_key = SecretKey::from_slice(&[42; 32]).unwrap();
    let payment_hash = bitcoin::hashes::sha256::Hash::hash(b"bullnym-admission-test");
    InvoiceBuilder::new(Currency::Bitcoin)
        .amount_milli_satoshis(amount_sat.saturating_mul(1_000))
        .description("Bullnym admission test".into())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([24; 32]))
        .duration_since_epoch(Duration::from_secs(auth_timestamp()))
        .expiry_time(Duration::from_secs(3_600))
        .min_final_cltv_expiry_delta(144)
        .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))
        .unwrap()
        .to_string()
}

fn fresh_replacement_bolt11(amount_sat: u64) -> String {
    let private_key = SecretKey::from_slice(&[44; 32]).unwrap();
    let payment_hash = bitcoin::hashes::sha256::Hash::hash(b"bullnym-terminal-replacement-test");
    InvoiceBuilder::new(Currency::Bitcoin)
        .amount_milli_satoshis(amount_sat.saturating_mul(1_000))
        .description("Bullnym terminal replacement test".into())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([26; 32]))
        .duration_since_epoch(Duration::from_secs(auth_timestamp()))
        .expiry_time(Duration::from_secs(3_600))
        .min_final_cltv_expiry_delta(144)
        .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))
        .unwrap()
        .to_string()
}

fn expired_bolt11(amount_sat: u64) -> String {
    let private_key = SecretKey::from_slice(&[43; 32]).unwrap();
    let payment_hash = bitcoin::hashes::sha256::Hash::hash(b"bullnym-expired-admission-test");
    InvoiceBuilder::new(Currency::Bitcoin)
        .amount_milli_satoshis(amount_sat.saturating_mul(1_000))
        .description("Bullnym expired admission test".into())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([25; 32]))
        .duration_since_epoch(Duration::from_secs(auth_timestamp().saturating_sub(3_600)))
        .expiry_time(Duration::from_secs(60))
        .min_final_cltv_expiry_delta(144)
        .build_signed(|hash| Secp256k1::new().sign_ecdsa_recoverable(hash, &private_key))
        .unwrap()
        .to_string()
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
    sign_register_with_verification_keypair(keypair, npub, nym, ct_descriptor, npub)
}

fn sign_register_with_verification_keypair(
    keypair: &Keypair,
    npub: &str,
    nym: &str,
    ct_descriptor: &str,
    verification_npub: &str,
) -> (String, u64) {
    sign_la_action(
        keypair,
        "register",
        npub,
        nym,
        &[ct_descriptor, verification_npub],
    )
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

fn sign_invoice_cancel_with_keypair(
    keypair: &Keypair,
    npub: &str,
    nym: &str,
    invoice_id: &str,
) -> (String, u64) {
    sign_la_action(keypair, "invoice-cancel", npub, nym, &[invoice_id])
}

fn sign_invoice_list_with_keypair(
    keypair: &Keypair,
    npub: &str,
    page: i64,
    page_size: i64,
    status: &str,
) -> (String, u64) {
    let page = page.to_string();
    let page_size = page_size.to_string();
    sign_la_action(
        keypair,
        "invoice-list",
        npub,
        "",
        &[&page, &page_size, status],
    )
}

// Recoverable-swaps detection list: npub-keyed, empty nym, ZERO payload fields.
fn sign_invoice_recovery_list_with_keypair(keypair: &Keypair, npub: &str) -> (String, u64) {
    sign_la_action(keypair, "invoice-recovery-list", npub, "", &[])
}

fn sign_invoice_recover_with_keypair(
    keypair: &Keypair,
    npub: &str,
    nym: &str,
    invoice_id: &str,
    btc_address: &str,
) -> (String, u64) {
    sign_la_action(
        keypair,
        "invoice-recover",
        npub,
        nym,
        &[invoice_id, btc_address],
    )
}

struct DonationSaveSignFields<'a> {
    header: &'a str,
    description: &'a str,
    display_currency: &'a str,
    website: &'a str,
    twitter: &'a str,
    instagram: &'a str,
    enabled: bool,
    pos_mode: Option<bool>,
    ct_descriptor: Option<&'a str>,
    kind: Option<&'a str>,
}

fn sign_donation_page_save_with_keypair(
    keypair: &Keypair,
    npub: &str,
    nym: &str,
    save: DonationSaveSignFields<'_>,
) -> (String, u64) {
    let enabled_str = if save.enabled { "1" } else { "0" };
    let pos_mode_str = save
        .pos_mode
        .map(|pos_mode| if pos_mode { "1" } else { "0" });
    let mut fields = vec![
        save.header,
        save.description,
        save.display_currency,
        save.website,
        save.twitter,
        save.instagram,
        enabled_str,
    ];
    if let Some(pos_mode_str) = pos_mode_str {
        fields.push(pos_mode_str);
    }
    if let Some(ct_descriptor) = save.ct_descriptor {
        fields.push(ct_descriptor);
    }
    if let Some(kind) = save.kind {
        fields.push(kind);
    }
    sign_la_action(keypair, "donation-page-save", npub, nym, &fields)
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

async fn post_json_from(
    app: &Router,
    uri: &str,
    body: Value,
    peer: SocketAddr,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut request = builder.body(Body::from(body.to_string())).unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let resp = app.clone().oneshot(request).await.unwrap();
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

async fn get_path_from(app: &Router, uri: &str, peer: SocketAddr) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let resp = app.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn spawn_counting_http_server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let task_calls = calls.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            task_calls.fetch_add(1, Ordering::SeqCst);
            let _ = stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 2\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{}",
                )
                .await;
        }
    });
    (format!("http://{address}"), calls, task)
}

#[derive(Clone)]
struct SuccessfulReverseBarrierState {
    response: Value,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
    request_barrier: Arc<Barrier>,
    release_barrier: Arc<Barrier>,
}

struct SuccessfulReverseBarrierServer {
    base_url: String,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
    request_barrier: Arc<Barrier>,
    release_barrier: Arc<Barrier>,
    task: tokio::task::JoinHandle<()>,
}

impl SuccessfulReverseBarrierServer {
    async fn wait_until_request_is_blocked(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.request_barrier.wait())
            .await
            .expect("Boltz reverse request did not reach the response barrier");
    }

    async fn release_response(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.release_barrier.wait())
            .await
            .expect("Boltz reverse response handler did not reach the release barrier");
    }

    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn successful_reverse_barrier_handler(
    axum::extract::State(state): axum::extract::State<SuccessfulReverseBarrierState>,
    axum::Json(request): axum::Json<Value>,
) -> axum::Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    state.requests.lock().await.push(request);
    state.request_barrier.wait().await;
    state.release_barrier.wait().await;
    axum::Json(state.response)
}

async fn spawn_successful_reverse_barrier_server(
    swap_id: &str,
    bolt11: &str,
) -> SuccessfulReverseBarrierServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind successful Boltz reverse fixture");
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let request_barrier = Arc::new(Barrier::new(2));
    let release_barrier = Arc::new(Barrier::new(2));
    let state = SuccessfulReverseBarrierState {
        response: json!({
            "id": swap_id,
            "invoice": bolt11,
            "swapTree": {
                "claimLeaf": {"output": "51", "version": 192},
                "refundLeaf": {"output": "51", "version": 192}
            },
            "lockupAddress": "lq1qqtestreversebarrier",
            "refundPublicKey": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "timeoutBlockHeight": 2_000_000,
            "onchainAmount": 1
        }),
        calls: calls.clone(),
        requests: requests.clone(),
        request_barrier: request_barrier.clone(),
        release_barrier: release_barrier.clone(),
    };
    let app = Router::new()
        .route("/swap/reverse", post(successful_reverse_barrier_handler))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("successful Boltz reverse fixture failed");
    });
    SuccessfulReverseBarrierServer {
        base_url: format!("http://{address}"),
        calls,
        requests,
        request_barrier,
        release_barrier,
        task,
    }
}

async fn get_json_with_headers(app: &Router, uri: &str) -> (StatusCode, HeaderMap, Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

async fn put_json(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
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

async fn delete_json_path(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
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

#[tokio::test]
async fn readiness_rejects_schema_before_latest_migration() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    sqlx::query(
        "ALTER TABLE invoices RENAME CONSTRAINT invoices_paid_via_or_closed_chk \
         TO invoices_paid_via_or_closed_chk_before_readiness_test",
    )
    .execute(&pool)
    .await
    .unwrap();

    let app = test_app(test_state(pool.clone()));
    let (pre_migration_status, pre_migration_body) = get_path(&app, "/ready").await;

    sqlx::query(
        "ALTER TABLE invoices RENAME CONSTRAINT \
         invoices_paid_via_or_closed_chk_before_readiness_test \
         TO invoices_paid_via_or_closed_chk",
    )
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(pre_migration_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pre_migration_body["ready"], false);
    assert_eq!(
        pre_migration_body["expected_schema_marker"],
        "048_cancelled_invoice_late_money"
    );

    let app = test_app(test_state(pool.clone()));
    let (current_status, current_body) = get_path(&app, "/ready").await;
    assert_eq!(current_status, StatusCode::OK, "body: {current_body}");
    assert_eq!(current_body["ready"], true);
}

// --- Registration tests ---

#[tokio::test]
async fn donation_page_upsert_round_trips_pos_mode() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "posround").await;

    let row = pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym: "posround",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "POS Store",
            description: "Counter checkout",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(true),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();
    assert!(row.pos_mode);

    let fetched = pay_service::db::get_donation_page_by_nym(
        &pool,
        "posround",
        pay_service::db::KIND_PAYMENT_PAGE,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(fetched.pos_mode);

    let row = pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym: "posround",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: None,
            header: "Donation Store",
            description: "Tip jar",
            display_currency: "CAD",
            website: Some("https://example.com"),
            twitter: Some("posround"),
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();
    assert!(!row.pos_mode);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn og_reconciler_schedules_a_bounded_retry_after_publish_failure() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "ogretry").await;

    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym: "ogretry",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Retry test",
            description: "A short retry description",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();

    // /proc cannot accept application-created directories, deterministically
    // exercising the render/write failure path without altering permissions on
    // a shared test directory.
    let cancel = tokio_util::sync::CancellationToken::new();
    let worker = pay_service::og_image::spawn_reconciler(
        pool.clone(),
        format!("/proc/bullnym-og-retry-test-{}", std::process::id()),
        cancel.clone(),
    );

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let observed = loop {
        let row = sqlx::query_as::<_, (i32, bool, Option<String>, Option<i32>)>(
            "SELECT generated_og_failure_count, \
                    generated_og_retry_after IS NOT NULL, \
                    generated_og_key, generated_og_template_version \
             FROM donation_pages WHERE nym = 'ogretry' AND kind = 'payment_page'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if row.0 > 0 {
            break row;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "OG reconciler did not persist retry state"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };

    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), worker)
        .await
        .expect("worker stops after cancellation")
        .expect("worker task succeeds");

    assert_eq!(observed.0, 1);
    assert!(observed.1, "retry time must be persisted");
    assert_eq!(observed.2, None);
    assert_eq!(
        observed.3,
        Some(pay_service::og_image::TEMPLATE_VERSION),
        "a failed first-generation attempt must select the branded fallback"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn og_reconciler_backfills_legacy_rows_and_repairs_missing_current_files() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "ogbackfill").await;
    create_test_user(&pool, "ogmissing").await;

    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym: "ogbackfill",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Legacy preview",
            description: "Backfill this Page after the worker starts.",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();

    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym: "ogmissing",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Missing preview",
            description: "Repair a database reference whose local file is absent.",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: Some(pay_service::og_image::TEMPLATE_VERSION),
            alias: None,
        },
    )
    .await
    .unwrap();
    let stale_missing_key = "33".repeat(32);
    assert_eq!(
        pay_service::db::attach_generated_og_if_current(
            &pool,
            "ogmissing",
            pay_service::db::KIND_PAYMENT_PAGE,
            "Missing preview",
            "Repair a database reference whose local file is absent.",
            pay_service::og_image::TEMPLATE_VERSION,
            &stale_missing_key,
        )
        .await
        .unwrap(),
        1
    );

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bullnym-og-reconcile-{unique}-{}",
        std::process::id()
    ));
    let root_str = root.to_string_lossy().into_owned();
    let cancel = tokio_util::sync::CancellationToken::new();
    let worker =
        pay_service::og_image::spawn_reconciler(pool.clone(), root_str.clone(), cancel.clone());

    let backfill_key = pay_service::og_image::content_key(
        "Legacy preview",
        "Backfill this Page after the worker starts.",
    );
    let repaired_key = pay_service::og_image::content_key(
        "Missing preview",
        "Repair a database reference whose local file is absent.",
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let backfilled = pay_service::db::get_donation_page_by_nym(
            &pool,
            "ogbackfill",
            pay_service::db::KIND_PAYMENT_PAGE,
        )
        .await
        .unwrap()
        .unwrap();
        let repaired = pay_service::db::get_donation_page_by_nym(
            &pool,
            "ogmissing",
            pay_service::db::KIND_PAYMENT_PAGE,
        )
        .await
        .unwrap()
        .unwrap();
        if backfilled.generated_og_key.as_deref() == Some(backfill_key.as_str())
            && repaired.generated_og_key.as_deref() == Some(repaired_key.as_str())
            && pay_service::og_image::generated_path(&root_str, &backfill_key).is_file()
            && pay_service::og_image::generated_path(&root_str, &repaired_key).is_file()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "OG reconciler did not complete backfill and missing-file repair"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), worker)
        .await
        .expect("worker stops after cancellation")
        .expect("worker task succeeds");
    std::fs::remove_dir_all(root).expect("remove reconciler image directory");
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn payment_page_save_commits_when_og_storage_is_unwritable() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let nym = "ogsavefail";
    let (npub, _, _, keypair) = sign_registration_with_keypair(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    let mut config = test_config();
    config.donation.image_root_path = format!("/proc/bullnym-og-save-test-{}", std::process::id());
    let app = test_app(test_state_with_config(pool.clone(), config));
    let (signature, timestamp) = sign_donation_page_save_with_keypair(
        &keypair,
        &npub,
        nym,
        DonationSaveSignFields {
            header: "Persist despite preview failure",
            description: "Payments must not depend on social image storage.",
            display_currency: "USD",
            website: "",
            twitter: "",
            instagram: "",
            enabled: true,
            pos_mode: None,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            kind: Some(pay_service::db::KIND_PAYMENT_PAGE),
        },
    );

    let (status, body) = put_json(
        &app,
        "/donation-page",
        json!({
            "nym": nym,
            "npub": npub,
            "ct_descriptor": TEST_DESCRIPTOR,
            "header": "Persist despite preview failure",
            "description": "Payments must not depend on social image storage.",
            "display_currency": "USD",
            "enabled": true,
            "kind": pay_service::db::KIND_PAYMENT_PAGE,
            "timestamp": timestamp,
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["nym"], nym);

    let row =
        pay_service::db::get_donation_page_by_nym(&pool, nym, pay_service::db::KIND_PAYMENT_PAGE)
            .await
            .unwrap()
            .expect("Page mutation persists despite OG failure");
    assert_eq!(row.header, "Persist despite preview failure");
    assert_eq!(row.generated_og_key, None);
    assert_eq!(
        row.generated_og_template_version,
        Some(pay_service::og_image::TEMPLATE_VERSION)
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn og_key_attaches_only_to_the_matching_persisted_page_content() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "ogcommit").await;

    fn make_page(description: &str) -> pay_service::db::UpsertDonationPage<'_> {
        pay_service::db::UpsertDonationPage {
            nym: "ogcommit",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Persist first",
            description,
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: Some(pay_service::og_image::TEMPLATE_VERSION),
            alias: None,
        }
    }

    let inserted = pay_service::db::upsert_donation_page(&pool, &make_page("Version one"))
        .await
        .unwrap();
    assert_eq!(inserted.generated_og_key, None);

    let first_key = "11".repeat(32);
    assert_eq!(
        pay_service::db::attach_generated_og_if_current(
            &pool,
            "ogcommit",
            pay_service::db::KIND_PAYMENT_PAGE,
            "Persist first",
            "Version one",
            pay_service::og_image::TEMPLATE_VERSION,
            &first_key,
        )
        .await
        .unwrap(),
        1
    );

    let unchanged = pay_service::db::upsert_donation_page(&pool, &make_page("Version one"))
        .await
        .unwrap();
    assert_eq!(
        unchanged.generated_og_key.as_deref(),
        Some(first_key.as_str())
    );

    let changed = pay_service::db::upsert_donation_page(&pool, &make_page("Version two"))
        .await
        .unwrap();
    assert_eq!(changed.generated_og_key, None);

    assert_eq!(
        pay_service::db::attach_generated_og_if_current(
            &pool,
            "ogcommit",
            pay_service::db::KIND_PAYMENT_PAGE,
            "Persist first",
            "Version one",
            pay_service::og_image::TEMPLATE_VERSION,
            &first_key,
        )
        .await
        .unwrap(),
        0,
        "a render for superseded content must never attach"
    );

    let second_key = "22".repeat(32);
    assert_eq!(
        pay_service::db::attach_generated_og_if_current(
            &pool,
            "ogcommit",
            pay_service::db::KIND_PAYMENT_PAGE,
            "Persist first",
            "Version two",
            pay_service::og_image::TEMPLATE_VERSION,
            &second_key,
        )
        .await
        .unwrap(),
        1
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_falls_back_to_nym_and_sets_pwa_metadata() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let nym = "manifestnym";
    create_test_user(&pool, nym).await;

    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym,
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "",
            description: "Manifest test",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();

    let (status, headers, body) =
        get_json_with_headers(&app, "/manifestnym/manifest.webmanifest").await;

    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/manifest+json")
    );
    assert_eq!(
        headers
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=300")
    );
    assert_eq!(body["name"], "manifestnym");
    assert_eq!(body["short_name"], "manifestnym");
    assert_eq!(body["start_url"], "/manifestnym");
    assert_eq!(body["scope"], "/");
    assert_eq!(body["display"], "standalone");
    assert_eq!(body["background_color"], "#161512");
    assert_eq!(body["theme_color"], "#161512");
    assert_eq!(body["icons"].as_array().expect("icons array").len(), 4);
    assert_eq!(body["icons"][0]["src"], "/pwa-assets/icons/icon-192.png");
    assert_eq!(body["icons"][0]["sizes"], "192x192");
    assert_eq!(body["icons"][0]["type"], "image/png");
    assert_eq!(body["icons"][0]["purpose"], "any");
    assert_eq!(body["icons"][1]["src"], "/pwa-assets/icons/icon-192.png");
    assert_eq!(body["icons"][1]["purpose"], "maskable");
    assert_eq!(body["icons"][2]["src"], "/pwa-assets/icons/icon-512.png");
    assert_eq!(body["icons"][2]["purpose"], "any");
    assert_eq!(body["icons"][3]["src"], "/pwa-assets/icons/icon-512.png");
    assert_eq!(body["icons"][3]["purpose"], "maskable");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_returns_404_for_unknown_nym() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (status, _, body) = get_json_with_headers(&app, "/unknownnym/manifest.webmanifest").await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body:?}");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn donation_page_save_legacy_payload_preserves_existing_pos_mode() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let nym = "poslegacy";
    let (npub, _, _, keypair) = sign_registration_with_keypair(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym,
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Existing POS",
            description: "Already counter mode",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(true),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();

    let (signature, timestamp) = sign_donation_page_save_with_keypair(
        &keypair,
        &npub,
        nym,
        DonationSaveSignFields {
            header: "Legacy Save",
            description: "Old clients do not sign pos_mode",
            display_currency: "USD",
            website: "",
            twitter: "",
            instagram: "",
            enabled: true,
            pos_mode: None,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            kind: None,
        },
    );
    let (status, body) = put_json(
        &app,
        "/donation-page",
        json!({
            "nym": nym,
            "npub": npub,
            "ct_descriptor": TEST_DESCRIPTOR,
            "header": "Legacy Save",
            "description": "Old clients do not sign pos_mode",
            "display_currency": "USD",
            "enabled": true,
            "timestamp": timestamp,
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["pos_mode"], true);

    let row =
        pay_service::db::get_donation_page_by_nym(&pool, nym, pay_service::db::KIND_PAYMENT_PAGE)
            .await
            .unwrap()
            .unwrap();
    assert!(row.pos_mode);
    assert_eq!(row.header, "Legacy Save");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn donation_page_save_new_payload_round_trips_pos_mode() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let nym = "posnew";
    let (npub, _, _, keypair) = sign_registration_with_keypair(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    let (signature, timestamp) = sign_donation_page_save_with_keypair(
        &keypair,
        &npub,
        nym,
        DonationSaveSignFields {
            header: "New POS",
            description: "New clients sign pos_mode",
            display_currency: "USD",
            website: "https://example.com",
            twitter: "posnew",
            instagram: "pos.new",
            enabled: true,
            pos_mode: Some(true),
            ct_descriptor: Some(TEST_DESCRIPTOR),
            kind: None,
        },
    );
    let (status, body) = put_json(
        &app,
        "/donation-page",
        json!({
            "nym": nym,
            "npub": npub,
            "ct_descriptor": TEST_DESCRIPTOR,
            "header": "New POS",
            "description": "New clients sign pos_mode",
            "display_currency": "USD",
            "website": "https://example.com",
            "twitter": "posnew",
            "instagram": "pos.new",
            "pos_mode": true,
            "enabled": true,
            "timestamp": timestamp,
            "signature": signature,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["pos_mode"], true);

    let row =
        pay_service::db::get_donation_page_by_nym(&pool, nym, pay_service::db::KIND_PAYMENT_PAGE)
            .await
            .unwrap()
            .unwrap();
    assert!(row.pos_mode);
    assert_eq!(row.website.as_deref(), Some("https://example.com"));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn pos_and_payment_page_surfaces_coexist_under_one_nym() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let nym = "posco";
    let (npub, _, _, keypair) = sign_registration_with_keypair(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    // Payment Page surface: kind omitted => payment_page (legacy contract).
    let (sig, ts) = sign_donation_page_save_with_keypair(
        &keypair,
        &npub,
        nym,
        DonationSaveSignFields {
            header: "Alice Page",
            description: "Tip jar",
            display_currency: "USD",
            website: "",
            twitter: "",
            instagram: "",
            enabled: true,
            pos_mode: None,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            kind: None,
        },
    );
    let (status, body) = put_json(
        &app,
        "/donation-page",
        json!({
            "nym": nym, "npub": npub, "ct_descriptor": TEST_DESCRIPTOR,
            "header": "Alice Page", "description": "Tip jar", "display_currency": "USD",
            "enabled": true, "timestamp": ts, "signature": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["kind"], "payment_page");

    // POS surface: kind='pos' with its own descriptor.
    let (sig, ts) = sign_donation_page_save_with_keypair(
        &keypair,
        &npub,
        nym,
        DonationSaveSignFields {
            header: "Alice POS",
            description: "Counter",
            display_currency: "USD",
            website: "",
            twitter: "",
            instagram: "",
            enabled: true,
            pos_mode: None,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            kind: Some("pos"),
        },
    );
    let (status, body) = put_json(
        &app,
        "/donation-page",
        json!({
            "nym": nym, "npub": npub, "ct_descriptor": TEST_DESCRIPTOR,
            "header": "Alice POS", "description": "Counter", "display_currency": "USD",
            "enabled": true, "kind": "pos", "timestamp": ts, "signature": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["kind"], "pos");
    assert!(body["public_url"].as_str().unwrap().ends_with("/posco/pos"));

    // Each surface resolves independently through the editor read.
    let (status, page) = get_path(&app, "/donation-page/posco").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["kind"], "payment_page");
    assert_eq!(page["header"], "Alice Page");
    let (status, pos) = get_path(&app, "/donation-page/posco?kind=pos").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pos["kind"], "pos");
    assert_eq!(pos["header"], "Alice POS");

    // Two rows for one nym.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM donation_pages WHERE nym = $1")
        .bind(nym)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn pos_save_without_descriptor_is_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let nym = "posnodesc";
    let (npub, _, _, keypair) = sign_registration_with_keypair(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    // kind='pos' with no descriptor: the POS surface owns wallet idx 103, so a
    // save without a descriptor is rejected (KR-1) rather than settling POS
    // receipts into the Lightning Address wallet.
    let (sig, ts) = sign_donation_page_save_with_keypair(
        &keypair,
        &npub,
        nym,
        DonationSaveSignFields {
            header: "No Desc POS",
            description: "Missing wallet",
            display_currency: "USD",
            website: "",
            twitter: "",
            instagram: "",
            enabled: true,
            pos_mode: None,
            ct_descriptor: None,
            kind: Some("pos"),
        },
    );
    let (status, body) = put_json(
        &app,
        "/donation-page",
        json!({
            "nym": nym, "npub": npub,
            "header": "No Desc POS", "description": "Missing wallet", "display_currency": "USD",
            "enabled": true, "kind": "pos", "timestamp": ts, "signature": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");
    assert_eq!(body["code"], "DonationPageInvalid");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn legacy_save_without_kind_writes_payment_page_row() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let nym = "poslegacy";
    let (npub, _, _, keypair) = sign_registration_with_keypair(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    // A client that omits kind entirely (legacy byte layout) still verifies
    // and lands in the payment_page row.
    let (sig, ts) = sign_donation_page_save_with_keypair(
        &keypair,
        &npub,
        nym,
        DonationSaveSignFields {
            header: "Legacy",
            description: "No kind field",
            display_currency: "USD",
            website: "",
            twitter: "",
            instagram: "",
            enabled: true,
            pos_mode: None,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            kind: None,
        },
    );
    let (status, body) = put_json(
        &app,
        "/donation-page",
        json!({
            "nym": nym, "npub": npub, "ct_descriptor": TEST_DESCRIPTOR,
            "header": "Legacy", "description": "No kind field", "display_currency": "USD",
            "enabled": true, "timestamp": ts, "signature": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["kind"], "payment_page");

    let row =
        pay_service::db::get_donation_page_by_nym(&pool, nym, pay_service::db::KIND_PAYMENT_PAGE)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.kind, "payment_page");
    // No POS row was created.
    assert!(
        pay_service::db::get_donation_page_by_nym(&pool, nym, pay_service::db::KIND_POS)
            .await
            .unwrap()
            .is_none()
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn pos_allocation_uses_pos_cursor_not_lightning_address_cursor() {
    // KR-1: a POS sale must settle to the POS surface's own descriptor + cursor
    // and never burn a Lightning Address (users) index.
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "posalloc";
    let (npub, _, _) = sign_registration(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    // Distinct starting cursors: Lightning Address at 3, POS at 7.
    sqlx::query("UPDATE users SET next_addr_idx = 3 WHERE nym = $1")
        .bind(nym)
        .execute(&pool)
        .await
        .unwrap();
    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym,
            kind: pay_service::db::KIND_POS,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "POS",
            description: "Counter",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: None,
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE donation_pages SET next_addr_idx = 7 WHERE nym = $1 AND kind = 'pos'")
        .bind(nym)
        .execute(&pool)
        .await
        .unwrap();

    let (address, index, descriptor) = pay_service::db::allocate_next_liquid_for_donation_page(
        &pool,
        nym,
        pay_service::db::KIND_POS,
        |d, i| {
            pay_service::descriptor::derive_address(d, i)
                .map_err(|e| sqlx::Error::Protocol(format!("{e}")))
        },
    )
    .await
    .unwrap()
    .expect("pos allocation");

    // Allocated from the POS cursor (7), settling to the POS descriptor.
    assert_eq!(index, 7);
    assert_eq!(descriptor, TEST_DESCRIPTOR);
    assert_eq!(
        address,
        pay_service::descriptor::derive_address(TEST_DESCRIPTOR, 7).unwrap()
    );

    // The Lightning Address cursor was untouched; the POS cursor advanced.
    let la_idx: i32 = sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = $1")
        .bind(nym)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(la_idx, 3, "POS allocation must not touch the LA cursor");
    let pos_idx: i32 = sqlx::query_scalar(
        "SELECT next_addr_idx FROM donation_pages WHERE nym = $1 AND kind = 'pos'",
    )
    .bind(nym)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pos_idx, 8);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn pos_invoice_hard_fails_without_pos_descriptor_no_la_fallback() {
    // A misconfigured POS row (enabled, no descriptor) must make POS checkout
    // hard-fail rather than fall back to the Lightning Address cursor (KR-1).
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let nym = "posnofb";
    let (npub, _, _) = sign_registration(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET next_addr_idx = 5 WHERE nym = $1")
        .bind(nym)
        .execute(&pool)
        .await
        .unwrap();

    // Save would reject a descriptor-less POS row; insert it directly to
    // exercise the checkout branch's hard-fail.
    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym,
            kind: pay_service::db::KIND_POS,
            ct_descriptor: None,
            header: "Broken POS",
            description: "No wallet",
            display_currency: "USD",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: None,
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();

    let (status, body) =
        post_json(&app, "/posnofb/pos/invoice", json!({ "amount_sat": 1000 })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");
    assert_eq!(body["code"], "DonationPageNotFound");

    // The Lightning Address cursor was never advanced — no leak.
    let la_idx: i32 = sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = $1")
        .bind(nym)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(la_idx, 5);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_and_resolve() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state_with_nip05(pool.clone()));

    let (npub, sig, timestamp) = sign_registration("alice", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "alice",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": npub,
            "verification_npub": npub,
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
async fn register_without_verification_npub_has_no_nip05() {
    // NIP-05 is opt-in (ISS-S-01): a registration that omits verification_npub
    // must NOT publish a nostr.json record. The server no longer falls back to
    // the auth key (`npub`), so the lookup 404s rather than leaking it.
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (xonly, _) = keypair.x_only_public_key();
    let npub = xonly.to_string();
    let (sig, timestamp) =
        sign_la_action(&keypair, "register", &npub, "legacyreg", &[TEST_DESCRIPTOR]);

    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "legacyreg",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": npub,
            "signature": sig,
            "timestamp": timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["nip05"], Value::Null);

    // LNURL still resolves — only NIP-05 is opt-in.
    let (status, _) = get_path(&app, "/.well-known/lnurlp/legacyreg").await;
    assert_eq!(status, StatusCode::OK);

    // No verification key supplied => no NIP-05 record. The server returns the
    // LNURL-style error envelope (HTTP 200 + status=ERROR) rather than
    // publishing the auth key, so `names` is absent.
    let (status, body) = get_path(&app, "/.well-known/nostr.json?name=legacyreg").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ERROR");
    assert_eq!(body["code"], "NymNotFound");
    assert!(body.get("names").is_none());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_response_has_null_nip05_when_feature_disabled() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    let (npub, sig, timestamp) = sign_registration("nipoff", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "nipoff",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": npub,
            "verification_npub": npub,
            "signature": sig,
            "timestamp": timestamp,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["lightning_address"], "nipoff@test.example.com");
    assert_eq!(body["nip05"], Value::Null);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_nip05_resolves_verification_npub() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state_with_nip05(pool.clone()));

    let secp = Secp256k1::new();
    let auth_keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (auth_xonly, _) = auth_keypair.x_only_public_key();
    let auth_npub = auth_xonly.to_string();
    let verification_keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (verification_xonly, _) = verification_keypair.x_only_public_key();
    let verification_npub = verification_xonly.to_string();
    let (sig, timestamp) = sign_register_with_verification_keypair(
        &auth_keypair,
        &auth_npub,
        "verifykey",
        TEST_DESCRIPTOR,
        &verification_npub,
    );

    let (status, _) = post_json(
        &app,
        "/register",
        json!({
            "nym": "verifykey",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": auth_npub,
            "verification_npub": verification_npub,
            "signature": sig,
            "timestamp": timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = get_path(&app, "/.well-known/nostr.json?name=verifykey").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["names"]["verifykey"], verification_npub);
    assert_ne!(body["names"]["verifykey"], auth_npub);

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
            "nym": "taken", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub1, "verification_npub": npub1, "signature": sig1, "timestamp": timestamp1,
        }),
    )
    .await;

    let (npub2, sig2, timestamp2) = sign_registration("taken", TEST_DESCRIPTOR);
    let (status, body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "taken", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "verification_npub": npub2, "signature": sig2, "timestamp": timestamp2,
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
        "nym": "badsig", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": "aa".repeat(32), "timestamp": timestamp,
    })).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn register_invalid_nym_rejected() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));

    // "a" removed: one-character nyms are valid since ef7e11b.
    for bad_nym in ["AB", "-bad", "bad-", "has space", "has_under", "a@b"] {
        let (npub, sig, timestamp) = sign_registration(bad_nym, TEST_DESCRIPTOR);
        let (_, body) = post_json(
            &app,
            "/register",
            json!({
                "nym": bad_nym, "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            key_index: None,
            root_fingerprint: None,
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
async fn closed_admission_still_schedules_funded_reverse_swap_claim() {
    let pool = constrained_test_pool(1, None);
    cleanup_db(&pool).await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let npub = create_test_user(&pool, "reversewebhook").await;
    let invoice =
        insert_test_invoice(&pool, "reversewebhook", &npub, "lq1reversewebhook", 3_600).await;
    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some("reversewebhook"),
            boltz_swap_id: "REVERSE_WEBHOOK_CLOSED_1",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-existing-obligation",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();

    let (status, body) = tokio::time::timeout(
        Duration::from_secs(2),
        post_json(
            &app,
            "/webhook/boltz",
            json!({
                "event": "swap.update",
                "data": {
                    "id": "REVERSE_WEBHOOK_CLOSED_1",
                    "status": "transaction.confirmed"
                }
            }),
        ),
    )
    .await
    .expect("invoice-bound reverse claim must progress with one connection");

    assert_eq!(status, StatusCode::OK, "{body}");
    let swap = pay_service::db::get_swap_by_boltz_id(&pool, "REVERSE_WEBHOOK_CLOSED_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.status, "lockup_confirmed");
    assert_eq!(swap.address.as_deref(), Some("lq1reversewebhook"));
    assert_eq!(swap.claim_attempts, 1);
    assert!(
        swap.last_claim_error
            .as_deref()
            .is_some_and(|error| error.contains("invalid boltz response json")),
        "funding evidence must reach claim construction and schedule its local failure: {:?}",
        swap.last_claim_error
    );
    let (claim_scheduled, failure_recorded): (bool, bool) = sqlx::query_as(
        "SELECT next_claim_attempt_at IS NOT NULL, last_claim_error_at IS NOT NULL \
         FROM swap_records WHERE id = $1",
    )
    .bind(swap.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(claim_scheduled);
    assert!(failure_recorded);

    let invoice_after = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invoice_after.status, "in_progress");
    assert_eq!(invoice_after.settlement_status, "pending");
    assert_eq!(invoice_after.direct_settlement_status, "none");
    assert_eq!(invoice_after.swap_settlement_status, "pending");
    assert_eq!(invoice_after.direct_payment_projection_version, 0);
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "the deterministic local claim failure must not escape to a live provider"
    );
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

async fn seed_claimable_reverse_pool_swap(
    pool: &PgPool,
    nym: &str,
    boltz_swap_id: &str,
    boltz_response_json: &str,
    invoice_id: Option<uuid::Uuid>,
) -> uuid::Uuid {
    pay_service::db::record_swap(
        pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some(nym),
            boltz_swap_id,
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-claim-pool-proof",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json,
            invoice_id,
        },
    )
    .await
    .unwrap();
    let swap = pay_service::db::get_swap_by_boltz_id(pool, boltz_swap_id)
        .await
        .unwrap()
        .unwrap();
    pay_service::db::update_swap_status(
        pool,
        swap.id,
        pay_service::db::SwapStatus::LockupConfirmed,
        None,
    )
    .await
    .unwrap();
    swap.id
}

async fn seed_claimable_chain_pool_swap(
    pool: &PgPool,
    invoice_id: uuid::Uuid,
    nym: &str,
    boltz_swap_id: &str,
    boltz_response_json: &str,
) -> uuid::Uuid {
    let swap = pay_service::db::record_chain_swap(
        pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id,
            nym: Some(nym),
            boltz_swap_id,
            lockup_address: "bc1qclaimpoolproof",
            lockup_bip21: None,
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json,
        },
    )
    .await
    .unwrap();
    pay_service::db::update_chain_swap_status(
        pool,
        swap.id,
        pay_service::db::ChainSwapStatus::ServerLockConfirmed,
        None,
    )
    .await
    .unwrap();
    swap.id
}

async fn reverse_claim_pool_error(pool: &PgPool, swap_id: uuid::Uuid) -> AppError {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        claimer::exercise_reverse_claim_with_malformed_response(pool, swap_id),
    )
    .await
    .expect("reverse claim preparation must complete within its bounded timeout");
    match result {
        Err(error) => error,
        Ok(outcome) => panic!("expected deterministic reverse construction error, got {outcome:?}"),
    }
}

async fn chain_claim_pool_error(pool: &PgPool, swap_id: uuid::Uuid) -> AppError {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        claimer::exercise_chain_claim_with_malformed_response(pool, swap_id),
    )
    .await
    .expect("chain claim preparation must complete within its bounded timeout");
    match result {
        Err(error) => error,
        Ok(outcome) => panic!("expected deterministic chain construction error, got {outcome:?}"),
    }
}

fn assert_local_claim_error(error: &AppError, expected: &str) {
    let message = error.to_string();
    assert!(
        message.contains(expected),
        "expected {expected:?}, got {message:?}"
    );
    assert!(
        !message.to_ascii_lowercase().contains("pool timed out"),
        "claim preparation self-starved on the SQLx pool: {message}"
    );
}

#[tokio::test]
async fn reverse_claim_preparation_progresses_with_one_connection() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    create_test_user(&admin, "reversepoolone").await;
    let swap_id =
        seed_claimable_reverse_pool_swap(&admin, "reversepoolone", "REVERSE_POOL_ONE", "{", None)
            .await;
    let constrained = constrained_test_pool(1, None);

    let first_error = reverse_claim_pool_error(&constrained, swap_id).await;
    assert_local_claim_error(&first_error, "invalid boltz response json");
    let first = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_ONE")
        .await
        .unwrap()
        .unwrap();
    let first_address = first
        .address
        .clone()
        .expect("resolved descriptor address must survive construction error");
    assert_eq!(first.address_index, Some(0));

    // Retry exercises the cached-address branch on the same one-connection
    // pool. It must not consume another descriptor index.
    let second_error = reverse_claim_pool_error(&constrained, swap_id).await;
    assert_local_claim_error(&second_error, "invalid boltz response json");
    let second = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_ONE")
        .await
        .unwrap()
        .unwrap();
    let next_addr_idx: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = 'reversepoolone'")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(second.address.as_deref(), Some(first_address.as_str()));
    assert_eq!(second.address_index, Some(0));
    assert_eq!(next_addr_idx, 1);
    assert_eq!(second.claim_attempts, 2);
    assert!(!second.cooperative_refused);

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn chain_claim_preparation_progresses_with_one_connection() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let npub = create_test_user(&admin, "chainpoolone").await;
    let invoice =
        insert_test_invoice(&admin, "chainpoolone", &npub, "lq1chainpoolone", 3_600).await;
    let swap_id =
        seed_claimable_chain_pool_swap(&admin, invoice.id, "chainpoolone", "CHAIN_POOL_ONE", "{")
            .await;
    let constrained = constrained_test_pool(1, None);

    let error = chain_claim_pool_error(&constrained, swap_id).await;
    assert_local_claim_error(&error, "invalid chain boltz response json");
    let swap = pay_service::db::get_chain_swap_by_boltz_id(&admin, "CHAIN_POOL_ONE")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.claim_attempts, 1);
    assert_eq!(swap.status, "server_lock_confirmed");
    assert!(!swap.cooperative_refused);

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn advisory_locked_chain_claim_skips_without_preparation() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let npub = create_test_user(&admin, "chainpoollocked").await;
    let invoice = insert_test_invoice(
        &admin,
        "chainpoollocked",
        &npub,
        "lq1chainpoollocked",
        3_600,
    )
    .await;
    let swap_id = seed_claimable_chain_pool_swap(
        &admin,
        invoice.id,
        "chainpoollocked",
        "CHAIN_POOL_LOCKED",
        "{",
    )
    .await;
    let mut lock_holder = admin.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(format!("chain-claim:{swap_id}"))
        .execute(&mut *lock_holder)
        .await
        .unwrap();
    let constrained = constrained_test_pool(1, None);

    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        claimer::exercise_chain_claim_with_malformed_response(&constrained, swap_id),
    )
    .await
    .expect("advisory-lock loser must return promptly")
    .unwrap();
    assert!(matches!(outcome, claimer::ClaimOutcome::SkippedLockHeld));
    let swap = pay_service::db::get_chain_swap_by_boltz_id(&admin, "CHAIN_POOL_LOCKED")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.status, "server_lock_confirmed");
    assert_eq!(swap.claim_attempts, 0);
    assert!(swap.claim_tx_hex.is_none());
    assert!(!swap.cooperative_refused);

    lock_holder.rollback().await.unwrap();
    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn malformed_claim_test_seams_reject_persisted_bytes_without_mutation() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    create_test_user(&admin, "reverseseamguard").await;
    let reverse_id = seed_claimable_reverse_pool_swap(
        &admin,
        "reverseseamguard",
        "REVERSE_SEAM_GUARD",
        "{",
        None,
    )
    .await;

    let npub = create_test_user(&admin, "chainseamguard").await;
    let invoice =
        insert_test_invoice(&admin, "chainseamguard", &npub, "lq1chainseamguard", 3_600).await;
    let chain_id = seed_claimable_chain_pool_swap(
        &admin,
        invoice.id,
        "chainseamguard",
        "CHAIN_SEAM_GUARD",
        "{",
    )
    .await;
    sqlx::query("UPDATE swap_records SET claim_tx_hex = '00' WHERE id = $1")
        .bind(reverse_id)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("UPDATE chain_swap_records SET claim_tx_hex = '00' WHERE id = $1")
        .bind(chain_id)
        .execute(&admin)
        .await
        .unwrap();

    let constrained = constrained_test_pool(1, None);
    let reverse_error =
        claimer::exercise_reverse_claim_with_malformed_response(&constrained, reverse_id)
            .await
            .expect_err("persisted reverse bytes must close the malformed-only seam");
    let chain_error = claimer::exercise_chain_claim_with_malformed_response(&constrained, chain_id)
        .await
        .expect_err("persisted chain bytes must close the malformed-only seam");
    assert!(reverse_error
        .to_string()
        .contains("without persisted claim bytes"));
    assert!(chain_error
        .to_string()
        .contains("without persisted claim bytes"));

    let reverse = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_SEAM_GUARD")
        .await
        .unwrap()
        .unwrap();
    let chain = pay_service::db::get_chain_swap_by_boltz_id(&admin, "CHAIN_SEAM_GUARD")
        .await
        .unwrap()
        .unwrap();
    let next_addr_idx: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = 'reverseseamguard'")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert!(reverse.address.is_none());
    assert!(reverse.address_index.is_none());
    assert_eq!(reverse.claim_attempts, 0);
    assert_eq!(reverse.status, "lockup_confirmed");
    assert_eq!(next_addr_idx, 0);
    assert_eq!(chain.claim_attempts, 0);
    assert_eq!(chain.status, "server_lock_confirmed");

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn reverse_claim_preparations_progress_at_saturated_capacity() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    create_test_user(&admin, "reversepoolsaturated").await;
    let first_id = seed_claimable_reverse_pool_swap(
        &admin,
        "reversepoolsaturated",
        "REVERSE_POOL_SATURATED_1",
        "{",
        None,
    )
    .await;
    let second_id = seed_claimable_reverse_pool_swap(
        &admin,
        "reversepoolsaturated",
        "REVERSE_POOL_SATURATED_2",
        "{",
        None,
    )
    .await;
    let constrained = constrained_test_pool(2, Some(Arc::new(tokio::sync::Barrier::new(2))));

    let (first_error, second_error) = tokio::time::timeout(Duration::from_secs(4), async {
        tokio::join!(
            reverse_claim_pool_error(&constrained, first_id),
            reverse_claim_pool_error(&constrained, second_id)
        )
    })
    .await
    .expect("two reverse preparations must progress with exactly two connections");
    assert_local_claim_error(&first_error, "invalid boltz response json");
    assert_local_claim_error(&second_error, "invalid boltz response json");

    let first = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_SATURATED_1")
        .await
        .unwrap()
        .unwrap();
    let second = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_SATURATED_2")
        .await
        .unwrap()
        .unwrap();
    let next_addr_idx: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = 'reversepoolsaturated'")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(next_addr_idx, 2);
    assert_ne!(first.address, second.address);
    assert_ne!(first.address_index, second.address_index);

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn concurrent_same_reverse_swap_has_one_locked_preparation() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    create_test_user(&admin, "reversesamepool").await;
    let swap_id =
        seed_claimable_reverse_pool_swap(&admin, "reversesamepool", "REVERSE_POOL_SAME", "{", None)
            .await;

    // Hold the row after both constrained-pool connections rendezvous. The
    // advisory-lock winner blocks here while the loser must promptly report
    // SkippedLockHeld; once released, exactly one preparation allocates.
    let mut row_blocker = admin.begin().await.unwrap();
    sqlx::query("SELECT id FROM swap_records WHERE id = $1 FOR UPDATE")
        .bind(swap_id)
        .execute(&mut *row_blocker)
        .await
        .unwrap();
    let constrained = constrained_test_pool(2, Some(Arc::new(tokio::sync::Barrier::new(2))));
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let pool = constrained.clone();
        attempts.spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(3),
                claimer::exercise_reverse_claim_with_malformed_response(&pool, swap_id),
            )
            .await
            .expect("same-swap claim attempt must remain bounded")
        });
    }

    let skipped = tokio::time::timeout(Duration::from_secs(2), attempts.join_next())
        .await
        .expect("advisory-lock loser must return before row-lock winner")
        .expect("one same-swap task must finish")
        .expect("same-swap task must not panic");
    assert!(matches!(
        skipped,
        Ok(claimer::ClaimOutcome::SkippedLockHeld)
    ));

    row_blocker.rollback().await.unwrap();
    let winner = attempts
        .join_next()
        .await
        .expect("advisory-lock winner must finish")
        .expect("winner task must not panic");
    let winner_error = match winner {
        Err(error) => error,
        Ok(outcome) => panic!("expected deterministic construction error, got {outcome:?}"),
    };
    assert_local_claim_error(&winner_error, "invalid boltz response json");

    let swap = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_SAME")
        .await
        .unwrap()
        .unwrap();
    let next_addr_idx: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = 'reversesamepool'")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(swap.address_index, Some(0));
    assert_eq!(next_addr_idx, 1);
    assert_eq!(swap.claim_attempts, 1);

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn chain_claim_preparations_progress_at_saturated_capacity() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let npub = create_test_user(&admin, "chainpoolsaturated").await;
    let first_invoice = insert_test_invoice(
        &admin,
        "chainpoolsaturated",
        &npub,
        "lq1chainpoolsaturated1",
        3_600,
    )
    .await;
    let second_invoice = insert_test_invoice(
        &admin,
        "chainpoolsaturated",
        &npub,
        "lq1chainpoolsaturated2",
        3_600,
    )
    .await;
    let first_id = seed_claimable_chain_pool_swap(
        &admin,
        first_invoice.id,
        "chainpoolsaturated",
        "CHAIN_POOL_SATURATED_1",
        "{",
    )
    .await;
    let second_id = seed_claimable_chain_pool_swap(
        &admin,
        second_invoice.id,
        "chainpoolsaturated",
        "CHAIN_POOL_SATURATED_2",
        "{",
    )
    .await;
    let constrained = constrained_test_pool(2, Some(Arc::new(tokio::sync::Barrier::new(2))));

    let (first_error, second_error) = tokio::time::timeout(Duration::from_secs(4), async {
        tokio::join!(
            chain_claim_pool_error(&constrained, first_id),
            chain_claim_pool_error(&constrained, second_id)
        )
    })
    .await
    .expect("two chain preparations must progress with exactly two connections");
    assert_local_claim_error(&first_error, "invalid chain boltz response json");
    assert_local_claim_error(&second_error, "invalid chain boltz response json");

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn reverse_cooperative_refusal_commits_with_one_connection() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    create_test_user(&admin, "reverserefusalpool").await;
    // A JSON string is deliberately the wrong response shape; serde includes
    // its value in the local type error, deterministically exercising the real
    // `swap expired` refusal classifier without a provider/Electrum fake.
    let swap_id = seed_claimable_reverse_pool_swap(
        &admin,
        "reverserefusalpool",
        "REVERSE_REFUSAL_POOL_ONE",
        "\"swap expired\"",
        None,
    )
    .await;
    let constrained = constrained_test_pool(1, None);

    let error = reverse_claim_pool_error(&constrained, swap_id).await;
    assert_local_claim_error(&error, "swap expired");
    let swap = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_REFUSAL_POOL_ONE")
        .await
        .unwrap()
        .unwrap();
    let next_addr_idx: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = 'reverserefusalpool'")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert!(swap.cooperative_refused);
    assert!(swap.address.is_some());
    assert_eq!(swap.address_index, Some(0));
    assert_eq!(next_addr_idx, 1);
    assert!(swap.claim_tx_hex.is_none());
    assert_eq!(swap.status, "lockup_confirmed");
    assert_eq!(swap.claim_attempts, 1);

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn chain_cooperative_refusal_commits_with_one_connection() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let npub = create_test_user(&admin, "chainrefusalpool").await;
    let invoice = insert_test_invoice(
        &admin,
        "chainrefusalpool",
        &npub,
        "lq1chainrefusalpool",
        3_600,
    )
    .await;
    // Same deterministic local classifier trigger as the reverse refusal test.
    let swap_id = seed_claimable_chain_pool_swap(
        &admin,
        invoice.id,
        "chainrefusalpool",
        "CHAIN_REFUSAL_POOL_ONE",
        "\"swap expired\"",
    )
    .await;
    let constrained = constrained_test_pool(1, None);

    let error = chain_claim_pool_error(&constrained, swap_id).await;
    assert_local_claim_error(&error, "swap expired");
    let swap = pay_service::db::get_chain_swap_by_boltz_id(&admin, "CHAIN_REFUSAL_POOL_ONE")
        .await
        .unwrap()
        .unwrap();
    assert!(swap.cooperative_refused);
    assert!(swap.claim_tx_hex.is_none());
    assert_eq!(swap.status, "server_lock_confirmed");
    assert_eq!(swap.claim_attempts, 1);

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn terminal_and_unsupported_claims_do_not_prepare_or_allocate() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    create_test_user(&admin, "claimpoolterminal").await;
    let reverse_id = seed_claimable_reverse_pool_swap(
        &admin,
        "claimpoolterminal",
        "REVERSE_POOL_TERMINAL",
        "{",
        None,
    )
    .await;
    pay_service::db::update_swap_status(
        &admin,
        reverse_id,
        pay_service::db::SwapStatus::Claimed,
        Some("terminal-proof-txid"),
    )
    .await
    .unwrap();

    create_test_user(&admin, "claimpoolunsupportedreverse").await;
    pay_service::db::record_swap(
        &admin,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some("claimpoolunsupportedreverse"),
            boltz_swap_id: "REVERSE_POOL_UNSUPPORTED",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-unsupported-claim-pool-proof",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{",
            invoice_id: None,
        },
    )
    .await
    .unwrap();
    let unsupported_reverse =
        pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_UNSUPPORTED")
            .await
            .unwrap()
            .unwrap();

    let npub = create_test_user(&admin, "claimpoolunsupported").await;
    let invoice = insert_test_invoice(
        &admin,
        "claimpoolunsupported",
        &npub,
        "lq1claimpoolunsupported",
        3_600,
    )
    .await;
    let chain = pay_service::db::record_chain_swap(
        &admin,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("claimpoolunsupported"),
            boltz_swap_id: "CHAIN_POOL_UNSUPPORTED",
            lockup_address: "bc1qclaimpoolunsupported",
            lockup_bip21: None,
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{",
        },
    )
    .await
    .unwrap();
    let constrained = constrained_test_pool(1, None);
    let reverse = claimer::exercise_reverse_claim_with_malformed_response(&constrained, reverse_id)
        .await
        .unwrap();
    assert!(matches!(reverse, claimer::ClaimOutcome::AlreadyTerminal));
    let reverse_unsupported = claimer::exercise_reverse_claim_with_malformed_response(
        &constrained,
        unsupported_reverse.id,
    )
    .await
    .unwrap();
    assert!(matches!(
        reverse_unsupported,
        claimer::ClaimOutcome::AlreadyTerminal
    ));
    let chain_outcome =
        claimer::exercise_chain_claim_with_malformed_response(&constrained, chain.id)
            .await
            .unwrap();
    assert!(matches!(
        chain_outcome,
        claimer::ClaimOutcome::AlreadyTerminal
    ));

    let reverse = pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_TERMINAL")
        .await
        .unwrap()
        .unwrap();
    let unsupported_reverse =
        pay_service::db::get_swap_by_boltz_id(&admin, "REVERSE_POOL_UNSUPPORTED")
            .await
            .unwrap()
            .unwrap();
    let chain = pay_service::db::get_chain_swap_by_boltz_id(&admin, "CHAIN_POOL_UNSUPPORTED")
        .await
        .unwrap()
        .unwrap();
    let next_addr_idx: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = 'claimpoolterminal'")
            .fetch_one(&admin)
            .await
            .unwrap();
    let unsupported_next_addr_idx: i32 = sqlx::query_scalar(
        "SELECT next_addr_idx FROM users WHERE nym = 'claimpoolunsupportedreverse'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert!(reverse.address.is_none());
    assert!(reverse.address_index.is_none());
    assert_eq!(next_addr_idx, 0);
    assert_eq!(unsupported_reverse.status, "pending");
    assert!(unsupported_reverse.address.is_none());
    assert!(unsupported_reverse.address_index.is_none());
    assert_eq!(unsupported_reverse.claim_attempts, 0);
    assert_eq!(unsupported_next_addr_idx, 0);
    assert_eq!(chain.status, "pending");
    assert_eq!(chain.claim_attempts, 0);
    assert!(!chain.cooperative_refused);

    drop(constrained);
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn webhook_advances_chain_swap_records() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    // Admission closure applies only to new obligations. Existing provider
    // evidence must continue through the same state transition path.
    state.admission.set_workers_enabled(false);
    let app = test_app(state);

    let npub = create_test_user(&pool, "chainwebhook").await;
    let invoice = insert_test_invoice(&pool, "chainwebhook", &npub, "lq1chainwebhook", 60).await;
    pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
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
    assert_eq!(invoice_after.direct_settlement_status, "none");
    assert_eq!(invoice_after.swap_settlement_status, "pending");
    assert_eq!(invoice_after.direct_payment_projection_version, 0);

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
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
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
            "nym": "amtuser", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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

#[tokio::test]
async fn closed_reverse_admission_precedes_key_and_provider_mutation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_fee_policy_ready(false);
    let app = test_app(state);

    let (npub, sig, timestamp) = sign_registration("admissionclosed", TEST_DESCRIPTOR);
    let (register_status, register_body) = post_json(
        &app,
        "/register",
        json!({
            "nym": "admissionclosed",
            "ct_descriptor": TEST_DESCRIPTOR,
            "npub": npub,
            "verification_npub": npub,
            "signature": sig,
            "timestamp": timestamp,
        }),
    )
    .await;
    assert_eq!(register_status, StatusCode::CREATED, "{register_body}");

    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let reverse_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    let chain_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (status, body) = get_path(&app, "/lnurlp/callback/admissionclosed?amount=100000").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["status"], "ERROR");
    assert_eq!(body["code"], "ServiceUnavailable");
    assert_eq!(
        body["reason"],
        "This payment method is temporarily unavailable. Try again later."
    );
    for private_term in ["fee_policy", "worker", "claimer", "reconciler", "schema"] {
        assert!(
            !body.to_string().contains(private_term),
            "private admission reason leaked: {private_term}"
        );
    }

    let sequence_after = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    assert_eq!(sequence_after, sequence_before);
    let swap_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        swap_count, reverse_before,
        "closed admission created a reverse provider obligation"
    );
    let chain_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        chain_count, chain_before,
        "closed admission created a chain provider obligation"
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "closed admission called the provider"
    );
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn whitelisted_liquid_admission_failure_does_not_fallback_to_lightning() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "liquidclosed").await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let mut state = test_state_with_config(pool.clone(), config);
    state.ip_whitelist =
        Arc::new(IpWhitelist::parse(&["127.0.0.1".to_string()]).expect("parse test whitelist"));
    let liquid_reporter = state
        .admission
        .reporter(pay_service::admission::Worker::LiquidWatcher);
    liquid_reporter.cycle_succeeded();
    drop(liquid_reporter);
    let app = test_app(state);
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();

    let (status, body) = get_path_from(
        &app,
        "/lnurlp/callback/liquidclosed?amount=100000&payment_method=L-BTC",
        "127.0.0.1:42000".parse().unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "ServiceUnavailable");
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before,
        "a hard Liquid admission failure fell through to Lightning"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn healthy_direct_liquid_checkout_omits_closed_swap_rails() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "directbaseline").await;
    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym: "directbaseline",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Direct baseline",
            description: "Direct Liquid remains independently payable",
            display_currency: "BTC",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_fee_policy_ready(true);
    state.admission.set_recovery_commitment_ready(false);
    let reverse_reporter = state
        .admission
        .reporter(pay_service::admission::Worker::ReverseReconciler);
    reverse_reporter.cycle_succeeded();
    drop(reverse_reporter);
    let app = test_app(state);
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let reverse_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    let chain_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();

    let (status, body) =
        post_json(&app, "/directbaseline/invoice", json!({"amount_sat": 1000})).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["invoice_id"].is_string(), "{body}");
    assert!(
        body["liquid_address"]
            .as_str()
            .is_some_and(|address| !address.is_empty()),
        "{body}"
    );
    assert_eq!(body["lightning_pr"], "");
    assert!(body["bitcoin_chain_address"].is_null());
    assert!(body["bitcoin_chain_bip21"].is_null());
    let sequence_after = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    assert_eq!(sequence_after, sequence_before);
    let reverse_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    let chain_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reverse_after, reverse_before);
    assert_eq!(chain_after, chain_before);
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "closed swap rails called Boltz"
    );
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn certification_invoice_scope_does_not_bypass_closed_admission() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "certclosed").await;
    pay_service::db::upsert_donation_page(
        &pool,
        &pay_service::db::UpsertDonationPage {
            nym: "certclosed",
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Certification closed",
            description: "Certification cannot bypass money safety",
            display_currency: "BTC",
            website: None,
            twitter: None,
            instagram: None,
            pos_mode: Some(false),
            enabled: true,
            generated_og_template_version: None,
            alias: None,
        },
    )
    .await
    .unwrap();

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    config.certification = CertificationConfig {
        enabled: true,
        source_allowlist: vec!["127.0.0.1".into()],
        token: "cert-admission-token".into(),
        scopes: vec!["invoice_create".into()],
    };
    let certification = certification::CertificationAllowlist::parse(&config.certification)
        .expect("parse certification allowlist");
    let mut state = test_state_with_config(pool.clone(), config);
    state.certification = Arc::new(certification);
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let cursor_before: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM donation_pages WHERE nym = $1 AND kind = $2")
            .bind("certclosed")
            .bind(pay_service::db::KIND_PAYMENT_PAGE)
            .fetch_one(&pool)
            .await
            .unwrap();
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let reverse_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    let chain_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();

    let (status, body) = post_json_from(
        &app,
        "/certclosed/invoice",
        json!({"amount_sat": 1000}),
        "127.0.0.1:42001".parse().unwrap(),
        &[("x-bullnym-certification-token", "cert-admission-token")],
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "ServiceUnavailable");
    let invoice_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(invoice_count, 0);
    let cursor_after: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM donation_pages WHERE nym = $1 AND kind = $2")
            .bind("certclosed")
            .bind(pay_service::db::KIND_PAYMENT_PAGE)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cursor_after, cursor_before);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before
    );
    let reverse_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    let chain_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reverse_after, reverse_before);
    assert_eq!(chain_after, chain_before);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn lazy_lightning_offer_lock_contention_fails_fast_without_mutation_and_retries() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "lazyofferlocked").await;
    let invoice =
        insert_test_invoice(&pool, "lazyofferlocked", &npub, "lq1lazyofferlocked", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();

    // Seed a reusable offer so the post-contention request can prove the
    // ordinary idempotent path still works without depending on Boltz output.
    let bolt11 = fresh_bolt11(1_000);
    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some("lazyofferlocked"),
            boltz_swap_id: "LAZY_OFFER_LOCKED_1",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: &bolt11,
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let app = test_app(test_state_with_config(pool.clone(), config));
    let path = format!("/api/v1/invoices/{}/lightning", invoice.id);
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let swaps_before: Vec<(String, String, Option<i64>, String)> = sqlx::query_as(
        "SELECT id::TEXT, boltz_swap_id, key_index, status \
         FROM swap_records ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let mut offer_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(pay_service::db::invoice_lightning_lock_key(invoice.id))
        .execute(&mut *offer_tx)
        .await
        .unwrap();

    let (locked_status, locked_body) = tokio::time::timeout(
        Duration::from_millis(500),
        post_json(&app, &path, json!({})),
    )
    .await
    .expect("lazy Lightning offer endpoint blocked instead of returning retry response");
    assert_eq!(
        locked_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{locked_body}"
    );
    assert_eq!(locked_body["code"], "ServiceUnavailable");
    assert!(
        locked_body["reason"]
            .as_str()
            .is_some_and(|reason| reason.to_ascii_lowercase().contains("retry")),
        "lock contention response was not retryable: {locked_body}"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before,
        "lock contention consumed a swap key"
    );
    let swaps_while_locked: Vec<(String, String, Option<i64>, String)> = sqlx::query_as(
        "SELECT id::TEXT, boltz_swap_id, key_index, status \
         FROM swap_records ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        swaps_while_locked, swaps_before,
        "lock contention created or changed a swap"
    );

    offer_tx.commit().await.unwrap();
    let (retry_status, retry_body) =
        tokio::time::timeout(Duration::from_secs(2), post_json(&app, &path, json!({})))
            .await
            .expect("lazy Lightning offer retry did not complete after lock release");
    assert_eq!(retry_status, StatusCode::OK, "{retry_body}");
    assert_eq!(retry_body["pr"], bolt11);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before
    );
    let swaps_after_retry: Vec<(String, String, Option<i64>, String)> = sqlx::query_as(
        "SELECT id::TEXT, boltz_swap_id, key_index, status \
         FROM swap_records ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(swaps_after_retry, swaps_before);

    provider_task.abort();
    let _ = provider_task.await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn reusable_lightning_offer_progresses_with_one_pool_connection() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let npub = create_test_user(&admin, "lazyofferoneconn").await;
    let invoice = insert_test_invoice(
        &admin,
        "lazyofferoneconn",
        &npub,
        "lq1lazyofferoneconn",
        3_600,
    )
    .await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&admin)
        .await
        .unwrap();

    let bolt11 = fresh_bolt11(1_000);
    pay_service::db::record_swap(
        &admin,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some("lazyofferoneconn"),
            boltz_swap_id: "LAZY_OFFER_ONE_CONNECTION_1",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: &bolt11,
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();
    let sequence_before = pay_service::db::swap_key_seq_next_value(&admin)
        .await
        .unwrap();
    let swaps_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&admin)
        .await
        .unwrap();

    let constrained = constrained_test_pool(1, None);
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let app = test_app(test_state_with_config(constrained.clone(), config));
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(2),
        post_json(
            &app,
            &format!("/api/v1/invoices/{}/lightning", invoice.id),
            json!({}),
        ),
    )
    .await
    .expect("offer reuse attempted a nested pool acquisition with one connection");

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pr"], bolt11);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&admin)
            .await
            .unwrap(),
        sequence_before,
        "cached offer reuse allocated a key before returning"
    );
    let swaps_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(
        swaps_after, swaps_before,
        "cached offer reuse mutated provider obligations"
    );

    drop(app);
    constrained.close().await;
    provider_task.abort();
    let _ = provider_task.await;
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn terminal_latest_lightning_swap_is_withdrawn_and_replaced_not_masked_by_older_pending() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "lazyofferterminal";
    let npub = create_test_user(&pool, nym).await;
    let invoice = insert_test_invoice(&pool, nym, &npub, "lq1lazyofferterminal", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();

    let older_pending_bolt11 = fresh_bolt11(1_000);
    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some(nym),
            boltz_swap_id: "LAZY_OFFER_OLDER_PENDING_1",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: &older_pending_bolt11,
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE swap_records SET created_at = NOW() - INTERVAL '2 minutes' \
         WHERE boltz_swap_id = $1",
    )
    .bind("LAZY_OFFER_OLDER_PENDING_1")
    .execute(&pool)
    .await
    .unwrap();

    let terminal_bolt11 = fresh_bolt11(1_000);
    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some(nym),
            boltz_swap_id: "LAZY_OFFER_TERMINAL_1",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: &terminal_bolt11,
            preimage_hex: "cc".repeat(32).as_str(),
            claim_key_hex: "dd".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();
    let terminal_swap = pay_service::db::get_swap_by_boltz_id(&pool, "LAZY_OFFER_TERMINAL_1")
        .await
        .unwrap()
        .unwrap();
    pay_service::db::update_swap_status(
        &pool,
        terminal_swap.id,
        pay_service::db::SwapStatus::Expired,
        None,
    )
    .await
    .unwrap();

    let replacement_bolt11 = fresh_replacement_bolt11(1_000);
    let provider = spawn_successful_reverse_barrier_server(
        "LAZY_OFFER_TERMINAL_REPLACEMENT_1",
        &replacement_bolt11,
    )
    .await;
    let mut config = test_config();
    config.boltz.api_url = provider.base_url.clone();
    let app = test_app(test_state_with_config(pool.clone(), config));
    let path = format!("/api/v1/invoices/{}/lightning", invoice.id);

    let (detail_status, detail) =
        get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(detail_status, StatusCode::OK, "{detail}");
    assert!(
        detail["lightning_pr"].is_null(),
        "terminal latest swap or older pending offer escaped: {detail}"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

    let request_app = app.clone();
    let request_path = path.clone();
    let request =
        tokio::spawn(async move { post_json(&request_app, &request_path, json!({})).await });
    provider.wait_until_request_is_blocked().await;
    provider.release_response().await;
    let (offer_status, offer) = tokio::time::timeout(Duration::from_secs(3), request)
        .await
        .expect("replacement offer request did not finish")
        .expect("replacement offer request task failed");
    assert_eq!(offer_status, StatusCode::OK, "{offer}");
    assert_eq!(offer["pr"], replacement_bolt11);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let requests = provider.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["invoiceAmount"], 1_000);
    drop(requests);

    let rows: Vec<(String, String, i64, Option<i64>)> = sqlx::query_as(
        "SELECT boltz_swap_id, status, amount_sat, key_index \
         FROM swap_records WHERE invoice_id = $1 ORDER BY created_at, id",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3, "unexpected reverse swap history: {rows:?}");
    assert!(rows.iter().any(|row| {
        row.0 == "LAZY_OFFER_OLDER_PENDING_1" && row.1 == "pending" && row.3.is_none()
    }));
    assert!(rows
        .iter()
        .any(|row| { row.0 == "LAZY_OFFER_TERMINAL_1" && row.1 == "expired" && row.3.is_none() }));
    assert!(rows.iter().any(|row| {
        row.0 == "LAZY_OFFER_TERMINAL_REPLACEMENT_1"
            && row.1 == "pending"
            && row.2 == 1_000
            && row.3.is_some()
    }));
    let reusable = pay_service::db::latest_lightning_pr_for_invoice(&pool, invoice.id)
        .await
        .unwrap();
    assert_eq!(reusable, Some((replacement_bolt11, 1_000)));

    provider.shutdown().await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn lazy_lightning_provider_result_is_recorded_but_hidden_after_partial_terminalizes() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "lazyofferpartialrace";
    let npub = create_test_user(&pool, nym).await;
    let invoice = insert_test_invoice(&pool, nym, &npub, "lq1lazyofferpartialrace", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();
    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:6161616161616161616161616161616161616161616161616161616161616161:0",
            400,
            "6161616161616161616161616161616161616161616161616161616161616161",
            0,
            "lq1lazyofferpartialrace",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_payment_events SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .execute(&pool)
    .await
    .unwrap();
    let before = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.status, "partially_paid");
    assert_eq!(before.presentation_status.as_deref(), Some("partial"));

    let stale_bolt11 = fresh_bolt11(600);
    let provider =
        spawn_successful_reverse_barrier_server("LAZY_OFFER_PARTIAL_RACE_1", &stale_bolt11).await;
    let mut config = test_config();
    config.boltz.api_url = provider.base_url.clone();
    let app = test_app(test_state_with_config(pool.clone(), config));
    let request_app = app.clone();
    let path = format!("/api/v1/invoices/{}/lightning", invoice.id);
    let request = tokio::spawn(async move { post_json(&request_app, &path, json!({})).await });

    provider.wait_until_request_is_blocked().await;
    let terminalized = tokio::time::timeout(
        Duration::from_secs(2),
        pay_service::db::terminalize_stale_checkout_partial_invoice(&pool, invoice.id, 900),
    )
    .await
    .expect("partial terminalization blocked behind provider I/O")
    .unwrap();
    assert_eq!(terminalized, 1);
    provider.release_response().await;

    let (status, body) = tokio::time::timeout(Duration::from_secs(3), request)
        .await
        .expect("lazy offer request did not finish after provider release")
        .expect("lazy offer request task failed");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "ServiceUnavailable");
    assert!(body.get("pr").is_none(), "stale offer escaped: {body}");
    assert!(!body.to_string().contains(&stale_bolt11));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let requests = provider.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["invoiceAmount"], 600);
    drop(requests);

    let recorded: (String, i64, Option<uuid::Uuid>, Option<i64>, String) = sqlx::query_as(
        "SELECT invoice, amount_sat, invoice_id, key_index, status \
         FROM swap_records WHERE boltz_swap_id = $1",
    )
    .bind("LAZY_OFFER_PARTIAL_RACE_1")
    .fetch_one(&pool)
    .await
    .expect("successful provider result was not durably recorded");
    assert_eq!(recorded.0, stale_bolt11);
    assert_eq!(recorded.1, 600);
    assert_eq!(recorded.2, Some(invoice.id));
    assert!(recorded.3.is_some());
    assert_eq!(recorded.4, "pending");
    let final_invoice = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_invoice.status, "underpaid");
    let (detail_status, detail) =
        get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(detail_status, StatusCode::OK, "{detail}");
    assert!(detail["lightning_pr"].is_null());

    provider.shutdown().await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn lazy_lightning_final_row_lock_orders_terminalization_after_offer_commit() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "lazyoffercommitorder";
    let npub = create_test_user(&pool, nym).await;
    let invoice = insert_test_invoice(&pool, nym, &npub, "lq1lazyoffercommitorder", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();
    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:7171717171717171717171717171717171717171717171717171717171717171:0",
            400,
            "7171717171717171717171717171717171717171717171717171717171717171",
            0,
            "lq1lazyoffercommitorder",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_payment_events SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .execute(&pool)
    .await
    .unwrap();

    let bolt11 = fresh_bolt11(600);
    let provider =
        spawn_successful_reverse_barrier_server("LAZY_OFFER_COMMIT_ORDER_1", &bolt11).await;
    let mut config = test_config();
    config.boltz.api_url = provider.base_url.clone();
    let app = test_app(test_state_with_config(pool.clone(), config));
    let commit_hook = invoice::install_invoice_integration_test_hook(
        invoice::InvoiceIntegrationTestHookPoint::OfferBeforeCommit,
    );
    let request_app = app.clone();
    let path = format!("/api/v1/invoices/{}/lightning", invoice.id);
    let request = tokio::spawn(async move { post_json(&request_app, &path, json!({})).await });

    provider.wait_until_request_is_blocked().await;
    provider.release_response().await;
    tokio::time::timeout(Duration::from_secs(2), commit_hook.wait_until_reached())
        .await
        .expect("offer did not reach its final validation/row-lock boundary");

    let terminal_pool = pool.clone();
    let invoice_id = invoice.id;
    let mut terminalizer = tokio::spawn(async move {
        pay_service::db::terminalize_stale_checkout_partial_invoice(&terminal_pool, invoice_id, 900)
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut terminalizer)
            .await
            .is_err(),
        "terminalization must wait for the validated offer transaction to commit"
    );

    commit_hook.release();
    let (status, body) = tokio::time::timeout(Duration::from_secs(3), request)
        .await
        .expect("offer request did not finish after commit release")
        .expect("offer request task failed");
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["pr"], bolt11);

    let terminalized = tokio::time::timeout(Duration::from_secs(2), terminalizer)
        .await
        .expect("terminalization did not finish after offer commit")
        .expect("terminalization task failed")
        .unwrap();
    assert_eq!(terminalized, 1);
    let final_invoice = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_invoice.status, "underpaid");
    let recorded: (String, i64, String) = sqlx::query_as(
        "SELECT invoice, amount_sat, status FROM swap_records WHERE boltz_swap_id = $1",
    )
    .bind("LAZY_OFFER_COMMIT_ORDER_1")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recorded, (bolt11, 600, "pending".to_string()));

    provider.shutdown().await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn lazy_lightning_provider_result_is_recorded_but_hidden_after_hard_expiry() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "lazyofferexpiryrace";
    let npub = create_test_user(&pool, nym).await;
    let invoice = insert_test_invoice(&pool, nym, &npub, "lq1lazyofferexpiryrace", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();

    let stale_bolt11 = fresh_bolt11(1_000);
    let provider =
        spawn_successful_reverse_barrier_server("LAZY_OFFER_EXPIRY_RACE_1", &stale_bolt11).await;
    let mut config = test_config();
    config.boltz.api_url = provider.base_url.clone();
    let app = test_app(test_state_with_config(pool.clone(), config));
    let request_app = app.clone();
    let path = format!("/api/v1/invoices/{}/lightning", invoice.id);
    let request = tokio::spawn(async move { post_json(&request_app, &path, json!({})).await });

    provider.wait_until_request_is_blocked().await;
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query("UPDATE invoices SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
            .bind(invoice.id)
            .execute(&pool),
    )
    .await
    .expect("hard-expiry update blocked behind provider I/O")
    .unwrap();
    let expired_snapshot = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        expired_snapshot.status, "unpaid",
        "the hard deadline must independently suppress a stale provider result"
    );
    provider.release_response().await;

    let (status, body) = tokio::time::timeout(Duration::from_secs(3), request)
        .await
        .expect("lazy offer request did not finish after provider release")
        .expect("lazy offer request task failed");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "ServiceUnavailable");
    assert!(body.get("pr").is_none(), "stale offer escaped: {body}");
    assert!(!body.to_string().contains(&stale_bolt11));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let requests = provider.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["invoiceAmount"], 1_000);
    drop(requests);

    let recorded: (String, i64, Option<uuid::Uuid>, Option<i64>, String) = sqlx::query_as(
        "SELECT invoice, amount_sat, invoice_id, key_index, status \
         FROM swap_records WHERE boltz_swap_id = $1",
    )
    .bind("LAZY_OFFER_EXPIRY_RACE_1")
    .fetch_one(&pool)
    .await
    .expect("successful provider result was not durably recorded");
    assert_eq!(recorded.0, stale_bolt11);
    assert_eq!(recorded.1, 1_000);
    assert_eq!(recorded.2, Some(invoice.id));
    assert!(recorded.3.is_some());
    assert_eq!(recorded.4, "pending");
    let (detail_status, detail) =
        get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(detail_status, StatusCode::OK, "{detail}");
    assert_eq!(detail["status"], "unpaid");
    assert!(detail["lightning_pr"].is_null());

    provider.shutdown().await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn closed_admission_returns_existing_reusable_lightning_offer() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "reusableclosed").await;
    let invoice =
        insert_test_invoice(&pool, "reusableclosed", &npub, "lq1reusableclosed", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();

    let bolt11 = fresh_bolt11(1_000);
    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some("reusableclosed"),
            boltz_swap_id: "REUSABLE_CLOSED_1",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: &bolt11,
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();

    let (status, body) = post_json(
        &app,
        &format!("/api/v1/invoices/{}/lightning", invoice.id),
        json!({}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pr"], bolt11);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn closed_admission_reuses_cached_liquid_proof_but_rejects_uncached_without_mutation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "liquidproofclosed";
    create_test_user(&pool, nym).await;

    let secp = Secp256k1::new();
    let cached_key = SecretKey::from_slice(&[7; 32]).unwrap();
    let cached_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &cached_key).to_string();
    let cached_outpoint = format!("{}:0", "11".repeat(32));
    let cached_index =
        pay_service::db::allocate_outpoint_address(&pool, nym, &cached_outpoint, &cached_pubkey)
            .await
            .unwrap();
    let expected_address =
        pay_service::descriptor::derive_address(TEST_DESCRIPTOR, cached_index as u32).unwrap();

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let proof_tag = config.proof.message_tag.clone();
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_workers_enabled(false);
    let app = test_app(state);

    let cursor_before: i32 = sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = $1")
        .bind(nym)
        .fetch_one(&pool)
        .await
        .unwrap();
    let reservations_before: Vec<(String, i32, Option<String>, bool)> = sqlx::query_as(
        "SELECT outpoint, addr_index, pubkey, fulfilled FROM outpoint_addresses \
         WHERE nym = $1 ORDER BY outpoint",
    )
    .bind(nym)
    .fetch_all(&pool)
    .await
    .unwrap();

    let sign_proof = |secret_key: &SecretKey, outpoint: &str| {
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, secret_key).to_string();
        let digest =
            pay_service::utxo::ownership_message_digest(proof_tag.as_bytes(), nym, outpoint);
        let signature = hex::encode(
            secp.sign_ecdsa(&Message::from_digest(digest), secret_key)
                .serialize_der(),
        );
        (pubkey, signature)
    };
    let (cached_pubkey, cached_sig) = sign_proof(&cached_key, &cached_outpoint);
    let proof_blinder = "01".repeat(32);
    let (status, body) = get_path(
        &app,
        &format!(
            "/lnurlp/callback/{nym}?amount=100000&payment_method=L-BTC&outpoint={cached_outpoint}&pubkey={cached_pubkey}&sig={cached_sig}&value=1000&value_bf={proof_blinder}&asset_bf={proof_blinder}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"L-BTC": {"address": expected_address}}));
    let cursor_after_cached: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = $1")
            .bind(nym)
            .fetch_one(&pool)
            .await
            .unwrap();
    let reservations_after_cached: Vec<(String, i32, Option<String>, bool)> = sqlx::query_as(
        "SELECT outpoint, addr_index, pubkey, fulfilled FROM outpoint_addresses \
         WHERE nym = $1 ORDER BY outpoint",
    )
    .bind(nym)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        cursor_after_cached, cursor_before,
        "cached Liquid proof moved the address cursor"
    );
    assert_eq!(
        reservations_after_cached, reservations_before,
        "cached Liquid proof changed its reservation"
    );

    let uncached_key = SecretKey::from_slice(&[8; 32]).unwrap();
    let uncached_outpoint = format!("{}:1", "22".repeat(32));
    let (uncached_pubkey, uncached_sig) = sign_proof(&uncached_key, &uncached_outpoint);
    let (status, body) = get_path(
        &app,
        &format!(
            "/lnurlp/callback/{nym}?amount=100000&payment_method=L-BTC&outpoint={uncached_outpoint}&pubkey={uncached_pubkey}&sig={uncached_sig}&value=1000&value_bf={proof_blinder}&asset_bf={proof_blinder}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        body,
        json!({
            "status": "ERROR",
            "code": "ServiceUnavailable",
            "reason": "This payment method is temporarily unavailable. Try again later."
        })
    );
    let cursor_after: i32 = sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = $1")
        .bind(nym)
        .fetch_one(&pool)
        .await
        .unwrap();
    let reservations_after: Vec<(String, i32, Option<String>, bool)> = sqlx::query_as(
        "SELECT outpoint, addr_index, pubkey, fulfilled FROM outpoint_addresses \
         WHERE nym = $1 ORDER BY outpoint",
    )
    .bind(nym)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        cursor_after, cursor_before,
        "closed admission moved the address cursor"
    );
    assert_eq!(
        reservations_after, reservations_before,
        "closed admission created or changed an outpoint reservation"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn closed_admission_rejects_absent_and_expired_lazy_lightning_without_mutation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_workers_enabled(false);
    let app = test_app(state);

    let cases = [("absent", None), ("expired", Some(expired_bolt11(1_000)))];
    for (case, previous_pr) in cases {
        let nym = format!("lazyclosed{case}");
        let npub = create_test_user(&pool, &nym).await;
        let invoice = insert_test_invoice(&pool, &nym, &npub, &format!("lq1{nym}"), 3_600).await;
        sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
            .bind(invoice.id)
            .execute(&pool)
            .await
            .unwrap();

        if let Some(previous_pr) = previous_pr {
            pay_service::db::record_swap(
                &pool,
                &pay_service::db::NewSwapRecord {
                    key_index: None,
                    root_fingerprint: None,
                    nym: Some(&nym),
                    boltz_swap_id: "EXPIRED_LAZY_CLOSED_1",
                    address: None,
                    address_index: None,
                    amount_sat: 1_000,
                    invoice: &previous_pr,
                    preimage_hex: "aa".repeat(32).as_str(),
                    claim_key_hex: "bb".repeat(32).as_str(),
                    boltz_response_json: "{}",
                    invoice_id: Some(invoice.id),
                },
            )
            .await
            .unwrap();
        }

        let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap();
        let swap_rows_before: Vec<(String, String, String, Option<i64>, String)> = sqlx::query_as(
            "SELECT id::TEXT, boltz_swap_id, invoice, key_index, status \
                 FROM swap_records ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let (status, body) = post_json(
            &app,
            &format!("/api/v1/invoices/{}/lightning", invoice.id),
            json!({}),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "case {case}: {body}"
        );
        assert_eq!(
            body,
            json!({
                "status": "ERROR",
                "code": "ServiceUnavailable",
                "reason": "This payment method is temporarily unavailable. Try again later."
            }),
            "case {case}"
        );
        assert_eq!(
            pay_service::db::swap_key_seq_next_value(&pool)
                .await
                .unwrap(),
            sequence_before,
            "case {case}: closed admission consumed a swap key"
        );
        let swap_rows_after: Vec<(String, String, String, Option<i64>, String)> = sqlx::query_as(
            "SELECT id::TEXT, boltz_swap_id, invoice, key_index, status \
                 FROM swap_records ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            swap_rows_after, swap_rows_before,
            "case {case}: closed admission changed swap rows"
        );
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            0,
            "case {case}: closed admission called Boltz"
        );
    }

    provider_task.abort();
    let _ = provider_task.await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn closed_admission_does_not_block_recovery_before_boltz_failure() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "recoverclosed";
    let (npub, keypair, invoice, swap) = seed_merchant_invoice_swap(
        &pool,
        nym,
        "RECOVER_CLOSED_1",
        JOURNAL_LOCKUP_ADDRESS,
        1_010,
        1_000,
    )
    .await;
    pay_service::db::mark_chain_swap_refund_due(&pool, swap.id)
        .await
        .unwrap();

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    config.features.chain_swap_merchant_recovery = true;
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let invoice_id = invoice.id.to_string();
    let (signature, timestamp) = sign_invoice_recover_with_keypair(
        &keypair,
        &npub,
        nym,
        &invoice_id,
        JOURNAL_DESTINATION_ADDRESS,
    );

    let (status, body) = post_json(
        &app,
        &format!("/api/v1/{nym}/invoices/{invoice_id}/recover"),
        json!({
            "npub": npub,
            "timestamp": timestamp,
            "signature": signature,
            "btc_address": JOURNAL_DESTINATION_ADDRESS,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "status": "ERROR",
            "code": "BoltzError",
            "reason": "Lightning swap service is unavailable."
        })
    );
    assert_ne!(body["code"], "ServiceUnavailable");
    assert_ne!(
        body["reason"],
        "This payment method is temporarily unavailable. Try again later."
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        1,
        "recovery must reach the Boltz safety pre-check exactly once"
    );
    let persisted = pay_service::db::get_chain_swap_by_id(&pool, swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.status, "refund_due");
    assert_eq!(
        persisted.refund_address.as_deref(),
        Some(JOURNAL_DESTINATION_ADDRESS),
        "the signed first-write recovery destination must survive provider failure"
    );
    provider_task.abort();
    let _ = provider_task.await;

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
        "nym": "deluser", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub_hex, "verification_npub": npub_hex, "signature": sig, "timestamp": timestamp,
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
            "nym": "lifecycle1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
        "nym": "lifecycle2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": new_sig, "timestamp": new_timestamp,
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
            "nym": "samename", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            "nym": "samename", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": re_sig, "timestamp": re_timestamp,
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
            "nym": "active1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            "nym": "active2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig2, "timestamp": timestamp2,
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
            "nym": "reserved", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub1, "verification_npub": npub1, "signature": sig1, "timestamp": timestamp1,
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
            "nym": "reserved", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "verification_npub": npub2, "signature": sig2, "timestamp": timestamp2,
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
            public_slug: None,
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
        pay_service::db::register_user_atomic(&pool, &npub, "idxlife", TEST_DESCRIPTOR, None, 5)
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

#[tokio::test]
async fn cancel_invoice_fail_closes_unknown_and_accepted_evidence_projections() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "cancelprojection").await;
    let unknown =
        insert_test_invoice(&pool, "cancelprojection", &npub, "lq1cancelunknown", 3_600).await;
    let evidence =
        insert_test_invoice(&pool, "cancelprojection", &npub, "lq1cancelevidence", 3_600).await;
    let workflow =
        insert_test_invoice(&pool, "cancelprojection", &npub, "lq1cancelworkflow", 3_600).await;

    sqlx::query("UPDATE invoices SET presentation_status = NULL WHERE id = $1")
        .bind(unknown.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        pay_service::db::cancel_invoice(&pool, unknown.id)
            .await
            .unwrap(),
        (0, "unpaid".to_string())
    );

    sqlx::query("UPDATE invoices SET presentation_status = 'payment_received' WHERE id = $1")
        .bind(evidence.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        pay_service::db::cancel_invoice(&pool, evidence.id)
            .await
            .unwrap(),
        (0, "unpaid".to_string())
    );

    sqlx::query(
        "UPDATE invoices SET swap_settlement_status = 'pending', settlement_status = 'pending' \
         WHERE id = $1",
    )
    .bind(workflow.id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        pay_service::db::cancel_invoice(&pool, workflow.id)
            .await
            .unwrap(),
        (0, "unpaid".to_string())
    );

    let states: Vec<(String, Option<String>, String, Option<i64>)> = sqlx::query_as(
        "SELECT status, presentation_status, settlement_status, \
                EXTRACT(EPOCH FROM cancelled_at)::BIGINT \
         FROM invoices WHERE id = ANY($1::UUID[]) ORDER BY id",
    )
    .bind([unknown.id, evidence.id, workflow.id])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(states.len(), 3);
    assert!(states
        .iter()
        .all(|(status, _, _, cancelled_at)| status == "unpaid" && cancelled_at.is_none()));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn cancel_invoice_rechecks_projection_after_waiting_on_the_invoice_row() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "cancelrace").await;
    let invoice = insert_test_invoice(&pool, "cancelrace", &npub, "lq1cancelrace", 3_600).await;

    let mut evidence_tx = pool.begin().await.unwrap();
    let _: uuid::Uuid = sqlx::query_scalar("SELECT id FROM invoices WHERE id = $1 FOR UPDATE")
        .bind(invoice.id)
        .fetch_one(&mut *evidence_tx)
        .await
        .unwrap();

    let cancel_pool = pool.clone();
    let invoice_id = invoice.id;
    let mut cancel_task =
        tokio::spawn(
            async move { pay_service::db::cancel_invoice(&cancel_pool, invoice_id).await },
        );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut cancel_task)
            .await
            .is_err(),
        "cancel must wait for the concurrent projection writer"
    );

    sqlx::query(
        "UPDATE invoices SET presentation_status = 'payment_received', \
             direct_settlement_status = 'pending', settlement_status = 'pending' \
         WHERE id = $1",
    )
    .bind(invoice.id)
    .execute(&mut *evidence_tx)
    .await
    .unwrap();
    evidence_tx.commit().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(2), cancel_task)
        .await
        .expect("cancel completes after evidence commit")
        .expect("cancel task")
        .expect("cancel query");
    assert_eq!(result, (0, "unpaid".to_string()));
    let final_row: (String, Option<String>, String, Option<i64>) = sqlx::query_as(
        "SELECT status, presentation_status, settlement_status, \
                EXTRACT(EPOCH FROM cancelled_at)::BIGINT \
         FROM invoices WHERE id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(final_row.0, "unpaid");
    assert_eq!(final_row.1.as_deref(), Some("payment_received"));
    assert_eq!(final_row.2, "pending");
    assert!(final_row.3.is_none());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn compatibility_payment_writer_waits_for_lightning_offer_projection_lock() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "paymentofferlock").await;
    let invoice = insert_test_invoice(
        &pool,
        "paymentofferlock",
        &npub,
        "lq1paymentofferlock",
        3_600,
    )
    .await;

    let mut offer_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(pay_service::db::invoice_lightning_lock_key(invoice.id))
        .execute(&mut *offer_tx)
        .await
        .unwrap();

    let writer_pool = pool.clone();
    let invoice_id = invoice.id;
    let mut writer = tokio::spawn(async move {
        invoice::flip_invoice_on_lightning_settlement(
            &writer_pool,
            Some(invoice_id),
            400,
            "payment-offer-lock",
            "7373737373737373737373737373737373737373737373737373737373737373",
            pay_service::db::InvoiceAccountingTolerances::default(),
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut writer)
            .await
            .is_err(),
        "payment projection writer must wait for the offer boundary"
    );

    offer_tx.commit().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .expect("payment writer completes after offer boundary")
        .expect("payment writer task"));
    let row = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "partially_paid");
    assert_eq!(row.presentation_status.as_deref(), Some("partial"));

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

#[allow(clippy::too_many_arguments)]
fn bitcoin_direct_observation<'a>(
    event_key: &'a str,
    amount_sat: i64,
    txid: &'a str,
    vout: i32,
    address: &'a str,
    confirmations: i32,
    block_height: Option<i32>,
    last_seen_state: &'a str,
) -> pay_service::db::NewInvoicePaymentObservation<'a> {
    pay_service::db::NewInvoicePaymentObservation {
        rail: "bitcoin",
        source: "bitcoin_direct",
        event_key,
        txid,
        vout,
        address,
        amount_sat,
        confirmations,
        block_height,
        last_seen_state,
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
            public_slug: None,
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

const DIRECT_LIFECYCLE_BLOCK_HASH: &str =
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const DIRECT_LIFECYCLE_LIQUID_ASSET: &str =
    "6f0279e9ed52d9e2846d9eb0f9e5f16a7a6f4f24f88c47f5b9b7b9a78f5d8b5a";

fn direct_lifecycle_tolerances() -> pay_service::db::InvoiceAccountingTolerances {
    pay_service::db::InvoiceAccountingTolerances {
        btc_sat: 0,
        liquid_sat: 0,
        lightning_sat: 0,
        payment_grace_secs: 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn bitcoin_lifecycle_observation<'a>(
    event_key: &'a str,
    txid: &'a str,
    vout: i32,
    address: &'a str,
    amount_sat: i64,
    confirmations: i32,
    phase: pay_service::db::DirectObservationPhase,
    supersedes_event_key: Option<&'a str>,
) -> pay_service::db::DirectOutputObservation<'a> {
    let confirmed = confirmations > 0;
    pay_service::db::DirectOutputObservation {
        event_key,
        txid,
        vout,
        address,
        amount_sat,
        asset_id: None,
        confirmations,
        block_height: confirmed.then_some(900_000),
        block_hash: confirmed.then_some(DIRECT_LIFECYCLE_BLOCK_HASH),
        verification: pay_service::db::DirectEvidenceVerification::Verified,
        phase,
        supersedes_event_key,
    }
}

#[allow(clippy::too_many_arguments)]
fn liquid_lifecycle_observation<'a>(
    event_key: &'a str,
    txid: &'a str,
    vout: i32,
    address: &'a str,
    amount_sat: i64,
    confirmations: i32,
    phase: pay_service::db::DirectObservationPhase,
    supersedes_event_key: Option<&'a str>,
) -> pay_service::db::DirectOutputObservation<'a> {
    let confirmed = confirmations > 0;
    pay_service::db::DirectOutputObservation {
        event_key,
        txid,
        vout,
        address,
        amount_sat,
        asset_id: Some(DIRECT_LIFECYCLE_LIQUID_ASSET),
        confirmations,
        block_height: confirmed.then_some(2_000_000),
        block_hash: confirmed.then_some(DIRECT_LIFECYCLE_BLOCK_HASH),
        verification: pay_service::db::DirectEvidenceVerification::Verified,
        phase,
        supersedes_event_key,
    }
}

async fn reserve_and_apply_direct_lifecycle<'a>(
    pool: &PgPool,
    invoice_id: uuid::Uuid,
    source: pay_service::db::DirectPaymentSource,
    observations: &'a [pay_service::db::DirectOutputObservation<'a>],
) -> (i64, pay_service::db::ApplyDirectObservationOutcome) {
    let generation =
        pay_service::db::reserve_direct_observation_generation(pool, invoice_id, source)
            .await
            .unwrap();
    let outcome = pay_service::db::apply_direct_observation_batch(
        pool,
        pay_service::db::DirectObservationBatch {
            invoice_id,
            source,
            authority: "integration-test",
            generation,
            observations,
        },
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap();
    (generation, outcome)
}

#[tokio::test]
async fn liquid_reducer_revalidates_199_legacy_outputs_without_double_count() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "liquidlegacycapacity";
    let address = "lq1liquidlegacycapacity";
    let npub = create_test_user(&pool, nym).await;
    let invoice = insert_test_invoice(&pool, nym, &npub, address, 3_600).await;
    let txids = (1..=199)
        .map(|index| format!("{index:064x}"))
        .collect::<Vec<_>>();
    let event_keys = txids
        .iter()
        .map(|txid| format!("liquid_direct:{txid}:0"))
        .collect::<Vec<_>>();

    sqlx::query(
        "INSERT INTO invoice_payment_events \
             (invoice_id, rail, event_key, amount_sat, source, txid, vout, address) \
         SELECT $1, 'liquid', 'liquid_direct:' || seeded.txid || ':0', 1, \
                'liquid_direct', seeded.txid, 0, $2 \
         FROM UNNEST($3::TEXT[]) AS seeded(txid)",
    )
    .bind(invoice.id)
    .bind(address)
    .bind(&txids[..197])
    .execute(&pool)
    .await
    .unwrap();

    let observations = txids
        .iter()
        .zip(&event_keys)
        .map(|(txid, event_key)| {
            liquid_lifecycle_observation(
                event_key,
                txid,
                0,
                address,
                1,
                1,
                pay_service::db::DirectObservationPhase::Confirmed,
                None,
            )
        })
        .collect::<Vec<_>>();
    let (_, first) = reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &observations,
    )
    .await;
    assert_eq!(
        first,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: true }
    );

    let (_, repeated) = reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &observations,
    )
    .await;
    assert_eq!(
        repeated,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: false }
    );

    let durable: (i64, i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT \
            (SELECT COUNT(*) FROM invoice_payment_events \
              WHERE invoice_id = $1 AND source = 'liquid_direct'), \
            (SELECT COUNT(*) FROM invoice_payment_observations \
              WHERE invoice_id = $1 AND source = 'liquid_direct'), \
            (SELECT COUNT(*) FROM invoice_direct_payment_transitions \
              WHERE invoice_id = $1 AND source = 'liquid_direct'), \
            (SELECT paid_amount_sat FROM invoices WHERE id = $1)",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(durable, (199, 199, 199, Some(199)));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_mempool_first_sighting_sets_only_the_direct_component() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directmempoolcache").await;
    let invoice =
        insert_test_btc_invoice(&pool, "directmempoolcache", &npub, "bc1qdirectmempoolcache")
            .await
            .unwrap();

    let flipped = pay_service::db::mark_invoice_in_progress_for_component(
        &pool,
        invoice.id,
        pay_service::db::InvoiceInProgressComponent::Direct,
    )
    .await
    .unwrap();
    assert!(flipped);

    let first = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.status, "in_progress");
    assert_eq!(first.settlement_status, "pending");
    assert_eq!(first.direct_settlement_status, "pending");
    assert_eq!(first.swap_settlement_status, "none");
    assert_eq!(first.direct_payment_projection_version, 1);

    assert!(!pay_service::db::mark_invoice_in_progress_for_component(
        &pool,
        invoice.id,
        pay_service::db::InvoiceInProgressComponent::Direct,
    )
    .await
    .unwrap());
    let repeated = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repeated.direct_payment_projection_version, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn new_invoice_initializes_known_unpaid_presentation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directinitial").await;
    let invoice =
        insert_test_invoice(&pool, "directinitial", &npub, "lq1directinitial", 3_600).await;

    assert_eq!(invoice.status, "unpaid");
    assert_eq!(invoice.presentation_status.as_deref(), Some("unpaid"));
    assert_eq!(invoice.settlement_status, "none");
}

#[tokio::test]
async fn public_contract_tracks_exact_provisional_value_and_accounting_finality() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (npub, _, _, keypair) = sign_registration_with_keypair("directcontract", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "directcontract", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice = insert_test_btc_invoice(&pool, "directcontract", &npub, "bc1qdirectcontract")
        .await
        .unwrap();
    let txid = "1919191919191919191919191919191919191919191919191919191919191919";
    let first_key = format!("bitcoin_direct:{txid}:0");
    let second_key = format!("bitcoin_direct:{txid}:1");

    let partial = [bitcoin_lifecycle_observation(
        &first_key,
        txid,
        0,
        "bc1qdirectcontract",
        400,
        0,
        pay_service::db::DirectObservationPhase::Provisional,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &partial,
    )
    .await;

    let app = test_app(test_state(pool.clone()));
    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "in_progress");
    assert_eq!(body["presentation_status"], "partial");
    assert_eq!(body["settlement_status"], "pending");
    assert_eq!(body["remaining_amount_sat"], 600);
    assert_eq!(body["paid_amount_sat"], Value::Null);

    let (sig, timestamp) = sign_invoice_list_with_keypair(&keypair, &npub, 1, 10, "");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={npub}&page=1&pageSize=10&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoices"][0]["status"], "in_progress");
    assert_eq!(body["invoices"][0]["presentation_status"], "partial");
    assert_eq!(body["invoices"][0]["settlement_status"], "pending");
    assert_eq!(body["invoices"][0]["remaining_amount_sat"], 600);
    assert_eq!(body["invoices"][0]["paid_amount_sat"], Value::Null);

    let (sig, timestamp) = sign_invoice_list_with_keypair(&keypair, &npub, 1, 10, "paid");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={npub}&page=1&pageSize=10&status=paid&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoices"].as_array().unwrap().len(), 0);

    let sufficient = [
        bitcoin_lifecycle_observation(
            &first_key,
            txid,
            0,
            "bc1qdirectcontract",
            400,
            0,
            pay_service::db::DirectObservationPhase::Provisional,
            None,
        ),
        bitcoin_lifecycle_observation(
            &second_key,
            txid,
            1,
            "bc1qdirectcontract",
            600,
            0,
            pay_service::db::DirectObservationPhase::Provisional,
            None,
        ),
    ];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &sufficient,
    )
    .await;
    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "in_progress");
    assert_eq!(body["presentation_status"], "payment_received");
    assert_eq!(body["remaining_amount_sat"], 0);
    assert_eq!(body["paid_amount_sat"], Value::Null);

    let confirmed = [
        bitcoin_lifecycle_observation(
            &first_key,
            txid,
            0,
            "bc1qdirectcontract",
            400,
            1,
            pay_service::db::DirectObservationPhase::Confirmed,
            None,
        ),
        bitcoin_lifecycle_observation(
            &second_key,
            txid,
            1,
            "bc1qdirectcontract",
            600,
            1,
            pay_service::db::DirectObservationPhase::Confirmed,
            None,
        ),
    ];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &confirmed,
    )
    .await;
    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "paid");
    assert_eq!(body["presentation_status"], "payment_received");
    assert_eq!(body["settlement_status"], "pending");
    assert_eq!(body["paid_amount_sat"], 1_000);

    let (sig, timestamp) = sign_invoice_list_with_keypair(&keypair, &npub, 1, 10, "paid");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={npub}&page=1&pageSize=10&status=paid&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoices"].as_array().unwrap().len(), 1);
    assert_eq!(body["invoices"][0]["settlement_status"], "pending");

    let finalized = [
        bitcoin_lifecycle_observation(
            &first_key,
            txid,
            0,
            "bc1qdirectcontract",
            400,
            3,
            pay_service::db::DirectObservationPhase::Finalized,
            None,
        ),
        bitcoin_lifecycle_observation(
            &second_key,
            txid,
            1,
            "bc1qdirectcontract",
            600,
            3,
            pay_service::db::DirectObservationPhase::Finalized,
            None,
        ),
    ];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &finalized,
    )
    .await;
    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "paid");
    assert_eq!(body["settlement_status"], "settled");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_zero_confirmation_is_presented_but_not_accounted() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directzero").await;
    let invoice = insert_test_btc_invoice(&pool, "directzero", &npub, "bc1qdirectzero")
        .await
        .unwrap();
    let txid = "1010101010101010101010101010101010101010101010101010101010101010";
    let event_key = format!("bitcoin_direct:{txid}:0");
    let observations = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectzero",
        1_000,
        0,
        pay_service::db::DirectObservationPhase::Provisional,
        None,
    )];

    let (_, outcome) = reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &observations,
    )
    .await;
    assert_eq!(
        outcome,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: true }
    );

    let projection: (
        String,
        Option<String>,
        String,
        String,
        Option<i64>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT status, presentation_status, direct_settlement_status, \
                settlement_status, paid_amount_sat, paid_via \
         FROM invoices WHERE id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        projection,
        (
            "in_progress".to_string(),
            Some("payment_received".to_string()),
            "pending".to_string(),
            "pending".to_string(),
            None,
            None,
        )
    );

    let evidence: (String, String, String, i64) = sqlx::query_as(
        "SELECT o.last_seen_state, e.accounting_state, e.verification_state, \
                e.amount_sat \
         FROM invoice_payment_observations o \
         JOIN invoice_payment_events e ON e.observation_id = o.id \
         WHERE o.invoice_id = $1 AND o.event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        evidence,
        (
            "seen_unconfirmed".to_string(),
            "inactive".to_string(),
            "verified".to_string(),
            1_000,
        )
    );
    let countable: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoice_payment_events \
         WHERE invoice_id = $1 \
           AND accounting_state IN ('active', 'legacy_unverified')",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(countable, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn legacy_confirmed_bitcoin_observation_enriches_its_missing_block_hash() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "legacyblockhash").await;
    let address = "bc1qlegacyblockhash";
    let invoice = insert_test_btc_invoice(&pool, "legacyblockhash", &npub, address)
        .await
        .unwrap();
    let txid = "3131313131313131313131313131313131313131313131313131313131313131";
    let event_key = format!("bitcoin_direct:{txid}:0");

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        bitcoin_direct_evidence(&event_key, 1_000, txid, 0, address),
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap();
    pay_service::db::upsert_invoice_payment_observation(
        &pool,
        invoice.id,
        bitcoin_direct_observation(
            &event_key,
            1_000,
            txid,
            0,
            address,
            6,
            Some(900_000),
            "counted",
        ),
    )
    .await
    .unwrap();

    let finalized = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        address,
        1_000,
        6,
        pay_service::db::DirectObservationPhase::Finalized,
        None,
    )];
    let (_, outcome) = reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &finalized,
    )
    .await;
    assert_eq!(
        outcome,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: true }
    );

    let state: (Option<String>, String, String, String) = sqlx::query_as(
        "SELECT o.inclusion_block_hash, o.verification_state, \
                e.accounting_state, e.verification_state \
         FROM invoice_payment_observations o \
         JOIN invoice_payment_events e ON e.observation_id = o.id \
         WHERE o.invoice_id = $1 AND o.event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state.0.as_deref(), Some(DIRECT_LIFECYCLE_BLOCK_HASH));
    assert_eq!(state.1, "verified");
    assert_eq!(state.2, "active");
    assert_eq!(state.3, "verified");
    let accounting: (Option<i64>, i64) = sqlx::query_as(
        "SELECT i.paid_amount_sat, COUNT(e.id) \
         FROM invoices i \
         LEFT JOIN invoice_payment_events e ON e.invoice_id = i.id \
         WHERE i.id = $1 GROUP BY i.id",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(accounting, (Some(1_000), 1));
    let transitions: Vec<String> = sqlx::query_scalar(
        "SELECT transition_kind FROM invoice_direct_payment_transitions \
         WHERE invoice_id = $1 ORDER BY generation",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(transitions, vec!["legacy_revalidated".to_owned()]);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_one_confirmation_activates_accounting_once() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directoneconf").await;
    let invoice = insert_test_btc_invoice(&pool, "directoneconf", &npub, "bc1qdirectoneconf")
        .await
        .unwrap();
    let txid = "2020202020202020202020202020202020202020202020202020202020202020";
    let event_key = format!("bitcoin_direct:{txid}:0");
    let observations = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectoneconf",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];

    let (_, outcome) = reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &observations,
    )
    .await;
    assert_eq!(
        outcome,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: true }
    );

    let projection: (
        String,
        Option<String>,
        String,
        String,
        Option<i64>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT status, presentation_status, direct_settlement_status, \
                    settlement_status, paid_amount_sat, paid_via \
             FROM invoices WHERE id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        projection,
        (
            "paid".to_string(),
            Some("payment_received".to_string()),
            "pending".to_string(),
            "pending".to_string(),
            Some(1_000),
            Some("bitcoin".to_string()),
        )
    );

    let event: (String, String, i64) = sqlx::query_as(
        "SELECT accounting_state, verification_state, COUNT(*) OVER () \
         FROM invoice_payment_events WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(event, ("active".to_string(), "verified".to_string(), 1));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_finality_promotes_the_same_accounting_event() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directfinality").await;
    let invoice = insert_test_btc_invoice(&pool, "directfinality", &npub, "bc1qdirectfinality")
        .await
        .unwrap();
    let txid = "3030303030303030303030303030303030303030303030303030303030303030";
    let event_key = format!("bitcoin_direct:{txid}:0");
    let confirmed = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectfinality",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &confirmed,
    )
    .await;
    let before: (uuid::Uuid, i64) = sqlx::query_as(
        "SELECT id, accounting_sequence FROM invoice_payment_events \
         WHERE invoice_id = $1 AND event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();

    let finalized = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectfinality",
        1_000,
        3,
        pay_service::db::DirectObservationPhase::Finalized,
        None,
    )];
    let (_, outcome) = reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &finalized,
    )
    .await;
    assert_eq!(
        outcome,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: true }
    );

    let after: (uuid::Uuid, i64, String, i64) = sqlx::query_as(
        "SELECT id, accounting_sequence, accounting_state, COUNT(*) OVER () \
         FROM invoice_payment_events WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((after.0, after.1), before);
    assert_eq!(after.2, "active");
    assert_eq!(after.3, 1);

    let lifecycle: (String, String, i64, i64) = sqlx::query_as(
        "SELECT o.last_seen_state, i.direct_settlement_status, \
                o.lifecycle_version, COUNT(t.id) \
         FROM invoice_payment_observations o \
         JOIN invoices i ON i.id = o.invoice_id \
         LEFT JOIN invoice_direct_payment_transitions t ON t.observation_id = o.id \
         WHERE o.invoice_id = $1 AND o.event_key = $2 \
         GROUP BY o.last_seen_state, i.direct_settlement_status, o.lifecycle_version",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        lifecycle,
        ("counted".to_string(), "settled".to_string(), 2, 2)
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_reversal_and_reactivation_reuse_durable_evidence() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directreactivate").await;
    let invoice = insert_test_btc_invoice(&pool, "directreactivate", &npub, "bc1qdirectreactivate")
        .await
        .unwrap();
    let txid = "4040404040404040404040404040404040404040404040404040404040404040";
    let event_key = format!("bitcoin_direct:{txid}:0");
    let confirmed = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectreactivate",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &confirmed,
    )
    .await;
    let original_event: (uuid::Uuid, i64) = sqlx::query_as(
        "SELECT id, accounting_sequence FROM invoice_payment_events \
         WHERE invoice_id = $1 AND event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();

    let regression = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectreactivate",
        1_000,
        0,
        pay_service::db::DirectObservationPhase::ResolutionPending(
            pay_service::db::DirectRegressionReason::Reorged,
        ),
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &regression,
    )
    .await;

    let reversed: (
        String,
        String,
        String,
        String,
        Option<i64>,
        String,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT i.status, i.presentation_status, i.direct_settlement_status, \
                i.settlement_status, i.paid_amount_sat, e.accounting_state, \
                e.deactivation_reason \
         FROM invoices i \
         JOIN invoice_payment_events e ON e.invoice_id = i.id \
         WHERE i.id = $1 AND e.event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        reversed,
        (
            "in_progress".to_string(),
            "unpaid".to_string(),
            "resolution_pending".to_string(),
            "resolution_pending".to_string(),
            None,
            "inactive".to_string(),
            Some("reorged".to_string()),
        )
    );

    let first_invalidation: String = sqlx::query_scalar(
        "SELECT invalidated_at::TEXT FROM invoice_payment_observations \
         WHERE invoice_id = $1 AND event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &regression,
    )
    .await;
    let repeated_invalidation: (String, String) = sqlx::query_as(
        "SELECT invalidation_reason, invalidated_at::TEXT \
         FROM invoice_payment_observations \
         WHERE invoice_id = $1 AND event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(repeated_invalidation.0, "reorged");
    assert_eq!(repeated_invalidation.1, first_invalidation);

    sqlx::query("SELECT pg_sleep(0.01)")
        .execute(&pool)
        .await
        .unwrap();
    let changed_regression = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectreactivate",
        1_000,
        0,
        pay_service::db::DirectObservationPhase::ResolutionPending(
            pay_service::db::DirectRegressionReason::Conflict,
        ),
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &changed_regression,
    )
    .await;
    let changed_invalidation: (String, String) = sqlx::query_as(
        "SELECT invalidation_reason, invalidated_at::TEXT \
         FROM invoice_payment_observations \
         WHERE invoice_id = $1 AND event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(changed_invalidation.0, "conflict");
    assert_ne!(changed_invalidation.1, first_invalidation);

    let reappeared = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectreactivate",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
        &reappeared,
    )
    .await;

    let reactivated: (uuid::Uuid, i64, String, String, String, Option<i64>) = sqlx::query_as(
        "SELECT e.id, e.accounting_sequence, e.accounting_state, \
                o.last_seen_state, i.status, i.paid_amount_sat \
         FROM invoice_payment_events e \
         JOIN invoice_payment_observations o ON o.id = e.observation_id \
         JOIN invoices i ON i.id = e.invoice_id \
         WHERE e.invoice_id = $1 AND e.event_key = $2",
    )
    .bind(invoice.id)
    .bind(&event_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((reactivated.0, reactivated.1), original_event);
    assert_eq!(reactivated.2, "active");
    assert_eq!(reactivated.3, "awaiting_confirmations");
    assert_eq!(reactivated.4, "paid");
    assert_eq!(reactivated.5, Some(1_000));

    let transitions: Vec<String> = sqlx::query_scalar(
        "SELECT transition_kind FROM invoice_direct_payment_transitions \
         WHERE invoice_id = $1 ORDER BY generation",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        transitions,
        vec![
            "accounting_activated".to_string(),
            "resolution_pending".to_string(),
            "resolution_pending".to_string(),
            "reactivated".to_string(),
        ]
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_valid_replacement_is_atomic_without_double_counting() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directreplace").await;
    let invoice =
        insert_test_invoice(&pool, "directreplace", &npub, "lq1directreplace", 3_600).await;
    let old_txid = "5050505050505050505050505050505050505050505050505050505050505050";
    let old_key = format!("liquid_direct:{old_txid}:0");
    let old = [liquid_lifecycle_observation(
        &old_key,
        old_txid,
        0,
        "lq1directreplace",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &old,
    )
    .await;

    let replacement_txid = "5151515151515151515151515151515151515151515151515151515151515151";
    let replacement_key = format!("liquid_direct:{replacement_txid}:1");
    let replacement = [liquid_lifecycle_observation(
        &replacement_key,
        replacement_txid,
        1,
        "lq1directreplace",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        Some(&old_key),
    )];
    let (_, outcome) = reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &replacement,
    )
    .await;
    assert_eq!(
        outcome,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: true }
    );

    let events: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT event_key, accounting_state, deactivation_reason \
         FROM invoice_payment_events WHERE invoice_id = $1 \
         ORDER BY accounting_sequence",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        events,
        vec![
            (
                old_key.clone(),
                "superseded".to_string(),
                Some("replaced".to_string()),
            ),
            (replacement_key.clone(), "active".to_string(), None),
        ]
    );
    let projection: (String, String, String, Option<i64>) = sqlx::query_as(
        "SELECT status, presentation_status, direct_settlement_status, paid_amount_sat \
         FROM invoices WHERE id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        projection,
        (
            "paid".to_string(),
            "payment_received".to_string(),
            "pending".to_string(),
            Some(1_000),
        )
    );
    let observations: Vec<(String, String, Option<uuid::Uuid>)> = sqlx::query_as(
        "SELECT event_key, last_seen_state, superseded_by_observation_id \
         FROM invoice_payment_observations WHERE invoice_id = $1 ORDER BY event_key",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].0, old_key);
    assert_eq!(observations[0].1, "superseded");
    assert!(observations[0].2.is_some());
    assert_eq!(observations[1].0, replacement_key);
    assert_eq!(observations[1].1, "awaiting_confirmations");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_stale_and_retried_generations_cannot_resurrect_value() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directgeneration").await;
    let invoice = insert_test_btc_invoice(&pool, "directgeneration", &npub, "bc1qdirectgeneration")
        .await
        .unwrap();
    let txid = "6060606060606060606060606060606060606060606060606060606060606060";
    let event_key = format!("bitcoin_direct:{txid}:0");
    let observations = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectgeneration",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    let generation_one = pay_service::db::reserve_direct_observation_generation(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
    )
    .await
    .unwrap();
    let generation_two = pay_service::db::reserve_direct_observation_generation(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
    )
    .await
    .unwrap();
    assert_eq!((generation_one, generation_two), (1, 2));

    let stale = pay_service::db::apply_direct_observation_batch(
        &pool,
        pay_service::db::DirectObservationBatch {
            invoice_id: invoice.id,
            source: pay_service::db::DirectPaymentSource::Bitcoin,
            authority: "stale-integration-check",
            generation: generation_one,
            observations: &observations,
        },
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap();
    assert_eq!(
        stale,
        pay_service::db::ApplyDirectObservationOutcome::Stale {
            current_generation: generation_two,
        }
    );
    let stale_writes: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT COUNT(*) FROM invoice_payment_observations WHERE invoice_id = $1), \
            (SELECT COUNT(*) FROM invoice_payment_events WHERE invoice_id = $1), \
            (SELECT COUNT(*) FROM invoice_direct_payment_transitions WHERE invoice_id = $1)",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stale_writes, (0, 0, 0));

    let batch = pay_service::db::DirectObservationBatch {
        invoice_id: invoice.id,
        source: pay_service::db::DirectPaymentSource::Bitcoin,
        authority: "current-integration-check",
        generation: generation_two,
        observations: &observations,
    };
    let applied = pay_service::db::apply_direct_observation_batch(
        &pool,
        batch,
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap();
    assert_eq!(
        applied,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: true }
    );

    let retry = pay_service::db::apply_direct_observation_batch(
        &pool,
        pay_service::db::DirectObservationBatch {
            invoice_id: invoice.id,
            source: pay_service::db::DirectPaymentSource::Bitcoin,
            authority: "current-integration-check",
            generation: generation_two,
            observations: &observations,
        },
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap();
    assert_eq!(
        retry,
        pay_service::db::ApplyDirectObservationOutcome::AlreadyApplied
    );
    let durable: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT h.applied_generation, \
            (SELECT COUNT(*) FROM invoice_payment_observations WHERE invoice_id = $1), \
            (SELECT COUNT(*) FROM invoice_payment_events WHERE invoice_id = $1), \
            (SELECT COUNT(*) FROM invoice_direct_payment_transitions WHERE invoice_id = $1) \
         FROM invoice_direct_scan_heads h \
         WHERE h.invoice_id = $1 AND h.source = 'bitcoin_direct'",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(durable, (2, 1, 1, 1));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_rejects_non_direct_event_identity_before_writing() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "directsourceguard").await;
    let invoice =
        insert_test_btc_invoice(&pool, "directsourceguard", &npub, "bc1qdirectsourceguard")
            .await
            .unwrap();
    let txid = "7070707070707070707070707070707070707070707070707070707070707070";
    let invalid_key = format!("lightning_boltz_reverse:{txid}:0");
    let observations = [bitcoin_lifecycle_observation(
        &invalid_key,
        txid,
        0,
        "bc1qdirectsourceguard",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    let generation = pay_service::db::reserve_direct_observation_generation(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
    )
    .await
    .unwrap();

    let error = pay_service::db::apply_direct_observation_batch(
        &pool,
        pay_service::db::DirectObservationBatch {
            invoice_id: invoice.id,
            source: pay_service::db::DirectPaymentSource::Bitcoin,
            authority: "integration-source-guard",
            generation,
            observations: &observations,
        },
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("event_key"));

    let writes: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT h.applied_generation, \
            (SELECT COUNT(*) FROM invoice_payment_observations WHERE invoice_id = $1), \
            (SELECT COUNT(*) FROM invoice_payment_events WHERE invoice_id = $1), \
            (SELECT COUNT(*) FROM invoice_direct_payment_transitions WHERE invoice_id = $1) \
         FROM invoice_direct_scan_heads h \
         WHERE h.invoice_id = $1 AND h.source = 'bitcoin_direct'",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(writes, (0, 0, 0, 0));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_lifecycle_transaction_rolls_back_every_projection_write() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    sqlx::query(
        "DROP TRIGGER IF EXISTS direct_lifecycle_apply_failure_test \
         ON invoice_direct_scan_heads",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS fail_direct_lifecycle_apply_test()")
        .execute(&pool)
        .await
        .unwrap();

    let npub = create_test_user(&pool, "directrollback").await;
    let invoice = insert_test_btc_invoice(&pool, "directrollback", &npub, "bc1qdirectrollback")
        .await
        .unwrap();
    let generation = pay_service::db::reserve_direct_observation_generation(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Bitcoin,
    )
    .await
    .unwrap();
    sqlx::query(
        "CREATE FUNCTION fail_direct_lifecycle_apply_test() \
         RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
             RAISE EXCEPTION 'forced direct lifecycle apply failure'; \
         END \
         $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER direct_lifecycle_apply_failure_test \
         BEFORE UPDATE ON invoice_direct_scan_heads \
         FOR EACH ROW EXECUTE FUNCTION fail_direct_lifecycle_apply_test()",
    )
    .execute(&pool)
    .await
    .unwrap();

    let txid = "8080808080808080808080808080808080808080808080808080808080808080";
    let event_key = format!("bitcoin_direct:{txid}:0");
    let observations = [bitcoin_lifecycle_observation(
        &event_key,
        txid,
        0,
        "bc1qdirectrollback",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    let error = pay_service::db::apply_direct_observation_batch(
        &pool,
        pay_service::db::DirectObservationBatch {
            invoice_id: invoice.id,
            source: pay_service::db::DirectPaymentSource::Bitcoin,
            authority: "integration-rollback",
            generation,
            observations: &observations,
        },
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("forced direct lifecycle apply failure"));

    sqlx::query(
        "DROP TRIGGER direct_lifecycle_apply_failure_test \
         ON invoice_direct_scan_heads",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION fail_direct_lifecycle_apply_test()")
        .execute(&pool)
        .await
        .unwrap();

    let durable: (
        String,
        Option<String>,
        String,
        Option<i64>,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        "SELECT i.status, i.presentation_status, i.direct_settlement_status, \
                i.paid_amount_sat, i.direct_payment_projection_version, \
                h.applied_generation, \
                (SELECT COUNT(*) FROM invoice_payment_observations WHERE invoice_id = i.id), \
                (SELECT COUNT(*) FROM invoice_payment_events WHERE invoice_id = i.id), \
                (SELECT COUNT(*) FROM invoice_direct_payment_transitions WHERE invoice_id = i.id) \
         FROM invoices i \
         JOIN invoice_direct_scan_heads h ON h.invoice_id = i.id \
         WHERE i.id = $1 AND h.source = 'bitcoin_direct'",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        durable,
        (
            "unpaid".to_string(),
            Some("unpaid".to_string()),
            "none".to_string(),
            None,
            0,
            0,
            0,
            0,
            0,
        )
    );

    cleanup_db(&pool).await;
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
async fn disabled_workers_reject_direct_invoice_before_publication() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let (npub, _, _, keypair) = sign_registration_with_keypair("directclosed", TEST_DESCRIPTOR);
    let expires_at_unix = auth_timestamp() as i64 + 3_600;
    let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let (signature, timestamp) =
        sign_invoice_create_with_keypair(&keypair, &npub, address, expires_at_unix);

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
            "bitcoin_address": address,
            "liquid_address": null,
            "liquid_blinding_key_hex": null,
            "expires_at_unix": expires_at_unix,
            "timestamp": timestamp,
            "signature": signature,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "ServiceUnavailable");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "closed direct admission published an invoice");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn disabled_workers_reject_signed_lightning_only_invoice_atomically() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let (npub, _, _, keypair) = sign_registration_with_keypair("lnonlyclosed", TEST_DESCRIPTOR);
    let expires_at_unix = auth_timestamp() as i64 + 3_600;
    let expires_at = expires_at_unix.to_string();
    let liquid_address =
        "lq1qqvxk052kf3qtkxmrakx50a9gc3smqad2ync54hzntjt980kfej9kkfe0247rp5h4yzmdftsahhw64uy8pzfe7cpg4fgykm7cv";
    let (signature, timestamp) = sign_la_action(
        &keypair,
        "invoice-create",
        &npub,
        "",
        &[
            "1000",
            "",
            "",
            "",
            "",
            "",
            "false",
            "true",
            "false",
            "",
            liquid_address,
            "",
            &expires_at,
        ],
    );
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();

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
            "accept_btc": false,
            "accept_ln": true,
            "accept_liquid": false,
            "bitcoin_address": null,
            "liquid_address": liquid_address,
            "liquid_blinding_key_hex": null,
            "expires_at_unix": expires_at_unix,
            "timestamp": timestamp,
            "signature": signature,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "ServiceUnavailable");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "closed Lightning admission published an invoice");
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before,
        "closed Lightning admission consumed a swap key"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    provider_task.abort();
    let _ = provider_task.await;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn direct_invoice_http_gate_reopens_only_after_two_healthy_watcher_cycles() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    let reporter = state
        .admission
        .reporter(pay_service::admission::Worker::BitcoinWatcher);
    reporter.cycle_succeeded();
    let app = test_app(state);
    let (npub, _, _, keypair) = sign_registration_with_keypair("directreopen", TEST_DESCRIPTOR);
    let expires_at_unix = auth_timestamp() as i64 + 3_600;
    let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let (signature, timestamp) =
        sign_invoice_create_with_keypair(&keypair, &npub, address, expires_at_unix);
    let request_body = || {
        json!({
            "npub": npub.clone(),
            "amount_sat": 1000,
            "fiat_amount_minor": null,
            "fiat_currency": null,
            "public_description": null,
            "recipient_name": null,
            "invoice_number": null,
            "accept_btc": true,
            "accept_ln": false,
            "accept_liquid": false,
            "bitcoin_address": address,
            "liquid_address": null,
            "liquid_blinding_key_hex": null,
            "expires_at_unix": expires_at_unix,
            "timestamp": timestamp,
            "signature": signature.clone(),
        })
    };

    for _ in 0..3 {
        reporter.cycle_failed();
    }
    let (status, body) = post_json(&app, "/api/v1/invoices", request_body()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        body,
        json!({
            "status": "ERROR",
            "code": "ServiceUnavailable",
            "reason": "This payment method is temporarily unavailable. Try again later."
        })
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);

    reporter.cycle_succeeded();
    let (status, body) = post_json(&app, "/api/v1/invoices", request_body()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "one recovery success reopened admission");

    reporter.cycle_succeeded();
    let (status, body) = post_json(&app, "/api/v1/invoices", request_body()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["invoice_id"].is_string(), "{body}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

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
async fn signed_invoice_list_is_auth_bound_and_npub_isolated() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (alice_npub, _, _, alice_keypair) =
        sign_registration_with_keypair("listalice", TEST_DESCRIPTOR);
    let (bob_npub, _, _, bob_keypair) = sign_registration_with_keypair("listbob", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "listalice", &alice_npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    pay_service::db::create_user(&pool, "listbob", &bob_npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let alice_invoice =
        insert_test_invoice(&pool, "listalice", &alice_npub, "lq1listalice", 3_600).await;
    let _bob_invoice = insert_test_invoice(&pool, "listbob", &bob_npub, "lq1listbob", 3_600).await;

    let (sig, timestamp) = sign_invoice_list_with_keypair(&alice_keypair, &alice_npub, 1, 10, "");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={alice_npub}&page=1&pageSize=10&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let invoices = body["invoices"].as_array().unwrap();
    assert_eq!(invoices.len(), 1, "body: {body}");
    assert_eq!(invoices[0]["id"], alice_invoice.id.to_string());
    assert_eq!(invoices[0]["nym_owner"], "listalice");
    assert_eq!(invoices[0]["presentation_status"], "unpaid");

    let (forged_sig, forged_timestamp) =
        sign_invoice_list_with_keypair(&bob_keypair, &alice_npub, 1, 10, "");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={alice_npub}&page=1&pageSize=10&timestamp={forged_timestamp}&signature={forged_sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "AuthError");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn signed_invoice_cancel_is_owner_bound_and_idempotent() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (alice_npub, _, _, alice_keypair) =
        sign_registration_with_keypair("cancelalice", TEST_DESCRIPTOR);
    let (bob_npub, _, _, bob_keypair) =
        sign_registration_with_keypair("cancelbob", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "cancelalice", &alice_npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    pay_service::db::create_user(&pool, "cancelbob", &bob_npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice =
        insert_test_invoice(&pool, "cancelalice", &alice_npub, "lq1cancelalice", 3_600).await;
    let invoice_id = invoice.id.to_string();

    let (wrong_sig, wrong_timestamp) =
        sign_invoice_cancel_with_keypair(&bob_keypair, &bob_npub, "cancelbob", &invoice_id);
    let (status, body) = delete_json_path(
        &app,
        &format!("/api/v1/cancelbob/invoices/{invoice_id}"),
        json!({
            "npub": bob_npub,
            "timestamp": wrong_timestamp,
            "signature": wrong_sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["code"], "InvoiceNotFound");
    let still_unpaid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_unpaid.status, "unpaid");

    let (sig, timestamp) =
        sign_invoice_cancel_with_keypair(&alice_keypair, &alice_npub, "cancelalice", &invoice_id);
    let (status, body) = delete_json_path(
        &app,
        &format!("/api/v1/cancelalice/invoices/{invoice_id}"),
        json!({
            "npub": alice_npub,
            "timestamp": timestamp,
            "signature": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoice_id"], invoice_id);
    assert_eq!(body["status"], "cancelled");

    let (sig, timestamp) =
        sign_invoice_cancel_with_keypair(&alice_keypair, &alice_npub, "cancelalice", &invoice_id);
    let (status, body) = delete_json_path(
        &app,
        &format!("/api/v1/cancelalice/invoices/{invoice_id}"),
        json!({
            "npub": alice_npub,
            "timestamp": timestamp,
            "signature": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "cancelled");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_render_paths_preserve_linked_owner_boundary() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let npub = create_test_user(&pool, "renderowner").await;
    let invoice = insert_test_invoice(&pool, "renderowner", &npub, "lq1renderowner", 3_600).await;

    let (status, _body) = get_path(&app, &format!("/renderowner/i/{}", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = get_path(&app, &format!("/wrongnym/i/{}", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["code"], "InvoiceNotFound");

    let (status, _body) = get_path(&app, &format!("/invoice/{}", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_status_and_render_share_terminal_state_after_payment() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let npub = create_test_user(&pool, "renderpaid").await;
    let invoice = insert_test_invoice(&pool, "renderpaid", &npub, "lq1renderpaid", 3_600).await;

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:6161616161616161616161616161616161616161616161616161616161616161:0",
            1_000,
            "6161616161616161616161616161616161616161616161616161616161616161",
            0,
            "lq1renderpaid",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();

    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "paid");
    assert_eq!(body["remaining_amount_sat"], 0);
    assert_eq!(body["lightning_pr"], Value::Null);

    let (status, _body) = get_path(&app, &format!("/renderpaid/i/{}", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn signed_invoice_cancel_after_paid_is_terminal_noop() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (npub, _, _, keypair) = sign_registration_with_keypair("cancelpaid", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "cancelpaid", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice = insert_test_invoice(&pool, "cancelpaid", &npub, "lq1cancelpaid", 3_600).await;
    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:6262626262626262626262626262626262626262626262626262626262626262:0",
            1_000,
            "6262626262626262626262626262626262626262626262626262626262626262",
            0,
            "lq1cancelpaid",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();

    let invoice_id = invoice.id.to_string();
    let (sig, timestamp) =
        sign_invoice_cancel_with_keypair(&keypair, &npub, "cancelpaid", &invoice_id);
    let (status, body) = delete_json_path(
        &app,
        &format!("/api/v1/cancelpaid/invoices/{invoice_id}"),
        json!({
            "npub": npub,
            "timestamp": timestamp,
            "signature": sig,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "paid");
    let still_paid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_paid.status, "paid");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn cancelled_invoice_records_late_boltz_settlement_once() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "cancellateboltz").await;
    let invoice =
        insert_test_invoice(&pool, "cancellateboltz", &npub, "lq1cancellateboltz", 3_600).await;
    assert_eq!(
        pay_service::db::cancel_invoice(&pool, invoice.id)
            .await
            .unwrap(),
        (1, "cancelled".to_string())
    );

    let tolerances = pay_service::db::InvoiceAccountingTolerances::default();
    let claim_txid = "6363636363636363636363636363636363636363636363636363636363636363";
    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: None,
            boltz_swap_id: "cancelled-repair-reproducer",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-cancelled-repair-reproducer",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE swap_records SET status = 'claimed', claim_txid = $2, updated_at = NOW() \
         WHERE boltz_swap_id = $1",
    )
    .bind("cancelled-repair-reproducer")
    .bind(claim_txid)
    .execute(&pool)
    .await
    .unwrap();
    let repair_epoch_micros: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000000)::BIGINT",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        pay_service::db::list_claimed_swaps_missing_lightning_event(
            &pool,
            7 * 24 * 60 * 60,
            repair_epoch_micros,
            None,
            10,
        )
        .await
        .unwrap()
        .len(),
        1,
        "the live #77 claimed+cancelled reproducer must enter settlement repair"
    );
    assert!(
        invoice::flip_invoice_on_lightning_settlement(
            &pool,
            Some(invoice.id),
            1_000,
            "cancelled-repair-reproducer",
            claim_txid,
            tolerances,
        )
        .await
    );
    assert!(
        pay_service::db::list_claimed_swaps_missing_lightning_event(
            &pool,
            7 * 24 * 60 * 60,
            repair_epoch_micros,
            None,
            10,
        )
        .await
        .unwrap()
        .is_empty(),
        "one successful late-money event must retire the row from repair"
    );
    assert!(
        invoice::flip_invoice_on_lightning_settlement(
            &pool,
            Some(invoice.id),
            1_000,
            "cancelled-repair-reproducer",
            claim_txid,
            tolerances,
        )
        .await,
        "settlement-repair replay remains an idempotent success"
    );

    let cancelled = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cancelled.status, "cancelled");
    assert_eq!(
        cancelled.presentation_status.as_deref(),
        Some("payment_received")
    );
    assert_eq!(cancelled.paid_via.as_deref(), Some("lightning"));
    assert_eq!(cancelled.paid_amount_sat, Some(1_000));
    assert_eq!(cancelled.swap_settlement_status, "settled");
    assert_eq!(cancelled.settlement_status, "settled");
    assert!(cancelled.paid_at_unix.is_some());

    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM invoice_payment_events WHERE invoice_id = $1")
            .bind(invoice.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(event_count, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn cancelled_invoice_keeps_lifecycle_marker_while_direct_money_is_visible() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let (npub, _, _, keypair) =
        sign_registration_with_keypair("cancellatedirect", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "cancellatedirect", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice = insert_test_invoice(
        &pool,
        "cancellatedirect",
        &npub,
        "lq1cancellatedirect",
        3_600,
    )
    .await;
    pay_service::db::cancel_invoice(&pool, invoice.id)
        .await
        .unwrap();

    let txid = "6464646464646464646464646464646464646464646464646464646464646464";
    let event_key = format!("liquid_direct:{txid}:0");
    let provisional = [liquid_lifecycle_observation(
        &event_key,
        txid,
        0,
        "lq1cancellatedirect",
        1_000,
        0,
        pay_service::db::DirectObservationPhase::Provisional,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &provisional,
    )
    .await;
    let provisional_projection = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(provisional_projection.status, "cancelled");
    assert_eq!(
        provisional_projection.presentation_status.as_deref(),
        Some("payment_received")
    );
    assert_eq!(provisional_projection.paid_amount_sat, None);
    assert_eq!(provisional_projection.paid_via, None);
    assert!(provisional_projection.paid_at_unix.is_none());
    assert_eq!(provisional_projection.direct_settlement_status, "pending");

    let confirmed = [liquid_lifecycle_observation(
        &event_key,
        txid,
        0,
        "lq1cancellatedirect",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &confirmed,
    )
    .await;

    let cancelled = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cancelled.status, "cancelled");
    assert_eq!(
        cancelled.presentation_status.as_deref(),
        Some("payment_received")
    );
    assert_eq!(cancelled.paid_via.as_deref(), Some("liquid"));
    assert_eq!(cancelled.paid_amount_sat, Some(1_000));
    assert_eq!(cancelled.direct_settlement_status, "pending");
    assert_eq!(cancelled.settlement_status, "pending");
    assert!(cancelled.paid_at_unix.is_some());

    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "cancelled");
    assert_eq!(body["presentation_status"], "payment_received");
    assert_eq!(body["paid_amount_sat"], 1_000);
    assert_eq!(body["remaining_amount_sat"], 0);
    assert_eq!(body["lightning_pr"], Value::Null);
    assert_eq!(body["bitcoin_chain_address"], Value::Null);

    let (sig, timestamp) = sign_invoice_list_with_keypair(&keypair, &npub, 1, 10, "");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={npub}&page=1&pageSize=10&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoices"][0]["status"], "cancelled");
    assert_eq!(
        body["invoices"][0]["presentation_status"],
        "payment_received"
    );
    assert_eq!(body["invoices"][0]["paid_amount_sat"], 1_000);
    assert_eq!(body["invoices"][0]["remaining_amount_sat"], 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn expired_invoice_keeps_lifecycle_marker_while_late_money_is_visible() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "expiredlate").await;
    let invoice = insert_test_invoice(&pool, "expiredlate", &npub, "lq1expiredlate", -10).await;
    assert_eq!(
        pay_service::db::expire_invoices_past_deadline(&pool, 0)
            .await
            .unwrap(),
        1
    );

    let txid = "6565656565656565656565656565656565656565656565656565656565656565";
    let event_key = format!("liquid_direct:{txid}:0");
    let confirmed = [liquid_lifecycle_observation(
        &event_key,
        txid,
        0,
        "lq1expiredlate",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &confirmed,
    )
    .await;

    let expired = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.status, "expired");
    assert_eq!(
        expired.presentation_status.as_deref(),
        Some("payment_received")
    );
    assert_eq!(expired.paid_via.as_deref(), Some("liquid"));
    assert_eq!(expired.paid_amount_sat, Some(1_000));
    assert_eq!(expired.direct_settlement_status, "pending");
    assert_eq!(expired.settlement_status, "pending");
    assert!(expired.paid_at_unix.is_some());

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
            public_slug: None,
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

#[tokio::test]
async fn liquid_outpoint_reservation_reuses_original_index_after_cursor_advances() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let _npub = create_test_user(&pool, "liquidlastunused").await;
    let outpoint_a = "00".repeat(32);
    let outpoint_b = "11".repeat(32);
    let pubkey_a = "02".repeat(33);
    let pubkey_b = "03".repeat(33);

    let first = pay_service::db::allocate_outpoint_address(
        &pool,
        "liquidlastunused",
        &outpoint_a,
        &pubkey_a,
    )
    .await
    .unwrap();
    assert_eq!(first, 0);

    sqlx::query("UPDATE users SET next_addr_idx = 7 WHERE nym = $1")
        .bind("liquidlastunused")
        .execute(&pool)
        .await
        .unwrap();

    let repeated = pay_service::db::allocate_outpoint_address(
        &pool,
        "liquidlastunused",
        &outpoint_a,
        &pubkey_a,
    )
    .await
    .unwrap();
    assert_eq!(repeated, 0);

    let different_outpoint = pay_service::db::allocate_outpoint_address(
        &pool,
        "liquidlastunused",
        &outpoint_b,
        &pubkey_b,
    )
    .await
    .unwrap();
    assert_eq!(different_outpoint, 7);

    let reservations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outpoint_addresses WHERE nym = $1")
            .bind("liquidlastunused")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reservations, 2);

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

    pay_service::db::mark_invoice_in_progress_for_component(
        &pool,
        expired_in_progress.id,
        pay_service::db::InvoiceInProgressComponent::Direct,
    )
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

    let expired_count = pay_service::db::expire_invoices_past_deadline(&pool, 0)
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
        payment_grace_secs: 0,
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
    assert_eq!(partial.presentation_status.as_deref(), Some("partial"));
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
    assert_eq!(
        paid.presentation_status.as_deref(),
        Some("payment_received")
    );
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
    assert_eq!(overpaid.presentation_status.as_deref(), Some("overpaid"));
    assert_eq!(overpaid.settlement_status, "settled");
    assert_eq!(overpaid.paid_amount_sat, Some(1_010));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn boltz_liquid_payout_does_not_double_count_lightning_invoice_payment() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "boltzpayout").await;
    let invoice = insert_test_invoice(&pool, "boltzpayout", &npub, "lq1boltzpayout", 60).await;
    let tolerances = pay_service::db::InvoiceAccountingTolerances::default();
    let claim_txid = "8843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e88";

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:8843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e88:0",
            951,
            claim_txid,
            0,
            "lq1boltzpayout",
        ),
        tolerances,
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    invoice::flip_invoice_on_lightning_settlement(
        &pool,
        Some(invoice.id),
        1_000,
        "boltz-payout-race",
        claim_txid,
        tolerances,
    )
    .await;

    let paid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paid.status, "paid");
    assert_eq!(
        paid.presentation_status.as_deref(),
        Some("payment_received")
    );
    assert_eq!(paid.paid_via.as_deref(), Some("lightning"));
    assert_eq!(paid.paid_amount_sat, Some(1_000));
    assert_eq!(paid.direct_settlement_status, "none");
    assert_eq!(paid.swap_settlement_status, "settled");
    assert_eq!(paid.direct_payment_projection_version, 1);

    #[allow(clippy::type_complexity)]
    let events: Vec<(
        uuid::Uuid,
        String,
        i64,
        String,
        Option<String>,
        Option<uuid::Uuid>,
    )> = sqlx::query_as(
        "SELECT id, source, amount_sat, accounting_state, \
                deactivation_reason, superseded_by_event_id \
         FROM invoice_payment_events \
         WHERE invoice_id = $1 ORDER BY source",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(events.len(), 2, "direct evidence must remain auditable");
    let boltz = events
        .iter()
        .find(|event| event.1 == "lightning_boltz_reverse")
        .unwrap();
    assert_eq!(boltz.2, 1_000);
    assert_eq!(boltz.3, "active");
    assert!(boltz.4.is_none());
    assert!(boltz.5.is_none());
    let direct = events
        .iter()
        .find(|event| event.1 == "liquid_direct")
        .unwrap();
    assert_eq!(direct.2, 951);
    assert_eq!(direct.3, "superseded");
    assert_eq!(direct.4.as_deref(), Some("boltz_supersession"));
    assert_eq!(direct.5, Some(boltz.0));

    #[allow(clippy::type_complexity)]
    let transition: (
        Option<uuid::Uuid>,
        uuid::Uuid,
        String,
        i64,
        String,
        String,
        Value,
    ) = sqlx::query_as(
        "SELECT observation_id, payment_event_id, source, generation, \
                transition_kind, reason, metadata \
         FROM invoice_direct_payment_transitions WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(transition.0.is_none());
    assert_eq!(transition.1, direct.0);
    assert_eq!(transition.2, "liquid_direct");
    assert_eq!(transition.3, 0);
    assert_eq!(transition.4, "superseded");
    assert_eq!(transition.5, "boltz_supersession");
    assert_eq!(
        transition.6["superseded_by_payment_event_id"],
        boltz.0.to_string()
    );
    let observation_snapshot: (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT from_observation_state, to_observation_state, \
                from_verification_state, to_verification_state \
         FROM invoice_direct_payment_transitions WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(observation_snapshot, (None, None, None, None));
    type InvoiceTransitionSnapshot = (
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        Option<i64>,
        Option<i64>,
    );
    let invoice_snapshot: InvoiceTransitionSnapshot = sqlx::query_as(
        "SELECT from_presentation_status, to_presentation_status, \
                    from_settlement_status, to_settlement_status, \
                    from_invoice_status, to_invoice_status, \
                    from_paid_amount_sat, to_paid_amount_sat \
             FROM invoice_direct_payment_transitions WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        invoice_snapshot,
        (
            Some("partial".to_string()),
            Some("payment_received".to_string()),
            "none".to_string(),
            "settled".to_string(),
            "partially_paid".to_string(),
            "paid".to_string(),
            Some(951),
            Some(1_000),
        )
    );

    assert!(
        invoice::flip_invoice_on_lightning_settlement(
            &pool,
            Some(invoice.id),
            1_000,
            "boltz-payout-race",
            claim_txid,
            tolerances,
        )
        .await
    );
    let retry_state: (i64, i64) = sqlx::query_as(
        "SELECT i.direct_payment_projection_version, COUNT(t.id) \
         FROM invoices i \
         LEFT JOIN invoice_direct_payment_transitions t ON t.invoice_id = i.id \
         WHERE i.id = $1 GROUP BY i.direct_payment_projection_version",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retry_state, (1, 1));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn boltz_supersession_terminates_linked_direct_observation_and_blocks_reactivation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "boltzlinkedobs").await;
    let invoice =
        insert_test_invoice(&pool, "boltzlinkedobs", &npub, "lq1boltzlinkedobs", 3_600).await;
    let claim_txid = "9191919191919191919191919191919191919191919191919191919191919191";
    let direct_key = format!("liquid_direct:{claim_txid}:0");
    let provisional = [liquid_lifecycle_observation(
        &direct_key,
        claim_txid,
        0,
        "lq1boltzlinkedobs",
        1_000,
        0,
        pay_service::db::DirectObservationPhase::Provisional,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &provisional,
    )
    .await;

    assert!(
        invoice::flip_invoice_on_lightning_settlement(
            &pool,
            Some(invoice.id),
            1_000,
            "boltz-linked-observation",
            claim_txid,
            direct_lifecycle_tolerances(),
        )
        .await
    );

    let canonical_event_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM invoice_payment_events \
         WHERE invoice_id = $1 AND source = 'lightning_boltz_reverse'",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    #[allow(clippy::type_complexity)]
    let superseded: (
        uuid::Uuid,
        uuid::Uuid,
        String,
        Option<uuid::Uuid>,
        String,
        String,
        Option<uuid::Uuid>,
    ) = sqlx::query_as(
        "SELECT o.id, e.id, o.last_seen_state, o.superseded_by_payment_event_id, \
                e.accounting_state, e.deactivation_reason, e.superseded_by_event_id \
         FROM invoice_payment_observations o \
         JOIN invoice_payment_events e ON e.observation_id = o.id \
         WHERE o.invoice_id = $1 AND o.event_key = $2",
    )
    .bind(invoice.id)
    .bind(&direct_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(superseded.2, "superseded");
    assert_eq!(superseded.3, Some(canonical_event_id));
    assert_eq!(superseded.4, "superseded");
    assert_eq!(superseded.5, "boltz_supersession");
    assert_eq!(superseded.6, Some(canonical_event_id));

    #[allow(clippy::type_complexity)]
    let transition: (
        i64,
        String,
        Option<uuid::Uuid>,
        uuid::Uuid,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        Option<i64>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT generation, transition_kind, observation_id, payment_event_id, \
                from_observation_state, to_observation_state, \
                from_event_state, to_event_state, from_invoice_status, \
                to_invoice_status, from_paid_amount_sat, to_paid_amount_sat \
         FROM invoice_direct_payment_transitions \
         WHERE invoice_id = $1 AND reason = 'boltz_supersession'",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(transition.0, 0);
    assert_eq!(transition.1, "superseded");
    assert_eq!(transition.2, Some(superseded.0));
    assert_eq!(transition.3, superseded.1);
    assert_eq!(transition.4.as_deref(), Some("seen_unconfirmed"));
    assert_eq!(transition.5.as_deref(), Some("superseded"));
    assert_eq!(transition.6, "inactive");
    assert_eq!(transition.7, "superseded");
    assert_eq!(transition.8, "in_progress");
    assert_eq!(transition.9, "paid");
    assert_eq!(transition.10, None);
    assert_eq!(transition.11, Some(1_000));

    let projection = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(projection.direct_settlement_status, "none");
    assert_eq!(projection.swap_settlement_status, "settled");
    assert_eq!(projection.settlement_status, "settled");
    assert_eq!(projection.direct_payment_projection_version, 2);

    assert!(
        invoice::flip_invoice_on_lightning_settlement(
            &pool,
            Some(invoice.id),
            1_000,
            "boltz-linked-observation",
            claim_txid,
            direct_lifecycle_tolerances(),
        )
        .await
    );
    let retry_state: (i64, i64) = sqlx::query_as(
        "SELECT i.direct_payment_projection_version, COUNT(t.id) \
         FROM invoices i \
         LEFT JOIN invoice_direct_payment_transitions t \
           ON t.invoice_id = i.id AND t.reason = 'boltz_supersession' \
         WHERE i.id = $1 GROUP BY i.direct_payment_projection_version",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retry_state, (2, 1));

    let generation = pay_service::db::reserve_direct_observation_generation(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
    )
    .await
    .unwrap();
    let confirmed = [liquid_lifecycle_observation(
        &direct_key,
        claim_txid,
        0,
        "lq1boltzlinkedobs",
        1_000,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];
    let reactivation = pay_service::db::apply_direct_observation_batch(
        &pool,
        pay_service::db::DirectObservationBatch {
            invoice_id: invoice.id,
            source: pay_service::db::DirectPaymentSource::Liquid,
            authority: "reactivation-must-fail",
            generation,
            observations: &confirmed,
        },
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap();
    assert_eq!(
        reactivation,
        pay_service::db::ApplyDirectObservationOutcome::Applied { changed: false },
        "a stale watcher result for the Boltz settlement transaction must be consumed without reactivating its direct observation"
    );
    let terminal_state: (String, String, i64) = sqlx::query_as(
        "SELECT o.last_seen_state, e.accounting_state, h.applied_generation \
         FROM invoice_payment_observations o \
         JOIN invoice_payment_events e ON e.observation_id = o.id \
         JOIN invoice_direct_scan_heads h \
           ON h.invoice_id = o.invoice_id AND h.source = o.source \
         WHERE o.invoice_id = $1 AND o.event_key = $2",
    )
    .bind(invoice.id)
    .bind(&direct_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        terminal_state,
        ("superseded".to_string(), "superseded".to_string(), 2)
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn liquid_scanner_ignores_known_boltz_settlement_txid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "boltzknown").await;
    let invoice = insert_test_invoice(&pool, "boltzknown", &npub, "lq1boltzknown", 60).await;
    let tolerances = pay_service::db::InvoiceAccountingTolerances::default();
    let claim_txid = "9843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e89";

    invoice::flip_invoice_on_lightning_settlement(
        &pool,
        Some(invoice.id),
        400,
        "boltz-known-first",
        claim_txid,
        tolerances,
    )
    .await;

    assert_eq!(
        pay_service::db::invoice_boltz_settlement_txids(&pool, invoice.id)
            .await
            .unwrap(),
        vec![claim_txid.to_string()],
        "the live Liquid watcher exclusion set must retain a partial Boltz claim txid"
    );

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:9843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e89:0",
            951,
            claim_txid,
            0,
            "lq1boltzknown",
        ),
        tolerances,
    )
    .await
    .unwrap();
    assert_eq!(rows, 0);

    let paid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paid.status, "partially_paid");
    assert_eq!(paid.paid_via.as_deref(), Some("lightning"));
    assert_eq!(paid.paid_amount_sat, Some(400));
    assert_eq!(paid.swap_settlement_status, "settled");

    let event_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM invoice_payment_events WHERE invoice_id = $1")
            .bind(invoice.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(event_count.0, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn liquid_reducer_rechecks_boltz_settlement_after_stale_network_discovery() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "boltzreducerrace").await;
    let invoice = insert_test_invoice(
        &pool,
        "boltzreducerrace",
        &npub,
        "lq1boltzreducerrace",
        3_600,
    )
    .await;
    let claim_txid = "8843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e88";
    let event_key = format!("liquid_direct:{claim_txid}:0");
    let generation = pay_service::db::reserve_direct_observation_generation(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
    )
    .await
    .unwrap();
    let stale_discovery = [liquid_lifecycle_observation(
        &event_key,
        claim_txid,
        0,
        "lq1boltzreducerrace",
        400,
        1,
        pay_service::db::DirectObservationPhase::Confirmed,
        None,
    )];

    // The provider settlement commits after network discovery/reservation but
    // before the stale watcher batch reaches the reducer advisory boundary.
    invoice::flip_invoice_on_lightning_settlement(
        &pool,
        Some(invoice.id),
        400,
        "boltz-reducer-race-first",
        claim_txid,
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await;
    let outcome = pay_service::db::apply_direct_observation_batch(
        &pool,
        pay_service::db::DirectObservationBatch {
            invoice_id: invoice.id,
            source: pay_service::db::DirectPaymentSource::Liquid,
            authority: "stale-liquid-network-view",
            generation,
            observations: &stale_discovery,
        },
        direct_lifecycle_tolerances(),
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        pay_service::db::ApplyDirectObservationOutcome::Applied { .. }
    ));

    let events: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT source, accounting_state, amount_sat \
         FROM invoice_payment_events WHERE invoice_id = $1 ORDER BY accounting_sequence",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        events,
        vec![("lightning_boltz_reverse".into(), "active".into(), 400)]
    );
    let direct_observations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoice_payment_observations \
         WHERE invoice_id = $1 AND source = 'liquid_direct'",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(direct_observations, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn production_invoice_read_snapshots_never_mix_projection_generations() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (npub, _, _, keypair) = sign_registration_with_keypair("invoicesnapshot", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "invoicesnapshot", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice =
        insert_test_invoice(&pool, "invoicesnapshot", &npub, "lq1invoicesnapshot", 3_600).await;
    let app = test_app(test_state(pool.clone()));
    let txid = "7843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e87";
    let first_key = format!("liquid_direct:{txid}:0");
    let second_key = format!("liquid_direct:{txid}:1");
    let partial = [liquid_lifecycle_observation(
        &first_key,
        txid,
        0,
        "lq1invoicesnapshot",
        400,
        0,
        pay_service::db::DirectObservationPhase::Provisional,
        None,
    )];

    // Exercise the real status handler: pause after its invoice-row read,
    // commit a reducer generation, then let every remaining projection read
    // continue on the handler's already-established RR snapshot.
    let status_hook = invoice::install_invoice_integration_test_hook(
        invoice::InvoiceIntegrationTestHookPoint::StatusAfterInvoiceRead,
    );
    let status_app = app.clone();
    let status_path = format!("/api/v1/invoices/{}/status", invoice.id);
    let status_request = tokio::spawn(async move { get_path(&status_app, &status_path).await });
    tokio::time::timeout(Duration::from_secs(2), status_hook.wait_until_reached())
        .await
        .expect("status handler did not reach its post-invoice snapshot boundary");
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &partial,
    )
    .await;
    status_hook.release();
    let (status, body) = tokio::time::timeout(Duration::from_secs(2), status_request)
        .await
        .expect("status handler did not finish after snapshot release")
        .expect("status task failed");
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "unpaid");
    assert_eq!(body["presentation_status"], "unpaid");
    assert_eq!(body["remaining_amount_sat"], 1_000);

    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "in_progress");
    assert_eq!(body["presentation_status"], "partial");
    assert_eq!(body["remaining_amount_sat"], 600);

    // The signed list uses the bulk exact-value helper, so cover that distinct
    // plumbing with another reducer commit between its row and sum reads.
    let list_hook = invoice::install_invoice_integration_test_hook(
        invoice::InvoiceIntegrationTestHookPoint::ListAfterInvoiceRead,
    );
    let (sig, timestamp) = sign_invoice_list_with_keypair(&keypair, &npub, 1, 10, "");
    let list_path = format!(
        "/api/v1/invoices?npub={npub}&page=1&pageSize=10&timestamp={timestamp}&signature={sig}"
    );
    let list_app = app.clone();
    let list_request = tokio::spawn(async move { get_path(&list_app, &list_path).await });
    tokio::time::timeout(Duration::from_secs(2), list_hook.wait_until_reached())
        .await
        .expect("list handler did not reach its post-row snapshot boundary");
    let sufficient = [
        liquid_lifecycle_observation(
            &first_key,
            txid,
            0,
            "lq1invoicesnapshot",
            400,
            0,
            pay_service::db::DirectObservationPhase::Provisional,
            None,
        ),
        liquid_lifecycle_observation(
            &second_key,
            txid,
            1,
            "lq1invoicesnapshot",
            600,
            0,
            pay_service::db::DirectObservationPhase::Provisional,
            None,
        ),
    ];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &sufficient,
    )
    .await;
    list_hook.release();
    let (status, body) = tokio::time::timeout(Duration::from_secs(2), list_request)
        .await
        .expect("list handler did not finish after snapshot release")
        .expect("list task failed");
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoices"][0]["status"], "in_progress");
    assert_eq!(body["invoices"][0]["presentation_status"], "partial");
    assert_eq!(body["invoices"][0]["remaining_amount_sat"], 600);

    let (sig, timestamp) = sign_invoice_list_with_keypair(&keypair, &npub, 1, 10, "");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={npub}&page=1&pageSize=10&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoices"][0]["status"], "in_progress");
    assert_eq!(
        body["invoices"][0]["presentation_status"],
        "payment_received"
    );
    assert_eq!(body["invoices"][0]["remaining_amount_sat"], 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn boltz_settlement_does_not_prune_direct_bitcoin_payment_events() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "boltzbtcdirect").await;
    let invoice = insert_test_btc_invoice(&pool, "boltzbtcdirect", &npub, "bc1qboltzbtcdirect")
        .await
        .unwrap();
    let tolerances = pay_service::db::InvoiceAccountingTolerances::default();
    let txid = "a843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e8a";

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        bitcoin_direct_evidence(
            "bitcoin_direct:a843a083f1db2d9f857f18025fbf9bf1e3b256fb0c06bebae207fa7a01218e8a:0",
            100,
            txid,
            0,
            "bc1qboltzbtcdirect",
        ),
        tolerances,
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    invoice::flip_invoice_on_lightning_settlement(
        &pool,
        Some(invoice.id),
        1_000,
        "boltz-does-not-prune-btc",
        txid,
        tolerances,
    )
    .await;

    let overpaid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(overpaid.status, "overpaid");
    assert_eq!(overpaid.paid_via.as_deref(), Some("mixed"));
    assert_eq!(overpaid.paid_amount_sat, Some(1_100));

    let events: Vec<(String, i64)> = sqlx::query_as(
        "SELECT source, amount_sat FROM invoice_payment_events \
         WHERE invoice_id = $1 ORDER BY source",
    )
    .bind(invoice.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        events,
        vec![
            ("bitcoin_direct".to_string(), 100),
            ("lightning_boltz_reverse".to_string(), 1_000),
        ]
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn bitcoin_payment_observations_do_not_count_as_paid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "btcobserve").await;
    let invoice = insert_test_btc_invoice(&pool, "btcobserve", &npub, "bc1qbtcobserve")
        .await
        .unwrap();

    let rows = pay_service::db::upsert_invoice_payment_observation(
        &pool,
        invoice.id,
        bitcoin_direct_observation(
            "bitcoin_direct:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee:0",
            1_000,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            0,
            "bc1qbtcobserve",
            0,
            None,
            "seen_unconfirmed",
        ),
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    let invoice = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invoice.status, "unpaid");
    assert_eq!(invoice.settlement_status, "none");
    assert_eq!(invoice.paid_amount_sat, None);
    assert_eq!(invoice.paid_via, None);

    let observations = pay_service::db::list_invoice_payment_observations(&pool, invoice.id, 10)
        .await
        .unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].last_seen_state, "seen_unconfirmed");
    assert_eq!(observations[0].confirmations, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn bitcoin_payment_observation_upsert_updates_confirmation_state() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "btcconfirm").await;
    let invoice = insert_test_btc_invoice(&pool, "btcconfirm", &npub, "bc1qbtcconfirm")
        .await
        .unwrap();
    let event_key =
        "bitcoin_direct:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:1";
    let txid = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    pay_service::db::upsert_invoice_payment_observation(
        &pool,
        invoice.id,
        bitcoin_direct_observation(
            event_key,
            1_000,
            txid,
            1,
            "bc1qbtcconfirm",
            0,
            None,
            "seen_unconfirmed",
        ),
    )
    .await
    .unwrap();
    pay_service::db::upsert_invoice_payment_observation(
        &pool,
        invoice.id,
        bitcoin_direct_observation(
            event_key,
            1_000,
            txid,
            1,
            "bc1qbtcconfirm",
            2,
            Some(800_000),
            "awaiting_confirmations",
        ),
    )
    .await
    .unwrap();

    let observations = pay_service::db::list_invoice_payment_observations(&pool, invoice.id, 10)
        .await
        .unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].confirmations, 2);
    assert_eq!(observations[0].block_height, Some(800_000));
    assert_eq!(observations[0].last_seen_state, "awaiting_confirmations");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn missing_bitcoin_observation_is_marked_not_seen_without_accounting_change() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "btcmissing").await;
    let invoice = insert_test_btc_invoice(&pool, "btcmissing", &npub, "bc1qbtcmissing")
        .await
        .unwrap();

    pay_service::db::upsert_invoice_payment_observation(
        &pool,
        invoice.id,
        bitcoin_direct_observation(
            "bitcoin_direct:1111111111111111111111111111111111111111111111111111111111111111:0",
            500,
            "1111111111111111111111111111111111111111111111111111111111111111",
            0,
            "bc1qbtcmissing",
            0,
            None,
            "seen_unconfirmed",
        ),
    )
    .await
    .unwrap();

    let rows =
        pay_service::db::mark_missing_bitcoin_payment_observations_not_seen(&pool, invoice.id, &[])
            .await
            .unwrap();
    assert_eq!(rows, 1);

    let observations = pay_service::db::list_invoice_payment_observations(&pool, invoice.id, 10)
        .await
        .unwrap();
    assert_eq!(observations[0].last_seen_state, "not_seen");
    let invoice = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invoice.paid_amount_sat, None);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_status_exposes_bitcoin_direct_observations() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "btcstatus").await;
    let invoice = insert_test_btc_invoice(&pool, "btcstatus", &npub, "bc1qbtcstatusx")
        .await
        .unwrap();
    pay_service::db::upsert_invoice_payment_observation(
        &pool,
        invoice.id,
        bitcoin_direct_observation(
            "bitcoin_direct:2222222222222222222222222222222222222222222222222222222222222222:0",
            750,
            "2222222222222222222222222222222222222222222222222222222222222222",
            0,
            "bc1qbtcstatusx",
            0,
            None,
            "seen_unconfirmed",
        ),
    )
    .await
    .unwrap();

    let app = test_app(test_state(pool.clone()));
    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);
    let observations = body["bitcoin_direct_observations"].as_array().unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0]["source"], "bitcoin_direct");
    assert_eq!(observations[0]["rail"], "bitcoin");
    assert_eq!(
        observations[0]["txid"],
        "2222222222222222222222222222222222222222222222222222222222222222"
    );
    assert_eq!(observations[0]["vout"], 0);
    assert_eq!(observations[0]["amount_sat"], 750);
    assert_eq!(observations[0]["state"], "seen_unconfirmed");
    assert_eq!(body["status"], "unpaid");
    assert_eq!(body["paid_amount_sat"], Value::Null);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn stale_checkout_partial_terminalizes_to_underpaid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "checkoutstale").await;
    let invoice =
        insert_test_invoice(&pool, "checkoutstale", &npub, "lq1checkoutstale", 3_600).await;

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1212121212121212121212121212121212121212121212121212121212121212:0",
            400,
            "1212121212121212121212121212121212121212121212121212121212121212",
            0,
            "lq1checkoutstale",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_payment_events \
         SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .execute(&pool)
    .await
    .unwrap();

    let rows = pay_service::db::terminalize_stale_checkout_partial_invoice(&pool, invoice.id, 900)
        .await
        .unwrap();
    assert_eq!(rows, 1);

    let underpaid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(underpaid.status, "underpaid");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn stale_wallet_partial_stays_payable() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "walletpartial").await;
    let blinding_key = "11".repeat(32);
    let invoice = pay_service::db::insert_invoice(
        &pool,
        &pay_service::db::NewInvoice {
            nym_owner: Some("walletpartial"),
            public_slug: None,
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
            liquid_address: Some("lq1walletpartial"),
            liquid_blinding_key_hex: Some(&blinding_key),
            expires_in_secs: 3_600,
        },
    )
    .await
    .unwrap();

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1313131313131313131313131313131313131313131313131313131313131313:0",
            400,
            "1313131313131313131313131313131313131313131313131313131313131313",
            0,
            "lq1walletpartial",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_payment_events \
         SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .execute(&pool)
    .await
    .unwrap();

    let rows = pay_service::db::terminalize_stale_checkout_partial_invoice(&pool, invoice.id, 900)
        .await
        .unwrap();
    assert_eq!(rows, 0);

    let partial = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(partial.status, "partially_paid");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn checkout_underpaid_liquid_address_remains_watchable_and_recoverable() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "underwatch").await;
    let invoice = insert_test_invoice(&pool, "underwatch", &npub, "lq1underwatch", 3_600).await;

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1414141414141414141414141414141414141414141414141414141414141414:0",
            400,
            "1414141414141414141414141414141414141414141414141414141414141414",
            0,
            "lq1underwatch",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_payment_events \
         SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .execute(&pool)
    .await
    .unwrap();
    pay_service::db::terminalize_stale_checkout_partial_invoice(&pool, invoice.id, 900)
        .await
        .unwrap();

    let candidates = pay_service::db::list_unpaid_invoices_with_liquid_address(&pool, 0)
        .await
        .unwrap();
    assert!(candidates
        .iter()
        .any(|(candidate_id, address, _, _)| *candidate_id == invoice.id
            && address == "lq1underwatch"));

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1515151515151515151515151515151515151515151515151515151515151515:1",
            600,
            "1515151515151515151515151515151515151515151515151515151515151515",
            1,
            "lq1underwatch",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    let paid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paid.status, "paid");
    assert_eq!(paid.paid_amount_sat, Some(1_000));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn checkout_underpaid_insufficient_topup_stays_underpaid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "undertopup").await;
    let invoice = insert_test_invoice(&pool, "undertopup", &npub, "lq1undertopup", 3_600).await;

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1616161616161616161616161616161616161616161616161616161616161616:0",
            300,
            "1616161616161616161616161616161616161616161616161616161616161616",
            0,
            "lq1undertopup",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_payment_events \
         SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .execute(&pool)
    .await
    .unwrap();
    pay_service::db::terminalize_stale_checkout_partial_invoice(&pool, invoice.id, 900)
        .await
        .unwrap();

    let rows = pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1717171717171717171717171717171717171717171717171717171717171717:1",
            200,
            "1717171717171717171717171717171717171717171717171717171717171717",
            1,
            "lq1undertopup",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    assert_eq!(rows, 1);

    let underpaid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(underpaid.status, "underpaid");
    assert_eq!(underpaid.paid_amount_sat, Some(500));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_status_terminalizes_stale_checkout_partial_before_response() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let npub = create_test_user(&pool, "statusunder").await;
    let invoice = insert_test_invoice(&pool, "statusunder", &npub, "lq1statusunder", 3_600).await;

    pay_service::db::record_invoice_payment(
        &pool,
        invoice.id,
        liquid_direct_evidence(
            "liquid_direct:1818181818181818181818181818181818181818181818181818181818181818:0",
            400,
            "1818181818181818181818181818181818181818181818181818181818181818",
            0,
            "lq1statusunder",
        ),
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoice_payment_events \
         SET created_at = NOW() - INTERVAL '20 minutes' \
         WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .execute(&pool)
    .await
    .unwrap();

    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "underpaid");
    assert_eq!(body["paid_amount_sat"], 400);
    assert_eq!(body["remaining_amount_sat"], 600);

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
            key_index: None,
            root_fingerprint: None,
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
async fn swap_component_writers_recompose_without_hiding_direct_resolution() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "settlementstate").await;
    let invoice =
        insert_test_invoice(&pool, "settlementstate", &npub, "lq1settlementstate", 60).await;

    let direct_txid = "7171717171717171717171717171717171717171717171717171717171717171";
    let direct_event_key = format!("liquid_direct:{direct_txid}:0");
    let resolution = [liquid_lifecycle_observation(
        &direct_event_key,
        direct_txid,
        0,
        "lq1settlementstate",
        400,
        0,
        pay_service::db::DirectObservationPhase::ResolutionPending(
            pay_service::db::DirectRegressionReason::Reorged,
        ),
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &resolution,
    )
    .await;

    pay_service::db::mark_invoice_in_progress_for_component(
        &pool,
        invoice.id,
        pay_service::db::InvoiceInProgressComponent::Swap,
    )
    .await
    .unwrap();
    let pending = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.status, "in_progress");
    assert_eq!(pending.direct_settlement_status, "resolution_pending");
    assert_eq!(pending.swap_settlement_status, "pending");
    assert_eq!(pending.settlement_status, "resolution_pending");

    pay_service::db::mark_invoice_settlement_status(&pool, Some(invoice.id), "settled")
        .await
        .unwrap();
    let settled = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settled.swap_settlement_status, "settled");
    assert_eq!(settled.settlement_status, "resolution_pending");

    pay_service::db::mark_invoice_settlement_status(&pool, Some(invoice.id), "claim_stuck")
        .await
        .unwrap();
    let stuck = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stuck.settlement_status, "claim_stuck");

    for incident in ["refunded", "failed"] {
        pay_service::db::mark_invoice_settlement_status(&pool, Some(invoice.id), incident)
            .await
            .unwrap();
        let row = pay_service::db::get_invoice_by_id(&pool, invoice.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.swap_settlement_status, incident);
        assert_eq!(row.settlement_status, incident);
    }

    pay_service::db::record_swap(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: None,
            boltz_swap_id: "settlement-component-swap",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-settlement-component",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{}",
            invoice_id: Some(invoice.id),
        },
    )
    .await
    .unwrap();
    let swap_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM swap_records WHERE boltz_swap_id = $1")
            .bind("settlement-component-swap")
            .fetch_one(&pool)
            .await
            .unwrap();
    pay_service::db::mark_invoice_settlement_status_for_swap(&pool, swap_id, "pending")
        .await
        .unwrap();
    let by_swap = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_swap.swap_settlement_status, "pending");
    assert_eq!(by_swap.settlement_status, "resolution_pending");

    assert!(
        invoice::flip_invoice_on_lightning_settlement(
            &pool,
            Some(invoice.id),
            1_000,
            "settlement-component-payment",
            "7272727272727272727272727272727272727272727272727272727272727272",
            direct_lifecycle_tolerances(),
        )
        .await
    );
    let paid = pay_service::db::get_invoice_by_id(&pool, invoice.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paid.status, "paid");
    assert_eq!(
        paid.presentation_status.as_deref(),
        Some("payment_received")
    );
    assert_eq!(paid.direct_settlement_status, "resolution_pending");
    assert_eq!(paid.swap_settlement_status, "settled");
    assert_eq!(paid.settlement_status, "resolution_pending");

    cleanup_db(&pool).await;
}

async fn apply_terminal_liquid_direct_payment(
    pool: &PgPool,
    invoice: &pay_service::db::Invoice,
    amount_sat: i64,
    seed: u64,
) {
    let txid = format!("{seed:064x}");
    let event_key = format!("liquid_direct:{txid}:0");
    let observations = [liquid_lifecycle_observation(
        &event_key,
        &txid,
        0,
        invoice
            .liquid_address
            .as_deref()
            .expect("test invoice has a Liquid address"),
        amount_sat,
        2,
        pay_service::db::DirectObservationPhase::Finalized,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &observations,
    )
    .await;
}

async fn write_test_swap_component(
    pool: &PgPool,
    invoice_id: uuid::Uuid,
    settlement_status: &str,
    seed: u64,
) {
    match settlement_status {
        "pending" => {
            pay_service::db::mark_invoice_in_progress_for_component(
                pool,
                invoice_id,
                pay_service::db::InvoiceInProgressComponent::Swap,
            )
            .await
            .unwrap();
        }
        "claim_stuck" | "refunded" => {
            assert_eq!(
                pay_service::db::mark_invoice_settlement_status(
                    pool,
                    Some(invoice_id),
                    settlement_status,
                )
                .await
                .unwrap(),
                1
            );
        }
        "failed" => {
            let boltz_swap_id = format!("component-writer-{seed}");
            let invoice = format!("lnbc-component-writer-{seed}");
            let preimage = "aa".repeat(32);
            let claim_key = "bb".repeat(32);
            pay_service::db::record_swap(
                pool,
                &pay_service::db::NewSwapRecord {
                    key_index: None,
                    root_fingerprint: None,
                    nym: None,
                    boltz_swap_id: &boltz_swap_id,
                    address: None,
                    address_index: None,
                    amount_sat: 1_000,
                    invoice: &invoice,
                    preimage_hex: &preimage,
                    claim_key_hex: &claim_key,
                    boltz_response_json: "{}",
                    invoice_id: Some(invoice_id),
                },
            )
            .await
            .unwrap();
            let swap_id: uuid::Uuid =
                sqlx::query_scalar("SELECT id FROM swap_records WHERE boltz_swap_id = $1")
                    .bind(&boltz_swap_id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(
                pay_service::db::mark_invoice_settlement_status_for_swap(
                    pool,
                    swap_id,
                    settlement_status,
                )
                .await
                .unwrap(),
                1
            );
        }
        other => panic!("unsupported test settlement status: {other}"),
    }
}

#[tokio::test]
async fn swap_component_writers_preserve_every_terminal_direct_writer_order() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "terminalcomponents").await;
    let terminal_variants = [
        ("paid", 3_600, 1_000),
        ("underpaid", -10, 400),
        ("overpaid", 3_600, 1_100),
    ];
    let swap_states = ["pending", "claim_stuck", "refunded", "failed"];
    let mut seed = 1_u64;

    for (terminal_status, expires_in_secs, direct_amount_sat) in terminal_variants {
        for swap_status in swap_states {
            let address = format!("lq1terminalfirst{seed}");
            let invoice = insert_test_invoice(
                &pool,
                "terminalcomponents",
                &npub,
                &address,
                expires_in_secs,
            )
            .await;
            apply_terminal_liquid_direct_payment(&pool, &invoice, direct_amount_sat, seed).await;

            let direct_first = pay_service::db::get_invoice_by_id(&pool, invoice.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(direct_first.status, terminal_status);
            assert_eq!(direct_first.direct_settlement_status, "settled");

            write_test_swap_component(&pool, invoice.id, swap_status, seed).await;
            let after_swap = pay_service::db::get_invoice_by_id(&pool, invoice.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                after_swap.status, terminal_status,
                "swap component must not regress terminal accounting"
            );
            assert_eq!(after_swap.direct_settlement_status, "settled");
            assert_eq!(after_swap.swap_settlement_status, swap_status);
            assert_eq!(after_swap.settlement_status, swap_status);
            seed += 1;
        }
    }

    for (terminal_status, expires_in_secs, direct_amount_sat) in terminal_variants {
        for swap_status in swap_states {
            let address = format!("lq1swapfirst{seed}");
            let invoice = insert_test_invoice(
                &pool,
                "terminalcomponents",
                &npub,
                &address,
                expires_in_secs,
            )
            .await;
            write_test_swap_component(&pool, invoice.id, swap_status, seed).await;
            apply_terminal_liquid_direct_payment(&pool, &invoice, direct_amount_sat, seed).await;

            let after_direct = pay_service::db::get_invoice_by_id(&pool, invoice.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after_direct.status, terminal_status);
            assert_eq!(after_direct.direct_settlement_status, "settled");
            assert_eq!(after_direct.swap_settlement_status, swap_status);
            assert_eq!(after_direct.settlement_status, swap_status);
            seed += 1;
        }
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn partial_boltz_claims_keep_swap_component_settled_in_production_order() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "partialboltzsettled").await;
    let reverse = insert_test_invoice(
        &pool,
        "partialboltzsettled",
        &npub,
        "lq1partialreverse",
        3_600,
    )
    .await;
    let chain = insert_test_invoice(
        &pool,
        "partialboltzsettled",
        &npub,
        "lq1partialchain",
        3_600,
    )
    .await;

    assert_eq!(
        pay_service::db::mark_invoice_settlement_status(&pool, Some(reverse.id), "settled")
            .await
            .unwrap(),
        1
    );
    assert!(
        invoice::flip_invoice_on_lightning_settlement(
            &pool,
            Some(reverse.id),
            400,
            "partial-reverse-settled",
            "8181818181818181818181818181818181818181818181818181818181818181",
            direct_lifecycle_tolerances(),
        )
        .await
    );
    let reverse = pay_service::db::get_invoice_by_id(&pool, reverse.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reverse.status, "partially_paid");
    assert_eq!(reverse.presentation_status.as_deref(), Some("partial"));
    assert_eq!(reverse.direct_settlement_status, "none");
    assert_eq!(reverse.swap_settlement_status, "settled");
    assert_eq!(reverse.settlement_status, "settled");
    assert_eq!(reverse.paid_via.as_deref(), Some("lightning"));
    assert_eq!(reverse.paid_amount_sat, Some(400));

    assert_eq!(
        pay_service::db::mark_invoice_settlement_status(&pool, Some(chain.id), "settled")
            .await
            .unwrap(),
        1
    );
    assert!(
        invoice::flip_invoice_on_bitcoin_boltz_settlement(
            &pool,
            Some(chain.id),
            400,
            "partial-chain-settled",
            "8282828282828282828282828282828282828282828282828282828282828282",
            direct_lifecycle_tolerances(),
        )
        .await
    );
    let chain = pay_service::db::get_invoice_by_id(&pool, chain.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(chain.status, "partially_paid");
    assert_eq!(chain.presentation_status.as_deref(), Some("partial"));
    assert_eq!(chain.direct_settlement_status, "none");
    assert_eq!(chain.swap_settlement_status, "settled");
    assert_eq!(chain.settlement_status, "settled");
    assert_eq!(chain.paid_via.as_deref(), Some("bitcoin"));
    assert_eq!(chain.paid_amount_sat, Some(400));

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
async fn liquid_watcher_retains_closed_rows_and_finalized_evidence() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "liquidscan").await;

    let expired = insert_test_invoice(&pool, "liquidscan", &npub, "lq1scanexpired", -10).await;
    let cancelled = insert_test_invoice(&pool, "liquidscan", &npub, "lq1scancancelled", 60).await;
    let fresh = insert_test_invoice(&pool, "liquidscan", &npub, "lq1scanfresh", 60).await;
    let finalized = insert_test_invoice(&pool, "liquidscan", &npub, "lq1scanfinalized", 60).await;
    let txid = "2929292929292929292929292929292929292929292929292929292929292929";
    let event_key = format!("liquid_direct:{txid}:0");
    let finalized_observation = [liquid_lifecycle_observation(
        &event_key,
        txid,
        0,
        "lq1scanfinalized",
        1_000,
        2,
        pay_service::db::DirectObservationPhase::Finalized,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        finalized.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &finalized_observation,
    )
    .await;
    let finalized_projection = pay_service::db::get_invoice_by_id(&pool, finalized.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finalized_projection.status, "paid");
    assert_eq!(finalized_projection.direct_settlement_status, "settled");
    pay_service::db::expire_invoices_past_deadline(&pool, 0)
        .await
        .unwrap();
    pay_service::db::cancel_invoice(&pool, cancelled.id)
        .await
        .unwrap();

    let rows = pay_service::db::list_unpaid_invoices_with_liquid_address(&pool, 0)
        .await
        .unwrap();
    let invoice_ids: std::collections::HashSet<_> =
        rows.into_iter().map(|(id, _, _, _)| id).collect();

    assert!(invoice_ids.contains(&expired.id));
    assert!(invoice_ids.contains(&cancelled.id));
    assert!(invoice_ids.contains(&fresh.id));
    assert!(
        invoice_ids.contains(&finalized.id),
        "finalized Liquid evidence must remain watchable for deep reorgs"
    );

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
            key_index: None,
            root_fingerprint: None,
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
            key_index: None,
            root_fingerprint: None,
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
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("chainswaprec"),
            boltz_swap_id: "chain-swap-rec-1",
            lockup_address: "bc1qchainswaplockup",
            // Payer-pays gross-up: server lockup (claimed to merchant) = invoice
            // (1000); user lockup (what the payer sends) is grossed up (1010).
            lockup_bip21: Some("bitcoin:bc1qchainswaplockup?amount=0.00001010"),
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
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
        Some("bitcoin:bc1qchainswaplockup?amount=0.00001010")
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
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
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
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
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
            key_index: None,
            root_fingerprint: None,
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
            "nym": "purger1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            "nym": "purger1", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub2, "verification_npub": npub2, "signature": sig2, "timestamp": timestamp2,
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
            "nym": "purger2", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            "nym": "purger3", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            "nym": "purger4", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            "nym": "purger5", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": sig, "timestamp": timestamp,
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
            "nym": "purger5", "ct_descriptor": TEST_DESCRIPTOR, "npub": npub, "verification_npub": npub, "signature": re_sig, "timestamp": re_timestamp,
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
    pay_service::db::register_user_atomic(&pool, &npub_hex, "filler-0", TEST_DESCRIPTOR, None, 3)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET is_active = FALSE WHERE nym = 'filler-0'")
        .execute(&pool)
        .await
        .unwrap();
    pay_service::db::register_user_atomic(&pool, &npub_hex, "filler-1", TEST_DESCRIPTOR, None, 3)
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
            "verification_npub": npub_hex,
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
            "verification_npub": npub_hex,
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

// =====================================================================
// GET /api/v1/invoices/recoverable — signed stuck-swap detection.
// =====================================================================

/// Seed a merchant + checkout invoice + one chain swap, returning
/// (npub, keypair, invoice, swap_row). The swap starts `pending`.
async fn seed_merchant_invoice_swap(
    pool: &PgPool,
    nym: &str,
    boltz_swap_id: &str,
    lockup_address: &str,
    user_lock_amount_sat: i64,
    server_lock_amount_sat: i64,
) -> (
    String,
    Keypair,
    pay_service::db::Invoice,
    pay_service::db::ChainSwapRecord,
) {
    let (npub, _, _, keypair) = sign_registration_with_keypair(nym, TEST_DESCRIPTOR);
    pay_service::db::create_user(pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice = insert_test_invoice(pool, nym, &npub, &format!("lq1{nym}"), 3_600).await;
    let swap = pay_service::db::record_chain_swap(
        pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some(nym),
            boltz_swap_id,
            lockup_address,
            lockup_bip21: Some(&format!("bitcoin:{lockup_address}?amount=0.00001010")),
            user_lock_amount_sat,
            server_lock_amount_sat,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"seed\"}",
        },
    )
    .await
    .unwrap();
    (npub, keypair, invoice, swap)
}

// ---------------------------------------------------------------------
// #62/#88: deterministic write-ahead recovery boundary harness.
// ---------------------------------------------------------------------

const JOURNAL_LOCKUP_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const JOURNAL_DESTINATION_ADDRESS: &str =
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

struct FakeRecoveryBuilder {
    transaction: BtcLikeTransaction,
    calls: AtomicUsize,
}

#[async_trait]
impl pay_service::chain_recovery::BitcoinRecoveryBuilder for FakeRecoveryBuilder {
    async fn construct(
        &self,
        _swap: &pay_service::db::ChainSwapRecord,
        _destination_address: &str,
    ) -> Result<BtcLikeTransaction, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.transaction.clone())
    }
}

#[derive(Default)]
struct FakeBitcoinChain {
    transactions: Mutex<HashMap<String, Vec<u8>>>,
    outspends: Mutex<HashMap<(String, u32), pay_service::chain_recovery::BitcoinOutspend>>,
}

#[async_trait]
impl pay_service::chain_recovery::BitcoinRecoveryEvidence for FakeBitcoinChain {
    async fn raw_transaction(&self, txid: &str) -> Result<Option<Vec<u8>>, AppError> {
        Ok(self.transactions.lock().await.get(txid).cloned())
    }

    async fn outspend(
        &self,
        txid: &str,
        vout: u32,
    ) -> Result<pay_service::chain_recovery::BitcoinOutspend, AppError> {
        Ok(self
            .outspends
            .lock()
            .await
            .get(&(txid.to_string(), vout))
            .cloned()
            .unwrap_or(pay_service::chain_recovery::BitcoinOutspend::Unspent))
    }
}

#[derive(Clone, Copy)]
enum FakeBroadcastResult {
    Accept,
    AcceptResponseLost,
    BackendUnavailable,
    Reject,
    WrongTxid,
}

struct FakeRecoveryBroadcaster {
    chain: Arc<FakeBitcoinChain>,
    source: (String, u32),
    results: Mutex<VecDeque<FakeBroadcastResult>>,
    calls: Mutex<Vec<String>>,
}

impl FakeRecoveryBroadcaster {
    fn new(
        chain: Arc<FakeBitcoinChain>,
        source: (String, u32),
        results: impl IntoIterator<Item = FakeBroadcastResult>,
    ) -> Self {
        Self {
            chain,
            source,
            results: Mutex::new(results.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }

    async fn accepted(&self, raw_tx_hex: &str, expected_txid: &str) {
        self.chain.transactions.lock().await.insert(
            expected_txid.to_string(),
            hex::decode(raw_tx_hex).expect("fake broadcaster receives valid hex"),
        );
        self.chain.outspends.lock().await.insert(
            self.source.clone(),
            pay_service::chain_recovery::BitcoinOutspend::Spent {
                txid: expected_txid.to_string(),
            },
        );
    }
}

#[async_trait]
impl pay_service::chain_recovery::BitcoinRecoveryBroadcaster for FakeRecoveryBroadcaster {
    async fn broadcast(&self, raw_tx_hex: &str, expected_txid: &str) -> Result<String, AppError> {
        self.calls.lock().await.push(raw_tx_hex.to_string());
        let result = self
            .results
            .lock()
            .await
            .pop_front()
            .unwrap_or(FakeBroadcastResult::Accept);
        match result {
            FakeBroadcastResult::Accept => {
                self.accepted(raw_tx_hex, expected_txid).await;
                Ok(expected_txid.to_string())
            }
            FakeBroadcastResult::AcceptResponseLost => {
                self.accepted(raw_tx_hex, expected_txid).await;
                Err(AppError::ClaimError(
                    "scripted broadcaster accepted the transaction but lost the response".into(),
                ))
            }
            FakeBroadcastResult::BackendUnavailable => Err(AppError::ElectrumError(
                "scripted Bitcoin broadcast backend unavailable".into(),
            )),
            FakeBroadcastResult::Reject => Err(AppError::ClaimError(
                "scripted broadcaster rejected the transaction".into(),
            )),
            FakeBroadcastResult::WrongTxid => Ok("ab".repeat(32)),
        }
    }
}

struct OneShotRecoveryFault {
    point: pay_service::chain_recovery::RecoveryFaultPoint,
    fired: AtomicBool,
}

impl OneShotRecoveryFault {
    fn at(point: pay_service::chain_recovery::RecoveryFaultPoint) -> Self {
        Self {
            point,
            fired: AtomicBool::new(false),
        }
    }
}

impl pay_service::chain_recovery::RecoveryFaultInjector for OneShotRecoveryFault {
    fn check(
        &self,
        point: pay_service::chain_recovery::RecoveryFaultPoint,
    ) -> Result<(), AppError> {
        if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(AppError::ClaimError(format!(
                "scripted worker stop at {point:?}"
            )));
        }
        Ok(())
    }
}

struct RecoveryJournalHarness {
    swap: pay_service::db::ChainSwapRecord,
    builder: Arc<FakeRecoveryBuilder>,
    chain: Arc<FakeBitcoinChain>,
    broadcaster: Arc<FakeRecoveryBroadcaster>,
    source_txid: String,
    expected_txid: String,
    expected_raw_hex: String,
}

async fn seed_recovery_journal_harness(
    pool: &PgPool,
    suffix: &str,
    broadcast_results: impl IntoIterator<Item = FakeBroadcastResult>,
) -> RecoveryJournalHarness {
    let lockup_script = bitcoin::Address::from_str(JOURNAL_LOCKUP_ADDRESS)
        .unwrap()
        .require_network(bitcoin::Network::Bitcoin)
        .unwrap()
        .script_pubkey();
    let destination_script = bitcoin::Address::from_str(JOURNAL_DESTINATION_ADDRESS)
        .unwrap()
        .require_network(bitcoin::Network::Bitcoin)
        .unwrap()
        .script_pubkey();

    let source_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: lockup_script,
        }],
    };
    let source_txid = source_tx.compute_txid().to_string();
    let recovery_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: source_tx.compute_txid(),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(99_000),
            script_pubkey: destination_script,
        }],
    };
    let expected_txid = recovery_tx.compute_txid().to_string();
    let expected_raw_hex = hex::encode(bitcoin::consensus::serialize(&recovery_tx));

    let chain = Arc::new(FakeBitcoinChain::default());
    chain.transactions.lock().await.insert(
        source_txid.clone(),
        bitcoin::consensus::serialize(&source_tx),
    );
    let builder = Arc::new(FakeRecoveryBuilder {
        transaction: BtcLikeTransaction::Bitcoin(recovery_tx),
        calls: AtomicUsize::new(0),
    });
    let broadcaster = Arc::new(FakeRecoveryBroadcaster::new(
        chain.clone(),
        (source_txid.clone(), 0),
        broadcast_results,
    ));

    let nym = format!("jrnl{suffix}");
    let boltz_id = format!("journal-{suffix}");
    let (_, _, _, swap) = seed_merchant_invoice_swap(
        pool,
        &nym,
        &boltz_id,
        JOURNAL_LOCKUP_ADDRESS,
        100_000,
        99_000,
    )
    .await;
    pay_service::db::mark_chain_swap_refund_due(pool, swap.id)
        .await
        .unwrap();
    pay_service::db::set_chain_swap_refund_address(pool, swap.id, JOURNAL_DESTINATION_ADDRESS)
        .await
        .unwrap();
    let swap = pay_service::db::get_chain_swap_by_id(pool, swap.id)
        .await
        .unwrap()
        .unwrap();

    RecoveryJournalHarness {
        swap,
        builder,
        chain,
        broadcaster,
        source_txid,
        expected_txid,
        expected_raw_hex,
    }
}

#[tokio::test]
async fn closed_admission_still_completes_existing_chain_recovery() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    state.admission.set_workers_enabled(false);
    assert!(
        !state
            .admission
            .decision(pay_service::admission::Rail::BitcoinChain)
            .allowed(),
        "test precondition: new chain obligations must be closed"
    );
    let harness =
        seed_recovery_journal_harness(&state.db, "closed", [FakeBroadcastResult::Accept]).await;

    let txid = execute_journaled_recovery_with_services(
        &state.db,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .expect("closed admission must not block an existing recovery obligation");

    assert_eq!(txid, harness.expected_txid);
    assert_eq!(harness.builder.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.broadcaster.calls.lock().await.len(), 1);
    let final_swap = pay_service::db::get_chain_swap_by_id(&state.db, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_swap.status, "refunded");
    assert_eq!(
        final_swap.refund_txid.as_deref(),
        Some(harness.expected_txid.as_str())
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_journal_resumes_safely_at_every_irreversible_boundary() {
    use pay_service::chain_recovery::{
        execute_journaled_recovery_with_services, NoRecoveryFaults, RecoveryFaultPoint,
    };

    let pool = test_pool().await;
    let points = [
        RecoveryFaultPoint::BeforeConstruction,
        RecoveryFaultPoint::AfterConstructionBeforeJournal,
        RecoveryFaultPoint::AfterJournalWriteBeforeCommit,
        RecoveryFaultPoint::AfterJournalCommitBeforeBroadcast,
        RecoveryFaultPoint::AfterBroadcastAttemptCommit,
        RecoveryFaultPoint::AfterBroadcastCallBeforeOutcomeCommit,
    ];

    for (index, point) in points.into_iter().enumerate() {
        cleanup_db(&pool).await;
        let harness = seed_recovery_journal_harness(
            &pool,
            &format!("boundary{index}"),
            [FakeBroadcastResult::Accept],
        )
        .await;
        let fault = OneShotRecoveryFault::at(point);
        let first = execute_journaled_recovery_with_services(
            &pool,
            harness.swap.id,
            harness.builder.as_ref(),
            harness.chain.as_ref(),
            harness.broadcaster.as_ref(),
            &fault,
        )
        .await;
        assert!(first.is_err(), "fault {point:?} must stop the first worker");

        let committed = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap();
        let should_be_committed = matches!(
            point,
            RecoveryFaultPoint::AfterJournalCommitBeforeBroadcast
                | RecoveryFaultPoint::AfterBroadcastAttemptCommit
                | RecoveryFaultPoint::AfterBroadcastCallBeforeOutcomeCommit
        );
        assert_eq!(
            committed.is_some(),
            should_be_committed,
            "fault {point:?} left the wrong commit state"
        );
        assert_eq!(
            harness.broadcaster.calls.lock().await.len(),
            usize::from(point == RecoveryFaultPoint::AfterBroadcastCallBeforeOutcomeCommit),
            "fault {point:?} reached the broadcaster at the wrong boundary"
        );
        if let Some(attempt) = committed.as_ref() {
            assert_eq!(attempt.raw_tx_hex, harness.expected_raw_hex);
            assert_eq!(attempt.txid, harness.expected_txid);
        }

        let resumed = execute_journaled_recovery_with_services(
            &pool,
            harness.swap.id,
            harness.builder.as_ref(),
            harness.chain.as_ref(),
            harness.broadcaster.as_ref(),
            &NoRecoveryFaults,
        )
        .await
        .unwrap_or_else(|e| panic!("fault {point:?} did not resume: {e}"));
        assert_eq!(resumed, harness.expected_txid);

        let final_attempt = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(final_attempt.status, "broadcast");
        assert_eq!(final_attempt.raw_tx_hex, harness.expected_raw_hex);
        let final_swap = pay_service::db::get_chain_swap_by_id(&pool, harness.swap.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(final_swap.status, "refunded");
        assert_eq!(
            final_swap.refund_txid.as_deref(),
            Some(harness.expected_txid.as_str())
        );

        let calls = harness.broadcaster.calls.lock().await;
        assert!(calls.iter().all(|raw| raw == &harness.expected_raw_hex));
        assert_eq!(
            harness.builder.calls.load(Ordering::SeqCst),
            if matches!(
                point,
                RecoveryFaultPoint::AfterConstructionBeforeJournal
                    | RecoveryFaultPoint::AfterJournalWriteBeforeCommit
            ) {
                2
            } else {
                1
            },
            "fault {point:?} rebuilt at the wrong boundary"
        );
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_journal_reconciles_accepted_response_loss_without_rebroadcast() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness = seed_recovery_journal_harness(
        &pool,
        "responselost",
        [FakeBroadcastResult::AcceptResponseLost],
    )
    .await;

    let txid = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .unwrap();
    assert_eq!(txid, harness.expected_txid);
    assert_eq!(harness.broadcaster.calls.lock().await.len(), 1);

    // A complete retry is a read-only idempotent success.
    let retry = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .unwrap();
    assert_eq!(retry, harness.expected_txid);
    assert_eq!(harness.broadcaster.calls.lock().await.len(), 1);
    assert_eq!(harness.builder.calls.load(Ordering::SeqCst), 1);
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_journal_retries_identical_bytes_after_rejection() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness = seed_recovery_journal_harness(
        &pool,
        "samebytes",
        [FakeBroadcastResult::Reject, FakeBroadcastResult::Accept],
    )
    .await;

    assert!(execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .is_err());
    let ambiguous = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ambiguous.status, "broadcast_ambiguous");

    execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .unwrap();
    let calls = harness.broadcaster.calls.lock().await;
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], harness.expected_raw_hex);
    assert_eq!(calls[1], harness.expected_raw_hex);
    assert_eq!(harness.builder.calls.load(Ordering::SeqCst), 1);
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_journal_preserves_systemic_broadcast_failure_scope() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness = seed_recovery_journal_harness(
        &pool,
        "backenddown",
        [FakeBroadcastResult::BackendUnavailable],
    )
    .await;

    let result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await;

    assert!(matches!(result, Err(AppError::ElectrumError(_))));
    let attempt = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.status, "broadcast_ambiguous");
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_journal_rejects_a_phantom_success_txid() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "wrongtxid", [FakeBroadcastResult::WrongTxid]).await;

    let result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await;
    assert!(result.is_err());
    let attempt = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.status, "broadcast_ambiguous");
    let swap = pay_service::db::get_chain_swap_by_id(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.status, "refunding");
    assert!(swap.refund_txid.is_none());
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_journal_rejects_destination_drift_before_commit_or_broadcast() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "baddestination", [FakeBroadcastResult::Accept]).await;
    let BtcLikeTransaction::Bitcoin(mut transaction) = harness.builder.transaction.clone() else {
        unreachable!()
    };
    transaction.output[0].script_pubkey = bitcoin::Address::from_str(JOURNAL_LOCKUP_ADDRESS)
        .unwrap()
        .require_network(bitcoin::Network::Bitcoin)
        .unwrap()
        .script_pubkey();
    let bad_builder = FakeRecoveryBuilder {
        transaction: BtcLikeTransaction::Bitcoin(transaction),
        calls: AtomicUsize::new(0),
    };

    let result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        &bad_builder,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await;
    assert!(result.is_err());
    assert!(harness.broadcaster.calls.lock().await.is_empty());
    assert!(
        pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap()
            .is_none()
    );
    let swap = pay_service::db::get_chain_swap_by_id(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.status, "refund_due");
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_journal_unknown_outspend_enters_integrity_hold() {
    use pay_service::chain_recovery::{
        execute_journaled_recovery_with_services, NoRecoveryFaults, RecoveryFaultPoint,
    };

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "unknownspend", [FakeBroadcastResult::Accept]).await;
    let fault = OneShotRecoveryFault::at(RecoveryFaultPoint::AfterJournalCommitBeforeBroadcast);
    assert!(execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &fault,
    )
    .await
    .is_err());
    let unknown_txid = "ab".repeat(32);
    harness.chain.outspends.lock().await.insert(
        (harness.source_txid.clone(), 0),
        pay_service::chain_recovery::BitcoinOutspend::Spent {
            txid: unknown_txid.clone(),
        },
    );

    let result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(harness.broadcaster.calls.lock().await.len(), 0);
    let held = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.status, "integrity_hold");
    assert!(held.integrity_reason.unwrap().contains(&unknown_txid));
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn concurrent_recovery_workers_share_one_immutable_intent() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "singleflight", [FakeBroadcastResult::Accept]).await;

    let first = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    );
    let second = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    );
    let (a, b) = tokio::join!(first, second);
    assert!(
        a.is_ok() || b.is_ok(),
        "at least one worker must finish: {a:?} {b:?}"
    );

    // A worker that lost the advisory-lock race can retry idempotently.
    execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .unwrap();
    assert_eq!(harness.builder.calls.load(Ordering::SeqCst), 1);
    let calls = harness.broadcaster.calls.lock().await;
    assert!(!calls.is_empty());
    assert!(calls.iter().all(|raw| raw == &harness.expected_raw_hex));
    drop(calls);

    let attempt = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    let mutation =
        sqlx::query("UPDATE chain_swap_tx_attempts SET destination_address = $2 WHERE id = $1")
            .bind(attempt.id)
            .bind(JOURNAL_LOCKUP_ADDRESS)
            .execute(&pool)
            .await;
    assert!(
        mutation.is_err(),
        "database must reject destination mutation"
    );
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn legacy_refunding_without_journal_is_never_reconstructed() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "legacyhold", [FakeBroadcastResult::Accept]).await;
    pay_service::db::mark_chain_swap_refunding(&pool, harness.swap.id)
        .await
        .unwrap();

    let result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(harness.builder.calls.load(Ordering::SeqCst), 0);
    assert!(harness.broadcaster.calls.lock().await.is_empty());
    assert!(
        pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap()
            .is_none()
    );
    let swap = pay_service::db::get_chain_swap_by_id(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.status, "refunding");
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recoverable_list_shows_refund_due_swap() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (npub, keypair, invoice, swap) = seed_merchant_invoice_swap(
        &pool,
        "recdue",
        "recdue-1",
        "bc1qrecduelockup",
        1_010,
        1_000,
    )
    .await;
    pay_service::db::mark_chain_swap_refund_due(&pool, swap.id)
        .await
        .unwrap();

    let (sig, timestamp) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (status, body) = get_path(
        &app,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={timestamp}&signature={sig}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["recovery_enabled"], false, "flag defaults OFF");
    assert_eq!(body["count"], 1, "body: {body}");
    assert_eq!(body["has_more"], false);
    let item = &body["items"][0];
    assert_eq!(item["recovery_status"], "refund_due");
    assert_eq!(item["nym"], "recdue");
    assert_eq!(item["invoice_id"], invoice.id.to_string());
    assert_eq!(item["user_lock_amount_sat"], 1_010);
    assert_eq!(item["server_lock_amount_sat"], 1_000);
    assert_eq!(item["lockup_address"], "bc1qrecduelockup");
    assert!(item["refund_address"].is_null());
    assert!(item["refund_txid"].is_null());
    assert_eq!(item["invoice"]["amount_sat"], 1_000);
    assert_eq!(item["invoice"]["status"], "unpaid");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recoverable_list_is_npub_scoped() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (a_npub, a_keypair, _, a_swap) =
        seed_merchant_invoice_swap(&pool, "recscopea", "recscopea-1", "bc1qreca", 1_010, 1_000)
            .await;
    pay_service::db::mark_chain_swap_refund_due(&pool, a_swap.id)
        .await
        .unwrap();
    let (b_npub, b_keypair, _, _) =
        seed_merchant_invoice_swap(&pool, "recscopeb", "recscopeb-1", "bc1qrecb", 1_010, 1_000)
            .await;

    // B sees none of A's stuck funds.
    let (sig, timestamp) = sign_invoice_recovery_list_with_keypair(&b_keypair, &b_npub);
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices/recoverable?npub={b_npub}&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["count"], 0, "npub-scoped: B must not see A's swap");

    // Signing A's npub with B's key is a forgery → 401.
    let (forged_sig, forged_ts) = sign_invoice_recovery_list_with_keypair(&b_keypair, &a_npub);
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices/recoverable?npub={a_npub}&timestamp={forged_ts}&signature={forged_sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "AuthError");
    let _ = a_keypair;

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recoverable_list_returns_committed_address_and_txid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (npub, keypair, _, swap) =
        seed_merchant_invoice_swap(&pool, "recrecon", "recrecon-1", "bc1qrecon", 1_010, 1_000)
            .await;
    let committed = "bc1qcommittedrefunddestination00000000000";
    pay_service::db::mark_chain_swap_refund_due(&pool, swap.id)
        .await
        .unwrap();
    pay_service::db::set_chain_swap_refund_address(&pool, swap.id, committed)
        .await
        .unwrap();

    // refund_due, address committed, no txid yet.
    let (sig, ts) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (_, body) = get_path(
        &app,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature={sig}"),
    )
    .await;
    assert_eq!(body["items"][0]["recovery_status"], "refund_due");
    assert_eq!(body["items"][0]["refund_address"], committed);
    assert!(body["items"][0]["refund_txid"].is_null());

    // refunding: address present, still no txid.
    pay_service::db::mark_chain_swap_refunding(&pool, swap.id)
        .await
        .unwrap();
    let (sig, ts) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (_, body) = get_path(
        &app,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature={sig}"),
    )
    .await;
    assert_eq!(body["items"][0]["recovery_status"], "refunding");
    assert_eq!(body["items"][0]["refund_address"], committed);
    assert!(body["items"][0]["refund_txid"].is_null());

    // refunded: terminal, txid present (the reinstall reconciliation payload).
    let txid = "aa".repeat(32);
    pay_service::db::mark_chain_swap_refunded(&pool, swap.id, &txid)
        .await
        .unwrap();
    let (sig, ts) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (_, body) = get_path(
        &app,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature={sig}"),
    )
    .await;
    assert_eq!(body["items"][0]["recovery_status"], "refunded");
    assert_eq!(body["items"][0]["refund_address"], committed);
    assert_eq!(body["items"][0]["refund_txid"], txid);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recoverable_list_orders_and_uses_effective_amount() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    // A refunded swap (created first) + a refund_due swap with a renegotiated
    // server-lock amount. refund_due must sort ahead of refunded, and the
    // renegotiated amount must win.
    let (npub, keypair, _, done_swap) =
        seed_merchant_invoice_swap(&pool, "recorder", "recorder-done", "bc1qdone", 1_010, 1_000)
            .await;
    pay_service::db::mark_chain_swap_refund_due(&pool, done_swap.id)
        .await
        .unwrap();
    pay_service::db::set_chain_swap_refund_address(
        &pool,
        done_swap.id,
        "bc1qdonedest0000000000000000000000000",
    )
    .await
    .unwrap();
    pay_service::db::mark_chain_swap_refunding(&pool, done_swap.id)
        .await
        .unwrap();
    pay_service::db::mark_chain_swap_refunded(&pool, done_swap.id, &"bb".repeat(32))
        .await
        .unwrap();

    let invoice2 = insert_test_invoice(&pool, "recorder", &npub, "lq1recorder2", 3_600).await;
    let due_swap = pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice2.id,
            nym: Some("recorder"),
            boltz_swap_id: "recorder-due",
            lockup_address: "bc1qduelock",
            lockup_bip21: None,
            user_lock_amount_sat: 2_020,
            server_lock_amount_sat: 2_000,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"recorder-due\"}",
        },
    )
    .await
    .unwrap();
    // Phase-3 renegotiation: the merchant-credit amount changed to 1900.
    sqlx::query(
        "UPDATE chain_swap_records SET renegotiated_server_lock_amount_sat = 1900 WHERE id = $1",
    )
    .bind(due_swap.id)
    .execute(&pool)
    .await
    .unwrap();
    pay_service::db::mark_chain_swap_refund_due(&pool, due_swap.id)
        .await
        .unwrap();

    let (sig, ts) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (status, body) = get_path(
        &app,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature={sig}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["count"], 2, "body: {body}");
    assert_eq!(
        body["items"][0]["recovery_status"], "refund_due",
        "refund_due sorts first"
    );
    assert_eq!(
        body["items"][0]["server_lock_amount_sat"], 1_900,
        "renegotiated (effective) amount must win over the stale original"
    );
    assert_eq!(body["items"][1]["recovery_status"], "refunded");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn public_status_never_leaks_recovery_state() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (_, _, invoice, swap) =
        seed_merchant_invoice_swap(&pool, "recleak", "recleak-1", "bc1qleaklock", 1_010, 1_000)
            .await;
    let canary = "bc1qLEAKCANARYrefunddestination0000000000";

    let public = [
        "refund_due",
        "refunding",
        "refunded",
        "refund_address",
        "refund_txid",
        canary,
    ];
    let allowed_settlement = [
        "none",
        "pending",
        "settled",
        "claim_stuck",
        "refunded",
        "failed",
    ];

    // Drive: refund_due (+committed address) → refunding → refunded, asserting
    // the anonymous status endpoint leaks none of it at each stage.
    pay_service::db::mark_chain_swap_refund_due(&pool, swap.id)
        .await
        .unwrap();
    pay_service::db::set_chain_swap_refund_address(&pool, swap.id, canary)
        .await
        .unwrap();

    for stage in ["refund_due", "refunding", "refunded"] {
        if stage == "refunding" {
            pay_service::db::mark_chain_swap_refunding(&pool, swap.id)
                .await
                .unwrap();
        }
        if stage == "refunded" {
            pay_service::db::mark_chain_swap_refunded(&pool, swap.id, &"cc".repeat(32))
                .await
                .unwrap();
        }

        let (status, body) =
            get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
        assert_eq!(status, StatusCode::OK, "stage {stage}: body {body}");
        let raw = body.to_string();
        for needle in public {
            assert!(
                !raw.contains(needle),
                "stage {stage}: public status leaked '{needle}' — body: {raw}"
            );
        }
        assert!(
            body["bitcoin_chain_address"].is_null(),
            "stage {stage}: a recovering swap is not a payable offer"
        );
        assert!(body["bitcoin_chain_bip21"].is_null(), "stage {stage}");
        let ss = body["settlement_status"].as_str().unwrap_or("");
        assert!(
            allowed_settlement.contains(&ss),
            "stage {stage}: settlement_status '{ss}' outside the public enum"
        );
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recoverable_list_auth_negative() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let (npub, keypair, _, swap) =
        seed_merchant_invoice_swap(&pool, "recauth", "recauth-1", "bc1qauthlock", 1_010, 1_000)
            .await;
    pay_service::db::mark_chain_swap_refund_due(&pool, swap.id)
        .await
        .unwrap();

    // Garbage signature.
    let ts = auth_timestamp();
    let (status, _) = get_path(
        &app,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature=deadbeef"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "garbage signature");

    // Stale timestamp (well outside the freshness window).
    let stale_ts = auth_timestamp() - 3_600;
    let stale_sig =
        sign_la_action_with_timestamp(&keypair, "invoice-recovery-list", &npub, "", &[], stale_ts);
    let (status, _) = get_path(
        &app,
        &format!(
            "/api/v1/invoices/recoverable?npub={npub}&timestamp={stale_ts}&signature={stale_sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "stale timestamp");

    // Tampered payload: signature covers a non-empty field the server does not
    // expect (it verifies over zero fields) → mismatch → 401.
    let (tampered_sig, tampered_ts) =
        sign_la_action(&keypair, "invoice-recovery-list", &npub, "", &["injected"]);
    let (status, _) = get_path(
        &app,
        &format!(
            "/api/v1/invoices/recoverable?npub={npub}&timestamp={tampered_ts}&signature={tampered_sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "tampered payload fields");

    // Unsigned / missing query params → 4xx (deserialization rejects).
    let (status, _) = get_path(&app, "/api/v1/invoices/recoverable").await;
    assert!(
        status.is_client_error(),
        "unsigned request must be rejected"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recoverable_list_reports_recovery_enabled_flag() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (npub, keypair, _, swap) =
        seed_merchant_invoice_swap(&pool, "recflag", "recflag-1", "bc1qflaglock", 1_010, 1_000)
            .await;
    pay_service::db::mark_chain_swap_refund_due(&pool, swap.id)
        .await
        .unwrap();

    // Flag OFF (default): items still returned, recovery_enabled false.
    let app_off = test_app(test_state(pool.clone()));
    let (sig, ts) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (status, body) = get_path(
        &app_off,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature={sig}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["recovery_enabled"], false);
    assert_eq!(
        body["count"], 1,
        "detection is always-on regardless of the flag"
    );

    // Flag ON: recovery_enabled true.
    let mut config = test_config();
    config.features.chain_swap_merchant_recovery = true;
    let app_on = test_app(test_state_with_config(pool.clone(), config));
    let (sig, ts) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (status, body) = get_path(
        &app_on,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature={sig}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["recovery_enabled"], true);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recoverable_list_skips_nymless_swap() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    // Good swap (has nym) + a legacy NULL-nym swap on a second invoice of the
    // same merchant. The NULL-nym row is unusable (no recover URL) and must be
    // silently skipped while the good one is still returned.
    let (npub, keypair, _, good_swap) = seed_merchant_invoice_swap(
        &pool,
        "recnymless",
        "recnymless-good",
        "bc1qgood",
        1_010,
        1_000,
    )
    .await;
    pay_service::db::mark_chain_swap_refund_due(&pool, good_swap.id)
        .await
        .unwrap();

    let invoice2 = insert_test_invoice(&pool, "recnymless", &npub, "lq1recnymless2", 3_600).await;
    let bad_swap = pay_service::db::record_chain_swap(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice2.id,
            nym: Some("recnymless"),
            boltz_swap_id: "recnymless-bad",
            lockup_address: "bc1qbad",
            lockup_bip21: None,
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"recnymless-bad\"}",
        },
    )
    .await
    .unwrap();
    pay_service::db::mark_chain_swap_refund_due(&pool, bad_swap.id)
        .await
        .unwrap();
    sqlx::query("UPDATE chain_swap_records SET nym = NULL WHERE id = $1")
        .bind(bad_swap.id)
        .execute(&pool)
        .await
        .unwrap();

    let (sig, ts) = sign_invoice_recovery_list_with_keypair(&keypair, &npub);
    let (status, body) = get_path(
        &app,
        &format!("/api/v1/invoices/recoverable?npub={npub}&timestamp={ts}&signature={sig}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["count"], 1, "NULL-nym swap must be skipped: {body}");
    assert_eq!(body["items"][0]["nym"], "recnymless");
    assert_eq!(body["items"][0]["lockup_address"], "bc1qgood");

    cleanup_db(&pool).await;
}
