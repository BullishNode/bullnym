use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post, put};
use axum::Router;
use futures_util::stream::BoxStream;
use http_body_util::BodyExt;
use object_store::memory::InMemory;
use object_store::path::Path as ObjectStorePath;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use serde_json::{json, Value};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Barrier, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

use pay_service::boltz::BoltzService;
use pay_service::chain_swap_creation_permit::{
    ChainSwapCreationPermit, ChainSwapCreationPermitError,
};
use pay_service::config::{
    BitcoinWatcherConfig, BoltzConfig, CertificationConfig, ClaimConfig, Config, DonationConfig,
    ElectrumConfig, FeaturesConfig, FeePolicyConfig, InvoiceAccountingConfig, LimitsConfig,
    LiquidWatcherConfig, PricerConfig, ProofConfig, PwaConfig, RateLimitConfig, ReconcilerConfig,
    WorkersConfig,
};
use pay_service::donation_render::PwaShells;
use pay_service::error::AppError;
use pay_service::ip_whitelist::IpWhitelist;
use pay_service::pricer::PricerClient;
use pay_service::rate_limit::RateLimiter;
use pay_service::swap_manifest::EncryptedSwapManifestV1;
use pay_service::swap_manifest_delivery::{
    resume_pending_manifest_delivery, ManifestDeliveryCoordinatorError,
    ManifestDeliveryResumeOutcome,
};
use pay_service::swap_manifest_runtime::{self, RecoveryManifestRuntimeV1};
use pay_service::swap_manifest_store::{
    ManifestObjectId, ManifestWriteOutcome, RecoveryManifestStore, S3ManifestCredentials,
    S3ManifestStoreConfig,
};
use pay_service::{
    certification, claimer, donation_page, donation_render, invoice, lnurl, nostr, readiness,
    recovery_address_registration, registration, AppState,
};

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{hash160, Hash as BitcoinHash};
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
};
use bitcoin::script::Builder;
use bitcoin::ScriptBuf;
use boltz_client::network::{BitcoinChain, LiquidChain, Network};
use boltz_client::swaps::boltz::{
    ChainPair, ChainSwapDetails, CreateChainResponse, HeightResponse, Leaf, PairMinerFees,
    ReverseFees, ReverseLimits, ReversePair, Side, SwapTree, SwapType,
};
use boltz_client::swaps::BtcLikeTransaction;
use boltz_client::util::secrets::{Preimage, SwapMasterKey};
use boltz_client::{
    BtcSwapScript, LBtcSwapScript, PublicKey as BoltzPublicKey, ZKKeyPair, ZKSecp256k1,
};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

#[path = "support/chain_swap_transaction_insert.rs"]
mod chain_swap_transaction_insert;
#[path = "support/local_chain_swap_recovery_snapshot.rs"]
mod local_chain_swap_recovery_snapshot;

// --- Test infrastructure ---

#[derive(Clone, Default)]
struct CapturedLogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

struct CapturedLogSink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogWriter {
    type Writer = CapturedLogSink;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedLogSink(self.0.clone())
    }
}

impl CapturedLogWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

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

/// Exercise the complete deployment readiness contract as a non-owner role.
/// The disposable database has no pre-053 deployment grants, so this role
/// inherits the protected 053-055 grants from `bullnym_app` and receives only
/// the legacy privileges that production provisioning supplies separately.
async fn readiness_runtime_role_test_pool(admin: &PgPool) -> PgPool {
    sqlx::query(
        "DO $role$ BEGIN \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bullnym_readiness_test') THEN \
                 CREATE ROLE bullnym_readiness_test NOLOGIN; \
             END IF; \
         END $role$",
    )
    .execute(admin)
    .await
    .unwrap();
    sqlx::query("GRANT bullnym_app TO bullnym_readiness_test")
        .execute(admin)
        .await
        .unwrap();
    sqlx::query("GRANT SELECT ON ALL TABLES IN SCHEMA public TO bullnym_readiness_test")
        .execute(admin)
        .await
        .unwrap();
    sqlx::query(
        "GRANT INSERT, UPDATE ON TABLE \
             invoice_direct_scan_heads, watcher_lane_progress \
         TO bullnym_readiness_test",
    )
    .execute(admin)
    .await
    .unwrap();
    sqlx::query(
        "GRANT INSERT ON TABLE \
             invoice_direct_payment_transitions, swap_key_allocations \
         TO bullnym_readiness_test",
    )
    .execute(admin)
    .await
    .unwrap();

    PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET ROLE bullnym_readiness_test")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&require_test_db())
        .await
        .expect("failed to connect deployment-shaped readiness test pool")
}

async fn named_single_connection_test_pool(application_name: &str) -> PgPool {
    let options = PgConnectOptions::from_str(&require_test_db())
        .expect("invalid TEST_DATABASE_URL")
        .application_name(application_name);
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("failed to connect named test pool")
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

fn test_reverse_pair(minimum_sat: u64, maximum_sat: u64) -> ReversePair {
    ReversePair {
        hash: "11".repeat(32),
        rate: 1.0,
        limits: ReverseLimits {
            minimal: minimum_sat,
            maximal: maximum_sat,
        },
        fees: ReverseFees {
            percentage: 0.25,
            miner_fees: PairMinerFees {
                lockup: 27,
                claim: 20,
            },
        },
    }
}

fn test_config() -> Config {
    Config {
        domain: "test.example.com".to_string(),
        listen: "127.0.0.1:0".to_string(),
        pool_size: 2,
        boltz: BoltzConfig {
            api_url: "http://127.0.0.1:1".to_string(),
            electrum_url: "blockstream.info:995".to_string(),
            key_epoch: 1,
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
        fee_policy: FeePolicyConfig::default(),
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
    test_state_with_provider_limits(
        pool,
        config,
        Some((Some(test_reverse_pair(100, 25_000_000)), Instant::now())),
    )
}

/// Build a test state with an explicit provider-limit refresh result.
///
/// The outer `None` preserves the runtime's initial missing state. An inner
/// `None` records a successful response that omitted the exact reverse pair.
/// Ordinary integration fixtures use a fresh safe snapshot so M11 does not
/// accidentally close unrelated pre-existing Lightning tests.
fn test_state_with_provider_limits(
    pool: PgPool,
    config: Config,
    refresh: Option<(Option<ReversePair>, Instant)>,
) -> AppState {
    let swap_master_key = SwapMasterKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        Network::Mainnet,
    ).unwrap();

    let rate_limiter = Arc::new(RateLimiter::new(pool.clone(), RateLimitConfig::default()));
    let pricer = Arc::new(PricerClient::new(PricerConfig::default()).unwrap());
    let boltz_api_url = config.boltz.api_url.clone();
    let boltz = Arc::new(BoltzService::new(&boltz_api_url, swap_master_key, None));
    if let Some((pair, completed_at)) = refresh {
        let _ = boltz
            .provider_limits()
            .record_successful_refresh(pair, completed_at);
    }
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
    let fee_runtime = Arc::new(
        pay_service::fee_runtime::FeeRuntime::from_config(
            &config.fee_policy,
            Arc::new(pay_service::fee_runtime::UnavailableFeeRuntimePersistence),
        )
        .unwrap(),
    );

    AppState {
        db: pool,
        config: Arc::new(config),
        admission: pay_service::admission::MoneyAdmission::healthy_test_fixture(),
        boltz,
        ip_whitelist: Arc::new(IpWhitelist::default()),
        certification: Arc::new(certification::CertificationAllowlist::default()),
        rate_limiter,
        utxo_backend: None,
        liquid_claim_client_factory: Some(liquid_claim_client_factory),
        bitcoin_recovery_backend: Some(bitcoin_recovery_backend),
        bitcoin_lockup_witness_adapter: None,
        fee_runtime,
        pricer,
        pwa_shells: Arc::new(PwaShells::default()),
        recovery_manifest_runtime_v1: None,
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
        .route(
            "/api/v1/recovery-address",
            put(recovery_address_registration::register).layer(DefaultBodyLimit::max(
                recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_BODY_LIMIT_BYTES,
            )),
        )
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

// Recovery lifecycle status: npub-keyed, empty nym, ZERO payload fields.
fn sign_invoice_recovery_list_with_keypair(keypair: &Keypair, npub: &str) -> (String, u64) {
    sign_la_action(keypair, "invoice-recovery-list", npub, "", &[])
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
    // Migration-055 evidence rejects ordinary DELETE and has restrictive
    // parent FKs. The isolated database owner must truncate the complete
    // dependency family atomically before removing operational parent rows.
    sqlx::query(
        "TRUNCATE merchant_settlement_retained_outputs, \
                  merchant_settlement_checkpoints, \
                  invoice_payment_events RESTART IDENTITY CASCADE",
    )
    .execute(pool)
    .await
    .ok();
    // Manifest delivery rows reject ordinary DELETE. Isolated test ownership
    // uses DDL before removing their operational source rows.
    sqlx::query("TRUNCATE chain_swap_manifest_deliveries")
        .execute(pool)
        .await
        .ok();
    // Renegotiation rows reject ordinary DELETE and hold a RESTRICT FK to the
    // chain swap. Test-database ownership uses DDL solely for test isolation.
    sqlx::query("TRUNCATE chain_swap_renegotiation_operations")
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM watcher_lane_progress")
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM processed_webhook_events")
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM chain_swap_records")
        .execute(pool)
        .await
        .ok();
    // Recovery-address commitments reject ordinary DELETE and are referenced
    // by post-053 chain rows. Test isolation removes those rows first, then
    // truncates the append-only policy ledger directly.
    sqlx::query("TRUNCATE recovery_address_commitments CASCADE")
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM swap_records")
        .execute(pool)
        .await
        .ok();
    // Allocation rows are deliberately immutable to normal UPDATE/DELETE;
    // test isolation uses DDL after every referencing swap row is gone.
    sqlx::query("TRUNCATE swap_key_allocations CASCADE")
        .execute(pool)
        .await
        .ok();
    sqlx::query("TRUNCATE swap_key_legacy_high_water")
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

/// Seed a row that deliberately models a database created before migration
/// 050. Production inserts must never use this path: migration 050 rejects
/// every new swap without allocation lineage. `session_replication_role` is
/// transaction-local and available only to the isolated test database owner.
async fn record_pre_050_reverse_fixture(
    pool: &PgPool,
    swap: &pay_service::db::NewSwapRecord<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await?;
    pay_service::db::record_swap_in_tx(&mut tx, swap).await?;
    tx.commit().await
}

async fn record_pre_050_chain_fixture(
    pool: &PgPool,
    swap: &pay_service::db::NewChainSwapRecord<'_>,
) -> Result<pay_service::db::ChainSwapRecord, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await?;
    let row = pay_service::db::record_chain_swap_in_tx(&mut tx, swap).await?;
    tx.commit().await?;
    Ok(row)
}

/// Complete database-valid creation evidence for tests whose assertions target
/// an invariant other than provider-response validation.
fn valid_chain_swap_creation_terms_fixture() -> pay_service::db::NewChainSwapCreationTerms<'static>
{
    pay_service::db::NewChainSwapCreationTerms {
        pinned_pair_hash: "1111111111111111111111111111111111111111111111111111111111111111",
        canonical_pair_quote_json: r#"{"hash":"fixture","rate":1}"#,
        creation_response_sha256:
            "2222222222222222222222222222222222222222222222222222222222222222",
        btc_claim_script_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
        btc_refund_script_sha256:
            "4444444444444444444444444444444444444444444444444444444444444444",
        liquid_claim_script_sha256:
            "5555555555555555555555555555555555555555555555555555555555555555",
        liquid_refund_script_sha256:
            "6666666666666666666666666666666666666666666666666666666666666666",
        btc_timeout_height: 958_033,
        liquid_timeout_height: 3_972_215,
        btc_network: "bitcoin",
        liquid_network: "liquid",
        liquid_asset_id: "6f0279e9ed041c3d710a9f57d0c02928416413f827c37bf6833e2407092ff84d",
        merchant_liquid_destination: "lq1qqintegrationfixturemerchantdestination",
        merchant_emergency_btc_address: None,
    }
}

async fn insert_test_recovery_commitment(
    pool: &PgPool,
    npub: &str,
    address: &str,
    commitment_version: i64,
    signature_byte: u8,
) -> uuid::Uuid {
    let commitment_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO recovery_address_commitments (\
             commitment_id, npub, contract_format_version, commitment_version, \
             canonical_btc_address, original_signature, signed_at_unix\
         ) VALUES ($1, $2, 1, $3, $4, $5, $6)",
    )
    .bind(commitment_id)
    .bind(npub)
    .bind(commitment_version)
    .bind(address)
    .bind(format!("{signature_byte:02x}").repeat(64))
    .bind(1_700_100_000_i64 + commitment_version)
    .execute(pool)
    .await
    .unwrap();
    commitment_id
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

async fn get_text_path(app: &Router, uri: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
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

#[derive(Debug, PartialEq, Eq)]
struct M11CreationMutationSnapshot {
    next_key_index: i64,
    key_allocations: i64,
    reverse_swaps: i64,
    chain_swaps: i64,
}

async fn m11_creation_mutation_snapshot(pool: &PgPool) -> M11CreationMutationSnapshot {
    M11CreationMutationSnapshot {
        next_key_index: pay_service::db::swap_key_seq_next_value(pool)
            .await
            .unwrap(),
        key_allocations: sqlx::query_scalar("SELECT COUNT(*) FROM swap_key_allocations")
            .fetch_one(pool)
            .await
            .unwrap(),
        reverse_swaps: sqlx::query_scalar("SELECT COUNT(*) FROM swap_records")
            .fetch_one(pool)
            .await
            .unwrap(),
        chain_swaps: sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
            .fetch_one(pool)
            .await
            .unwrap(),
    }
}

fn test_recovery_manifest_runtime() -> Arc<RecoveryManifestRuntimeV1> {
    let signing_secret = [0x31; 32];
    let signing_key = Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&signing_secret).unwrap(),
    );
    let values = HashMap::from([
        (
            swap_manifest_runtime::S3_ENDPOINT_ENV,
            "http://127.0.0.1:1".to_owned(),
        ),
        (swap_manifest_runtime::S3_REGION_ENV, "us-east-1".to_owned()),
        (
            swap_manifest_runtime::S3_BUCKET_ENV,
            "bullnym-recovery-test".to_owned(),
        ),
        (
            swap_manifest_runtime::S3_PREFIX_ENV,
            "bullnym/tests".to_owned(),
        ),
        (swap_manifest_runtime::S3_PATH_STYLE_ENV, "true".to_owned()),
        (swap_manifest_runtime::S3_ALLOW_HTTP_ENV, "true".to_owned()),
        (
            swap_manifest_runtime::S3_ACCESS_KEY_ID_ENV,
            "ACCESSKEYTEST".to_owned(),
        ),
        (
            swap_manifest_runtime::S3_SECRET_ACCESS_KEY_ENV,
            "secret-access-key-test".to_owned(),
        ),
        (
            swap_manifest_runtime::ENCRYPTION_KEY_ID_ENV,
            "manifest-key-route-test".to_owned(),
        ),
        (
            swap_manifest_runtime::ENCRYPTION_KEY_HEX_ENV,
            hex::encode([0x42; 32]),
        ),
        (
            swap_manifest_runtime::SIGNING_SECRET_KEY_HEX_ENV,
            hex::encode(signing_secret),
        ),
        (
            swap_manifest_runtime::EXPECTED_SIGNER_XONLY_HEX_ENV,
            signing_key.x_only_public_key().0.to_string(),
        ),
    ]);
    Arc::new(
        RecoveryManifestRuntimeV1::from_lookup(|name| values.get(name).cloned())
            .expect("valid route-test recovery runtime"),
    )
}

fn in_memory_recovery_manifest_runtime() -> Arc<RecoveryManifestRuntimeV1> {
    Arc::new(RecoveryManifestRuntimeV1::from_store_for_integration_tests(
        coordinator_manifest_store(InstrumentedManifestObjectStore::new()),
    ))
}

async fn seed_chain_offer_checkout_surface(pool: &PgPool, nym: &str) {
    let npub = create_test_user(pool, nym).await;
    insert_test_recovery_commitment(pool, &npub, RECOVERY_COMMITMENT_P2WPKH, 1, 0x84).await;
    pay_service::db::upsert_donation_page(
        pool,
        &pay_service::db::UpsertDonationPage {
            nym,
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Recovery-gated checkout",
            description: "Chain creation must remain behind recovery readiness",
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
    let mut response = state.response.clone();
    response["onchainAmount"] = request.get("onchainAmount").cloned().unwrap_or(Value::Null);
    state.requests.lock().await.push(request);
    state.request_barrier.wait().await;
    state.release_barrier.wait().await;
    axum::Json(response)
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
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let runtime = readiness_runtime_role_test_pool(&admin).await;

    sqlx::query(
        "ALTER TABLE swap_key_allocations RENAME CONSTRAINT \
         swap_key_allocations_derivation_identity_key \
         TO swap_key_allocations_derivation_identity_key_before_readiness_test",
    )
    .execute(&admin)
    .await
    .unwrap();

    let app = test_app(test_state(runtime.clone()));
    let (pre_migration_status, pre_migration_body) = get_path(&app, "/ready").await;

    sqlx::query(
        "ALTER TABLE swap_key_allocations RENAME CONSTRAINT \
         swap_key_allocations_derivation_identity_key_before_readiness_test \
         TO swap_key_allocations_derivation_identity_key",
    )
    .execute(&admin)
    .await
    .unwrap();

    assert_eq!(pre_migration_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pre_migration_body["ready"], false);
    assert_eq!(
        pre_migration_body["expected_schema_marker"],
        "056_chain_swap_renegotiation_journal"
    );

    let app = test_app(test_state(runtime.clone()));
    let (current_status, current_body) = get_path(&app, "/ready").await;
    assert_eq!(current_status, StatusCode::OK, "body: {current_body}");
    assert_eq!(current_body["ready"], true);

    // A nonredundant immutability member is part of the marker too: retaining
    // the tables and unique constraints is not enough if an allocation can be
    // deleted and its single-use identity freed.
    sqlx::query(
        "ALTER TABLE swap_key_allocations DISABLE TRIGGER swap_key_allocations_reject_delete",
    )
    .execute(&admin)
    .await
    .unwrap();
    let app = test_app(test_state(runtime.clone()));
    let (missing_delete_guard_status, missing_delete_guard_body) = get_path(&app, "/ready").await;
    sqlx::query(
        "ALTER TABLE swap_key_allocations ENABLE TRIGGER swap_key_allocations_reject_delete",
    )
    .execute(&admin)
    .await
    .unwrap();
    assert_eq!(missing_delete_guard_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(missing_delete_guard_body["ready"], false);

    let app = test_app(test_state(runtime.clone()));
    let (restored_status, restored_body) = get_path(&app, "/ready").await;
    assert_eq!(restored_status, StatusCode::OK, "body: {restored_body}");
    assert_eq!(restored_body["ready"], true);

    // Migration 051 is incomplete if its all-or-none creation-evidence shape
    // constraint is missing, even when every column happens to be present.
    sqlx::query(
        "ALTER TABLE chain_swap_records RENAME CONSTRAINT \
         chain_swap_records_creation_terms_shape_check \
         TO chain_swap_records_creation_terms_shape_check_before_readiness_test",
    )
    .execute(&admin)
    .await
    .unwrap();
    let app = test_app(test_state(runtime.clone()));
    let (missing_shape_guard_status, missing_shape_guard_body) = get_path(&app, "/ready").await;
    sqlx::query(
        "ALTER TABLE chain_swap_records RENAME CONSTRAINT \
         chain_swap_records_creation_terms_shape_check_before_readiness_test \
         TO chain_swap_records_creation_terms_shape_check",
    )
    .execute(&admin)
    .await
    .unwrap();
    assert_eq!(missing_shape_guard_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(missing_shape_guard_body["ready"], false);

    let app = test_app(test_state(runtime.clone()));
    let (restored_status, restored_body) = get_path(&app, "/ready").await;
    assert_eq!(restored_status, StatusCode::OK, "body: {restored_body}");
    assert_eq!(restored_body["ready"], true);

    // The immutable creation packet is also part of the deployed schema
    // boundary: disabling its update guard must remove the service from ready.
    sqlx::query(
        "ALTER TABLE chain_swap_records DISABLE TRIGGER \
         chain_swap_records_reject_creation_terms_update",
    )
    .execute(&admin)
    .await
    .unwrap();
    let app = test_app(test_state(runtime.clone()));
    let (mutable_terms_status, mutable_terms_body) = get_path(&app, "/ready").await;
    sqlx::query(
        "ALTER TABLE chain_swap_records ENABLE TRIGGER \
         chain_swap_records_reject_creation_terms_update",
    )
    .execute(&admin)
    .await
    .unwrap();
    assert_eq!(mutable_terms_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(mutable_terms_body["ready"], false);

    let app = test_app(test_state(runtime));
    let (restored_status, restored_body) = get_path(&app, "/ready").await;
    assert_eq!(restored_status, StatusCode::OK, "body: {restored_body}");
    assert_eq!(restored_body["ready"], true);
}

#[tokio::test]
async fn merchant_settlement_fee_schema_readiness_rejects_constraint_drift() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let runtime = readiness_runtime_role_test_pool(&admin).await;

    assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());

    let (shape_definition, shape_expression, value_definition, value_expression) =
        sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT \
            (SELECT pg_get_constraintdef(constraint_info.oid, TRUE) \
               FROM pg_constraint constraint_info \
               JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
              WHERE namespace.nspname = 'public' \
                AND relation.relname = 'chain_swap_tx_attempts' \
                AND constraint_info.conname = \
                    'chain_swap_tx_attempts_fee_authority_shape_check'), \
            (SELECT pg_get_expr( \
                        constraint_info.conbin, constraint_info.conrelid, TRUE \
                    ) \
               FROM pg_constraint constraint_info \
               JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
              WHERE namespace.nspname = 'public' \
                AND relation.relname = 'chain_swap_tx_attempts' \
                AND constraint_info.conname = \
                    'chain_swap_tx_attempts_fee_authority_shape_check'), \
            (SELECT pg_get_constraintdef(constraint_info.oid, TRUE) \
               FROM pg_constraint constraint_info \
               JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
              WHERE namespace.nspname = 'public' \
                AND relation.relname = 'chain_swap_tx_attempts' \
                AND constraint_info.conname = \
                    'chain_swap_tx_attempts_fee_authority_value_check'), \
            (SELECT pg_get_expr( \
                        constraint_info.conbin, constraint_info.conrelid, TRUE \
                    ) \
               FROM pg_constraint constraint_info \
               JOIN pg_class relation ON relation.oid = constraint_info.conrelid \
               JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
              WHERE namespace.nspname = 'public' \
                AND relation.relname = 'chain_swap_tx_attempts' \
                AND constraint_info.conname = \
                    'chain_swap_tx_attempts_fee_authority_value_check')",
        )
        .fetch_one(&admin)
        .await
        .unwrap();

    for (constraint_name, temporary_name) in [
        (
            "chain_swap_tx_attempts_fee_authority_shape_check",
            "chain_swap_tx_attempts_fee_authority_shape_check_before_readiness_test",
        ),
        (
            "chain_swap_tx_attempts_fee_authority_value_check",
            "chain_swap_tx_attempts_fee_authority_value_check_before_readiness_test",
        ),
    ] {
        sqlx::query(&format!(
            "ALTER TABLE chain_swap_tx_attempts RENAME CONSTRAINT \
             {constraint_name} TO {temporary_name}"
        ))
        .execute(&admin)
        .await
        .unwrap();
        let renamed = readiness::schema_and_journal_ready(&runtime).await;
        sqlx::query(&format!(
            "ALTER TABLE chain_swap_tx_attempts RENAME CONSTRAINT \
             {temporary_name} TO {constraint_name}"
        ))
        .execute(&admin)
        .await
        .unwrap();

        assert!(!renamed.unwrap(), "renamed {constraint_name} stayed ready");
        assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());
    }

    sqlx::query(
        "ALTER TABLE chain_swap_tx_attempts DROP CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_shape_check",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(&format!(
        "ALTER TABLE chain_swap_tx_attempts ADD CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_shape_check CHECK ( \
             ({shape_expression}) OR fee_decision_purpose IS NOT NULL \
         )"
    ))
    .execute(&admin)
    .await
    .unwrap();
    let weakened_shape = readiness::schema_and_journal_ready(&runtime).await;
    sqlx::query(
        "ALTER TABLE chain_swap_tx_attempts DROP CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_shape_check",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(&format!(
        "ALTER TABLE chain_swap_tx_attempts ADD CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_shape_check {shape_definition}"
    ))
    .execute(&admin)
    .await
    .unwrap();

    assert!(
        !weakened_shape.unwrap(),
        "weakened shape constraint stayed ready"
    );
    assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());

    sqlx::query(
        "ALTER TABLE chain_swap_tx_attempts DROP CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_value_check",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(&format!(
        "ALTER TABLE chain_swap_tx_attempts ADD CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_value_check CHECK ( \
             ({value_expression}) OR fee_decision_purpose IS NOT NULL \
         )"
    ))
    .execute(&admin)
    .await
    .unwrap();
    let weakened_value = readiness::schema_and_journal_ready(&runtime).await;
    sqlx::query(
        "ALTER TABLE chain_swap_tx_attempts DROP CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_value_check",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(&format!(
        "ALTER TABLE chain_swap_tx_attempts ADD CONSTRAINT \
         chain_swap_tx_attempts_fee_authority_value_check {value_definition}"
    ))
    .execute(&admin)
    .await
    .unwrap();

    assert!(
        !weakened_value.unwrap(),
        "weakened value constraint stayed ready"
    );
    assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());
}

#[tokio::test]
async fn merchant_settlement_readiness_rejects_trigger_function_drift() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let runtime = readiness_runtime_role_test_pool(&admin).await;

    assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());

    let canonical_function_definition: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef( \
             'public.reject_merchant_settlement_delete()'::REGPROCEDURE \
         )",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.reject_merchant_settlement_delete() \
         RETURNS TRIGGER LANGUAGE plpgsql AS $drift$ \
         BEGIN \
             RETURN OLD; \
         END \
         $drift$",
    )
    .execute(&admin)
    .await
    .unwrap();
    let body_drift = readiness::schema_and_journal_ready(&runtime).await;
    sqlx::query(&canonical_function_definition)
        .execute(&admin)
        .await
        .unwrap();
    assert!(
        !body_drift.unwrap(),
        "weakened delete function stayed ready"
    );
    assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());

    sqlx::query("ALTER FUNCTION public.reject_merchant_settlement_delete() SECURITY DEFINER")
        .execute(&admin)
        .await
        .unwrap();
    let security_drift = readiness::schema_and_journal_ready(&runtime).await;
    sqlx::query("ALTER FUNCTION public.reject_merchant_settlement_delete() SECURITY INVOKER")
        .execute(&admin)
        .await
        .unwrap();
    assert!(
        !security_drift.unwrap(),
        "security-definer trigger function stayed ready"
    );
    assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());

    let canonical_trigger_definition: String = sqlx::query_scalar(
        "SELECT pg_get_triggerdef(trigger_info.oid, TRUE) \
           FROM pg_trigger trigger_info \
           JOIN pg_class relation ON relation.oid = trigger_info.tgrelid \
           JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
          WHERE namespace.nspname = 'public' \
            AND relation.relname = 'merchant_settlement_checkpoints' \
            AND trigger_info.tgname = 'merchant_settlement_checkpoint_reject_delete'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    sqlx::query(
        "DROP TRIGGER merchant_settlement_checkpoint_reject_delete \
         ON merchant_settlement_checkpoints",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER merchant_settlement_checkpoint_reject_delete \
         BEFORE DELETE ON merchant_settlement_checkpoints \
         FOR EACH ROW WHEN (FALSE) \
         EXECUTE FUNCTION reject_merchant_settlement_delete()",
    )
    .execute(&admin)
    .await
    .unwrap();
    let conditional_trigger = readiness::schema_and_journal_ready(&runtime).await;
    sqlx::query(
        "DROP TRIGGER merchant_settlement_checkpoint_reject_delete \
         ON merchant_settlement_checkpoints",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(&canonical_trigger_definition)
        .execute(&admin)
        .await
        .unwrap();
    assert!(
        !conditional_trigger.unwrap(),
        "conditional delete trigger stayed ready"
    );
    assert!(readiness::schema_and_journal_ready(&runtime).await.unwrap());

    let sequence_value: i64 = sqlx::query_scalar(
        "SELECT nextval('public.invoice_payment_events_accounting_sequence_seq')",
    )
    .fetch_one(&runtime)
    .await
    .expect("runtime role must be able to consume the accounting BIGSERIAL default");
    assert!(sequence_value > 0);
}

#[tokio::test]
async fn recovery_commitment_readiness_fails_closed_on_acl_fk_and_trigger_drift() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;

    sqlx::query(
        "DO $$ BEGIN \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bullnym_app') THEN \
                 CREATE ROLE bullnym_app NOLOGIN; \
             END IF; \
         END $$",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query("REVOKE ALL ON recovery_address_commitments FROM bullnym_app")
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("GRANT SELECT, INSERT ON recovery_address_commitments TO bullnym_app")
        .execute(&admin)
        .await
        .unwrap();

    let runtime = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET ROLE bullnym_app")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&require_test_db())
        .await
        .unwrap();

    assert!(readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap());

    sqlx::query(
        "ALTER TABLE chain_swap_records DROP CONSTRAINT \
         chain_swap_records_recovery_commitment_pair_check",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records \
         ADD CONSTRAINT chain_swap_records_recovery_commitment_pair_check CHECK ( \
             (recovery_address_commitment_id IS NULL) \
             OR (merchant_emergency_btc_address IS NULL) \
         )",
    )
    .execute(&admin)
    .await
    .unwrap();
    let wrong_pair_expression = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records DROP CONSTRAINT \
         chain_swap_records_recovery_commitment_pair_check",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records \
         ADD CONSTRAINT chain_swap_records_recovery_commitment_pair_check CHECK ( \
             (recovery_address_commitment_id IS NULL) \
             = (merchant_emergency_btc_address IS NULL) \
         )",
    )
    .execute(&admin)
    .await
    .unwrap();

    sqlx::query("GRANT UPDATE ON recovery_address_commitments TO bullnym_app")
        .execute(&admin)
        .await
        .unwrap();
    let update_acl_drift = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    sqlx::query("REVOKE UPDATE ON recovery_address_commitments FROM bullnym_app")
        .execute(&admin)
        .await
        .unwrap();

    sqlx::query("GRANT SELECT ON recovery_address_commitments TO PUBLIC")
        .execute(&admin)
        .await
        .unwrap();
    let public_acl_drift = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    sqlx::query("REVOKE SELECT ON recovery_address_commitments FROM PUBLIC")
        .execute(&admin)
        .await
        .unwrap();

    sqlx::query(
        "ALTER TABLE chain_swap_records DISABLE TRIGGER \
         chain_swap_records_reject_recovery_commitment_update",
    )
    .execute(&admin)
    .await
    .unwrap();
    let disabled_trigger = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records ENABLE TRIGGER \
         chain_swap_records_reject_recovery_commitment_update",
    )
    .execute(&admin)
    .await
    .unwrap();

    sqlx::query(
        "DROP TRIGGER chain_swap_records_reject_recovery_commitment_update \
         ON chain_swap_records",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER chain_swap_records_reject_recovery_commitment_update \
         BEFORE UPDATE OF status ON chain_swap_records \
         FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_recovery_commitment_mutation()",
    )
    .execute(&admin)
    .await
    .unwrap();
    let wrong_update_columns = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    sqlx::query(
        "DROP TRIGGER chain_swap_records_reject_recovery_commitment_update \
         ON chain_swap_records",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER chain_swap_records_reject_recovery_commitment_update \
         BEFORE UPDATE OF \
             recovery_address_commitment_id, merchant_emergency_btc_address \
         ON chain_swap_records \
         FOR EACH ROW EXECUTE FUNCTION reject_chain_swap_recovery_commitment_mutation()",
    )
    .execute(&admin)
    .await
    .unwrap();

    sqlx::query(
        "ALTER TABLE chain_swap_records RENAME CONSTRAINT \
         chain_swap_records_recovery_commitment_fkey \
         TO chain_swap_records_recovery_commitment_fkey_before_readiness_test",
    )
    .execute(&admin)
    .await
    .unwrap();
    let missing_foreign_key = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records RENAME CONSTRAINT \
         chain_swap_records_recovery_commitment_fkey_before_readiness_test \
         TO chain_swap_records_recovery_commitment_fkey",
    )
    .execute(&admin)
    .await
    .unwrap();

    sqlx::query(
        "ALTER TABLE chain_swap_records DROP CONSTRAINT \
         chain_swap_records_recovery_commitment_fkey",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records \
         ADD CONSTRAINT chain_swap_records_recovery_commitment_fkey \
         FOREIGN KEY (recovery_address_commitment_id, merchant_emergency_btc_address) \
         REFERENCES recovery_address_commitments (commitment_id, canonical_btc_address) \
         ON UPDATE RESTRICT ON DELETE CASCADE",
    )
    .execute(&admin)
    .await
    .unwrap();
    let wrong_foreign_key = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records DROP CONSTRAINT \
         chain_swap_records_recovery_commitment_fkey",
    )
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_records \
         ADD CONSTRAINT chain_swap_records_recovery_commitment_fkey \
         FOREIGN KEY (recovery_address_commitment_id, merchant_emergency_btc_address) \
         REFERENCES recovery_address_commitments (commitment_id, canonical_btc_address) \
         ON UPDATE RESTRICT ON DELETE RESTRICT",
    )
    .execute(&admin)
    .await
    .unwrap();

    let restored = readiness::recovery_commitment_ready(&runtime)
        .await
        .unwrap();
    runtime.close().await;

    assert!(!update_acl_drift, "runtime UPDATE must close admission");
    assert!(!public_acl_drift, "PUBLIC read ACL must close admission");
    assert!(
        !wrong_pair_expression,
        "a same-name wrong null-pair expression must close admission"
    );
    assert!(
        !disabled_trigger,
        "disabled immutability must close admission"
    );
    assert!(
        !wrong_update_columns,
        "an UPDATE trigger on unrelated columns must close admission"
    );
    assert!(
        !missing_foreign_key,
        "missing exact FK must close admission"
    );
    assert!(!wrong_foreign_key, "wrong FK actions must close admission");
    assert!(
        restored,
        "restored exact migration-053 contract must reopen"
    );
}

#[tokio::test]
async fn swap_key_registry_is_global_concurrent_and_immutable() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let single_use_indexes: (bool, bool, bool) = sqlx::query_as(
        "SELECT \
            (SELECT indisunique FROM pg_index \
              WHERE indexrelid = 'swap_records_key_allocation_id_key'::regclass), \
            (SELECT indisunique FROM pg_index \
              WHERE indexrelid = 'chain_swap_records_claim_key_allocation_id_key'::regclass), \
            (SELECT indisunique FROM pg_index \
              WHERE indexrelid = 'chain_swap_records_refund_key_allocation_id_key'::regclass)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(single_use_indexes, (true, true, true));

    let root = "1111111111111111";
    let first_public = format!("02{}", "11".repeat(32));
    let first_hash = "aa".repeat(32);
    let first_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_000,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &first_public,
            preimage_hash_hex: Some(&first_hash),
        },
    )
    .await
    .unwrap();

    let cross_purpose = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_000,
            purpose: pay_service::db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &format!("03{}", "22".repeat(32)),
            preimage_hash_hex: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        cross_purpose
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23505")
    );

    // Epoch is an operational generation label, not part of the key
    // derivation itself. Re-labeling the same root/index under another epoch
    // must still fail on the globally unique derived public key.
    let epoch_only_hash = "ac".repeat(32);
    let epoch_only_reuse = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_000,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &first_public,
            preimage_hash_hex: Some(&epoch_only_hash),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        epoch_only_reuse
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_key_allocations_public_key_key")
    );

    let concurrent_public = format!("02{}", "33".repeat(32));
    let concurrent_hash = "bb".repeat(32);
    let reserve = |pool: PgPool| {
        let concurrent_public = concurrent_public.clone();
        let concurrent_hash = concurrent_hash.clone();
        async move {
            pay_service::db::reserve_swap_key_allocation(
                &pool,
                &pay_service::db::NewSwapKeyAllocation {
                    root_fingerprint: root,
                    key_epoch: 1,
                    derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
                    child_index: 8_001,
                    purpose: pay_service::db::SwapKeyPurpose::ChainClaim,
                    public_key_hex: &concurrent_public,
                    preimage_hash_hex: Some(&concurrent_hash),
                },
            )
            .await
        }
    };
    let (left, right) = tokio::join!(reserve(pool.clone()), reserve(pool.clone()));
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let concurrent_error = left.err().or_else(|| right.err()).unwrap();
    assert_eq!(
        concurrent_error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23505")
    );

    let mutation = sqlx::query("UPDATE swap_key_allocations SET child_index = 9000 WHERE id = $1")
        .bind(first_id)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );

    let npub = "55".repeat(32);
    pay_service::db::create_user(&pool, "lineageimmutable", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let recovery_commitment_id =
        insert_test_recovery_commitment(&pool, &npub, RECOVERY_COMMITMENT_P2WPKH, 1, 0x71).await;
    let reverse_preimage = "66".repeat(32);
    let reverse_claim_key = "77".repeat(32);
    pay_service::db::record_swap_with_lineage(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("lineageimmutable"),
            boltz_swap_id: "LINEAGE_IMMUTABLE_REVERSE",
            address: None,
            address_index: None,
            amount_sat: 8_000,
            invoice: "lnbc-lineage-immutable",
            preimage_hex: &reverse_preimage,
            claim_key_hex: &reverse_claim_key,
            boltz_response_json: "{}",
            invoice_id: None,
            key_index: Some(8_000),
            root_fingerprint: Some(root),
        },
        &pay_service::db::ReverseSwapLineage {
            allocation_id: first_id,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &first_public,
            preimage_hash_hex: &first_hash,
        },
    )
    .await
    .unwrap();
    let reverse_reuse = pay_service::db::record_swap_with_lineage(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("lineageimmutable"),
            boltz_swap_id: "LINEAGE_REUSED_REVERSE_ALLOCATION",
            address: None,
            address_index: None,
            amount_sat: 8_000,
            invoice: "lnbc-lineage-reused",
            preimage_hex: &reverse_preimage,
            claim_key_hex: &reverse_claim_key,
            boltz_response_json: "{}",
            invoice_id: None,
            key_index: Some(8_000),
            root_fingerprint: Some(root),
        },
        &pay_service::db::ReverseSwapLineage {
            allocation_id: first_id,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &first_public,
            preimage_hash_hex: &first_hash,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        reverse_reuse
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_records_key_allocation_id_key") | Some("swap_records_fingerprint_key_index_key")
    ));
    sqlx::query("UPDATE swap_records SET status = 'lockup_mempool' WHERE boltz_swap_id = $1")
        .bind("LINEAGE_IMMUTABLE_REVERSE")
        .execute(&pool)
        .await
        .unwrap();
    let row_mutation =
        sqlx::query("UPDATE swap_records SET key_epoch = 2 WHERE boltz_swap_id = $1")
            .bind("LINEAGE_IMMUTABLE_REVERSE")
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(
        row_mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    let reverse_delete = sqlx::query("DELETE FROM swap_records WHERE boltz_swap_id = $1")
        .bind("LINEAGE_IMMUTABLE_REVERSE")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(reverse_delete.rows_affected(), 1);
    let reverse_allocation_persisted: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM swap_key_allocations WHERE id = $1)")
            .bind(first_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(reverse_allocation_persisted);
    let post_purge_public = format!("03{}", "78".repeat(32));
    let post_purge_hash = "79".repeat(32);
    let post_purge_identity_reuse = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_000,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &post_purge_public,
            preimage_hash_hex: Some(&post_purge_hash),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        post_purge_identity_reuse
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_key_allocations_derivation_identity_key")
    );

    let chain_invoice = insert_test_invoice(
        &pool,
        "lineageimmutable",
        &npub,
        "lq1lineageimmutable",
        3_600,
    )
    .await;
    let chain_root = "3333333333333333";
    let chain_claim_public = format!("02{}", "88".repeat(32));
    let chain_refund_public = format!("03{}", "99".repeat(32));
    let chain_hash = "cc".repeat(32);
    let chain_claim_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: chain_root,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_100,
            purpose: pay_service::db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &chain_claim_public,
            preimage_hash_hex: Some(&chain_hash),
        },
    )
    .await
    .unwrap();
    let chain_refund_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: chain_root,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_101,
            purpose: pay_service::db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &chain_refund_public,
            preimage_hash_hex: None,
        },
    )
    .await
    .unwrap();
    let chain_preimage = "dd".repeat(32);
    let chain_claim_key = "ee".repeat(32);
    let chain_refund_key = "ff".repeat(32);
    let mut chain_creation_terms = valid_chain_swap_creation_terms_fixture();
    chain_creation_terms.merchant_emergency_btc_address = Some(RECOVERY_COMMITMENT_P2WPKH);
    let chain_creation_evidence = pay_service::db::NewChainSwapCreationEvidence {
        creation_terms: chain_creation_terms,
        recovery_address_commitment_id: Some(recovery_commitment_id),
    };
    pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: chain_invoice.id,
            nym: Some("lineageimmutable"),
            boltz_swap_id: "LINEAGE_IMMUTABLE_CHAIN",
            lockup_address: "bc1qlineageimmutable",
            lockup_bip21: None,
            user_lock_amount_sat: 8_200,
            server_lock_amount_sat: 8_000,
            preimage_hex: &chain_preimage,
            claim_key_hex: &chain_claim_key,
            refund_key_hex: &chain_refund_key,
            boltz_response_json: "{}",
            claim_key_index: Some(8_100),
            refund_key_index: Some(8_101),
            root_fingerprint: Some(chain_root),
        },
        &pay_service::db::ChainSwapLineage {
            claim_allocation_id: chain_claim_id,
            refund_allocation_id: chain_refund_id,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &chain_claim_public,
            refund_public_key_hex: &chain_refund_public,
            preimage_hash_hex: &chain_hash,
        },
        &chain_creation_evidence,
    )
    .await
    .unwrap();
    let alternate_refund_public = format!("02{}", "ab".repeat(32));
    let alternate_refund_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: chain_root,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_102,
            purpose: pay_service::db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &alternate_refund_public,
            preimage_hash_hex: None,
        },
    )
    .await
    .unwrap();
    let reused_claim = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: chain_invoice.id,
            nym: Some("lineageimmutable"),
            boltz_swap_id: "LINEAGE_REUSED_CHAIN_CLAIM",
            lockup_address: "bc1qlineagereusedclaim",
            lockup_bip21: None,
            user_lock_amount_sat: 8_200,
            server_lock_amount_sat: 8_000,
            preimage_hex: &chain_preimage,
            claim_key_hex: &chain_claim_key,
            refund_key_hex: &chain_refund_key,
            boltz_response_json: "{}",
            claim_key_index: Some(8_100),
            refund_key_index: Some(8_102),
            root_fingerprint: Some(chain_root),
        },
        &pay_service::db::ChainSwapLineage {
            claim_allocation_id: chain_claim_id,
            refund_allocation_id: alternate_refund_id,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &chain_claim_public,
            refund_public_key_hex: &alternate_refund_public,
            preimage_hash_hex: &chain_hash,
        },
        &chain_creation_evidence,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        reused_claim
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_records_claim_key_allocation_id_key")
            | Some("chain_swap_records_fingerprint_claim_index_key")
    ));

    let alternate_claim_public = format!("03{}", "bc".repeat(32));
    let alternate_claim_hash = "de".repeat(32);
    let alternate_claim_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: chain_root,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_103,
            purpose: pay_service::db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &alternate_claim_public,
            preimage_hash_hex: Some(&alternate_claim_hash),
        },
    )
    .await
    .unwrap();
    let reused_refund = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: chain_invoice.id,
            nym: Some("lineageimmutable"),
            boltz_swap_id: "LINEAGE_REUSED_CHAIN_REFUND",
            lockup_address: "bc1qlineagereusedrefund",
            lockup_bip21: None,
            user_lock_amount_sat: 8_200,
            server_lock_amount_sat: 8_000,
            preimage_hex: &chain_preimage,
            claim_key_hex: &chain_claim_key,
            refund_key_hex: &chain_refund_key,
            boltz_response_json: "{}",
            claim_key_index: Some(8_103),
            refund_key_index: Some(8_101),
            root_fingerprint: Some(chain_root),
        },
        &pay_service::db::ChainSwapLineage {
            claim_allocation_id: alternate_claim_id,
            refund_allocation_id: chain_refund_id,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &alternate_claim_public,
            refund_public_key_hex: &chain_refund_public,
            preimage_hash_hex: &alternate_claim_hash,
        },
        &chain_creation_evidence,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        reused_refund
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_records_refund_key_allocation_id_key")
            | Some("chain_swap_records_fingerprint_refund_index_key")
    ));
    let persisted_chain_lineage: (String, String, String, String) = sqlx::query_as(
        "SELECT claim_public_key_hex, refund_public_key_hex, preimage_hash_hex, \
                key_epoch::TEXT \
           FROM chain_swap_records WHERE boltz_swap_id = $1",
    )
    .bind("LINEAGE_IMMUTABLE_CHAIN")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(persisted_chain_lineage.0, chain_claim_public);
    assert_eq!(persisted_chain_lineage.1, chain_refund_public);
    assert_eq!(persisted_chain_lineage.2, chain_hash);
    assert_eq!(persisted_chain_lineage.3, "2");
    let chain_delete = sqlx::query("DELETE FROM chain_swap_records WHERE boltz_swap_id = $1")
        .bind("LINEAGE_IMMUTABLE_CHAIN")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(chain_delete.rows_affected(), 1);
    let retained_chain_allocations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM swap_key_allocations WHERE id IN ($1, $2)")
            .bind(chain_claim_id)
            .bind(chain_refund_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained_chain_allocations, 2);
    let post_purge_chain_public = format!("02{}", "bd".repeat(32));
    let post_purge_chain_hash = "df".repeat(32);
    let post_purge_chain_identity_reuse = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: chain_root,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_100,
            purpose: pay_service::db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &post_purge_chain_public,
            preimage_hash_hex: Some(&post_purge_chain_hash),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        post_purge_chain_identity_reuse
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_key_allocations_derivation_identity_key")
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn derivation_guard_covers_orphans_active_generation_rotation_and_legacy_rows() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let root = "4444444444444444";
    let next = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let orphan_index = next + 5;
    let orphan_public = format!("02{}", "41".repeat(32));
    let orphan_hash = "42".repeat(32);
    pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 7,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: orphan_index,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &orphan_public,
            preimage_hash_hex: Some(&orphan_hash),
        },
    )
    .await
    .unwrap();

    assert!(
        pay_service::derivation_guard::check_rollback(
            &pool,
            root,
            7,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
        .unwrap(),
        "a rewound sequence missed a durable orphan allocation"
    );
    assert!(
        !pay_service::derivation_guard::check_rollback(
            &pool,
            root,
            8,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
        .unwrap(),
        "an inactive epoch incorrectly closed the rotated generation"
    );
    assert!(
        !pay_service::derivation_guard::check_rollback(
            &pool,
            "5555555555555555",
            7,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
        .unwrap(),
        "a different derivation root incorrectly closed admission"
    );

    // A coordinated rotation uses both a new root and a higher epoch. The same
    // child number is a distinct derivation identity only because the secret
    // root changed; both generations remain independently auditable.
    let rotated_root = "5555555555555555";
    let rotated_public = format!("03{}", "49".repeat(32));
    let rotated_hash = "4a".repeat(32);
    pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: rotated_root,
            key_epoch: 8,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: orphan_index,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &rotated_public,
            preimage_hash_hex: Some(&rotated_hash),
        },
    )
    .await
    .unwrap();
    let generations: Vec<(String, i32, i64)> = sqlx::query_as(
        "SELECT root_fingerprint, key_epoch, child_index \
           FROM swap_key_allocations \
          WHERE child_index = $1 ORDER BY root_fingerprint",
    )
    .bind(orphan_index)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        generations,
        vec![
            (root.to_string(), 7, orphan_index),
            (rotated_root.to_string(), 8, orphan_index),
        ]
    );

    sqlx::query("SELECT setval('swap_key_seq', $1, true)")
        .bind(orphan_index)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !pay_service::derivation_guard::check_rollback(
            &pool,
            root,
            7,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
        .unwrap(),
        "guard did not recover after the sequence advanced past the orphan"
    );
    assert!(
        !pay_service::derivation_guard::check_rollback(
            &pool,
            rotated_root,
            8,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
        .unwrap(),
        "the active rotated generation did not evaluate independently"
    );

    // Migration-044 rows remain a conservative bound even when queried under
    // another epoch because their historical epoch was unknowable.
    let npub = "43".repeat(32);
    pay_service::db::create_user(&pool, "legacyguard", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let legacy_index = orphan_index + 10;
    let legacy_preimage = "44".repeat(32);
    let legacy_claim_key = "45".repeat(32);
    let legacy_swap = pay_service::db::NewSwapRecord {
        nym: Some("legacyguard"),
        boltz_swap_id: "LEGACY_DERIVATION_GUARD",
        address: None,
        address_index: None,
        amount_sat: 1_000,
        invoice: "lnbc-legacy-guard",
        preimage_hex: &legacy_preimage,
        claim_key_hex: &legacy_claim_key,
        boltz_response_json: "{}",
        invoice_id: None,
        key_index: Some(legacy_index),
        root_fingerprint: Some(root),
    };
    let post_migration_legacy_insert = pay_service::db::record_swap(&pool, &legacy_swap)
        .await
        .unwrap_err();
    assert_eq!(
        post_migration_legacy_insert
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );

    // Seed a true pre-050 row for upgrade-compatibility behavior.
    record_pre_050_reverse_fixture(&pool, &legacy_swap)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO swap_key_legacy_high_water (root_fingerprint, max_child_index) \
         VALUES ($1, $2)",
    )
    .bind(root)
    .bind(legacy_index)
    .execute(&pool)
    .await
    .unwrap();

    let legacy_public_key = format!("02{}", "46".repeat(32));
    let legacy_hash = "47".repeat(32);
    let legacy_reuse = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 99,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: legacy_index,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &legacy_public_key,
            preimage_hash_hex: Some(&legacy_hash),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        legacy_reuse
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_key_allocations_legacy_high_water")
    );
    let legacy_delete = sqlx::query("DELETE FROM swap_records WHERE boltz_swap_id = $1")
        .bind("LEGACY_DERIVATION_GUARD")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(legacy_delete.rows_affected(), 1);
    assert_eq!(
        pay_service::db::max_legacy_swap_key_index(&pool, root)
            .await
            .unwrap(),
        Some(legacy_index)
    );
    let purged_legacy_public = format!("03{}", "4b".repeat(32));
    let purged_legacy_hash = "4c".repeat(32);
    let purged_legacy_reuse = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 100,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: legacy_index - 1,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &purged_legacy_public,
            preimage_hash_hex: Some(&purged_legacy_hash),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        purged_legacy_reuse
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_key_allocations_legacy_high_water")
    );
    assert!(
        pay_service::derivation_guard::check_rollback(
            &pool,
            root,
            99,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
        .unwrap(),
        "legacy migration-044 lineage stopped protecting a rotated epoch"
    );
    sqlx::query("SELECT setval('swap_key_seq', $1, true)")
        .bind(legacy_index)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!pay_service::derivation_guard::check_rollback(
        &pool,
        root,
        99,
        pay_service::db::DERIVATION_SCHEME_VERSION,
    )
    .await
    .unwrap());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn derivation_guard_does_not_false_positive_during_concurrent_allocation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let root = "5656565656565656";
    let expected_index = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();

    // Pause after every durable maximum is read but immediately before NEXT.
    // With the unsafe sequence-first order, NEXT has already been sampled at
    // this seam; with the safe order, the concurrent allocation advances it
    // before the guard reads it.
    let hook = pay_service::derivation_guard::install_derivation_guard_integration_test_hook(
        root,
        1,
        pay_service::db::DERIVATION_SCHEME_VERSION,
    );
    assert!(
        !pay_service::derivation_guard::check_rollback(
            &pool,
            "5757575757575757",
            1,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
        .unwrap(),
        "unrelated guard probe unexpectedly reported rollback"
    );
    let guard_pool = pool.clone();
    let guard = tokio::spawn(async move {
        pay_service::derivation_guard::check_rollback(
            &guard_pool,
            root,
            1,
            pay_service::db::DERIVATION_SCHEME_VERSION,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), hook.wait_until_reached())
        .await
        .expect("derivation guard did not reach the pre-sequence boundary");

    let issued_index = pay_service::db::next_swap_key_index(&pool).await.unwrap();
    assert_eq!(issued_index as i64, expected_index);
    let public_key = format!("02{}", "57".repeat(32));
    let preimage_hash = "58".repeat(32);
    pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: issued_index as i64,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &public_key,
            preimage_hash_hex: Some(&preimage_hash),
        },
    )
    .await
    .unwrap();

    hook.release();
    assert!(
        !tokio::time::timeout(Duration::from_secs(2), guard)
            .await
            .expect("derivation guard remained blocked")
            .expect("derivation guard task panicked")
            .unwrap(),
        "a normal concurrent allocation was misclassified as sequence rollback"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn chain_swap_creation_terms_are_complete_immutable_and_legacy_compatible() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let nym = "creationterms";
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let recovery_timestamp = auth_timestamp();
    let first_recovery_commitment = pay_service::db::persist_recovery_address_commitment(
        &pool,
        &verified_recovery_commitment(
            &keypair,
            &npub,
            RECOVERY_COMMITMENT_P2WPKH,
            recovery_timestamp,
        ),
    )
    .await
    .unwrap();
    let rotated_recovery_commitment = pay_service::db::persist_recovery_address_commitment(
        &pool,
        &verified_recovery_commitment(
            &keypair,
            &npub,
            RECOVERY_COMMITMENT_P2PKH,
            recovery_timestamp,
        ),
    )
    .await
    .unwrap();
    let first_recovery_commitment_id = first_recovery_commitment.commitment_id;
    let rotated_recovery_commitment_id = rotated_recovery_commitment.commitment_id;
    let invoice = insert_test_invoice(
        &pool,
        nym,
        &npub,
        "lq1creationtermsmerchantdestination",
        3_600,
    )
    .await;

    let root = "8080808080808080";
    let claim_public_key = format!("02{}", "81".repeat(32));
    let refund_public_key = format!("03{}", "82".repeat(32));
    let preimage_hash = "83".repeat(32);
    let claim_allocation_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_001,
            purpose: pay_service::db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &claim_public_key,
            preimage_hash_hex: Some(&preimage_hash),
        },
    )
    .await
    .unwrap();
    let refund_allocation_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 8_002,
            purpose: pay_service::db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &refund_public_key,
            preimage_hash_hex: None,
        },
    )
    .await
    .unwrap();

    let preimage = "84".repeat(32);
    let claim_key = "85".repeat(32);
    let refund_key = "86".repeat(32);
    let response_json = r#"{"id":"CHAIN_CREATION_TERMS"}"#;
    let swap = pay_service::db::NewChainSwapRecord {
        invoice_id: invoice.id,
        nym: Some(nym),
        boltz_swap_id: "CHAIN_CREATION_TERMS",
        lockup_address: "bc1qcreationtermslockup",
        lockup_bip21: Some("bitcoin:bc1qcreationtermslockup?amount=0.00025431"),
        user_lock_amount_sat: 25_431,
        server_lock_amount_sat: 25_000,
        preimage_hex: &preimage,
        claim_key_hex: &claim_key,
        refund_key_hex: &refund_key,
        boltz_response_json: response_json,
        claim_key_index: Some(8_001),
        refund_key_index: Some(8_002),
        root_fingerprint: Some(root),
    };
    let lineage = pay_service::db::ChainSwapLineage {
        claim_allocation_id,
        refund_allocation_id,
        key_epoch: 1,
        derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
        claim_public_key_hex: &claim_public_key,
        refund_public_key_hex: &refund_public_key,
        preimage_hash_hex: &preimage_hash,
    };

    let missing_terms = pay_service::db::record_chain_swap_with_lineage(&pool, &swap, &lineage)
        .await
        .unwrap_err();
    assert_eq!(
        missing_terms
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );

    let pair_quote = r#"{"fees":{"minerFees":{"server":405},"percentage":0.1},"hash":"014261","limits":{"maximal":25000000,"minimal":25000},"rate":1}"#;
    let creation_terms = pay_service::db::NewChainSwapCreationTerms {
        pinned_pair_hash: &"87".repeat(32),
        canonical_pair_quote_json: pair_quote,
        creation_response_sha256: &"88".repeat(32),
        btc_claim_script_sha256: &"89".repeat(32),
        btc_refund_script_sha256: &"8a".repeat(32),
        liquid_claim_script_sha256: &"8b".repeat(32),
        liquid_refund_script_sha256: &"8c".repeat(32),
        btc_timeout_height: 958_033,
        liquid_timeout_height: 3_972_215,
        btc_network: "bitcoin",
        liquid_network: "liquid",
        liquid_asset_id: &"8d".repeat(32),
        merchant_liquid_destination: "lq1qqcreationtermsmerchantdestination",
        merchant_emergency_btc_address: Some(RECOVERY_COMMITMENT_P2WPKH),
    };

    let missing_commitment = pay_service::db::record_chain_swap_with_lineage_and_creation_terms(
        &pool,
        &swap,
        &lineage,
        &creation_terms,
    )
    .await
    .unwrap_err();
    assert_eq!(
        missing_commitment
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_records_recovery_commitment_pair_check")
    );

    let mismatched_creation_evidence = pay_service::db::NewChainSwapCreationEvidence {
        creation_terms: pay_service::db::NewChainSwapCreationTerms {
            merchant_emergency_btc_address: Some(RECOVERY_COMMITMENT_P2PKH),
            ..creation_terms
        },
        recovery_address_commitment_id: Some(first_recovery_commitment_id),
    };
    let mismatch = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &swap,
        &lineage,
        &mismatched_creation_evidence,
    )
    .await
    .unwrap_err();
    assert_eq!(
        mismatch
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_records_recovery_commitment_fkey")
    );

    let creation_evidence = pay_service::db::NewChainSwapCreationEvidence {
        creation_terms,
        recovery_address_commitment_id: Some(first_recovery_commitment_id),
    };
    let expected_terms = pay_service::db::ChainSwapCreationTerms::from(&creation_evidence);
    let inserted = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &swap,
        &lineage,
        &creation_evidence,
    )
    .await
    .unwrap();
    assert_eq!(inserted.creation_terms.as_ref(), Some(&expected_terms));

    let fetched = pay_service::db::get_chain_swap_by_boltz_id(&pool, "CHAIN_CREATION_TERMS")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.creation_terms.as_ref(), Some(&expected_terms));
    assert_eq!(
        fetched
            .creation_terms
            .as_ref()
            .unwrap()
            .canonical_pair_quote_json,
        pair_quote
    );
    assert_eq!(
        fetched
            .creation_terms
            .as_ref()
            .unwrap()
            .recovery_address_commitment_id,
        Some(first_recovery_commitment_id)
    );

    // The CHECK remains authoritative even if an owner bypasses ordinary
    // triggers: no address-only historical shape can be introduced.
    let mut pair_check_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *pair_check_tx)
        .await
        .unwrap();
    let partial_pair = sqlx::query(
        "UPDATE chain_swap_records \
            SET recovery_address_commitment_id = NULL \
          WHERE id = $1",
    )
    .bind(inserted.id)
    .execute(&mut *pair_check_tx)
    .await
    .unwrap_err();
    assert_eq!(
        partial_pair
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_records_recovery_commitment_pair_check")
    );
    pair_check_tx.rollback().await.unwrap();

    let current_commitment =
        pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        current_commitment.commitment_id,
        rotated_recovery_commitment_id
    );
    assert_eq!(
        fetched
            .creation_terms
            .as_ref()
            .unwrap()
            .recovery_address_commitment_id,
        Some(first_recovery_commitment_id),
        "rotation must not retarget an already-created swap"
    );

    let recovery_mutation = sqlx::query(
        "UPDATE chain_swap_records \
            SET recovery_address_commitment_id = $2, \
                merchant_emergency_btc_address = $3 \
          WHERE id = $1",
    )
    .bind(inserted.id)
    .bind(rotated_recovery_commitment_id)
    .bind(RECOVERY_COMMITMENT_P2PKH)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        recovery_mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );

    let mutation = sqlx::query(
        "UPDATE chain_swap_records SET btc_timeout_height = btc_timeout_height + 1 WHERE id = $1",
    )
    .bind(inserted.id)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    let response_mutation = sqlx::query(
        "UPDATE chain_swap_records SET boltz_response_json = '{\"id\":\"mutated\"}' WHERE id = $1",
    )
    .bind(inserted.id)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        response_mutation
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("55000")
    );
    pay_service::db::update_chain_swap_status(
        &pool,
        inserted.id,
        pay_service::db::ChainSwapStatus::UserLockMempool,
        None,
    )
    .await
    .unwrap();

    let legacy_preimage = "8e".repeat(32);
    let legacy_claim_key = "8f".repeat(32);
    let legacy_refund_key = "90".repeat(32);
    let legacy = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some(nym),
            boltz_swap_id: "CHAIN_CREATION_TERMS_LEGACY",
            lockup_address: "bc1qcreationtermslegacy",
            lockup_bip21: None,
            user_lock_amount_sat: 26_000,
            server_lock_amount_sat: 25_000,
            preimage_hex: &legacy_preimage,
            claim_key_hex: &legacy_claim_key,
            refund_key_hex: &legacy_refund_key,
            boltz_response_json: "{}",
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
        },
    )
    .await
    .unwrap();
    assert!(legacy.creation_terms.is_none());
    pay_service::db::update_chain_swap_status(
        &pool,
        legacy.id,
        pay_service::db::ChainSwapStatus::UserLockMempool,
        None,
    )
    .await
    .unwrap();
    assert!(pay_service::db::get_chain_swap_by_id(&pool, legacy.id)
        .await
        .unwrap()
        .unwrap()
        .creation_terms
        .is_none());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_staging_evidence_reads_exact_public_lineage_and_fails_on_dangling_rows() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;

    let nym = "manifeststage";
    let npub = "91".repeat(32);
    pay_service::db::create_user(&pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice = insert_test_invoice(
        &pool,
        nym,
        &npub,
        "lq1manifeststagingmerchantdestination",
        3_600,
    )
    .await;

    let root = "9191919191919191";
    let claim_public_key = format!("02{}", "92".repeat(32));
    let refund_public_key = format!("03{}", "93".repeat(32));
    let later_public_key = format!("02{}", "94".repeat(32));
    let preimage_hash = "95".repeat(32);
    let later_preimage_hash = "96".repeat(32);
    let claim_allocation_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 3,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 9_001,
            purpose: pay_service::db::SwapKeyPurpose::ChainClaim,
            public_key_hex: &claim_public_key,
            preimage_hash_hex: Some(&preimage_hash),
        },
    )
    .await
    .unwrap();
    let refund_allocation_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 3,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 9_002,
            purpose: pay_service::db::SwapKeyPurpose::ChainRefund,
            public_key_hex: &refund_public_key,
            preimage_hash_hex: None,
        },
    )
    .await
    .unwrap();
    pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 3,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 9_003,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &later_public_key,
            preimage_hash_hex: Some(&later_preimage_hash),
        },
    )
    .await
    .unwrap();

    const PRIVATE_PREIMAGE_CANARY: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const PRIVATE_CLAIM_KEY_CANARY: &str =
        "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    const PRIVATE_REFUND_KEY_CANARY: &str =
        "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    const PROVIDER_RESPONSE_CANARY: &str = "{\"private_provider_response\":\"must-not-load\"}";
    let recovery_address_commitment_id =
        insert_test_recovery_commitment(&pool, &npub, RECOVERY_COMMITMENT_P2WPKH, 1, 0x97).await;
    let mut creation_terms = valid_chain_swap_creation_terms_fixture();
    creation_terms.merchant_emergency_btc_address = Some(RECOVERY_COMMITMENT_P2WPKH);
    let inserted = pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            invoice_id: invoice.id,
            nym: Some(nym),
            boltz_swap_id: "MANIFEST_STAGE_EVIDENCE",
            lockup_address: "bc1qmanifeststaginglockup",
            lockup_bip21: Some("bitcoin:bc1qmanifeststaginglockup?amount=0.00025431"),
            user_lock_amount_sat: 25_431,
            server_lock_amount_sat: 25_000,
            preimage_hex: PRIVATE_PREIMAGE_CANARY,
            claim_key_hex: PRIVATE_CLAIM_KEY_CANARY,
            refund_key_hex: PRIVATE_REFUND_KEY_CANARY,
            boltz_response_json: PROVIDER_RESPONSE_CANARY,
            claim_key_index: Some(9_001),
            refund_key_index: Some(9_002),
            root_fingerprint: Some(root),
        },
        &pay_service::db::ChainSwapLineage {
            claim_allocation_id,
            refund_allocation_id,
            key_epoch: 3,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &claim_public_key,
            refund_public_key_hex: &refund_public_key,
            preimage_hash_hex: &preimage_hash,
        },
        &pay_service::db::NewChainSwapCreationEvidence {
            creation_terms,
            recovery_address_commitment_id: Some(recovery_address_commitment_id),
        },
    )
    .await
    .unwrap();

    let evidence = pay_service::db::load_manifest_staging_evidence(&pool, inserted.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence.persisted_lineage.chain_swap_id, inserted.id);
    assert_eq!(evidence.persisted_lineage.root_fingerprint, root);
    assert_eq!(evidence.persisted_lineage.key_epoch, 3);
    assert_eq!(
        evidence.persisted_lineage.claim.allocation_id,
        claim_allocation_id
    );
    assert_eq!(
        evidence.persisted_lineage.refund.allocation_id,
        refund_allocation_id
    );
    assert_eq!(evidence.claim_allocation.child_index, 9_001);
    assert_eq!(
        evidence.claim_allocation.purpose,
        pay_service::db::SwapKeyPurpose::ChainClaim
    );
    assert_eq!(
        evidence.claim_allocation.preimage_hash_hex,
        Some(preimage_hash)
    );
    assert_eq!(evidence.refund_allocation.child_index, 9_002);
    assert_eq!(
        evidence.refund_allocation.purpose,
        pay_service::db::SwapKeyPurpose::ChainRefund
    );
    assert_eq!(evidence.refund_allocation.preimage_hash_hex, None);
    assert_eq!(evidence.allocation_high_water.child_index, 9_003);

    let rendered = format!("{evidence:?}");
    for secret in [
        PRIVATE_PREIMAGE_CANARY,
        PRIVATE_CLAIM_KEY_CANARY,
        PRIVATE_REFUND_KEY_CANARY,
        PROVIDER_RESPONSE_CANARY,
    ] {
        assert!(!rendered.contains(secret));
    }
    assert!(
        pay_service::db::load_manifest_staging_evidence(&pool, uuid::Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );

    // Model a damaged restore with a dangling lineage reference. The loader's
    // LEFT JOIN must distinguish the present chain row from an absent chain
    // row and fail closed instead of manufacturing allocation evidence.
    let mut corruption = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corruption)
        .await
        .unwrap();
    sqlx::query("DELETE FROM swap_key_allocations WHERE id = $1")
        .bind(refund_allocation_id)
        .execute(&mut *corruption)
        .await
        .unwrap();
    corruption.commit().await.unwrap();

    let error = pay_service::db::load_manifest_staging_evidence(&pool, inserted.id)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        pay_service::db::ManifestStagingEvidenceReadError::IncompleteStoredEvidence {
            field: "refund_allocation.id"
        }
    );
    assert!(std::error::Error::source(&error).is_none());
    let rendered = format!("{error:?} {error}");
    for secret in [
        PRIVATE_PREIMAGE_CANARY,
        PRIVATE_CLAIM_KEY_CANARY,
        PRIVATE_REFUND_KEY_CANARY,
        PROVIDER_RESPONSE_CANARY,
    ] {
        assert!(!rendered.contains(secret));
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn watcher_lane_progress_resumes_independently_and_repeats_after_crash_gap() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    use pay_service::db::{WatcherLane, WatcherLaneWorker, WatcherScanCursor};

    assert!(pay_service::db::load_watcher_lane_cursor(
        &pool,
        WatcherLaneWorker::BitcoinDirect,
        WatcherLane::Recent,
    )
    .await
    .unwrap()
    .is_none());

    // A nullable pair is a valid initialized-but-unadvanced lane and remains
    // distinct from the other worker/lane keys.
    sqlx::query("INSERT INTO watcher_lane_progress (worker, lane) VALUES ($1, $2)")
        .bind(WatcherLaneWorker::BitcoinDirect.as_str())
        .bind(WatcherLane::Historical.as_str())
        .execute(&pool)
        .await
        .unwrap();
    assert!(pay_service::db::load_watcher_lane_cursor(
        &pool,
        WatcherLaneWorker::BitcoinDirect,
        WatcherLane::Historical,
    )
    .await
    .unwrap()
    .is_none());

    let completed = WatcherScanCursor {
        created_at: "2026-07-12 11:10:00+00".to_string(),
        id: uuid::Uuid::from_u128(10),
    };
    pay_service::db::persist_watcher_lane_cursor(
        &pool,
        WatcherLaneWorker::BitcoinDirect,
        WatcherLane::Recent,
        &completed,
    )
    .await
    .unwrap();

    let resumed = pay_service::db::load_watcher_lane_cursor(
        &pool,
        WatcherLaneWorker::BitcoinDirect,
        WatcherLane::Recent,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(resumed.id, completed.id);
    assert!(resumed.created_at.starts_with("2026-07-12 11:10:00"));

    // Simulate an idempotent invoice obligation committing immediately before
    // process death: without the later cursor upsert, restart repeats from the
    // last completed key instead of skipping the obligation.
    let applied_before_crash = WatcherScanCursor {
        created_at: "2026-07-12 11:20:00+00".to_string(),
        id: uuid::Uuid::from_u128(20),
    };
    let after_crash = pay_service::db::load_watcher_lane_cursor(
        &pool,
        WatcherLaneWorker::BitcoinDirect,
        WatcherLane::Recent,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(after_crash.id, completed.id);

    pay_service::db::persist_watcher_lane_cursor(
        &pool,
        WatcherLaneWorker::BitcoinDirect,
        WatcherLane::Recent,
        &applied_before_crash,
    )
    .await
    .unwrap();
    assert_eq!(
        pay_service::db::load_watcher_lane_cursor(
            &pool,
            WatcherLaneWorker::BitcoinDirect,
            WatcherLane::Recent,
        )
        .await
        .unwrap()
        .unwrap()
        .id,
        applied_before_crash.id
    );

    let keys: Vec<(String, String)> =
        sqlx::query_as("SELECT worker, lane FROM watcher_lane_progress ORDER BY worker, lane")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        keys,
        vec![
            ("bitcoin_direct".to_string(), "historical".to_string()),
            ("bitcoin_direct".to_string(), "recent".to_string()),
        ]
    );

    cleanup_db(&pool).await;
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
async fn issue30_webhook_rejects_malformed_payload_with_retryable_status() {
    let pool = test_pool().await;
    let app = test_app(test_state(pool.clone()));

    // A malformed delivery must retain the structured AppError contract while
    // returning non-2xx so Boltz retries instead of treating it as handled.
    let (status, body) = post_json(&app, "/webhook/boltz", json!({"id": "x", "status": "y"})).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["status"], "ERROR");
    assert_eq!(body["code"], "ClaimError");
    assert_eq!(body["reason"], "Swap claim failed.");
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

    record_pre_050_reverse_fixture(
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
    record_pre_050_reverse_fixture(
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
    let pending = pay_service::db::get_swap_by_boltz_id(&pool, "REVERSE_WEBHOOK_CLOSED_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.status, "lockup_confirmed");
    assert_eq!(pending.address, None);
    assert_eq!(pending.claim_attempts, 0);

    // Claim construction deliberately has no implicit fee fallback. The
    // webhook records funding evidence but must wait without allocating or
    // attempting construction until the worker has an accepted typed decision.
    let claim_error = reverse_claim_pool_error(&pool, pending.id).await;
    assert!(claim_error
        .to_string()
        .contains("invalid boltz response json"));

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
    record_pre_050_reverse_fixture(
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
    let swap = record_pre_050_chain_fixture(
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

fn accepted_live_liquid_fee_decision() -> pay_service::fee_policy::LiquidFeeDecision {
    use pay_service::fee_policy::{FeeProvenance, LiquidFeePolicy, LiveLiquid, SatPerVbyte};

    let observation = LiveLiquid::new(
        SatPerVbyte::try_from(0.5).unwrap(),
        1_000,
        FeeProvenance::new("claim-integration-test").unwrap(),
    );
    LiquidFeePolicy::default()
        .decide_typed(Some(&observation), None, 1_000)
        .unwrap()
}

async fn attach_post_051_creation_terms(
    pool: &PgPool,
    chain_swap_id: uuid::Uuid,
    canonical_response_json: &str,
) {
    let terms = valid_chain_swap_creation_terms_fixture();
    let response_digest = hex::encode(Sha256::digest(canonical_response_json.as_bytes()));
    let liquid_asset_id = boltz_client::elements::AssetId::LIQUID_BTC.to_string();
    let merchant_destination = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chain_swap_records SET \
             pinned_pair_hash = $2, canonical_pair_quote_json = $3, \
             creation_response_sha256 = $4, btc_claim_script_sha256 = $5, \
             btc_refund_script_sha256 = $6, liquid_claim_script_sha256 = $7, \
             liquid_refund_script_sha256 = $8, btc_timeout_height = $9, \
             liquid_timeout_height = $10, btc_network = $11, liquid_network = $12, \
             liquid_asset_id = $13, merchant_liquid_destination = $14 \
         WHERE id = $1",
    )
    .bind(chain_swap_id)
    .bind(terms.pinned_pair_hash)
    .bind(terms.canonical_pair_quote_json)
    .bind(response_digest)
    .bind(terms.btc_claim_script_sha256)
    .bind(terms.btc_refund_script_sha256)
    .bind(terms.liquid_claim_script_sha256)
    .bind(terms.liquid_refund_script_sha256)
    .bind(terms.btc_timeout_height)
    .bind(terms.liquid_timeout_height)
    .bind(terms.btc_network)
    .bind(terms.liquid_network)
    .bind(liquid_asset_id)
    .bind(merchant_destination)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn reverse_claim_pool_error(pool: &PgPool, swap_id: uuid::Uuid) -> AppError {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        claimer::exercise_reverse_claim_with_malformed_response(
            pool,
            swap_id,
            &accepted_live_liquid_fee_decision(),
        ),
    )
    .await
    .expect("reverse claim preparation must complete within its bounded timeout");
    match result {
        Err(error) => error,
        Ok(outcome) => panic!("expected deterministic reverse construction error, got {outcome:?}"),
    }
}

async fn chain_claim_pool_error(pool: &PgPool, swap_id: uuid::Uuid) -> AppError {
    let fee_decision = accepted_live_liquid_fee_decision();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        match claimer::exercise_chain_claim_with_malformed_response(pool, swap_id, &fee_decision)
            .await
        {
            Ok(claimer::ClaimOutcome::SkippedLockHeld) => {}
            result => return result,
        }

        // Dropping the preceding no-fee SQLx transaction schedules its
        // rollback, so the webhook can return just before its transaction
        // advisory lock is released. Block on that exact lock once; when
        // this acquisition succeeds the rollback handoff is complete.
        // Commit releases our handoff lock before one final seam attempt.
        let lock_key = format!("chain-claim:{swap_id}");
        let mut handoff = pool
            .begin()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&lock_key)
            .execute(&mut *handoff)
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;
        handoff
            .commit()
            .await
            .map_err(|error| AppError::DbError(error.to_string()))?;

        claimer::exercise_chain_claim_with_malformed_response(pool, swap_id, &fee_decision).await
    })
    .await
    .expect("chain claim preparation must complete within its bounded timeout");
    match result {
        Err(error) => error,
        Ok(outcome) => panic!("expected deterministic chain construction error, got {outcome:?}"),
    }
}

#[tokio::test]
async fn provider_ready_claims_without_a_liquid_quote_stay_pending_without_construction() {
    use pay_service::claimer::LIQUID_FEE_DECISION_PENDING_REASON;
    use pay_service::db::{ChainSwapProviderStatusInput, ChainSwapStatus, SwapStatus};

    let pool = test_pool().await;
    cleanup_db(&pool).await;

    create_test_user(&pool, "nofeereverse").await;
    record_pre_050_reverse_fixture(
        &pool,
        &pay_service::db::NewSwapRecord {
            key_index: None,
            root_fingerprint: None,
            nym: Some("nofeereverse"),
            boltz_swap_id: "NO_FEE_REVERSE",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-no-fee-reverse",
            preimage_hex: "aa".repeat(32).as_str(),
            claim_key_hex: "bb".repeat(32).as_str(),
            boltz_response_json: "{",
            invoice_id: None,
        },
    )
    .await
    .unwrap();
    let reverse = pay_service::db::get_swap_by_boltz_id(&pool, "NO_FEE_REVERSE")
        .await
        .unwrap()
        .unwrap();
    pay_service::db::update_swap_status(&pool, reverse.id, SwapStatus::LockupConfirmed, None)
        .await
        .unwrap();

    let legacy_npub = create_test_user(&pool, "nofeelegacy").await;
    let legacy_invoice =
        insert_test_invoice(&pool, "nofeelegacy", &legacy_npub, "lq1nofeelegacy", 3_600).await;
    let legacy_response = r#"{"id":"NO_FEE_CHAIN_LEGACY"}"#;
    let legacy = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: legacy_invoice.id,
            nym: Some("nofeelegacy"),
            boltz_swap_id: "NO_FEE_CHAIN_LEGACY",
            lockup_address: "bc1qnofeelegacy",
            lockup_bip21: None,
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: legacy_response,
        },
    )
    .await
    .unwrap();
    let post_npub = create_test_user(&pool, "nofeepost").await;
    let post_invoice =
        insert_test_invoice(&pool, "nofeepost", &post_npub, "lq1nofeepost", 3_600).await;
    let post_response = r#"{"id":"NO_FEE_CHAIN_POST_051"}"#;
    let post = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: post_invoice.id,
            nym: Some("nofeepost"),
            boltz_swap_id: "NO_FEE_CHAIN_POST_051",
            lockup_address: "bc1qnofeepost",
            lockup_bip21: None,
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: "44".repeat(32).as_str(),
            claim_key_hex: "55".repeat(32).as_str(),
            refund_key_hex: "66".repeat(32).as_str(),
            boltz_response_json: post_response,
        },
    )
    .await
    .unwrap();
    attach_post_051_creation_terms(&pool, post.id, post_response).await;

    for swap_id in [legacy.id, post.id] {
        let delivered = pay_service::db::apply_chain_swap_provider_status(
            &pool,
            swap_id,
            ChainSwapProviderStatusInput::ServerLockConfirmed,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(delivered.changed);
        assert_eq!(
            delivered.current_status,
            ChainSwapStatus::ServerLockConfirmed
        );
    }

    let reverse_outcome = claimer::exercise_reverse_claim_without_fee(&pool, reverse.id)
        .await
        .unwrap();
    let legacy_outcome = claimer::exercise_chain_claim_without_fee(&pool, legacy.id)
        .await
        .unwrap();
    let post_outcome = claimer::exercise_chain_claim_without_fee(&pool, post.id)
        .await
        .unwrap();
    for outcome in [reverse_outcome, legacy_outcome, post_outcome] {
        assert!(matches!(
            outcome,
            claimer::ClaimOutcome::PendingFeeUnavailable { reason }
                if reason == LIQUID_FEE_DECISION_PENDING_REASON
        ));
    }

    let reverse = pay_service::db::get_swap_by_boltz_id(&pool, "NO_FEE_REVERSE")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reverse.status, "lockup_confirmed");
    assert_eq!(reverse.claim_attempts, 0);
    assert!(reverse.claim_tx_hex.is_none());
    assert!(reverse.address.is_none());
    assert!(reverse.address_index.is_none());
    let reverse_cursor: i32 =
        sqlx::query_scalar("SELECT next_addr_idx FROM users WHERE nym = 'nofeereverse'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reverse_cursor, 0);

    for (swap_id, post_051) in [(legacy.id, false), (post.id, true)] {
        let row = pay_service::db::get_chain_swap_by_id(&pool, swap_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "server_lock_confirmed");
        assert_eq!(row.claim_attempts, 0);
        assert!(row.claim_tx_hex.is_none());
        assert_eq!(row.creation_terms.is_some(), post_051);

        let duplicate = pay_service::db::apply_chain_swap_provider_status(
            &pool,
            swap_id,
            ChainSwapProviderStatusInput::ServerLockConfirmed,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!duplicate.changed);
        assert_eq!(
            duplicate.current_status,
            ChainSwapStatus::ServerLockConfirmed
        );
    }

    // Supplying an accepted live decision on a later retry re-enters the
    // ordinary construction path. The deliberately malformed fixtures fail
    // locally there, proving the no-quote outcome did not terminalize either
    // obligation or consume an attempt.
    let reverse_error = reverse_claim_pool_error(&pool, reverse.id).await;
    assert_local_claim_error(&reverse_error, "invalid boltz response json");
    let post_error = chain_claim_pool_error(&pool, post.id).await;
    assert_local_claim_error(&post_error, "invalid chain boltz response json");

    let reverse = pay_service::db::get_swap_by_boltz_id(&pool, "NO_FEE_REVERSE")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reverse.status, "lockup_confirmed");
    assert_eq!(reverse.claim_attempts, 1);
    assert!(reverse.claim_tx_hex.is_none());
    let post = pay_service::db::get_chain_swap_by_id(&pool, post.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(post.status, "server_lock_confirmed");
    assert_eq!(post.claim_attempts, 1);
    assert!(post.claim_tx_hex.is_none());

    cleanup_db(&pool).await;
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
        claimer::exercise_chain_claim_with_malformed_response(
            &constrained,
            swap_id,
            &accepted_live_liquid_fee_decision(),
        ),
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
    let mut legacy_claim_bytes = admin.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *legacy_claim_bytes)
        .await
        .unwrap();
    sqlx::query("UPDATE swap_records SET claim_tx_hex = '00' WHERE id = $1")
        .bind(reverse_id)
        .execute(&mut *legacy_claim_bytes)
        .await
        .unwrap();
    sqlx::query("UPDATE chain_swap_records SET claim_tx_hex = '00' WHERE id = $1")
        .bind(chain_id)
        .execute(&mut *legacy_claim_bytes)
        .await
        .unwrap();
    legacy_claim_bytes.commit().await.unwrap();

    let constrained = constrained_test_pool(1, None);
    let reverse_error = claimer::exercise_reverse_claim_with_malformed_response(
        &constrained,
        reverse_id,
        &accepted_live_liquid_fee_decision(),
    )
    .await
    .expect_err("persisted reverse bytes must close the malformed-only seam");
    let chain_error = claimer::exercise_chain_claim_with_malformed_response(
        &constrained,
        chain_id,
        &accepted_live_liquid_fee_decision(),
    )
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
                claimer::exercise_reverse_claim_with_malformed_response(
                    &pool,
                    swap_id,
                    &accepted_live_liquid_fee_decision(),
                ),
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
    // Same deterministic classifier phrase as the reverse test. The guarded
    // chain seam refuses valid provider evidence and network I/O; its malformed
    // packet reaches the shared durable-refusal boundary only in test mode.
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
    record_pre_050_reverse_fixture(
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
    let chain = record_pre_050_chain_fixture(
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
    let reverse = claimer::exercise_reverse_claim_with_malformed_response(
        &constrained,
        reverse_id,
        &accepted_live_liquid_fee_decision(),
    )
    .await
    .unwrap();
    assert!(matches!(reverse, claimer::ClaimOutcome::AlreadyTerminal));
    let reverse_unsupported = claimer::exercise_reverse_claim_with_malformed_response(
        &constrained,
        unsupported_reverse.id,
        &accepted_live_liquid_fee_decision(),
    )
    .await
    .unwrap();
    assert!(matches!(
        reverse_unsupported,
        claimer::ClaimOutcome::AlreadyTerminal
    ));
    let chain_outcome = claimer::exercise_chain_claim_with_malformed_response(
        &constrained,
        chain.id,
        &accepted_live_liquid_fee_decision(),
    )
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
    record_pre_050_chain_fixture(
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
async fn issue30_chain_provider_transition_is_atomic_forward_safe_and_retryable() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "chaintransitiondb").await;
    let invoice = insert_test_invoice(
        &pool,
        "chaintransitiondb",
        &npub,
        "lq1chaintransitiondb",
        60,
    )
    .await;
    let row = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("chaintransitiondb"),
            boltz_swap_id: "CHAIN_TRANSITION_DB_1",
            lockup_address: "bc1qchaintransitiondb",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{}",
        },
    )
    .await
    .unwrap();

    sqlx::query(
        "UPDATE chain_swap_records SET updated_at = '2000-01-01 00:00:00+00' WHERE id = $1",
    )
    .bind(row.id)
    .execute(&pool)
    .await
    .unwrap();
    let initial_updated_at: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::BIGINT \
         FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // A provider failure while still pending is only a reconciliation hint. It
    // cannot mutate lifecycle state or retain a bit that later authorizes
    // Bitcoin recovery.
    let pending_failure = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::FundingFailed,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        pending_failure.current_status,
        pay_service::db::ChainSwapStatus::Pending
    );
    assert!(!pending_failure.changed);
    assert!(!pending_failure.cooperative_refused);
    let failure_updated_at: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::BIGINT \
         FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(failure_updated_at, initial_updated_at);

    let duplicate_failure = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::FundingFailed,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!duplicate_failure.changed);
    let duplicate_failure_updated_at: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::BIGINT \
         FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(duplicate_failure_updated_at, failure_updated_at);

    let user_after_failure = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::UserLockConfirmed,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        user_after_failure.current_status,
        pay_service::db::ChainSwapStatus::UserLockConfirmed
    );

    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'pending', cooperative_refused = FALSE WHERE id = $1",
    )
    .bind(row.id)
    .execute(&pool)
    .await
    .unwrap();
    pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::UserLockConfirmed,
    )
    .await
    .unwrap()
    .unwrap();
    let failed_after_user = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::FundingFailed,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        failed_after_user.current_status,
        pay_service::db::ChainSwapStatus::UserLockConfirmed
    );
    assert!(!failed_after_user.changed);
    assert!(!failed_after_user.cooperative_refused);

    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'pending', cooperative_refused = FALSE WHERE id = $1",
    )
    .bind(row.id)
    .execute(&pool)
    .await
    .unwrap();
    let pending_expiry = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::SwapExpired,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        pending_expiry.current_status,
        pay_service::db::ChainSwapStatus::Pending
    );
    assert!(!pending_expiry.changed);
    assert!(!pending_expiry.cooperative_refused);
    let duplicate_expiry = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::SwapExpired,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!duplicate_expiry.changed);
    let user_after_expiry = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::UserLockMempool,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        user_after_expiry.current_status,
        pay_service::db::ChainSwapStatus::UserLockMempool
    );
    assert!(!user_after_expiry.cooperative_refused);

    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'pending', cooperative_refused = FALSE WHERE id = $1",
    )
    .bind(row.id)
    .execute(&pool)
    .await
    .unwrap();
    pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::UserLockMempool,
    )
    .await
    .unwrap()
    .unwrap();
    let expiry_after_user = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::SwapExpired,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        expiry_after_user.current_status,
        pay_service::db::ChainSwapStatus::UserLockMempool
    );
    assert!(!expiry_after_user.changed);
    assert!(!expiry_after_user.cooperative_refused);

    // A later server-lock observation can still advance the ordinary provider
    // progress projection; no recovery branch was ever created.
    let late_server = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::ServerLockConfirmed,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        late_server.current_status,
        pay_service::db::ChainSwapStatus::ServerLockConfirmed
    );
    let before_reordered: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::BIGINT \
         FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let reordered = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::UserLockMempool,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        reordered.current_status,
        pay_service::db::ChainSwapStatus::ServerLockConfirmed
    );
    assert!(!reordered.changed);
    let after_reordered: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::BIGINT \
         FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_reordered, before_reordered);

    // Concurrent stale/new evidence converges regardless of lock acquisition
    // order because both calls reduce under the same row lock.
    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'pending', cooperative_refused = FALSE WHERE id = $1",
    )
    .bind(row.id)
    .execute(&pool)
    .await
    .unwrap();
    let older = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::UserLockMempool,
    );
    let newer = pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::ServerLockConfirmed,
    );
    let (older_result, newer_result) = tokio::join!(older, newer);
    older_result.unwrap().unwrap();
    newer_result.unwrap().unwrap();
    let final_row = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_row.status, "server_lock_confirmed");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn issue30_failure_hints_observe_and_user_lock_projection_converges() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let app = test_app(test_state_with_config(pool.clone(), config));
    let npub = create_test_user(&pool, "chainprojectionorder").await;
    let invoice = insert_test_invoice(
        &pool,
        "chainprojectionorder",
        &npub,
        "lq1chainprojectionorder",
        60,
    )
    .await;
    let row = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("chainprojectionorder"),
            boltz_swap_id: "CHAIN_PROJECTION_ORDER_1",
            lockup_address: "bc1qchainprojectionorder",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{}",
        },
    )
    .await
    .unwrap();

    // The counting Boltz endpoint returns 503 to every request. HTTP 200 plus a
    // zero count for lockupFailed proves this production webhook boundary made
    // no legacy get_quote/accept_quote call.
    for failure_status in [
        "transaction.failed",
        "transaction.refunded",
        "transaction.lockupFailed",
    ] {
        sqlx::query(
            "UPDATE chain_swap_records \
             SET status = 'pending', cooperative_refused = FALSE WHERE id = $1",
        )
        .bind(row.id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE invoices \
             SET status = 'unpaid', settlement_status = 'none', \
                 swap_settlement_status = 'none' WHERE id = $1",
        )
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();

        let (failure_first_status, failure_first_body) = post_json(
            &app,
            "/webhook/boltz",
            json!({
                "event": "swap.update",
                "data": {"id": "CHAIN_PROJECTION_ORDER_1", "status": failure_status}
            }),
        )
        .await;
        assert_eq!(
            failure_first_status,
            StatusCode::OK,
            "{failure_status}: {failure_first_body}"
        );
        let pending_failure = pay_service::db::get_chain_swap_by_id(&pool, row.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending_failure.status, "pending", "{failure_status}");
        assert!(!pending_failure.cooperative_refused, "{failure_status}");
        assert_eq!(
            pending_failure.renegotiated_server_lock_amount_sat, None,
            "{failure_status}"
        );
        let not_yet_funded = pay_service::db::get_invoice_by_id(&pool, invoice.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(not_yet_funded.status, "unpaid", "{failure_status}");
        assert_eq!(
            not_yet_funded.swap_settlement_status, "none",
            "{failure_status}"
        );

        let (user_after_failure_status, user_after_failure_body) = post_json(
            &app,
            "/webhook/boltz",
            json!({
                "event": "swap.update",
                "data": {
                    "id": "CHAIN_PROJECTION_ORDER_1",
                    "status": "transaction.confirmed"
                }
            }),
        )
        .await;
        assert_eq!(
            user_after_failure_status,
            StatusCode::OK,
            "{failure_status}: {user_after_failure_body}"
        );
        let failure_first_final = pay_service::db::get_chain_swap_by_id(&pool, row.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            failure_first_final.status, "user_lock_confirmed",
            "{failure_status}"
        );
        let failure_first_invoice = pay_service::db::get_invoice_by_id(&pool, invoice.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            failure_first_invoice.status, "in_progress",
            "{failure_status}"
        );
        assert_eq!(
            failure_first_invoice.settlement_status, "pending",
            "{failure_status}"
        );
        assert_eq!(
            failure_first_invoice.swap_settlement_status, "pending",
            "{failure_status}"
        );

        // Simulate cancellation after the atomic swap-row commit but before
        // the invoice side effect. Re-delivering identical user-lock evidence
        // must repair the projection even though the reducer is now a no-op.
        sqlx::query(
            "UPDATE invoices \
             SET status = 'unpaid', settlement_status = 'none', \
                 swap_settlement_status = 'none' WHERE id = $1",
        )
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();
        let (retry_status, retry_body) = post_json(
            &app,
            "/webhook/boltz",
            json!({
                "event": "swap.update",
                "data": {
                    "id": "CHAIN_PROJECTION_ORDER_1",
                    "status": "transaction.confirmed"
                }
            }),
        )
        .await;
        assert_eq!(
            retry_status,
            StatusCode::OK,
            "{failure_status}: {retry_body}"
        );
        let repaired_invoice = pay_service::db::get_invoice_by_id(&pool, invoice.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(repaired_invoice.status, "in_progress", "{failure_status}");
        assert_eq!(
            repaired_invoice.settlement_status, "pending",
            "{failure_status}"
        );
        assert_eq!(
            repaired_invoice.swap_settlement_status, "pending",
            "{failure_status}"
        );

        sqlx::query(
            "UPDATE chain_swap_records \
             SET status = 'pending', cooperative_refused = FALSE WHERE id = $1",
        )
        .bind(row.id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE invoices \
             SET status = 'unpaid', settlement_status = 'none', \
                 swap_settlement_status = 'none' WHERE id = $1",
        )
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();

        let (user_first_status, user_first_body) = post_json(
            &app,
            "/webhook/boltz",
            json!({
                "event": "swap.update",
                "data": {
                    "id": "CHAIN_PROJECTION_ORDER_1",
                    "status": "transaction.confirmed"
                }
            }),
        )
        .await;
        assert_eq!(
            user_first_status,
            StatusCode::OK,
            "{failure_status}: {user_first_body}"
        );
        let (failure_after_user_status, failure_after_user_body) = post_json(
            &app,
            "/webhook/boltz",
            json!({
                "event": "swap.update",
                "data": {"id": "CHAIN_PROJECTION_ORDER_1", "status": failure_status}
            }),
        )
        .await;
        assert_eq!(
            failure_after_user_status,
            StatusCode::OK,
            "{failure_status}: {failure_after_user_body}"
        );
        let user_first_final = pay_service::db::get_chain_swap_by_id(&pool, row.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            user_first_final.status, "user_lock_confirmed",
            "{failure_status}"
        );
        let user_first_invoice = pay_service::db::get_invoice_by_id(&pool, invoice.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_first_invoice.status, "in_progress", "{failure_status}");
        assert_eq!(
            user_first_invoice.settlement_status, "pending",
            "{failure_status}"
        );
        assert_eq!(
            user_first_invoice.swap_settlement_status, "pending",
            "{failure_status}"
        );
    }

    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "provider failure hints must not start legacy renegotiation network I/O"
    );
    provider_task.abort();

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn issue30_chain_webhook_ignores_permanent_dedup_and_redrives_late_server_lock() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let npub = create_test_user(&pool, "chainredrive").await;
    let invoice = insert_test_invoice(&pool, "chainredrive", &npub, "lq1chainredrive", 60).await;
    let row = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("chainredrive"),
            boltz_swap_id: "CHAIN_REDRIVE_1",
            lockup_address: "bc1qchainredrive",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{",
        },
    )
    .await
    .unwrap();
    pay_service::db::apply_chain_swap_provider_status(
        &pool,
        row.id,
        pay_service::db::ChainSwapProviderStatusInput::UserLockConfirmed,
    )
    .await
    .unwrap()
    .unwrap();

    let (failed_status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "CHAIN_REDRIVE_1", "status": "transaction.failed"}
        }),
    )
    .await;
    assert_eq!(failed_status, StatusCode::OK);
    let after_failure_hint = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_failure_hint.status, "user_lock_confirmed");
    assert!(!after_failure_hint.cooperative_refused);

    // Seed the legacy permanent status key: chain correctness must not consult
    // it, and the late server lock must still advance and redrive the normal
    // Liquid claim path after a non-authoritative failure hint.
    sqlx::query("INSERT INTO processed_webhook_events (event_id) VALUES ($1)")
        .bind("CHAIN_REDRIVE_1:transaction.server.confirmed")
        .execute(&pool)
        .await
        .unwrap();
    let (server_status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "CHAIN_REDRIVE_1", "status": "transaction.server.confirmed"}
        }),
    )
    .await;
    assert_eq!(server_status, StatusCode::OK);
    let pending_without_quote = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending_without_quote.status, "server_lock_confirmed");
    assert_eq!(pending_without_quote.claim_attempts, 0);
    assert_eq!(pending_without_quote.last_claim_error, None);

    // Review-25 deliberately removed the implicit Liquid fee fallback. The
    // webhook therefore preserves the forward transition while construction
    // waits for accepted same-rail evidence. Inject that typed test evidence
    // through the guarded production claim seam so each delivery can exercise
    // action redrive without weakening the fail-closed runtime path.
    let first_claim_error = chain_claim_pool_error(&pool, row.id).await;
    assert!(first_claim_error
        .to_string()
        .contains("invalid chain boltz response json"));
    let claimed_branch = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed_branch.status, "server_lock_confirmed");
    assert_eq!(claimed_branch.claim_attempts, 1);
    assert!(claimed_branch
        .last_claim_error
        .as_deref()
        .is_some_and(|error| error.contains("invalid chain boltz response json")));

    let (repeat_status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "CHAIN_REDRIVE_1", "status": "transaction.server.confirmed"}
        }),
    )
    .await;
    assert_eq!(repeat_status, StatusCode::OK);
    let repeat_claim_error = chain_claim_pool_error(&pool, row.id).await;
    assert!(repeat_claim_error
        .to_string()
        .contains("invalid chain boltz response json"));
    let repeated = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repeated.status, "server_lock_confirmed");
    assert_eq!(
        repeated.claim_attempts, 2,
        "identical later evidence must redrive a previously failed claim action"
    );

    let (reordered_failure_status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "CHAIN_REDRIVE_1", "status": "transaction.lockupFailed"}
        }),
    )
    .await;
    assert_eq!(reordered_failure_status, StatusCode::OK);
    let reordered_claim_error = chain_claim_pool_error(&pool, row.id).await;
    assert!(reordered_claim_error
        .to_string()
        .contains("invalid chain boltz response json"));
    let after_reordered_failure = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_reordered_failure.status, "server_lock_confirmed");
    assert_eq!(
        after_reordered_failure.claim_attempts, 3,
        "reordered failure evidence must preserve and redrive the late Liquid claim branch"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn issue30_cancelled_chain_transition_can_retry_the_identical_evidence() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    let npub = create_test_user(&pool, "chainretry").await;
    let invoice = insert_test_invoice(&pool, "chainretry", &npub, "lq1chainretry", 60).await;
    let row = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("chainretry"),
            boltz_swap_id: "CHAIN_RETRY_1",
            lockup_address: "bc1qchainretry",
            lockup_bip21: None,
            user_lock_amount_sat: 1_000,
            server_lock_amount_sat: 990,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{}",
        },
    )
    .await
    .unwrap();

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM chain_swap_records WHERE id = $1 FOR UPDATE")
        .bind(row.id)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let first = tokio::time::timeout(
        Duration::from_millis(100),
        post_json(
            &app,
            "/webhook/boltz",
            json!({
                "event": "swap.update",
                "data": {"id": "CHAIN_RETRY_1", "status": "transaction.confirmed"}
            }),
        ),
    )
    .await;
    assert!(
        first.is_err(),
        "the first transition must be cancelled at its row lock"
    );
    blocker.rollback().await.unwrap();

    let after_cancel = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_cancel.status, "pending");
    let dedup_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM processed_webhook_events WHERE event_id = $1")
            .bind("CHAIN_RETRY_1:transaction.confirmed")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dedup_rows, 0);

    let (retry_status, _) = post_json(
        &app,
        "/webhook/boltz",
        json!({
            "event": "swap.update",
            "data": {"id": "CHAIN_RETRY_1", "status": "transaction.confirmed"}
        }),
    )
    .await;
    assert_eq!(retry_status, StatusCode::OK);
    let after_retry = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_retry.status, "user_lock_confirmed");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn issue82_unfunded_finalize_is_exact_once_across_retry_restart_and_reordering() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "chain82finalize").await;
    let invoice =
        insert_test_invoice(&pool, "chain82finalize", &npub, "lq1chain82finalize", 60).await;
    let row = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("chain82finalize"),
            boltz_swap_id: "CHAIN_82_FINALIZE_1",
            lockup_address: "bc1qchain82finalize",
            lockup_bip21: None,
            user_lock_amount_sat: 42_000,
            server_lock_amount_sat: 41_000,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{}",
        },
    )
    .await
    .unwrap();

    let empty_primary_audit =
        pay_service::chain_lockup_witness_audit::ChainLockupManifestWitnessAuditV1 {
            manifest_sequence: 1,
            manifest_id: Uuid::from_u128(1),
            chain_swap_id: row.id,
            expected_amount_sat: 42_000,
            classification:
                pay_service::chain_lockup_witness_audit::ChainLockupManifestClassificationV1::Missing,
            findings: vec![],
        };
    let project_primary = || {
        pay_service::chain_swap_primary_source::project_primary_bitcoin_source_v1(
            &empty_primary_audit,
            None,
            pay_service::chain_swap_primary_source::PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
        )
        .unwrap()
    };
    let runtime_evidence = pay_service::chain_swap_action::ChainSwapEvidence {
        quality: pay_service::chain_swap_action::EvidenceQuality::CompleteAndAgreed,
        provider_status: pay_service::chain_swap_action::ProviderStatusEvidence::Unknown,
        bitcoin_source: pay_service::chain_swap_action::BitcoinSourceEvidence::Unknown,
        liquid_lock: pay_service::chain_swap_action::LiquidLockEvidence::NotObserved,
        liquid_path: pay_service::chain_swap_action::LiquidPathEvidence::Unavailable,
        renegotiation: pay_service::chain_swap_action::RenegotiationEvidence::ExplicitlyUnavailable,
        recovery_destination:
            pay_service::chain_swap_action::RecoveryDestinationEvidence::Committed,
        cooperative_recovery:
            pay_service::chain_swap_action::CooperativeRecoveryEvidence::Unavailable,
        bitcoin_timeout: pay_service::chain_swap_action::BitcoinTimeoutEvidence::BeforeTimeout,
        liquid_claim_transaction: pay_service::chain_swap_action::MerchantTransactionEvidence::None,
        bitcoin_recovery_transaction:
            pay_service::chain_swap_action::MerchantTransactionEvidence::None,
    };

    let inconclusive_primary =
        pay_service::chain_swap_primary_source::project_primary_bitcoin_source_v1(
            &empty_primary_audit,
            None,
            pay_service::chain_swap_primary_source::PrimaryBitcoinSourceAuthorityV1::UntrustedSingleBackend,
        )
        .unwrap();
    let inconclusive_input = pay_service::chain_swap_runtime::ChainSwapProviderEvidence {
        evidence: runtime_evidence,
        primary_bitcoin: Some(&inconclusive_primary),
    };
    assert_eq!(
        pay_service::chain_swap_runtime::apply_chain_swap_provider_effect_with_evidence(
            &pool,
            row.id,
            "swap.expired",
            inconclusive_input,
        )
        .await
        .unwrap(),
        pay_service::chain_swap_runtime::ChainSwapProviderApplyOutcome::Observed
    );
    assert_eq!(
        pay_service::db::get_chain_swap_by_id(&pool, row.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );

    let first_primary = project_primary();
    let first_input = pay_service::chain_swap_runtime::ChainSwapProviderEvidence {
        evidence: runtime_evidence,
        primary_bitcoin: Some(&first_primary),
    };
    assert_eq!(
        pay_service::chain_swap_runtime::decide_chain_swap_provider_effect(
            "swap.expired",
            first_input,
        ),
        pay_service::chain_swap_runtime::ChainSwapProviderEffect::FinalizeUnfunded
    );
    assert_eq!(
        pay_service::chain_swap_runtime::apply_chain_swap_provider_effect_with_evidence(
            &pool,
            row.id,
            "swap.expired",
            first_input,
        )
        .await
        .unwrap(),
        pay_service::chain_swap_runtime::ChainSwapProviderApplyOutcome::Finalized
    );

    let first_updated_at: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::BIGINT \
         FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Rebuild the projection/input as a restarted process would, replay the
    // exact delivery, then reorder active and unknown provider observations.
    let restarted_primary = project_primary();
    let restarted_input = pay_service::chain_swap_runtime::ChainSwapProviderEvidence {
        evidence: runtime_evidence,
        primary_bitcoin: Some(&restarted_primary),
    };
    let exact_retry =
        pay_service::chain_swap_runtime::apply_chain_swap_provider_effect_with_evidence(
            &pool,
            row.id,
            "swap.expired",
            restarted_input,
        )
        .await
        .unwrap();
    assert_eq!(
        exact_retry,
        pay_service::chain_swap_runtime::ChainSwapProviderApplyOutcome::AlreadyFinalized
    );

    for reordered_status in ["transaction.confirmed", "provider.unknown"] {
        assert_eq!(
            pay_service::chain_swap_runtime::apply_chain_swap_provider_effect_with_evidence(
                &pool,
                row.id,
                reordered_status,
                restarted_input,
            )
            .await
            .unwrap(),
            pay_service::chain_swap_runtime::ChainSwapProviderApplyOutcome::AlreadyFinalized,
            "reordered_status={reordered_status}"
        );
    }
    assert_eq!(
        pay_service::chain_swap_runtime::apply_chain_swap_provider_effect_with_evidence(
            &pool,
            row.id,
            "swap.expired",
            restarted_input,
        )
        .await
        .unwrap(),
        pay_service::chain_swap_runtime::ChainSwapProviderApplyOutcome::AlreadyFinalized
    );

    let persisted = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.status, "expired");
    let after_replays_updated_at: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::BIGINT \
         FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_replays_updated_at, first_updated_at);

    let scan_epoch_micros: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM NOW()) * 1000000)::BIGINT")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(pay_service::db::list_non_terminal_chain_swaps_oldest_first(
        &pool,
        0,
        scan_epoch_micros,
        None,
        100,
    )
    .await
    .unwrap()
    .into_iter()
    .all(|candidate| candidate.id != row.id));
    assert!(pay_service::db::get_ready_to_claim_chain_swaps(&pool)
        .await
        .unwrap()
        .into_iter()
        .all(|candidate| candidate.id != row.id));

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
    let row = record_pre_050_chain_fixture(
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
async fn m11_fresh_provider_range_is_cached_and_callback_revalidates_before_mutation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    create_test_user(&pool, "m11freshlimits").await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_provider_limits(
        pool.clone(),
        config,
        Some((Some(test_reverse_pair(250, 2_000)), Instant::now())),
    );
    let boltz = state.boltz.clone();
    let app = test_app(state);

    for request in 1..=3 {
        let (status, body) = get_path(&app, "/.well-known/lnurlp/m11freshlimits").await;
        assert_eq!(status, StatusCode::OK, "metadata request {request}: {body}");
        assert_eq!(
            body["minSendable"], 250_000,
            "metadata request {request}: {body}"
        );
        assert_eq!(
            body["maxSendable"], 2_000_000,
            "metadata request {request}: {body}"
        );
    }
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "metadata reads performed provider I/O"
    );

    let _ = boltz
        .provider_limits()
        .record_successful_refresh(Some(test_reverse_pair(500, 1_500)), Instant::now());
    let before = m11_creation_mutation_snapshot(&pool).await;
    let (status, body) = get_path(&app, "/lnurlp/callback/m11freshlimits?amount=250000").await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "status": "ERROR",
            "code": "InvalidAmount",
            "reason": "minimum is 500000 msat"
        })
    );
    assert_eq!(
        m11_creation_mutation_snapshot(&pool).await,
        before,
        "changed provider limits mutated a key, reservation, or swap row"
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "changed-limit refusal reached the provider"
    );

    provider_task.abort();
    let _ = provider_task.await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn m11_unsafe_provider_snapshots_disable_only_lightning() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let now = Instant::now();
    let cases = [
        ("missing", None),
        ("exactmissing", Some((None, now))),
        ("malformed", Some((Some(test_reverse_pair(0, 1_000)), now))),
        (
            "stale",
            Some((
                Some(test_reverse_pair(100, 1_000)),
                now.checked_sub(Duration::from_secs(91)).unwrap(),
            )),
        ),
        (
            "future",
            Some((
                Some(test_reverse_pair(100, 1_000)),
                now.checked_add(Duration::from_secs(300)).unwrap(),
            )),
        ),
    ];

    for (case, refresh) in cases {
        let nym = format!("m11unsafe{case}");
        create_test_user(&pool, &nym).await;
        let mut config = test_config();
        config.boltz.api_url = boltz_url.clone();
        let product_min_sendable = config.limits.min_sendable_msat;
        let product_max_sendable = config.limits.max_sendable_msat;
        let metadata_origin = format!("https://{}", config.domain);
        let mut state = test_state_with_provider_limits(pool.clone(), config, refresh);
        state.ip_whitelist =
            Arc::new(IpWhitelist::parse(&["127.0.0.1".to_string()]).expect("parse test whitelist"));
        let app = test_app(state);
        let before = m11_creation_mutation_snapshot(&pool).await;

        let (metadata_status, metadata_body) =
            get_path(&app, &format!("/.well-known/lnurlp/{nym}")).await;
        assert_eq!(
            metadata_status,
            StatusCode::OK,
            "case {case}: {metadata_body}"
        );
        assert_eq!(metadata_body["tag"], "payRequest", "case {case}");
        assert_eq!(
            metadata_body["minSendable"],
            json!(product_min_sendable),
            "case {case}"
        );
        assert_eq!(
            metadata_body["maxSendable"],
            json!(product_max_sendable),
            "case {case}"
        );
        assert_eq!(
            metadata_body["payment_methods"],
            json!(["L-BTC"]),
            "case {case}"
        );
        let callback = metadata_body["callback"]
            .as_str()
            .expect("metadata callback string");
        let expected_callback = format!("{metadata_origin}/lnurlp/callback/{nym}");
        assert_eq!(callback, expected_callback, "case {case}");
        let callback_path = callback
            .strip_prefix(&metadata_origin)
            .expect("callback on configured metadata origin");
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            0,
            "case {case}: metadata performed provider I/O"
        );

        let (liquid_status, liquid_body) = get_path_from(
            &app,
            &format!("{callback_path}?amount=100000&payment_method=L-BTC"),
            "127.0.0.1:42111".parse().unwrap(),
        )
        .await;
        assert_eq!(liquid_status, StatusCode::OK, "case {case}: {liquid_body}");
        assert!(
            liquid_body["L-BTC"]["address"]
                .as_str()
                .is_some_and(|address| !address.is_empty()),
            "case {case}: {liquid_body}"
        );
        assert_eq!(
            m11_creation_mutation_snapshot(&pool).await,
            before,
            "case {case}: direct Liquid touched provider-creation state"
        );
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            0,
            "case {case}: direct Liquid caused provider I/O"
        );

        let (lightning_status, lightning_body) =
            get_path(&app, &format!("{callback_path}?amount=100000")).await;
        assert_eq!(
            lightning_status,
            StatusCode::SERVICE_UNAVAILABLE,
            "case {case}: {lightning_body}"
        );
        assert_eq!(
            lightning_body,
            json!({
                "status": "ERROR",
                "code": "ServiceUnavailable",
                "reason": "This payment method is temporarily unavailable. Try again later."
            }),
            "case {case}"
        );
        assert_eq!(
            m11_creation_mutation_snapshot(&pool).await,
            before,
            "case {case}: unavailable Lightning mutated creation state"
        );
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            0,
            "case {case}: unavailable Lightning reached the provider"
        );
    }

    provider_task.abort();
    let _ = provider_task.await;
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
async fn chain_offer_missing_runtime_refuses_before_key_or_provider_mutation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    seed_chain_offer_checkout_surface(&pool, "chainruntimemissing").await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);
    assert!(state.recovery_manifest_runtime_v1().is_none());
    let app = test_app(state);
    let hook = invoice::install_invoice_integration_test_hook(
        invoice::InvoiceIntegrationTestHookPoint::ChainOfferBeforeRecoveryGate,
    );
    let request_app = app.clone();
    let request = tokio::spawn(async move {
        post_json(
            &request_app,
            "/chainruntimemissing/invoice",
            json!({"amount_sat": 1_000}),
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(5), hook.wait_until_reached())
        .await
        .expect("chain offer did not reach its recovery gate");
    let mutation_at_gate = m11_creation_mutation_snapshot(&pool).await;
    let provider_calls_at_gate = provider_calls.load(Ordering::SeqCst);
    assert_eq!(mutation_at_gate.key_allocations, 1);
    assert_eq!(mutation_at_gate.chain_swaps, 0);
    assert_eq!(provider_calls_at_gate, 1);
    hook.release();

    let (status, body) = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .expect("runtime-refused checkout did not finish")
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lightning_pr"], "");
    assert!(body["lightning_amount_sat"].is_null());
    assert_eq!(body["liquid_amount_sat"], 1_000);
    assert!(body["bitcoin_chain_address"].is_null(), "{body}");
    assert!(body["bitcoin_chain_bip21"].is_null(), "{body}");
    assert_eq!(
        m11_creation_mutation_snapshot(&pool).await,
        mutation_at_gate
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        provider_calls_at_gate
    );

    provider_task.abort();
    let _ = provider_task.await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn chain_offer_permit_contention_refuses_before_key_or_provider_mutation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    seed_chain_offer_checkout_surface(&pool, "chainpermitbusy").await;
    let runtime = test_recovery_manifest_runtime();
    let held_permit = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("hold competing chain-creation permit");
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let mut state = test_state_with_config(pool.clone(), config);
    state.recovery_manifest_runtime_v1 = Some(runtime);
    let app = test_app(state);
    let hook = invoice::install_invoice_integration_test_hook(
        invoice::InvoiceIntegrationTestHookPoint::ChainOfferBeforeRecoveryGate,
    );
    let request_app = app.clone();
    let request = tokio::spawn(async move {
        post_json(
            &request_app,
            "/chainpermitbusy/invoice",
            json!({"amount_sat": 1_000}),
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(5), hook.wait_until_reached())
        .await
        .expect("chain offer did not reach its permit gate");
    let mutation_at_gate = m11_creation_mutation_snapshot(&pool).await;
    let provider_calls_at_gate = provider_calls.load(Ordering::SeqCst);
    assert_eq!(mutation_at_gate.key_allocations, 1);
    assert_eq!(mutation_at_gate.chain_swaps, 0);
    assert_eq!(provider_calls_at_gate, 1);
    hook.release();

    let (status, body) = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .expect("permit-refused checkout did not finish")
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lightning_pr"], "");
    assert!(body["bitcoin_chain_address"].is_null(), "{body}");
    assert!(body["bitcoin_chain_bip21"].is_null(), "{body}");
    assert_eq!(
        m11_creation_mutation_snapshot(&pool).await,
        mutation_at_gate
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        provider_calls_at_gate
    );

    held_permit
        .release()
        .await
        .expect("release competing chain-creation permit");
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
    let bolt11 = fresh_bolt11(1_050);
    record_pre_050_reverse_fixture(
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
    assert_eq!(retry_body["lightning_amount_sat"], 1_050);
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

    let bolt11 = fresh_bolt11(1_050);
    record_pre_050_reverse_fixture(
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
    let backend_before: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&constrained)
        .await
        .unwrap();
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let app = test_app(test_state_with_config(constrained.clone(), config));
    let path = format!("/api/v1/invoices/{}/lightning", invoice.id);
    let (status, body) =
        tokio::time::timeout(Duration::from_secs(2), post_json(&app, &path, json!({})))
            .await
            .expect("offer reuse attempted a nested pool acquisition with one connection");

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pr"], bolt11);
    assert_eq!(body["lightning_amount_sat"], 1_050);
    let (second_status, second_body) =
        tokio::time::timeout(Duration::from_secs(2), post_json(&app, &path, json!({})))
            .await
            .expect("second offer reuse did not return its connection to the pool");
    assert_eq!(second_status, StatusCode::OK, "{second_body}");
    assert_eq!(second_body["pr"], bolt11);
    let backend_after: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&constrained)
        .await
        .unwrap();
    assert_eq!(
        backend_after, backend_before,
        "successful cached-offer paths churned the physical PostgreSQL session"
    );
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
async fn cancelled_lazy_offer_does_not_leak_its_session_advisory_lock() {
    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let nym = "lazyoffercancelled";
    let npub = create_test_user(&admin, nym).await;
    let invoice = insert_test_invoice(&admin, nym, &npub, "lq1lazyoffercancelled", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&admin)
        .await
        .unwrap();

    let bolt11 = fresh_bolt11(1_050);
    let provider =
        spawn_successful_reverse_barrier_server("LAZY_OFFER_CANCEL_RETRY_1", &bolt11).await;
    let mut config = test_config();
    config.boltz.api_url = provider.base_url.clone();
    let constrained = constrained_test_pool(1, None);
    let app = test_app(test_state_with_config(constrained.clone(), config));
    let path = format!("/api/v1/invoices/{}/lightning", invoice.id);

    let first_app = app.clone();
    let first_path = path.clone();
    let first = tokio::spawn(async move { post_json(&first_app, &first_path, json!({})).await });
    provider.wait_until_request_is_blocked().await;
    first.abort();
    assert!(
        first.await.unwrap_err().is_cancelled(),
        "first lazy-offer request was not cancelled at provider I/O"
    );
    // Let the fixture finish the abandoned HTTP handler. The request future's
    // drop must already have closed the one PostgreSQL session that still held
    // the advisory lock.
    provider.release_response().await;

    let retry_app = app.clone();
    let retry_path = path.clone();
    let retry = tokio::spawn(async move { post_json(&retry_app, &retry_path, json!({})).await });
    provider.wait_until_request_is_blocked().await;
    provider.release_response().await;
    let (status, body) = tokio::time::timeout(Duration::from_secs(3), retry)
        .await
        .expect("retry could not acquire the single-connection pool after cancellation")
        .expect("lazy-offer retry task failed");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pr"], bolt11);
    assert_eq!(body["lightning_amount_sat"], 1_050);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);

    let allocation_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM swap_key_allocations WHERE purpose = 'reverse_claim'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(
        allocation_count, 2,
        "cancelled provider I/O should leave one auditable gap before retry"
    );
    let attached_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM swap_records WHERE boltz_swap_id = 'LAZY_OFFER_CANCEL_RETRY_1'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(attached_count, 1);

    provider.shutdown().await;
    drop(app);
    constrained.close().await;
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn failed_lazy_provider_call_leaves_durable_auditable_key_gap() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "lazyofferproviderfailure";
    let npub = create_test_user(&pool, nym).await;
    let invoice =
        insert_test_invoice(&pool, nym, &npub, "lq1lazyofferproviderfailure", 3_600).await;
    sqlx::query("UPDATE invoices SET accept_ln = TRUE WHERE id = $1")
        .bind(invoice.id)
        .execute(&pool)
        .await
        .unwrap();

    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let app = test_app(test_state_with_config(pool.clone(), config));

    let (status, body) = post_json(
        &app,
        &format!("/api/v1/invoices/{}/lightning", invoice.id),
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "LNURL errors use a JSON error envelope"
    );
    assert_eq!(body["code"], "BoltzError", "unexpected response: {body}");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before + 1
    );

    let orphan: (i64, String, i32, i32, String, String, String) = sqlx::query_as(
        "SELECT child_index, root_fingerprint, key_epoch, \
                derivation_scheme_version, purpose, public_key_hex, \
                preimage_hash_hex \
           FROM swap_key_allocations WHERE child_index = $1",
    )
    .bind(sequence_before)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(orphan.0, sequence_before);
    assert_eq!(orphan.1, "0000000000000000");
    assert_eq!(orphan.2, 1);
    assert_eq!(orphan.3, pay_service::db::DERIVATION_SCHEME_VERSION);
    assert_eq!(orphan.4, "reverse_claim");
    assert_eq!(orphan.5.len(), 66);
    assert_eq!(orphan.6.len(), 64);
    let attached: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM swap_records WHERE key_allocation_id IN (\
             SELECT id FROM swap_key_allocations WHERE child_index = $1\
         )",
    )
    .bind(sequence_before)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        attached, 0,
        "failed provider allocation was attached to a swap"
    );

    provider_task.abort();
    let _ = provider_task.await;
    cleanup_db(&pool).await;
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
    record_pre_050_reverse_fixture(
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
    record_pre_050_reverse_fixture(
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

    let replacement_bolt11 = fresh_replacement_bolt11(1_050);
    let provider = spawn_successful_reverse_barrier_server(
        "LAZY_OFFER_TERMINAL_REPLACEMENT_1",
        &replacement_bolt11,
    )
    .await;
    let mut config = test_config();
    config.boltz.api_url = provider.base_url.clone();
    let constrained = constrained_test_pool(1, None);
    let app = test_app(test_state_with_config(constrained.clone(), config));
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
    assert_eq!(offer["lightning_amount_sat"], 1_050);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let requests = provider.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert!(requests[0].get("invoiceAmount").is_none());
    assert_eq!(requests[0]["onchainAmount"], 1_020);
    assert_eq!(requests[0]["pairHash"], "11".repeat(32));
    let requested_claim_public_key = requests[0]["claimPublicKey"]
        .as_str()
        .expect("reverse request claimPublicKey")
        .to_string();
    let requested_preimage_hash = requests[0]["preimageHash"]
        .as_str()
        .expect("reverse request preimageHash")
        .to_string();
    drop(requests);

    let lineage: (
        i64,
        String,
        i32,
        i32,
        String,
        String,
        String,
        i64,
        String,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT s.key_index, s.root_fingerprint, s.key_epoch, \
                s.derivation_scheme_version, s.claim_public_key_hex, \
                s.preimage_hash_hex, a.purpose, a.child_index, \
                a.public_key_hex, a.preimage_hash_hex \
           FROM swap_records s \
           JOIN swap_key_allocations a ON a.id = s.key_allocation_id \
          WHERE s.boltz_swap_id = 'LAZY_OFFER_TERMINAL_REPLACEMENT_1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lineage.0, lineage.7);
    assert_eq!(lineage.1, "0000000000000000");
    assert_eq!(lineage.2, 1);
    assert_eq!(lineage.3, pay_service::db::DERIVATION_SCHEME_VERSION);
    assert_eq!(lineage.4, requested_claim_public_key);
    assert_eq!(lineage.5, requested_preimage_hash);
    assert_eq!(lineage.6, "reverse_claim");
    assert_eq!(lineage.4, lineage.8);
    assert_eq!(Some(lineage.5), lineage.9);

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
    drop(app);
    constrained.close().await;
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

    let stale_bolt11 = fresh_bolt11(649);
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
    assert!(requests[0].get("invoiceAmount").is_none());
    assert_eq!(requests[0]["onchainAmount"], 620);
    assert_eq!(requests[0]["pairHash"], "11".repeat(32));
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

    let bolt11 = fresh_bolt11(649);
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
    assert_eq!(body["lightning_amount_sat"], 649);

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

    let stale_bolt11 = fresh_bolt11(1_050);
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
    assert!(requests[0].get("invoiceAmount").is_none());
    assert_eq!(requests[0]["onchainAmount"], 1_020);
    assert_eq!(requests[0]["pairHash"], "11".repeat(32));
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

    let bolt11 = fresh_bolt11(1_050);
    record_pre_050_reverse_fixture(
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
    assert_eq!(body["lightning_amount_sat"], 1_050);
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
    let stored_cached_pubkey = cached_pubkey.to_ascii_uppercase();
    let cached_outpoint = format!("{}:0", "11".repeat(32));
    let cached_index = pay_service::db::allocate_outpoint_address(
        &pool,
        nym,
        &cached_outpoint,
        &stored_cached_pubkey,
    )
    .await
    .unwrap();
    let expected_address =
        pay_service::descriptor::derive_address(TEST_DESCRIPTOR, cached_index as u32).unwrap();

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    config.rate_limit.per_ip_limit = 1;
    config.rate_limit.per_pubkey_limit = 1;
    config.rate_limit.distinct_nyms_per_ip_limit = 1;
    config.rate_limit.distinct_nyms_per_outpoint_limit = 1;
    config.rate_limit.max_pending_reservations_per_nym = 1;
    let proof_tag = config.proof.message_tag.clone();
    let rate_limit_config = config.rate_limit.clone();
    let mut state = test_state_with_config(pool.clone(), config);
    let rate_limiter = Arc::new(RateLimiter::new(pool.clone(), rate_limit_config));
    state.rate_limiter = rate_limiter.clone();
    state.admission.set_workers_enabled(false);

    let caller = SocketAddr::from(([203, 0, 113, 31], 31_031));
    let pubkey_bucket = format!("pubkey:{cached_pubkey}");
    let caller_source = pay_service::ip_whitelist::source_key(caller.ip());
    let outpoint_source = format!("outpoint:{cached_outpoint}");
    sqlx::query("DELETE FROM rate_limit_events WHERE bucket = $1")
        .bind(&pubkey_bucket)
        .execute(&pool)
        .await
        .unwrap();
    for source in [&caller_source, &outpoint_source] {
        sqlx::query("DELETE FROM nym_access_events WHERE source_key = $1")
            .bind(source)
            .execute(&pool)
            .await
            .unwrap();
    }
    rate_limiter.check_per_pubkey(&cached_pubkey).await.unwrap();
    rate_limiter
        .check_distinct_nyms_per_ip(caller.ip(), "other-nym")
        .await
        .unwrap();
    rate_limiter
        .check_distinct_nyms_per_outpoint(&cached_outpoint, "other-nym")
        .await
        .unwrap();
    assert!(
        state.utxo_backend.is_none(),
        "fixture must prove replay without any configured Liquid backend"
    );
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
    let cached_replay_path = format!(
        "/lnurlp/callback/{nym}?amount=100000&payment_method=L-BTC&outpoint={cached_outpoint}&pubkey={cached_pubkey}&sig={cached_sig}&value=1000&value_bf={proof_blinder}&asset_bf={proof_blinder}"
    );
    let (status, body) = get_path_from(&app, &cached_replay_path, caller).await;

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
    let pubkey_events_after_cached: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM rate_limit_events WHERE bucket = $1")
            .bind(&pubkey_bucket)
            .fetch_one(&pool)
            .await
            .unwrap();
    let caller_fanout_after_cached: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM nym_access_events WHERE source_key = $1")
            .bind(&caller_source)
            .fetch_one(&pool)
            .await
            .unwrap();
    let outpoint_fanout_after_cached: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM nym_access_events WHERE source_key = $1")
            .bind(&outpoint_source)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pubkey_events_after_cached, 1, "replay spent pubkey budget");
    assert_eq!(
        caller_fanout_after_cached, 1,
        "replay spent caller fanout budget"
    );
    assert_eq!(
        outpoint_fanout_after_cached, 1,
        "replay spent outpoint fanout budget"
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);

    // The cache fast path remains inside the callback's outer source gate.
    let (status, body) = get_path_from(&app, &cached_replay_path, caller).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["code"], "RateLimitedSender", "{body}");

    // A fresh, cryptographically valid signature by a different key cannot
    // adopt the cached mapping and must fail before any later gate or mutation.
    let mismatched_key = SecretKey::from_slice(&[9; 32]).unwrap();
    let (mismatched_pubkey, mismatched_sig) = sign_proof(&mismatched_key, &cached_outpoint);
    let mismatched_bucket = format!("pubkey:{mismatched_pubkey}");
    sqlx::query("DELETE FROM rate_limit_events WHERE bucket = $1")
        .bind(&mismatched_bucket)
        .execute(&pool)
        .await
        .unwrap();
    let user_before_mismatch: (i32, Option<String>, bool) = sqlx::query_as(
        "SELECT next_addr_idx, last_callback_at::TEXT, has_been_used FROM users WHERE nym = $1",
    )
    .bind(nym)
    .fetch_one(&pool)
    .await
    .unwrap();
    let (status, body) = get_path(
        &app,
        &format!(
            "/lnurlp/callback/{nym}?amount=100000&payment_method=L-BTC&outpoint={cached_outpoint}&pubkey={mismatched_pubkey}&sig={mismatched_sig}&value=1000&value_bf={proof_blinder}&asset_bf={proof_blinder}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["code"], "PubkeyUtxoMismatch", "{body}");

    let user_after_mismatch: (i32, Option<String>, bool) = sqlx::query_as(
        "SELECT next_addr_idx, last_callback_at::TEXT, has_been_used FROM users WHERE nym = $1",
    )
    .bind(nym)
    .fetch_one(&pool)
    .await
    .unwrap();
    let reservations_after_mismatch: Vec<(String, i32, Option<String>, bool)> = sqlx::query_as(
        "SELECT outpoint, addr_index, pubkey, fulfilled FROM outpoint_addresses \
         WHERE nym = $1 ORDER BY outpoint",
    )
    .bind(nym)
    .fetch_all(&pool)
    .await
    .unwrap();
    let mismatched_pubkey_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM rate_limit_events WHERE bucket = $1")
            .bind(&mismatched_bucket)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(user_after_mismatch, user_before_mismatch);
    assert_eq!(reservations_after_mismatch, reservations_after_cached);
    assert_eq!(mismatched_pubkey_events, 0);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);

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

    for bucket in [
        pubkey_bucket,
        mismatched_bucket,
        format!("pubkey:{uncached_pubkey}"),
    ] {
        sqlx::query("DELETE FROM rate_limit_events WHERE bucket = $1")
            .bind(bucket)
            .execute(&pool)
            .await
            .unwrap();
    }
    for source in [caller_source, outpoint_source] {
        sqlx::query("DELETE FROM nym_access_events WHERE source_key = $1")
            .bind(source)
            .execute(&pool)
            .await
            .unwrap();
    }
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn failed_lightning_fallback_returns_original_liquid_throttle_without_retry() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "liquidthrottletruth";
    create_test_user(&pool, nym).await;

    let secp = Secp256k1::new();
    let proof_key = SecretKey::from_slice(&[10; 32]).unwrap();
    let proof_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &proof_key).to_string();
    let proof_outpoint = format!("{}:0", "33".repeat(32));

    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    config.rate_limit.per_pubkey_limit = 1;
    let proof_tag = config.proof.message_tag.clone();
    let rate_limit_config = config.rate_limit.clone();
    let mut state = test_state_with_config(pool.clone(), config);
    let rate_limiter = Arc::new(RateLimiter::new(pool.clone(), rate_limit_config));
    state.rate_limiter = rate_limiter.clone();
    assert!(state.utxo_backend.is_none());

    let pubkey_bucket = format!("pubkey:{proof_pubkey}");
    sqlx::query("DELETE FROM rate_limit_events WHERE bucket = $1")
        .bind(&pubkey_bucket)
        .execute(&pool)
        .await
        .unwrap();
    rate_limiter.check_per_pubkey(&proof_pubkey).await.unwrap();
    let app = test_app(state);

    let digest =
        pay_service::utxo::ownership_message_digest(proof_tag.as_bytes(), nym, &proof_outpoint);
    let proof_sig = hex::encode(
        secp.sign_ecdsa(&Message::from_digest(digest), &proof_key)
            .serialize_der(),
    );
    let proof_blinder = "01".repeat(32);
    let (status, body) = get_path(
        &app,
        &format!(
            "/lnurlp/callback/{nym}?amount=100000&payment_method=L-BTC&outpoint={proof_outpoint}&pubkey={proof_pubkey}&sig={proof_sig}&value=1000&value_bf={proof_blinder}&asset_bf={proof_blinder}"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "status": "ERROR",
            "code": "RateLimitedSender",
            "reason": "Request rate limit exceeded for this source. Retry later."
        }),
        "failed fallback did not return the original Liquid throttle"
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        1,
        "Lightning fallback should make exactly one provider attempt"
    );
    let pubkey_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM rate_limit_events WHERE bucket = $1")
            .bind(&pubkey_bucket)
            .fetch_one(&pool)
            .await
            .unwrap();
    let reservations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM outpoint_addresses WHERE nym = $1")
            .bind(nym)
            .fetch_one(&pool)
            .await
            .unwrap();
    let swaps: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = $1")
        .bind(nym)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        pubkey_events, 2,
        "expected only the seed and first rejected Liquid attempt; Liquid was retried"
    );
    assert_eq!(reservations, 0);
    assert_eq!(swaps, 0);

    provider_task.abort();
    let _ = provider_task.await;
    sqlx::query("DELETE FROM rate_limit_events WHERE bucket = $1")
        .bind(pubkey_bucket)
        .execute(&pool)
        .await
        .unwrap();
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
            record_pre_050_reverse_fixture(
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
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
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
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
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

#[tokio::test]
async fn bitcoin_watcher_priority_lanes_are_disjoint_complete_and_rotation_bounded() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "btclanes").await;
    let old_partial = insert_test_btc_invoice(&pool, "btclanes", &npub, "bc1qlaneoldpartial")
        .await
        .unwrap();
    let old_settling = insert_test_btc_invoice(&pool, "btclanes", &npub, "bc1qlaneoldsettling")
        .await
        .unwrap();
    let old_cancelled = insert_test_btc_invoice(&pool, "btclanes", &npub, "bc1qlaneoldcancelled")
        .await
        .unwrap();
    let old_expired = insert_test_btc_invoice(&pool, "btclanes", &npub, "bc1qlaneoldexpired")
        .await
        .unwrap();
    let new_unpaid = insert_test_btc_invoice(&pool, "btclanes", &npub, "bc1qlanenew000")
        .await
        .unwrap();

    sqlx::query(
        "UPDATE invoices SET \
             created_at = TIMESTAMPTZ '2026-07-12 08:00:00+00', \
             expires_at = TIMESTAMPTZ '2026-07-13 00:00:00+00', \
             status = 'cancelled', presentation_status = 'unpaid', \
             cancelled_at = TIMESTAMPTZ '2026-07-12 08:01:00+00' \
         WHERE id = $1",
    )
    .bind(old_cancelled.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices SET \
             created_at = TIMESTAMPTZ '2026-07-12 08:30:00+00', \
             expires_at = TIMESTAMPTZ '2026-07-12 08:31:00+00', \
             status = 'expired', presentation_status = 'unpaid' \
         WHERE id = $1",
    )
    .bind(old_expired.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices SET \
             created_at = TIMESTAMPTZ '2026-07-12 09:00:00+00', \
             expires_at = TIMESTAMPTZ '2026-07-13 00:00:00+00', \
             status = 'cancelled', presentation_status = 'partial', \
             cancelled_at = TIMESTAMPTZ '2026-07-12 09:01:00+00', \
             paid_via = 'bitcoin', paid_amount_sat = 100 \
         WHERE id = $1",
    )
    .bind(old_partial.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices SET \
             created_at = TIMESTAMPTZ '2026-07-12 10:00:00+00', \
             expires_at = TIMESTAMPTZ '2026-07-13 00:00:00+00', \
             status = 'in_progress', presentation_status = 'payment_received', \
             direct_settlement_status = 'pending', settlement_status = 'pending' \
         WHERE id = $1",
    )
    .bind(old_settling.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices SET \
             created_at = TIMESTAMPTZ '2026-07-12 11:30:00+00', \
             expires_at = TIMESTAMPTZ '2026-07-13 00:00:00+00' \
         WHERE id = $1",
    )
    .bind(new_unpaid.id)
    .execute(&pool)
    .await
    .unwrap();

    let snapshot = "2026-07-12 12:00:00+00";
    let recent = pay_service::db::list_bitcoin_watcher_invoice_page(
        &pool,
        3_600,
        0,
        snapshot,
        pay_service::db::WatcherLane::Recent,
        None,
        None,
        100,
    )
    .await
    .unwrap();
    assert!(!recent.has_more);
    assert_eq!(
        recent.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![old_partial.id, old_settling.id, new_unpaid.id]
    );
    let bounded_recent = pay_service::db::list_bitcoin_watcher_invoice_page(
        &pool,
        3_600,
        0,
        snapshot,
        pay_service::db::WatcherLane::Recent,
        None,
        None,
        2,
    )
    .await
    .unwrap();
    assert!(bounded_recent.has_more);
    assert_eq!(
        bounded_recent
            .rows
            .iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        vec![old_partial.id, old_settling.id]
    );

    let historical = pay_service::db::list_bitcoin_watcher_invoice_page(
        &pool,
        3_600,
        0,
        snapshot,
        pay_service::db::WatcherLane::Historical,
        None,
        None,
        100,
    )
    .await
    .unwrap();
    assert!(!historical.has_more);
    assert_eq!(
        historical.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![old_cancelled.id, old_expired.id]
    );

    let rotation_start = old_settling.id;
    let rotation_cursor = pay_service::db::WatcherScanCursor {
        created_at: "2026-07-12 10:00:00+00".to_string(),
        id: rotation_start,
    };
    let tail = pay_service::db::list_bitcoin_watcher_invoice_page(
        &pool,
        3_600,
        0,
        snapshot,
        pay_service::db::WatcherLane::Recent,
        Some(&rotation_cursor),
        None,
        100,
    )
    .await
    .unwrap();
    assert_eq!(
        tail.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![new_unpaid.id]
    );
    let wrap = pay_service::db::list_bitcoin_watcher_invoice_page(
        &pool,
        3_600,
        0,
        snapshot,
        pay_service::db::WatcherLane::Recent,
        None,
        Some(&rotation_cursor),
        100,
    )
    .await
    .unwrap();
    assert_eq!(
        wrap.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![old_partial.id, old_settling.id]
    );

    let (recent_count, recent_oldest, recent_lag) = pay_service::db::bitcoin_watcher_lane_lag(
        &pool,
        3_600,
        0,
        snapshot,
        pay_service::db::WatcherLane::Recent,
    )
    .await
    .unwrap();
    assert_eq!(recent_count, 3);
    assert!(recent_oldest.unwrap().starts_with("2026-07-12 09:00:00"));
    assert_eq!(recent_lag, 10_800);

    cleanup_db(&pool).await;
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
    record_pre_050_reverse_fixture(
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
    let repair_epoch_micros: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000000)::BIGINT")
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
async fn payable_lightning_only_invoice_keeps_liquid_claim_destination_private() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (npub, _, _, keypair) = sign_registration_with_keypair("lnonlyprivate", TEST_DESCRIPTOR);
    pay_service::db::create_user(&pool, "lnonlyprivate", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let invoice = pay_service::db::insert_invoice(
        &pool,
        &pay_service::db::NewInvoice {
            nym_owner: Some("lnonlyprivate"),
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
            accept_ln: true,
            accept_liquid: false,
            bitcoin_address: None,
            liquid_address: Some("lq1internalclaimdestination"),
            liquid_blinding_key_hex: None,
            expires_in_secs: 3_600,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        invoice.liquid_address.as_deref(),
        Some("lq1internalclaimdestination")
    );

    let app = test_app(test_state(pool.clone()));
    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "unpaid");
    assert_eq!(body["accept_ln"], true);
    assert_eq!(body["accept_liquid"], false);
    assert_eq!(body["liquid_address"], Value::Null);
    assert_eq!(body["bitcoin_address"], Value::Null);

    for path in [
        format!("/lnonlyprivate/i/{}", invoice.id),
        format!("/invoice/{}", invoice.id),
    ] {
        let (status, html) = get_text_path(&app, &path).await;
        assert_eq!(status, StatusCode::OK, "path: {path}");
        assert!(
            !html.contains("lq1internalclaimdestination"),
            "path: {path}"
        );
        assert!(
            html.contains("const INITIAL_LIQUID_ADDRESS = \"\";"),
            "path: {path}"
        );
        assert!(!html.contains("id=\"rail-liquid\""), "path: {path}");
    }

    let (sig, timestamp) = sign_invoice_list_with_keypair(&keypair, &npub, 1, 10, "");
    let (status, body) = get_path(
        &app,
        &format!(
            "/api/v1/invoices?npub={npub}&page=1&pageSize=10&timestamp={timestamp}&signature={sig}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["invoices"][0]["accept_ln"], true);
    assert_eq!(body["invoices"][0]["accept_liquid"], false);
    assert_eq!(
        body["invoices"][0]["liquid_address"],
        "lq1internalclaimdestination"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn cancelled_invoice_keeps_lifecycle_marker_while_direct_money_is_visible() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let state = test_state(pool.clone());
    state.admission.set_workers_enabled(false);
    let app = test_app(state);
    let (npub, _, _, keypair) = sign_registration_with_keypair("cancellatedirect", TEST_DESCRIPTOR);
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

    let finalized = [liquid_lifecycle_observation(
        &event_key,
        txid,
        0,
        "lq1cancellatedirect",
        1_000,
        2,
        pay_service::db::DirectObservationPhase::Finalized,
        None,
    )];
    reserve_and_apply_direct_lifecycle(
        &pool,
        invoice.id,
        pay_service::db::DirectPaymentSource::Liquid,
        &finalized,
    )
    .await;

    let (status, body) = get_path(&app, &format!("/api/v1/invoices/{}/status", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "cancelled");
    assert_eq!(body["presentation_status"], "payment_received");
    assert_eq!(body["settlement_status"], "settled");
    assert_eq!(body["paid_amount_sat"], 1_000);
    assert_eq!(body["remaining_amount_sat"], 0);
    assert_eq!(body["lightning_pr"], Value::Null);
    assert_eq!(body["liquid_address"], Value::Null);
    assert_eq!(body["bitcoin_address"], Value::Null);
    assert_eq!(body["bitcoin_chain_address"], Value::Null);

    let (status, html) = get_text_path(&app, &format!("/cancellatedirect/i/{}", invoice.id)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("lq1cancellatedirect"));
    assert!(html.contains("const INITIAL_LIQUID_ADDRESS = \"\";"));

    let (status, body) = post_json(
        &app,
        &format!("/api/v1/invoices/{}/lightning", invoice.id),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["code"], "InvalidAmount");
    assert!(body.get("pr").is_none());

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
    assert_eq!(body["invoices"][0]["settlement_status"], "settled");
    assert_eq!(body["invoices"][0]["liquid_address"], "lq1cancellatedirect");

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

#[tokio::test]
async fn confirmed_lightning_address_history_advances_cursor_and_fulfills_once() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let _npub = create_test_user(&pool, "confirmedcursor").await;
    let outpoint = "22".repeat(32);
    let pubkey = "02".repeat(33);

    let index =
        pay_service::db::allocate_outpoint_address(&pool, "confirmedcursor", &outpoint, &pubkey)
            .await
            .unwrap();
    assert_eq!(index, 0);

    assert_eq!(
        pay_service::db::mark_reservations_fulfilled_at_idx(
            &pool,
            "confirmedcursor",
            index as u32,
        )
        .await
        .unwrap(),
        1,
    );
    pay_service::db::advance_next_addr_idx(&pool, "confirmedcursor", index as u32)
        .await
        .unwrap();

    assert_eq!(
        pay_service::db::mark_reservations_fulfilled_at_idx(
            &pool,
            "confirmedcursor",
            index as u32,
        )
        .await
        .unwrap(),
        0,
        "replayed confirmation must not fulfill the reservation twice",
    );
    pay_service::db::advance_next_addr_idx(&pool, "confirmedcursor", index as u32)
        .await
        .unwrap();

    let (next_addr_idx, fulfilled): (i32, bool) = sqlx::query_as(
        "SELECT users.next_addr_idx, outpoint_addresses.fulfilled \
         FROM users JOIN outpoint_addresses USING (nym) \
         WHERE users.nym = $1 AND outpoint_addresses.outpoint = $2",
    )
    .bind("confirmedcursor")
    .bind(&outpoint)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(next_addr_idx, 1);
    assert!(fulfilled);

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

    record_pre_050_reverse_fixture(
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

    record_pre_050_reverse_fixture(
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
            record_pre_050_reverse_fixture(
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
async fn liquid_watcher_priority_and_historical_lanes_are_exact_complements() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "liquidlane").await;

    let old_partial =
        insert_test_invoice(&pool, "liquidlane", &npub, "lq1laneoldpartial", 3_600).await;
    let old_settling =
        insert_test_invoice(&pool, "liquidlane", &npub, "lq1laneoldsettling", 3_600).await;
    let old_cancelled =
        insert_test_invoice(&pool, "liquidlane", &npub, "lq1laneoldcancelled", 3_600).await;
    let old_expired =
        insert_test_invoice(&pool, "liquidlane", &npub, "lq1laneoldexpired", -10).await;
    let new_unpaid =
        insert_test_invoice(&pool, "liquidlane", &npub, "lq1lanenewunpaid", 3_600).await;

    sqlx::query(
        "UPDATE invoices \
         SET created_at = NOW() - INTERVAL '2 days', \
             status = 'cancelled', presentation_status = 'partial', \
             cancelled_at = NOW() \
         WHERE id = $1",
    )
    .bind(old_partial.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices \
         SET created_at = NOW() - INTERVAL '2 days', \
             direct_settlement_status = 'pending' \
         WHERE id = $1",
    )
    .bind(old_settling.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices \
         SET created_at = NOW() - INTERVAL '2 days', \
             status = 'cancelled', cancelled_at = NOW() \
         WHERE id = $1",
    )
    .bind(old_cancelled.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invoices \
         SET created_at = NOW() - INTERVAL '2 days', status = 'expired' \
         WHERE id = $1",
    )
    .bind(old_expired.id)
    .execute(&pool)
    .await
    .unwrap();

    let snapshot = pay_service::db::watcher_scan_snapshot(&pool).await.unwrap();
    let recent = pay_service::db::list_liquid_watcher_invoice_lane_page(
        &pool, 0, 86_400, &snapshot, true, None, None,
    )
    .await
    .unwrap();
    let historical = pay_service::db::list_liquid_watcher_invoice_lane_page(
        &pool, 0, 86_400, &snapshot, false, None, None,
    )
    .await
    .unwrap();
    let recent_rotation_start = recent.rows.first().unwrap().scan_cursor();
    let recent_ids: std::collections::HashSet<_> =
        recent.rows.into_iter().map(|row| row.id).collect();
    let historical_ids: std::collections::HashSet<_> =
        historical.rows.into_iter().map(|row| row.id).collect();

    assert!(recent_ids.is_disjoint(&historical_ids));
    assert!(recent_ids.contains(&old_partial.id));
    assert!(recent_ids.contains(&old_settling.id));
    assert!(recent_ids.contains(&new_unpaid.id));
    assert!(historical_ids.contains(&old_cancelled.id));
    assert!(historical_ids.contains(&old_expired.id));

    let after_saved = pay_service::db::list_liquid_watcher_invoice_lane_page(
        &pool,
        0,
        86_400,
        &snapshot,
        true,
        Some(&recent_rotation_start),
        None,
    )
    .await
    .unwrap();
    let through_saved = pay_service::db::list_liquid_watcher_invoice_lane_page(
        &pool,
        0,
        86_400,
        &snapshot,
        true,
        None,
        Some(&recent_rotation_start),
    )
    .await
    .unwrap();
    let after_saved_ids: std::collections::HashSet<_> =
        after_saved.rows.into_iter().map(|row| row.id).collect();
    let through_saved_ids: std::collections::HashSet<_> =
        through_saved.rows.into_iter().map(|row| row.id).collect();
    assert!(after_saved_ids.is_disjoint(&through_saved_ids));
    assert_eq!(
        after_saved_ids
            .union(&through_saved_ids)
            .copied()
            .collect::<std::collections::HashSet<_>>(),
        recent_ids
    );

    let (recent_backlog, recent_oldest_due, recent_lag_secs) =
        pay_service::db::liquid_watcher_lane_lag(&pool, 0, 86_400, &snapshot, true)
            .await
            .unwrap();
    let (historical_backlog, historical_oldest_due, historical_lag_secs) =
        pay_service::db::liquid_watcher_lane_lag(&pool, 0, 86_400, &snapshot, false)
            .await
            .unwrap();
    assert_eq!(recent_backlog, recent_ids.len() as i64);
    assert!(recent_oldest_due.is_some());
    assert!(recent_lag_secs >= 0);
    assert_eq!(historical_backlog, historical_ids.len() as i64);
    assert!(historical_oldest_due.is_some());
    assert!(historical_lag_secs >= 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn latest_lightning_pr_for_invoice_uses_newest_swap_row() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "latestpr").await;
    let invoice = insert_test_invoice(&pool, "latestpr", &npub, "lq1latestpr", 60).await;

    record_pre_050_reverse_fixture(
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

    record_pre_050_reverse_fixture(
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

    let row = record_pre_050_chain_fixture(
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
async fn chain_swap_renegotiation_journal_survives_each_accept_crash_boundary() {
    use pay_service::chain_swap_renegotiation::{
        RenegotiationDomainError, RenegotiationErrorClass, RenegotiationIdentity,
        RenegotiationState, TransitionDisposition,
    };
    use pay_service::db::ChainSwapRenegotiationStoreError;

    let admin = test_pool().await;
    cleanup_db(&admin).await;
    let npub = create_test_user(&admin, "renegotiationjournal").await;
    let invoice = insert_test_invoice(
        &admin,
        "renegotiationjournal",
        &npub,
        "lq1renegotiationjournal",
        60,
    )
    .await;
    let row = record_pre_050_chain_fixture(
        &admin,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some("renegotiationjournal"),
            boltz_swap_id: "renegotiation-journal-swap",
            lockup_address: "bc1qrenegotiationjournal",
            lockup_bip21: None,
            user_lock_amount_sat: 25_000,
            server_lock_amount_sat: 24_750,
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: "{\"id\":\"renegotiation-journal-swap\"}",
        },
    )
    .await
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let identity = RenegotiationIdentity::new(
        row.id,
        24_750,
        "aa".repeat(32),
        now - 2,
        "issue38-v1",
        "bb".repeat(32),
        now - 1,
    )
    .unwrap();

    let runtime = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET ROLE bullnym_app")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&require_test_db())
        .await
        .unwrap();
    let quoted = pay_service::db::persist_quoted_chain_swap_renegotiation(&runtime, &identity)
        .await
        .unwrap();
    assert_eq!(quoted.state, RenegotiationState::Quoted);
    assert_eq!(quoted.version, 1);

    // A Liquid branch that wins after quote observation but before durable
    // accept intent must close the provider-mutation boundary. The journal
    // stays quoted and no version/attempt counter is invented.
    sqlx::query("UPDATE chain_swap_records SET status = 'server_lock_confirmed' WHERE id = $1")
        .bind(row.id)
        .execute(&admin)
        .await
        .unwrap();
    let progressed_parent =
        pay_service::db::request_chain_swap_renegotiation_accept(&runtime, &identity, 1)
            .await
            .unwrap_err();
    assert!(matches!(
        progressed_parent,
        ChainSwapRenegotiationStoreError::ParentNotEligible { chain_swap_id }
            if chain_swap_id == row.id
    ));
    let still_quoted = pay_service::db::get_chain_swap_renegotiation(&runtime, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_quoted.state, RenegotiationState::Quoted);
    assert_eq!(still_quoted.version, 1);
    assert_eq!(still_quoted.accept_attempt_count, 0);
    sqlx::query("UPDATE chain_swap_records SET status = 'user_lock_confirmed' WHERE id = $1")
        .bind(row.id)
        .execute(&admin)
        .await
        .unwrap();

    // Crash before intent commit: the transaction-local request vanishes and
    // a new process still observes the exact retryable quote.
    let mut before_intent = runtime.begin().await.unwrap();
    let staged_state: String = sqlx::query_scalar(
        "UPDATE chain_swap_renegotiation_operations \
            SET state = 'accept_requested', accept_attempt_count = 1, \
                accept_requested_at = clock_timestamp(), version = 2 \
          WHERE chain_swap_id = $1 RETURNING state",
    )
    .bind(row.id)
    .fetch_one(&mut *before_intent)
    .await
    .unwrap();
    assert_eq!(staged_state, "accept_requested");
    before_intent.rollback().await.unwrap();
    let after_before_intent_crash = pay_service::db::get_chain_swap_renegotiation(&runtime, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_before_intent_crash.state, RenegotiationState::Quoted);
    assert_eq!(after_before_intent_crash.version, 1);

    // The typed adapter commits the intent before any external accept is
    // permitted. A restart and an exact retry retain that durable fact.
    let requested =
        pay_service::db::request_chain_swap_renegotiation_accept(&runtime, &identity, 1)
            .await
            .unwrap();
    assert_eq!(requested.disposition, TransitionDisposition::Apply);
    assert_eq!(
        requested.operation.state,
        RenegotiationState::AcceptRequested
    );
    assert_eq!(requested.operation.version, 2);
    let restarted_requested = pay_service::db::get_chain_swap_renegotiation(&runtime, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        restarted_requested.state,
        RenegotiationState::AcceptRequested
    );
    let request_retry =
        pay_service::db::request_chain_swap_renegotiation_accept(&runtime, &identity, 1)
            .await
            .unwrap();
    assert_eq!(request_retry.disposition, TransitionDisposition::ExactRetry);
    assert_eq!(request_retry.operation.version, 2);

    let ambiguous = pay_service::db::mark_chain_swap_renegotiation_ambiguous(
        &runtime,
        &identity,
        2,
        RenegotiationErrorClass::Transport,
    )
    .await
    .unwrap();
    assert_eq!(ambiguous.operation.state, RenegotiationState::Ambiguous);
    assert_eq!(ambiguous.operation.version, 3);
    let false_decline = pay_service::db::mark_chain_swap_renegotiation_declined(
        &runtime,
        &identity,
        3,
        "cc".repeat(32),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        false_decline,
        ChainSwapRenegotiationStoreError::Domain(RenegotiationDomainError::IllegalTransition {
            from: RenegotiationState::Ambiguous,
            to: RenegotiationState::Declined,
        })
    ));

    let redriven = pay_service::db::request_chain_swap_renegotiation_accept(&runtime, &identity, 3)
        .await
        .unwrap();
    assert_eq!(
        redriven.operation.state,
        RenegotiationState::AcceptRequested
    );
    assert_eq!(redriven.operation.accept_attempt_count, 2);
    assert_eq!(redriven.operation.version, 4);
    assert_eq!(
        redriven.operation.last_error_class,
        Some(RenegotiationErrorClass::Transport)
    );

    // Crash after provider response but before result commit: rollback leaves
    // the durable request unresolved, so fallback/decline is still blocked.
    let mut before_result = runtime.begin().await.unwrap();
    let staged_terminal: String = sqlx::query_scalar(
        "UPDATE chain_swap_renegotiation_operations \
            SET state = 'accepted', terminal_response_digest = $2, \
                terminal_observed_at = clock_timestamp(), version = 5 \
          WHERE chain_swap_id = $1 RETURNING state",
    )
    .bind(row.id)
    .bind("dd".repeat(32))
    .fetch_one(&mut *before_result)
    .await
    .unwrap();
    assert_eq!(staged_terminal, "accepted");
    before_result.rollback().await.unwrap();
    let after_before_result_crash = pay_service::db::get_chain_swap_renegotiation(&runtime, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after_before_result_crash.state,
        RenegotiationState::AcceptRequested
    );
    assert_eq!(after_before_result_crash.version, 4);
    assert!(after_before_result_crash
        .terminal_response_digest()
        .is_none());

    let accepted = pay_service::db::mark_chain_swap_renegotiation_accepted(
        &runtime,
        &identity,
        4,
        "dd".repeat(32),
    )
    .await
    .unwrap();
    assert_eq!(accepted.operation.state, RenegotiationState::Accepted);
    assert_eq!(accepted.operation.version, 5);
    let accepted_retry = pay_service::db::mark_chain_swap_renegotiation_accepted(
        &runtime,
        &identity,
        4,
        "dd".repeat(32),
    )
    .await
    .unwrap();
    assert_eq!(
        accepted_retry.disposition,
        TransitionDisposition::ExactRetry
    );
    assert_eq!(accepted_retry.operation.version, 5);

    let stale = pay_service::db::request_chain_swap_renegotiation_accept(&runtime, &identity, 1)
        .await
        .unwrap_err();
    assert!(matches!(
        stale,
        ChainSwapRenegotiationStoreError::Domain(RenegotiationDomainError::StaleVersion {
            expected: 1,
            actual: 5,
        })
    ));

    runtime.close().await;
    cleanup_db(&admin).await;
}

#[tokio::test]
async fn ready_to_claim_chain_swaps_includes_retry_rows_with_claim_txid() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let npub = create_test_user(&pool, "chainretry").await;
    let invoice = insert_test_invoice(&pool, "chainretry", &npub, "lq1chainretry", 60).await;

    let row = record_pre_050_chain_fixture(
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
    let mut legacy_claim_bytes = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *legacy_claim_bytes)
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
    .execute(&mut *legacy_claim_bytes)
    .await
    .unwrap();
    legacy_claim_bytes.commit().await.unwrap();

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

    let row = record_pre_050_chain_fixture(
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

    record_pre_050_reverse_fixture(
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

    let mut legacy_claim_bytes = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *legacy_claim_bytes)
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
    .execute(&mut *legacy_claim_bytes)
    .await
    .unwrap();
    legacy_claim_bytes.commit().await.unwrap();

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
async fn purge_deletes_terminal_swap_secrets_but_retains_key_exclusions() {
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

    let chain_invoice =
        insert_test_invoice(&pool, "purger3", &npub, "lq1purger3chainswap", 60).await;
    let chain = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: chain_invoice.id,
            nym: Some("purger3"),
            boltz_swap_id: "PURGE_TERMINAL_CHAIN_SECRETS",
            lockup_address: "bc1qpurger3terminalchain",
            lockup_bip21: None,
            user_lock_amount_sat: 1_010,
            server_lock_amount_sat: 1_000,
            preimage_hex: "86".repeat(32).as_str(),
            claim_key_hex: "87".repeat(32).as_str(),
            refund_key_hex: "88".repeat(32).as_str(),
            boltz_response_json: "{}",
        },
    )
    .await
    .unwrap();
    pay_service::db::update_chain_swap_status(
        &pool,
        chain.id,
        pay_service::db::ChainSwapStatus::Expired,
        None,
    )
    .await
    .unwrap();

    let root = "9191919191919191";
    let public_key = format!("02{}", "92".repeat(32));
    let preimage_hash = "93".repeat(32);
    let allocation_id = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 9_100,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &public_key,
            preimage_hash_hex: Some(&preimage_hash),
        },
    )
    .await
    .unwrap();
    let preimage = "94".repeat(32);
    let claim_key = "95".repeat(32);
    pay_service::db::record_swap_with_lineage(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("purger3"),
            boltz_swap_id: "PURGE_RETAINED_LINEAGE",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-purge-retained-lineage",
            preimage_hex: &preimage,
            claim_key_hex: &claim_key,
            boltz_response_json: "{}",
            invoice_id: None,
            key_index: Some(9_100),
            root_fingerprint: Some(root),
        },
        &pay_service::db::ReverseSwapLineage {
            allocation_id,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &public_key,
            preimage_hash_hex: &preimage_hash,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE swap_records SET status = 'claimed' WHERE boltz_swap_id = $1")
        .bind("PURGE_RETAINED_LINEAGE")
        .execute(&pool)
        .await
        .unwrap();

    // Model a complete migration-044 identity and the migration-050 backfill
    // that permanently survives deletion of its secret-bearing row.
    let legacy_root = "9696969696969696";
    let legacy_index = 9_600_i64;
    let legacy_preimage = "97".repeat(32);
    let legacy_claim_key = "98".repeat(32);
    record_pre_050_reverse_fixture(
        &pool,
        &pay_service::db::NewSwapRecord {
            nym: Some("purger3"),
            boltz_swap_id: "PURGE_MIGRATION_044_SECRETS",
            address: None,
            address_index: None,
            amount_sat: 1_000,
            invoice: "lnbc-purge-migration-044",
            preimage_hex: &legacy_preimage,
            claim_key_hex: &legacy_claim_key,
            boltz_response_json: "{}",
            invoice_id: None,
            key_index: Some(legacy_index),
            root_fingerprint: Some(legacy_root),
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE swap_records SET status = 'expired' WHERE boltz_swap_id = $1")
        .bind("PURGE_MIGRATION_044_SECRETS")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO swap_key_legacy_high_water (root_fingerprint, max_child_index) \
         VALUES ($1, $2)",
    )
    .bind(legacy_root)
    .bind(legacy_index)
    .execute(&pool)
    .await
    .unwrap();

    let (purge_sig, purge_timestamp) = sign_purge_with_keypair(&keypair, &npub, "purger3");
    let (status, _) = delete_request(
        &app,
        json!({
            "npub": npub, "nym": "purger3", "signature": purge_sig, "purge": true, "timestamp": purge_timestamp,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let reverse_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM swap_records WHERE nym = 'purger3'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let chain_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records WHERE nym = 'purger3'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reverse_rows, 0, "purge retained reverse private secrets");
    assert_eq!(chain_rows, 0, "purge retained chain private secrets");

    let retained_allocation: (String, i64, String, String) = sqlx::query_as(
        "SELECT root_fingerprint, child_index, public_key_hex, preimage_hash_hex \
           FROM swap_key_allocations WHERE id = $1",
    )
    .bind(allocation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        retained_allocation,
        (
            root.to_string(),
            9_100,
            public_key.clone(),
            preimage_hash.clone(),
        )
    );
    let reused_identity_public = format!("03{}", "99".repeat(32));
    let reused_identity_hash = "9a".repeat(32);
    let reused_identity = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: root,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: 9_100,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &reused_identity_public,
            preimage_hash_hex: Some(&reused_identity_hash),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        reused_identity
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_key_allocations_derivation_identity_key")
    );

    assert_eq!(
        pay_service::db::max_legacy_swap_key_index(&pool, legacy_root)
            .await
            .unwrap(),
        Some(legacy_index)
    );
    let legacy_reuse_public = format!("02{}", "9b".repeat(32));
    let legacy_reuse_hash = "9c".repeat(32);
    let reused_legacy_index = pay_service::db::reserve_swap_key_allocation(
        &pool,
        &pay_service::db::NewSwapKeyAllocation {
            root_fingerprint: legacy_root,
            key_epoch: 2,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            child_index: legacy_index,
            purpose: pay_service::db::SwapKeyPurpose::ReverseClaim,
            public_key_hex: &legacy_reuse_public,
            preimage_hash_hex: Some(&legacy_reuse_hash),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        reused_legacy_index
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("swap_key_allocations_legacy_high_water")
    );

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
    let swap = record_pre_050_chain_fixture(
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

/// Test-only fixture shortcut. Production materializes the immutable address
/// atomically while scheduling automatic fallback; tests that exercise later
/// journal states may seed that already-established fact directly.
async fn set_test_refund_destination(pool: &PgPool, id: Uuid, address: &str) {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET refund_address = $2, updated_at = NOW() \
         WHERE id = $1 AND refund_address IS NULL AND status = 'refund_due'",
    )
    .bind(id)
    .bind(address)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        result.rows_affected(),
        1,
        "fixture address must be seeded once"
    );
}

fn bitcoin_fee_decision(rate: f64) -> pay_service::fee_policy::BitcoinFeeDecision {
    bitcoin_fee_decision_with_cap(rate, 500.0)
}

fn bitcoin_fee_decision_with_cap(
    rate: f64,
    cap: f64,
) -> pay_service::fee_policy::BitcoinFeeDecision {
    use pay_service::fee_policy::{BitcoinFeePolicy, FeeProvenance, LiveBitcoin, SatPerVbyte};

    let observation = LiveBitcoin::new(
        SatPerVbyte::try_from(rate).unwrap(),
        1_000,
        FeeProvenance::new("integration-test").unwrap(),
    );
    BitcoinFeePolicy::new(
        SatPerVbyte::try_from(1.0).unwrap(),
        SatPerVbyte::try_from(cap).unwrap(),
        120,
        900,
    )
    .unwrap()
    .decide_typed(Some(&observation), None, 1_000)
    .unwrap()
}

fn midrange_bitcoin_fee_decision() -> pay_service::fee_policy::BitcoinFeeDecision {
    bitcoin_fee_decision(2.0)
}

#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
struct PersistedRecoveryFeeDecision {
    fee_decision_purpose: String,
    fee_decision_rail: String,
    fee_decision_target: String,
    fee_decision_source: String,
    fee_decision_rate_sat_vb: f64,
    fee_decision_quoted_at_unix: i64,
    fee_decision_evaluated_at_unix: i64,
    fee_decision_freshness_age_secs: i64,
    fee_decision_freshness_max_age_secs: i64,
    fee_decision_provenance: String,
    fee_decision_policy_floor_sat_vb: f64,
    fee_decision_policy_cap_sat_vb: f64,
    fee_decision_policy_version: String,
}

async fn persisted_recovery_fee_decision(
    pool: &PgPool,
    chain_swap_id: uuid::Uuid,
) -> PersistedRecoveryFeeDecision {
    sqlx::query_as(
        "SELECT fee_decision_purpose, fee_decision_rail, fee_decision_target, \
                fee_decision_source, fee_decision_rate_sat_vb, \
                fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
                fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
                fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
                fee_decision_policy_cap_sat_vb, fee_decision_policy_version \
           FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND purpose = 'btc_recovery'",
    )
    .bind(chain_swap_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

struct FakeRecoveryBuilder {
    transaction: BtcLikeTransaction,
    source_amount_sat: u64,
    calls: AtomicUsize,
    fee_rates: Mutex<Vec<f64>>,
}

impl FakeRecoveryBuilder {
    fn construct_for_fee_decision(
        &self,
        fee_decision: pay_service::builder_fee::BitcoinBuilderFeeDecision,
    ) -> Result<BtcLikeTransaction, AppError> {
        let BtcLikeTransaction::Bitcoin(mut transaction) = self.transaction.clone() else {
            return Err(AppError::ClaimError(
                "scripted Bitcoin recovery template is not Bitcoin".into(),
            ));
        };
        let final_vbytes = u64::try_from(transaction.vsize()).map_err(|_| {
            AppError::ClaimError("scripted Bitcoin recovery virtual size exceeds u64".into())
        })?;
        let fee_sat = fee_decision
            .rate()
            .checked_fee_for_vbytes(final_vbytes)
            .map_err(|error| {
                AppError::ClaimError(format!("scripted Bitcoin recovery fee is invalid: {error}"))
            })?;
        let destination_sat = self
            .source_amount_sat
            .checked_sub(fee_sat)
            .filter(|amount| *amount > 0)
            .ok_or_else(|| {
                AppError::ClaimError("scripted fee consumes the recovery output".into())
            })?;
        let destination = transaction.output.get_mut(0).ok_or_else(|| {
            AppError::ClaimError("scripted Bitcoin recovery has no destination output".into())
        })?;
        destination.value = bitcoin::Amount::from_sat(destination_sat);
        Ok(BtcLikeTransaction::Bitcoin(transaction))
    }
}

#[async_trait]
impl pay_service::chain_recovery::BitcoinRecoveryBuilder for FakeRecoveryBuilder {
    async fn construct(
        &self,
        _swap: &pay_service::db::ChainSwapRecord,
        _destination_address: &str,
        fee_decision: pay_service::builder_fee::BitcoinBuilderFeeDecision,
    ) -> Result<BtcLikeTransaction, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.fee_rates
            .lock()
            .await
            .push(fee_decision.rate().as_f64());
        self.construct_for_fee_decision(fee_decision)
    }
}

struct FeeSensitiveRecoveryBuilder {
    template: bitcoin::Transaction,
    source_amount_sat: u64,
    calls: AtomicUsize,
    fee_rates: Mutex<Vec<f64>>,
    raw_transactions: Mutex<Vec<String>>,
}

impl FeeSensitiveRecoveryBuilder {
    fn construct_for_rate(&self, rate: f64) -> Result<bitcoin::Transaction, AppError> {
        let mut transaction = self.template.clone();
        let fee_sat = (rate * transaction.vsize() as f64).ceil() as u64;
        let destination_sat = self
            .source_amount_sat
            .checked_sub(fee_sat)
            .filter(|amount| *amount > 0)
            .ok_or_else(|| {
                AppError::ClaimError("scripted fee consumes the recovery output".into())
            })?;
        transaction.output[0].value = bitcoin::Amount::from_sat(destination_sat);
        Ok(transaction)
    }
}

#[async_trait]
impl pay_service::chain_recovery::BitcoinRecoveryBuilder for FeeSensitiveRecoveryBuilder {
    async fn construct(
        &self,
        _swap: &pay_service::db::ChainSwapRecord,
        _destination_address: &str,
        fee_decision: pay_service::builder_fee::BitcoinBuilderFeeDecision,
    ) -> Result<BtcLikeTransaction, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let rate = fee_decision.rate().as_f64();
        self.fee_rates.lock().await.push(rate);
        let transaction = self.construct_for_rate(rate)?;
        self.raw_transactions
            .lock()
            .await
            .push(hex::encode(bitcoin::consensus::serialize(&transaction)));
        Ok(BtcLikeTransaction::Bitcoin(transaction))
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

struct DelayedRecoveryFault {
    point: pay_service::chain_recovery::RecoveryFaultPoint,
    delay: Duration,
    fired: AtomicBool,
}

impl DelayedRecoveryFault {
    fn at(point: pay_service::chain_recovery::RecoveryFaultPoint, delay: Duration) -> Self {
        Self {
            point,
            delay,
            fired: AtomicBool::new(false),
        }
    }
}

impl pay_service::chain_recovery::RecoveryFaultInjector for DelayedRecoveryFault {
    fn check(
        &self,
        point: pay_service::chain_recovery::RecoveryFaultPoint,
    ) -> Result<(), AppError> {
        if point == self.point && !self.fired.swap(true, Ordering::SeqCst) {
            std::thread::sleep(self.delay);
        }
        Ok(())
    }
}

struct RecoveryJournalHarness {
    swap: pay_service::db::ChainSwapRecord,
    builder: Arc<FakeRecoveryBuilder>,
    fee_decision: pay_service::fee_policy::BitcoinFeeDecision,
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
    let fee_decision = midrange_bitcoin_fee_decision();
    let recovery_template = bitcoin::Transaction {
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
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: destination_script,
        }],
    };
    let builder = Arc::new(FakeRecoveryBuilder {
        transaction: BtcLikeTransaction::Bitcoin(recovery_template),
        source_amount_sat: 100_000,
        calls: AtomicUsize::new(0),
        fee_rates: Mutex::new(Vec::new()),
    });
    let BtcLikeTransaction::Bitcoin(recovery_tx) = builder
        .construct_for_fee_decision(pay_service::builder_fee::BitcoinBuilderFeeDecision::from(
            &fee_decision,
        ))
        .unwrap()
    else {
        unreachable!("scripted recovery builder returns a Bitcoin transaction")
    };
    let expected_txid = recovery_tx.compute_txid().to_string();
    let expected_raw_hex = hex::encode(bitcoin::consensus::serialize(&recovery_tx));

    let chain = Arc::new(FakeBitcoinChain::default());
    chain.transactions.lock().await.insert(
        source_txid.clone(),
        bitcoin::consensus::serialize(&source_tx),
    );
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
    set_test_refund_destination(pool, swap.id, JOURNAL_DESTINATION_ADDRESS).await;
    let swap = pay_service::db::get_chain_swap_by_id(pool, swap.id)
        .await
        .unwrap()
        .unwrap();

    RecoveryJournalHarness {
        swap,
        builder,
        fee_decision,
        chain,
        broadcaster,
        source_txid,
        expected_txid,
        expected_raw_hex,
    }
}

async fn seed_liquid_merchant_settlement_attempt(pool: &PgPool, suffix: &str) -> (Uuid, String) {
    const DESTINATION_ADDRESS: &str =
        "lq1qqvxk052kf3qtkxmrakx50a9gc3smqad2ync54hzntjt980kfej9kkfe0247rp5h4yzmdftsahhw64uy8pzfe7cpg4fgykm7cv";
    const ASSET_ID: &str = "6f0279e9ed041c3d710a9f57d0c02928416453c0e87cbbe43c8ca792a3b6e499";

    let nym = format!("lmjs{suffix}");
    let boltz_id = format!("liquid-merchant-journal-{suffix}");
    let (_, _, _, swap) = seed_merchant_invoice_swap(
        pool,
        &nym,
        &boltz_id,
        &format!("el1qqlockup{suffix}"),
        1_100,
        1_000,
    )
    .await;
    let destination_script = lwk_wollet::elements::Address::from_str(DESTINATION_ADDRESS)
        .unwrap()
        .script_pubkey();
    let destination_script_hex = hex::encode(destination_script.as_bytes());
    let source_txid =
        lwk_wollet::elements::Txid::from_str(&format!("{:064x}", swap.id.as_u128())).unwrap();
    let asset = lwk_wollet::elements::AssetId::from_str(ASSET_ID).unwrap();
    let transaction = lwk_wollet::elements::Transaction {
        version: 2,
        lock_time: lwk_wollet::elements::LockTime::ZERO,
        input: vec![lwk_wollet::elements::TxIn {
            previous_output: lwk_wollet::elements::OutPoint::new(source_txid, 0),
            is_pegin: false,
            script_sig: lwk_wollet::elements::Script::new(),
            sequence: lwk_wollet::elements::Sequence::MAX,
            asset_issuance: lwk_wollet::elements::AssetIssuance::default(),
            witness: lwk_wollet::elements::TxInWitness::default(),
        }],
        output: vec![
            lwk_wollet::elements::TxOut {
                asset: lwk_wollet::elements::confidential::Asset::Explicit(asset),
                value: lwk_wollet::elements::confidential::Value::Explicit(1_000),
                nonce: lwk_wollet::elements::confidential::Nonce::Null,
                script_pubkey: destination_script,
                witness: lwk_wollet::elements::TxOutWitness::default(),
            },
            lwk_wollet::elements::TxOut {
                asset: lwk_wollet::elements::confidential::Asset::Explicit(asset),
                value: lwk_wollet::elements::confidential::Value::Explicit(100),
                nonce: lwk_wollet::elements::confidential::Nonce::Null,
                script_pubkey: lwk_wollet::elements::Script::new(),
                witness: lwk_wollet::elements::TxOutWitness::default(),
            },
        ],
    };
    let txid = transaction.txid().to_string();
    let raw_tx_hex = hex::encode(lwk_wollet::elements::encode::serialize(&transaction));
    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'claiming', claim_tx_hex = $2, claim_txid = $3, \
             claim_actual_fee_sat = 100, claim_actual_fee_rate_sat_vb = 1.5, \
             claim_fee_decision_purpose = 'chain_liquid_claim', \
             claim_fee_decision_rail = 'liquid', claim_fee_decision_target = '1', \
             claim_fee_decision_source = 'liquid_live', \
             claim_fee_decision_rate_sat_vb = 1.5, \
             claim_fee_decision_quoted_at_unix = 1700000100, \
             claim_fee_decision_evaluated_at_unix = 1700000105, \
             claim_fee_decision_freshness_age_secs = 5, \
             claim_fee_decision_freshness_max_age_secs = 60, \
             claim_fee_decision_provenance = 'integration-test-liquid-live', \
             claim_fee_decision_policy_floor_sat_vb = 0.1, \
             claim_fee_decision_policy_cap_sat_vb = 10.0, \
             claim_fee_decision_policy_version = 'review25-v1', \
             updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(swap.id)
    .bind(&raw_tx_hex)
    .bind(&txid)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chain_swap_tx_attempts (\
             chain_swap_id, purpose, replaces_txid, raw_tx_hex, txid, source_prevouts, \
             destination_address, destination_script_hex, destination_asset_id, \
             destination_vout, destination_amount_sat, fee_amount_sat, fee_rate_sat_vb, \
             liquid_blinding_key_hex, \
             fee_decision_purpose, fee_decision_rail, fee_decision_target, \
             fee_decision_source, fee_decision_rate_sat_vb, \
             fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
             fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
             fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
             fee_decision_policy_cap_sat_vb, fee_decision_policy_version\
         ) VALUES (\
             $1,'liquid_claim',NULL,$2,$3,$4,$5,$6,$7,0,1000,100,1.5,$8, \
             'chain_liquid_claim','liquid','1','liquid_live',1.5, \
             1700000100,1700000105,5,60,'integration-test-liquid-live', \
             0.1,10.0,'review25-v1'\
         )",
    )
    .bind(swap.id)
    .bind(&raw_tx_hex)
    .bind(&txid)
    .bind(json!([{
        "txid": source_txid.to_string(),
        "vout": 0,
        "amount_sat": 1_100,
        "script_pubkey_hex": "0014abcd"
    }]))
    .bind(DESTINATION_ADDRESS)
    .bind(destination_script_hex)
    .bind(ASSET_ID)
    .bind("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .execute(pool)
    .await
    .unwrap();
    (swap.id, txid)
}

fn verified_liquid_merchant_output(
    txid: &str,
    destination_address: &str,
    destination_script_hex: &str,
    asset_id: &str,
    confirmations: u32,
    block_height: u32,
    block_hash: &str,
) -> pay_service::merchant_output_verifier::VerifiedMerchantOutput {
    use pay_service::merchant_output_verifier::{
        verify_merchant_output, ApprovedMerchantDestination, JournaledMerchantTransaction,
        MerchantAsset, MerchantOutputEvidence, ObservedMerchantOutput,
    };

    let asset = MerchantAsset::Liquid(asset_id.to_owned());
    let approved =
        ApprovedMerchantDestination::liquid(destination_address, destination_script_hex, asset_id);
    let journal = JournaledMerchantTransaction::original(
        txid,
        destination_address,
        destination_script_hex,
        asset.clone(),
        1_000,
        0,
    );
    verify_merchant_output(
        txid,
        &journal,
        &approved,
        &MerchantOutputEvidence::Authoritative(ObservedMerchantOutput::new(
            txid,
            destination_script_hex,
            asset,
            1_000,
            0,
            confirmations,
            Some(block_height),
            Some(block_hash.to_owned()),
        )),
        1,
    )
    .unwrap()
}

struct FakeChainClaimSource {
    raw_transactions: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl pay_service::utxo::UtxoBackend for FakeChainClaimSource {
    async fn get_raw_tx(&self, txid_hex: &str) -> Result<Vec<u8>, AppError> {
        self.raw_transactions
            .get(txid_hex)
            .cloned()
            .ok_or(AppError::UtxoNotFound)
    }

    async fn is_unspent(
        &self,
        _script_pubkey: &lwk_wollet::elements::Script,
        _txid_hex: &str,
        _vout: u32,
    ) -> Result<bool, AppError> {
        Ok(false)
    }

    async fn script_history(
        &self,
        _script_pubkey: &lwk_wollet::elements::Script,
    ) -> Result<pay_service::utxo::LiquidScriptHistory, AppError> {
        Ok(pay_service::utxo::LiquidScriptHistory::Empty)
    }

    async fn history_txids(
        &self,
        _script_pubkey: &lwk_wollet::elements::Script,
    ) -> Result<Vec<String>, AppError> {
        Ok(Vec::new())
    }

    async fn find_spending_txid(
        &self,
        _script_pubkey: &lwk_wollet::elements::Script,
        _txid_hex: &str,
        _vout: u32,
    ) -> Result<Option<String>, AppError> {
        Ok(None)
    }
}

fn persisted_liquid_claim_fixture(
    response: &CreateChainResponse,
    merchant_address: &str,
    merchant_blinding_key_hex: &str,
) -> (
    String,
    String,
    i64,
    f64,
    Arc<dyn pay_service::utxo::UtxoBackend>,
) {
    use boltz_client::elements;

    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let mut rng = elements::secp256k1_zkp::rand::thread_rng();
    let asset = elements::AssetId::LIQUID_BTC;
    let source_address = elements::Address::from_str(&response.claim_details.lockup_address)
        .expect("issue84 fixture has a valid Liquid source address");
    let source_blinding_key = elements::secp256k1_zkp::SecretKey::from_str(
        response
            .claim_details
            .blinding_key
            .as_deref()
            .expect("issue84 fixture has a Liquid blinding key"),
    )
    .unwrap();
    let source_blinding_pubkey =
        elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &source_blinding_key);
    let source_amount = response.claim_details.amount;
    let source_input_secrets = elements::TxOutSecrets::new(
        asset,
        elements::confidential::AssetBlindingFactor::new(&mut rng),
        source_amount,
        elements::confidential::ValueBlindingFactor::new(&mut rng),
    );
    let (source_output, source_abf, source_vbf, _) = elements::TxOut::new_last_confidential(
        &mut rng,
        &secp,
        source_amount,
        asset,
        source_address.script_pubkey(),
        source_blinding_pubkey,
        &[source_input_secrets],
        &[],
    )
    .unwrap();
    let source_secrets = elements::TxOutSecrets::new(asset, source_abf, source_amount, source_vbf);
    let source_transaction = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: Vec::new(),
        output: vec![source_output],
    };
    let source_txid = source_transaction.txid();

    let merchant_address = elements::Address::from_str(merchant_address).unwrap();
    let merchant_blinding_key =
        elements::secp256k1_zkp::SecretKey::from_str(merchant_blinding_key_hex).unwrap();
    let merchant_blinding_pubkey =
        elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &merchant_blinding_key);
    let fee_sat = 1_000_u64;
    let merchant_amount = source_amount - fee_sat;
    let (merchant_output, _, _, _) = elements::TxOut::new_last_confidential(
        &mut rng,
        &secp,
        merchant_amount,
        asset,
        merchant_address.script_pubkey(),
        merchant_blinding_pubkey,
        &[source_secrets],
        &[],
    )
    .unwrap();
    let claim_transaction = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::new(source_txid, 0),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: elements::AssetIssuance::default(),
            witness: elements::TxInWitness::default(),
        }],
        output: vec![merchant_output, elements::TxOut::new_fee(fee_sat, asset)],
    };
    let actual_fee_sat = i64::try_from(fee_sat).unwrap();
    let discounted_vbytes = u64::try_from(claim_transaction.discount_vsize()).unwrap();
    let actual_fee_rate_sat_vb = fee_sat as f64 / discounted_vbytes as f64;
    assert!((0.1..=10.0).contains(&actual_fee_rate_sat_vb));
    assert_eq!(
        pay_service::fee_policy::SatPerVbyte::try_from(actual_fee_rate_sat_vb)
            .unwrap()
            .checked_fee_for_vbytes(discounted_vbytes)
            .unwrap(),
        fee_sat
    );
    let claim_txid = claim_transaction.txid().to_string();
    let claim_tx_hex = hex::encode(elements::encode::serialize(&claim_transaction));
    let backend = Arc::new(FakeChainClaimSource {
        raw_transactions: HashMap::from([(
            source_txid.to_string(),
            elements::encode::serialize(&source_transaction),
        )]),
    });
    (
        claim_tx_hex,
        claim_txid,
        actual_fee_sat,
        actual_fee_rate_sat_vb,
        backend,
    )
}

async fn spawn_counting_liquid_broadcast_server(
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let broadcast_calls = Arc::new(AtomicUsize::new(0));
    let task_calls = broadcast_calls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let calls = task_calls.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let request: Value = serde_json::from_str(&line).unwrap();
                    let method = request["method"].as_str().unwrap_or_default();
                    if method == "blockchain.transaction.broadcast" {
                        calls.fetch_add(1, Ordering::SeqCst);
                    }
                    let result = match method {
                        "server.version" => json!(["bullnym-test", "1.4"]),
                        "blockchain.transaction.broadcast" => json!("00".repeat(32)),
                        _ => Value::Null,
                    };
                    let response = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
                    writer
                        .write_all(format!("{response}\n").as_bytes())
                        .await
                        .unwrap();
                }
            });
        }
    });
    (format!("tcp://{address}"), broadcast_calls, task)
}

#[tokio::test]
async fn persisted_liquid_claim_without_journal_fails_real_retry_before_broadcast() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "claimnojournal";
    let (npub, _) = issue84_test_merchant(&pool, nym).await;
    let invoice = issue84_chain_invoice(&pool, nym, &npub, 0).await;
    let boltz_swap_id = "CLAIM_WITHOUT_JOURNAL";
    let (_, _, response) = issue84_chain_creation_response(401, 402, boltz_swap_id);
    let response_json = serde_json::to_string(&response).unwrap();
    let swap = record_pre_050_chain_fixture(
        &pool,
        &pay_service::db::NewChainSwapRecord {
            claim_key_index: None,
            refund_key_index: None,
            root_fingerprint: None,
            invoice_id: invoice.id,
            nym: Some(nym),
            boltz_swap_id,
            lockup_address: &response.lockup_details.lockup_address,
            lockup_bip21: response.lockup_details.bip21.as_deref(),
            user_lock_amount_sat: i64::try_from(response.lockup_details.amount).unwrap(),
            server_lock_amount_sat: i64::try_from(response.claim_details.amount).unwrap(),
            preimage_hex: "11".repeat(32).as_str(),
            claim_key_hex: "22".repeat(32).as_str(),
            refund_key_hex: "33".repeat(32).as_str(),
            boltz_response_json: &response_json,
        },
    )
    .await
    .unwrap();
    let merchant_address = invoice.liquid_address.as_deref().unwrap();
    let merchant_blinding_key = invoice.liquid_blinding_key_hex.as_deref().unwrap();
    let (claim_tx_hex, claim_txid, claim_fee_sat, claim_fee_rate_sat_vb, backend) =
        persisted_liquid_claim_fixture(&response, merchant_address, merchant_blinding_key);
    // This fixture deliberately omits only the immutable transaction journal.
    // The parent bytes still carry a complete, valid Review-25 authority
    // packet; otherwise migration 054 correctly rejects the setup before the
    // missing-journal retry boundary can be exercised.
    sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'claiming', claim_tx_hex = $2, claim_txid = $3, \
             claim_actual_fee_sat = $4, claim_actual_fee_rate_sat_vb = $5, \
             claim_fee_decision_purpose = 'chain_liquid_claim', \
             claim_fee_decision_rail = 'liquid', claim_fee_decision_target = '1', \
             claim_fee_decision_source = 'liquid_live', \
             claim_fee_decision_rate_sat_vb = $6, \
             claim_fee_decision_quoted_at_unix = 1700000100, \
             claim_fee_decision_evaluated_at_unix = 1700000105, \
             claim_fee_decision_freshness_age_secs = 5, \
             claim_fee_decision_freshness_max_age_secs = 60, \
             claim_fee_decision_provenance = 'integration-test-liquid-live', \
             claim_fee_decision_policy_floor_sat_vb = 0.1, \
             claim_fee_decision_policy_cap_sat_vb = 10.0, \
             claim_fee_decision_policy_version = 'review25-v1' \
         WHERE id = $1",
    )
    .bind(swap.id)
    .bind(&claim_tx_hex)
    .bind(&claim_txid)
    .bind(claim_fee_sat)
    .bind(claim_fee_rate_sat_vb)
    .bind(claim_fee_rate_sat_vb)
    .execute(&pool)
    .await
    .unwrap();
    let parent_before: Value =
        sqlx::query_scalar("SELECT to_jsonb(parent) FROM chain_swap_records parent WHERE id = $1")
            .bind(swap.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (electrum_url, broadcast_calls, server_task) =
        spawn_counting_liquid_broadcast_server().await;
    let claim_clients = claimer::LiquidClaimClientFactory::try_new(vec![electrum_url]).unwrap();

    let error = tokio::time::timeout(
        Duration::from_secs(3),
        claimer::exercise_journaled_chain_claim_retry(&pool, swap.id, &claim_clients, &backend),
    )
    .await
    .expect("missing-journal retry must fail locally")
    .unwrap_err();

    assert!(
        matches!(
            &error,
            AppError::DbError(message)
                if message
                    == "load exact Liquid merchant settlement journal: merchant settlement transaction journal is incomplete"
        ),
        "unexpected retry error: {error}"
    );
    assert_eq!(broadcast_calls.load(Ordering::SeqCst), 0);
    let parent_after: Value =
        sqlx::query_scalar("SELECT to_jsonb(parent) FROM chain_swap_records parent WHERE id = $1")
            .bind(swap.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(parent_after, parent_before);
    let journal_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_tx_attempts WHERE chain_swap_id = $1")
            .bind(swap.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(journal_count, 0);

    server_task.abort();
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn liquid_merchant_settlement_broadcast_marker_requires_exact_unheld_parent_journal() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (swap_id, txid) = seed_liquid_merchant_settlement_attempt(&pool, "broadcast").await;

    assert_eq!(
        pay_service::db::mark_liquid_merchant_settlement_broadcast_started(
            &pool,
            swap_id,
            &txid,
            "liquid_claim",
        )
        .await
        .unwrap(),
        pay_service::db::LiquidMerchantSettlementBroadcastStartDisposition::Started
    );
    pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        swap_id,
        &txid,
        "liquid_claim",
        "broadcast accepted",
    )
    .await
    .unwrap();
    let first: (String, i32, Option<String>, bool, bool, bool) = sqlx::query_as(
        "SELECT status, broadcast_attempts, last_broadcast_result, \
                first_broadcast_attempt_at IS NOT NULL, \
                last_broadcast_attempt_at IS NOT NULL, broadcast_at IS NOT NULL \
           FROM chain_swap_tx_attempts WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(first.0, "broadcast");
    assert_eq!(first.1, 1);
    assert_eq!(first.2.as_deref(), Some("broadcast accepted"));
    assert!(first.3 && first.4 && first.5);

    let wrong_purpose = pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        swap_id,
        &txid,
        "liquid_claim_replacement",
        "must not match",
    )
    .await;
    assert!(matches!(
        wrong_purpose,
        Err(pay_service::db::MerchantSettlementRepositoryError::ImmutableIdentityConflict)
    ));
    let wrong_txid = pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        swap_id,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "liquid_claim",
        "must not match",
    )
    .await;
    assert!(matches!(
        wrong_txid,
        Err(pay_service::db::MerchantSettlementRepositoryError::ImmutableIdentityConflict)
    ));

    sqlx::query("UPDATE chain_swap_records SET claim_txid = $2 WHERE id = $1")
        .bind(swap_id)
        .bind("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
        .execute(&pool)
        .await
        .unwrap();
    let wrong_parent = pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        swap_id,
        &txid,
        "liquid_claim",
        "must not match parent",
    )
    .await;
    assert!(matches!(
        wrong_parent,
        Err(pay_service::db::MerchantSettlementRepositoryError::ImmutableIdentityConflict)
    ));
    sqlx::query("UPDATE chain_swap_records SET claim_txid = $2 WHERE id = $1")
        .bind(swap_id)
        .bind(&txid)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "UPDATE chain_swap_tx_attempts SET status = 'integrity_hold', \
             integrity_reason = 'test hold', integrity_hold_at = NOW() \
          WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .execute(&pool)
    .await
    .unwrap();
    let held = pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        swap_id,
        &txid,
        "liquid_claim",
        "must not escape hold",
    )
    .await;
    assert!(matches!(
        held,
        Err(pay_service::db::MerchantSettlementRepositoryError::ImmutableIdentityConflict)
    ));
    let held_metadata: (String, i32, Option<String>) = sqlx::query_as(
        "SELECT status, broadcast_attempts, last_broadcast_result \
           FROM chain_swap_tx_attempts WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(held_metadata.0, "integrity_hold");
    assert_eq!(held_metadata.1, 1);
    assert_eq!(held_metadata.2.as_deref(), Some("broadcast accepted"));

    let (settled_swap_id, settled_txid) =
        seed_liquid_merchant_settlement_attempt(&pool, "settled").await;
    pay_service::db::mark_liquid_merchant_settlement_broadcast_started(
        &pool,
        settled_swap_id,
        &settled_txid,
        "liquid_claim",
    )
    .await
    .unwrap();
    pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        settled_swap_id,
        &settled_txid,
        "liquid_claim",
        "initial broadcast accepted",
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chain_swap_tx_attempts SET status = 'confirmed', confirmed_at = NOW() \
          WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(settled_swap_id)
    .bind(&settled_txid)
    .execute(&pool)
    .await
    .unwrap();
    pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        settled_swap_id,
        &settled_txid,
        "liquid_claim",
        "confirmed retry observed",
    )
    .await
    .unwrap();
    let status: String = sqlx::query_scalar(
        "SELECT status FROM chain_swap_tx_attempts WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(settled_swap_id)
    .bind(&settled_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "confirmed");

    sqlx::query(
        "UPDATE chain_swap_tx_attempts SET status = 'finalized', finalized_at = NOW() \
          WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(settled_swap_id)
    .bind(&settled_txid)
    .execute(&pool)
    .await
    .unwrap();
    pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        settled_swap_id,
        &settled_txid,
        "liquid_claim",
        "finalized retry observed",
    )
    .await
    .unwrap();
    let settled_metadata: (String, i32, Option<String>) = sqlx::query_as(
        "SELECT status, broadcast_attempts, last_broadcast_result \
           FROM chain_swap_tx_attempts WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(settled_swap_id)
    .bind(&settled_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(settled_metadata.0, "finalized");
    assert_eq!(settled_metadata.1, 1);
    assert_eq!(
        settled_metadata.2.as_deref(),
        Some("finalized retry observed")
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn merchant_settlement_cas_persists_confirm_finalize_and_reorg_demote() {
    use pay_service::merchant_settlement_adoption::{
        MerchantSettlementContext, MerchantSettlementPath,
    };
    use pay_service::merchant_settlement_lifecycle::SettlementFinalityPolicy;
    use pay_service::merchant_settlement_service::MerchantSettlementAdoptionService;

    const BLOCK_HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (swap_id, txid) = seed_liquid_merchant_settlement_attempt(&pool, "cas").await;
    sqlx::query("UPDATE chain_swap_records SET status = 'claim_failed' WHERE id = $1")
        .bind(swap_id)
        .execute(&pool)
        .await
        .unwrap();
    let non_claiming_start = pay_service::db::mark_liquid_merchant_settlement_broadcast_started(
        &pool,
        swap_id,
        &txid,
        "liquid_claim",
    )
    .await;
    assert_eq!(
        non_claiming_start.unwrap(),
        pay_service::db::LiquidMerchantSettlementBroadcastStartDisposition::Superseded
    );
    let refused_attempts: i32 = sqlx::query_scalar(
        "SELECT broadcast_attempts FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(refused_attempts, 0);
    sqlx::query("UPDATE chain_swap_records SET status = 'claiming' WHERE id = $1")
        .bind(swap_id)
        .execute(&pool)
        .await
        .unwrap();
    pay_service::db::mark_liquid_merchant_settlement_broadcast_started(
        &pool,
        swap_id,
        &txid,
        "liquid_claim",
    )
    .await
    .unwrap();
    pay_service::db::mark_liquid_merchant_settlement_broadcast(
        &pool,
        swap_id,
        &txid,
        "liquid_claim",
        "initial broadcast accepted",
    )
    .await
    .unwrap();

    let (invoice_id, boltz_swap_id, destination_address, destination_script_hex, asset_id): (
        Uuid,
        String,
        String,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT parent.invoice_id, parent.boltz_swap_id, attempt.destination_address, \
                attempt.destination_script_hex, attempt.destination_asset_id \
           FROM chain_swap_records parent \
           JOIN chain_swap_tx_attempts attempt ON attempt.chain_swap_id = parent.id \
          WHERE parent.id = $1 AND attempt.txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    let context = MerchantSettlementContext::new(
        invoice_id,
        swap_id,
        boltz_swap_id,
        MerchantSettlementPath::LiquidClaim,
    )
    .unwrap();
    let policy = SettlementFinalityPolicy::new(2, 3).unwrap();
    let mut service = MerchantSettlementAdoptionService::new(context, &txid, policy).unwrap();

    let one_confirmation = verified_liquid_merchant_output(
        &txid,
        &destination_address,
        &destination_script_hex,
        &asset_id,
        1,
        100,
        BLOCK_HASH,
    );
    let confirmed_outcome = service
        .apply_verified_confirmation(&one_confirmation)
        .unwrap();
    let confirmed_snapshot = service.snapshot();
    sqlx::query(
        "UPDATE chain_swap_records SET status = 'claim_failed', \
             last_claim_error = 'ambiguous broadcast', last_claim_error_at = NOW(), \
             next_claim_attempt_at = NOW() WHERE id = $1",
    )
    .bind(swap_id)
    .execute(&pool)
    .await
    .unwrap();
    let confirmed = pay_service::db::persist_merchant_settlement_outcome(
        &pool,
        0,
        &confirmed_snapshot,
        &confirmed_outcome,
        policy,
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    assert_eq!(confirmed.checkpoint_version, 1);
    assert!(!confirmed.journal_rebroadcast_required);
    assert_eq!(confirmed.parent_transition.previous_status, "claim_failed");
    assert_eq!(confirmed.parent_transition.current_status, "claiming");
    assert!(confirmed.parent_transition.changed);
    let cleared_confirmed_failure: (Option<String>, bool, bool) = sqlx::query_as(
        "SELECT last_claim_error, last_claim_error_at IS NULL, next_claim_attempt_at IS NULL \
           FROM chain_swap_records WHERE id = $1",
    )
    .bind(swap_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cleared_confirmed_failure, (None, true, true));
    let confirmed_event: (i64, String, bool, String, String) = sqlx::query_as(
        "SELECT amount_sat, accounting_state, merchant_settlement_finalized, source, rail \
           FROM invoice_payment_events WHERE merchant_chain_swap_id = $1",
    )
    .bind(swap_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(confirmed_event.0, 1_000);
    assert_eq!(confirmed_event.1, "active");
    assert!(!confirmed_event.2);
    assert_eq!(confirmed_event.3, "bitcoin_boltz_chain");
    assert_eq!(confirmed_event.4, "bitcoin");
    let confirmed_invoice: (Option<i64>, Option<String>, String, String) = sqlx::query_as(
        "SELECT paid_amount_sat, paid_via, status, swap_settlement_status \
           FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(confirmed_invoice.0, Some(1_000));
    assert_eq!(confirmed_invoice.1.as_deref(), Some("bitcoin"));
    assert_eq!(confirmed_invoice.2, "paid");
    assert_eq!(confirmed_invoice.3, "pending");
    let confirmed_attempt: String = sqlx::query_scalar(
        "SELECT status FROM chain_swap_tx_attempts WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(confirmed_attempt, "confirmed");

    let final_confirmation = verified_liquid_merchant_output(
        &txid,
        &destination_address,
        &destination_script_hex,
        &asset_id,
        2,
        100,
        BLOCK_HASH,
    );
    let finalized_outcome = service
        .apply_verified_confirmation(&final_confirmation)
        .unwrap();
    let finalized_snapshot = service.snapshot();
    sqlx::query(
        "UPDATE chain_swap_records SET status = 'claim_stuck', \
             last_claim_error = 'retry budget exhausted', last_claim_error_at = NOW(), \
             next_claim_attempt_at = NOW() WHERE id = $1",
    )
    .bind(swap_id)
    .execute(&pool)
    .await
    .unwrap();
    let finalized = pay_service::db::persist_merchant_settlement_outcome(
        &pool,
        1,
        &finalized_snapshot,
        &finalized_outcome,
        policy,
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    assert_eq!(finalized.checkpoint_version, 2);
    assert_eq!(finalized.parent_transition.previous_status, "claim_stuck");
    assert_eq!(finalized.parent_transition.current_status, "claimed");
    assert!(finalized.parent_transition.changed);
    let finalized_state: (String, bool, String, String) = sqlx::query_as(
        "SELECT event.accounting_state, event.merchant_settlement_finalized, \
                attempt.status, parent.status \
           FROM invoice_payment_events event \
           JOIN chain_swap_records parent ON parent.id = event.merchant_chain_swap_id \
           JOIN chain_swap_tx_attempts attempt ON attempt.chain_swap_id = parent.id \
          WHERE parent.id = $1 AND attempt.txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(finalized_state.0, "active");
    assert!(finalized_state.1);
    assert_eq!(finalized_state.2, "finalized");
    assert_eq!(finalized_state.3, "claimed");
    let cleared_finalized_failure: (Option<String>, bool, bool) = sqlx::query_as(
        "SELECT last_claim_error, last_claim_error_at IS NULL, next_claim_attempt_at IS NULL \
           FROM chain_swap_records WHERE id = $1",
    )
    .bind(swap_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cleared_finalized_failure, (None, true, true));
    assert_eq!(
        pay_service::db::mark_liquid_merchant_settlement_broadcast_started(
            &pool,
            swap_id,
            &txid,
            "liquid_claim",
        )
        .await
        .unwrap(),
        pay_service::db::LiquidMerchantSettlementBroadcastStartDisposition::AlreadySettled
    );
    let settled_broadcast_attempts: i32 = sqlx::query_scalar(
        "SELECT broadcast_attempts FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(settled_broadcast_attempts, 1);

    let stale = pay_service::db::persist_merchant_settlement_outcome(
        &pool,
        1,
        &finalized_snapshot,
        &finalized_outcome,
        policy,
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await;
    assert!(matches!(
        stale,
        Err(
            pay_service::db::MerchantSettlementRepositoryError::CheckpointConflict {
                expected: 1,
                actual: 2
            }
        )
    ));

    let reorg_outcome = service.apply_reorg(100, BLOCK_HASH).unwrap();
    let reorg_snapshot = service.snapshot();
    let demoted = pay_service::db::persist_merchant_settlement_outcome(
        &pool,
        2,
        &reorg_snapshot,
        &reorg_outcome,
        policy,
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();
    assert_eq!(demoted.checkpoint_version, 3);
    assert!(demoted.journal_rebroadcast_required);
    assert_eq!(demoted.parent_transition.previous_status, "claimed");
    assert_eq!(demoted.parent_transition.current_status, "claiming");
    assert!(demoted.parent_transition.changed);
    let demoted_state: (String, bool, Option<String>, String, String) = sqlx::query_as(
        "SELECT event.accounting_state, event.merchant_settlement_finalized, \
                event.deactivation_reason, attempt.status, parent.status \
           FROM invoice_payment_events event \
           JOIN chain_swap_records parent ON parent.id = event.merchant_chain_swap_id \
           JOIN chain_swap_tx_attempts attempt ON attempt.chain_swap_id = parent.id \
          WHERE parent.id = $1 AND attempt.txid = $2",
    )
    .bind(swap_id)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(demoted_state.0, "inactive");
    assert!(!demoted_state.1);
    assert_eq!(demoted_state.2.as_deref(), Some("reorged"));
    assert_eq!(demoted_state.3, "broadcast_ambiguous");
    assert_eq!(demoted_state.4, "claiming");
    let demoted_invoice: (Option<i64>, Option<String>, String, String) = sqlx::query_as(
        "SELECT paid_amount_sat, paid_via, status, swap_settlement_status \
           FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(demoted_invoice.0, None);
    assert_eq!(demoted_invoice.1, None);
    assert_eq!(demoted_invoice.2, "in_progress");
    assert_eq!(demoted_invoice.3, "pending");
    let checkpoint_version: i64 = sqlx::query_scalar(
        "SELECT checkpoint_version FROM merchant_settlement_checkpoints \
          WHERE chain_swap_id = $1 AND settlement_path = 'liquid_claim'",
    )
    .bind(swap_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(checkpoint_version, 3);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn merchant_settlement_replacement_persists_reason_after_child_confirmation() {
    use pay_service::merchant_output_verifier::{
        verify_merchant_output, ApprovedMerchantDestination, JournaledMerchantTransaction,
        MerchantAsset, MerchantOutputEvidence, ObservedMerchantOutput,
    };
    use pay_service::merchant_settlement_adoption::{
        MerchantSettlementContext, MerchantSettlementPath,
    };
    use pay_service::merchant_settlement_lifecycle::SettlementFinalityPolicy;
    use pay_service::merchant_settlement_service::MerchantSettlementAdoptionService;

    const ORIGINAL_BLOCK: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const REPLACEMENT_BLOCK: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (swap_id, original_txid) =
        seed_liquid_merchant_settlement_attempt(&pool, "replacement-reason").await;
    let (
        invoice_id,
        boltz_swap_id,
        destination_address,
        destination_script_hex,
        asset_id,
        original_raw_tx_hex,
    ): (Uuid, String, String, String, String, String) = sqlx::query_as(
        "SELECT parent.invoice_id, parent.boltz_swap_id, attempt.destination_address, \
                attempt.destination_script_hex, attempt.destination_asset_id, \
                attempt.raw_tx_hex \
           FROM chain_swap_records parent \
           JOIN chain_swap_tx_attempts attempt ON attempt.chain_swap_id = parent.id \
          WHERE parent.id = $1 AND attempt.txid = $2",
    )
    .bind(swap_id)
    .bind(&original_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    let context = MerchantSettlementContext::new(
        invoice_id,
        swap_id,
        boltz_swap_id,
        MerchantSettlementPath::LiquidClaim,
    )
    .unwrap();
    let policy = SettlementFinalityPolicy::new(2, 3).unwrap();
    let mut service =
        MerchantSettlementAdoptionService::new(context, &original_txid, policy).unwrap();
    let original = verified_liquid_merchant_output(
        &original_txid,
        &destination_address,
        &destination_script_hex,
        &asset_id,
        1,
        100,
        ORIGINAL_BLOCK,
    );
    let original_outcome = service.apply_verified_confirmation(&original).unwrap();
    pay_service::db::persist_merchant_settlement_outcome(
        &pool,
        0,
        &service.snapshot(),
        &original_outcome,
        policy,
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();

    let mut replacement_transaction: lwk_wollet::elements::Transaction =
        lwk_wollet::elements::encode::deserialize(&hex::decode(&original_raw_tx_hex).unwrap())
            .unwrap();
    replacement_transaction.input[0].sequence = lwk_wollet::elements::Sequence::ZERO;
    let replacement_txid = replacement_transaction.txid().to_string();
    let replacement_raw_tx_hex = hex::encode(lwk_wollet::elements::encode::serialize(
        &replacement_transaction,
    ));
    let inserted = sqlx::query(
        "INSERT INTO chain_swap_tx_attempts (\
             chain_swap_id, purpose, replaces_txid, raw_tx_hex, txid, source_prevouts, \
             destination_address, destination_script_hex, destination_asset_id, \
             destination_vout, destination_amount_sat, fee_amount_sat, fee_rate_sat_vb, \
             liquid_blinding_key_hex, fee_decision_purpose, fee_decision_rail, \
             fee_decision_target, fee_decision_source, fee_decision_rate_sat_vb, \
             fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
             fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
             fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
             fee_decision_policy_cap_sat_vb, fee_decision_policy_version\
         ) SELECT \
             chain_swap_id, 'liquid_claim_replacement', txid, $3, $4, source_prevouts, \
             destination_address, destination_script_hex, destination_asset_id, \
             destination_vout, destination_amount_sat, fee_amount_sat, fee_rate_sat_vb, \
             liquid_blinding_key_hex, fee_decision_purpose, fee_decision_rail, \
             fee_decision_target, fee_decision_source, fee_decision_rate_sat_vb, \
             fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
             fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
             fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
             fee_decision_policy_cap_sat_vb, fee_decision_policy_version \
           FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND txid = $2 AND purpose = 'liquid_claim'",
    )
    .bind(swap_id)
    .bind(&original_txid)
    .bind(&replacement_raw_tx_hex)
    .bind(&replacement_txid)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(inserted.rows_affected(), 1);
    let parent_updated = sqlx::query(
        "UPDATE chain_swap_records SET claim_txid = $2, updated_at = NOW() \
          WHERE id = $1 AND claim_txid = $3",
    )
    .bind(swap_id)
    .bind(&replacement_txid)
    .bind(&original_txid)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(parent_updated.rows_affected(), 1);

    let asset = MerchantAsset::Liquid(asset_id.clone());
    let approved = ApprovedMerchantDestination::liquid(
        &destination_address,
        &destination_script_hex,
        &asset_id,
    );
    let replacement_journal = JournaledMerchantTransaction::linked_replacement(
        &replacement_txid,
        &original_txid,
        &destination_address,
        &destination_script_hex,
        asset.clone(),
        1_000,
        0,
    );
    let replacement = verify_merchant_output(
        &original_txid,
        &replacement_journal,
        &approved,
        &MerchantOutputEvidence::Authoritative(ObservedMerchantOutput::new(
            &replacement_txid,
            &destination_script_hex,
            asset,
            1_000,
            0,
            1,
            Some(101),
            Some(REPLACEMENT_BLOCK.to_owned()),
        )),
        1,
    )
    .unwrap();
    let replacement_outcome = service.apply_verified_confirmation(&replacement).unwrap();
    pay_service::db::persist_merchant_settlement_outcome(
        &pool,
        1,
        &service.snapshot(),
        &replacement_outcome,
        policy,
        pay_service::db::InvoiceAccountingTolerances::default(),
    )
    .await
    .unwrap();

    let events: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT txid, accounting_state, deactivation_reason \
           FROM invoice_payment_events WHERE merchant_chain_swap_id = $1 \
          ORDER BY accounting_sequence",
    )
    .bind(swap_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        events,
        vec![
            (
                original_txid,
                "inactive".to_owned(),
                Some("replaced".to_owned()),
            ),
            (replacement_txid, "active".to_owned(), None),
        ]
    );

    cleanup_db(&pool).await;
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
        &harness.fee_decision,
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
    assert_eq!(final_swap.status, "refunding");
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
            &harness.fee_decision,
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

        // Dropping the faulted SQLx transaction queues its rollback; it does
        // not wait for PostgreSQL to release the transaction advisory lock.
        // Model the real worker contract by retrying only that transient lock
        // loss, while still surfacing every other resume failure immediately.
        let retry_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let resumed = loop {
            match execute_journaled_recovery_with_services(
                &pool,
                harness.swap.id,
                harness.builder.as_ref(),
                &harness.fee_decision,
                harness.chain.as_ref(),
                harness.broadcaster.as_ref(),
                &NoRecoveryFaults,
            )
            .await
            {
                Err(AppError::ClaimError(message))
                    if message
                        == "chain swap is busy (claim/recovery in progress); retry shortly" =>
                {
                    assert!(
                        tokio::time::Instant::now() < retry_deadline,
                        "fault {point:?} did not release its recovery advisory lock"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                result => {
                    break result.unwrap_or_else(|e| panic!("fault {point:?} did not resume: {e}"))
                }
            }
        };
        assert_eq!(resumed, harness.expected_txid);

        let final_attempt = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(final_attempt.status, "broadcast");
        assert_eq!(final_attempt.raw_tx_hex, harness.expected_raw_hex);
        assert!(
            pay_service::db::mark_recovery_broadcast_started(&pool, final_attempt.id)
                .await
                .unwrap()
                .is_some(),
            "fault {point:?} left a broadcast attempt that could not redrive"
        );
        let restarted = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restarted.status, "broadcast");
        assert_eq!(
            restarted.broadcast_attempts,
            final_attempt.broadcast_attempts + 1
        );
        assert_eq!(
            restarted.last_broadcast_result.as_deref(),
            Some("attempt started")
        );
        let final_swap = pay_service::db::get_chain_swap_by_id(&pool, harness.swap.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(final_swap.status, "refunding");
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
async fn changed_fee_applies_before_journal_and_no_quote_replays_persisted_bytes() {
    use pay_service::chain_recovery::{
        execute_journaled_recovery_with_optional_fee_services,
        execute_journaled_recovery_with_services, NoRecoveryFaults, RecoveryFaultPoint,
    };

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "feeretry", [FakeBroadcastResult::Accept]).await;
    let BtcLikeTransaction::Bitcoin(template) = harness.builder.transaction.clone() else {
        unreachable!()
    };
    let builder = FeeSensitiveRecoveryBuilder {
        template,
        source_amount_sat: 100_000,
        calls: AtomicUsize::new(0),
        fee_rates: Mutex::new(Vec::new()),
        raw_transactions: Mutex::new(Vec::new()),
    };

    // The first construction uses the policy minimum but stops before a
    // journal exists. A later eligible attempt is therefore allowed to use a
    // changed decision and construct different bytes.
    let minimum_decision = bitcoin_fee_decision(1.0);
    let before_journal =
        OneShotRecoveryFault::at(RecoveryFaultPoint::AfterConstructionBeforeJournal);
    assert!(execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        &builder,
        &minimum_decision,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &before_journal,
    )
    .await
    .is_err());
    assert!(
        pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap()
            .is_none()
    );

    // Retry only transient advisory-lock handoff while proving the changed
    // maximum decision reaches construction and commits before broadcast.
    let after_commit =
        OneShotRecoveryFault::at(RecoveryFaultPoint::AfterJournalCommitBeforeBroadcast);
    let maximum_decision = bitcoin_fee_decision(500.0);
    let retry_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match execute_journaled_recovery_with_services(
            &pool,
            harness.swap.id,
            &builder,
            &maximum_decision,
            harness.chain.as_ref(),
            harness.broadcaster.as_ref(),
            &after_commit,
        )
        .await
        {
            Err(AppError::ClaimError(message))
                if message == "chain swap is busy (claim/recovery in progress); retry shortly" =>
            {
                assert!(tokio::time::Instant::now() < retry_deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(AppError::ClaimError(message)) => {
                assert!(message.contains("AfterJournalCommitBeforeBroadcast"));
                break;
            }
            result => panic!("changed construction did not stop after journal commit: {result:?}"),
        }
    }

    let committed = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    let raw_transactions = builder.raw_transactions.lock().await.clone();
    assert_eq!(raw_transactions.len(), 2);
    assert_ne!(raw_transactions[0], raw_transactions[1]);
    assert_eq!(committed.raw_tx_hex, raw_transactions[1]);
    let committed_transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(&committed.raw_tx_hex).unwrap()).unwrap();
    let expected_fee_sat = 100_000 - committed_transaction.output[0].value.to_sat();
    assert_eq!(committed.fee_amount_sat, expected_fee_sat as i64);
    assert_eq!(
        committed.fee_rate_sat_vb,
        expected_fee_sat as f64 / committed_transaction.vsize() as f64
    );
    assert!((committed.fee_rate_sat_vb - 500.0).abs() < f64::EPSILON);
    let expected_fee_decision = PersistedRecoveryFeeDecision {
        fee_decision_purpose: "bitcoin_recovery".into(),
        fee_decision_rail: "bitcoin".into(),
        fee_decision_target: "fastestFee".into(),
        fee_decision_source: "bitcoin_live".into(),
        fee_decision_rate_sat_vb: 500.0,
        fee_decision_quoted_at_unix: 1_000,
        fee_decision_evaluated_at_unix: 1_000,
        fee_decision_freshness_age_secs: 0,
        fee_decision_freshness_max_age_secs: 120,
        fee_decision_provenance: "integration-test".into(),
        fee_decision_policy_floor_sat_vb: 1.0,
        fee_decision_policy_cap_sat_vb: 500.0,
        fee_decision_policy_version: "review25-v1".into(),
    };
    let committed_fee_decision = persisted_recovery_fee_decision(&pool, harness.swap.id).await;
    assert_eq!(&committed_fee_decision, &expected_fee_decision);
    drop(raw_transactions);

    // Estimator movement after the journal commit cannot authorize new bytes
    // or rewrite the decision evidence bound to the committed transaction.
    // This decision is valid under its originating policy but outside the
    // compatibility seam's default 500 sat/vB cap. Existing-byte replay must
    // ignore it rather than rebuilding current construction authority.
    let moved_estimator_decision = bitcoin_fee_decision_with_cap(750.0, 1_000.0);
    let replay_fault =
        OneShotRecoveryFault::at(RecoveryFaultPoint::AfterJournalCommitBeforeBroadcast);
    let replay_result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        &builder,
        &moved_estimator_decision,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &replay_fault,
    )
    .await;
    assert!(matches!(
        replay_result,
        Err(AppError::ClaimError(message))
            if message.contains("AfterJournalCommitBeforeBroadcast")
    ));
    assert_eq!(builder.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        persisted_recovery_fee_decision(&pool, harness.swap.id).await,
        expected_fee_decision
    );

    // No new quote is required after the write-ahead commit: the executor
    // reuses the committed maximum-rate bytes and their actual fee evidence
    // without invoking the builder again.
    execute_journaled_recovery_with_optional_fee_services(
        &pool,
        harness.swap.id,
        &builder,
        None,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .unwrap();
    assert_eq!(builder.calls.load(Ordering::SeqCst), 2);
    assert_eq!(*builder.fee_rates.lock().await, vec![1.0, 500.0]);
    let finalized = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finalized.raw_tx_hex, committed.raw_tx_hex);
    assert_eq!(finalized.fee_amount_sat, committed.fee_amount_sat);
    assert_eq!(finalized.fee_rate_sat_vb, committed.fee_rate_sat_vb);
    assert_eq!(
        persisted_recovery_fee_decision(&pool, harness.swap.id).await,
        committed_fee_decision
    );
    assert_eq!(
        harness.broadcaster.calls.lock().await.as_slice(),
        &[committed.raw_tx_hex]
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn fee_authority_expiring_after_journal_write_rolls_back_before_commit() {
    use pay_service::chain_recovery::{
        execute_journaled_recovery_with_services, RecoveryFaultPoint,
        BITCOIN_FEE_DECISION_PENDING_REASON,
    };
    use pay_service::fee_policy::{BitcoinFeePolicy, FeeProvenance, LiveBitcoin, SatPerVbyte};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "feeexpires", [FakeBroadcastResult::Accept]).await;
    let observation = LiveBitcoin::new(
        SatPerVbyte::try_from(2.0).unwrap(),
        1_000,
        FeeProvenance::new("expiring-integration-test").unwrap(),
    );
    let expiring_decision = BitcoinFeePolicy::new(
        SatPerVbyte::try_from(1.0).unwrap(),
        SatPerVbyte::try_from(500.0).unwrap(),
        3,
        900,
    )
    .unwrap()
    .decide_typed(Some(&observation), None, 1_000)
    .unwrap();
    let delayed_commit = DelayedRecoveryFault::at(
        RecoveryFaultPoint::AfterJournalWriteBeforeCommit,
        Duration::from_millis(3_100),
    );

    let result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        &expiring_decision,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &delayed_commit,
    )
    .await;

    assert!(delayed_commit.fired.load(Ordering::SeqCst));
    assert!(matches!(
        result,
        Err(AppError::RecoveryNotAvailable(reason))
            if reason == BITCOIN_FEE_DECISION_PENDING_REASON
    ));
    assert_eq!(harness.builder.calls.load(Ordering::SeqCst), 1);
    assert!(harness.broadcaster.calls.lock().await.is_empty());
    assert!(
        pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
            .await
            .unwrap()
            .is_none(),
        "expired construction authority must roll back the journal insert"
    );
    let swap = pay_service::db::get_chain_swap_by_id(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(swap.status, "refund_due");
    assert!(swap.refund_txid.is_none());

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn unjournaled_recovery_without_a_quote_stays_retryable_and_constructs_no_bytes() {
    use pay_service::chain_recovery::{
        execute_journaled_recovery_with_optional_fee_services,
        execute_journaled_recovery_with_services, NoRecoveryFaults,
        BITCOIN_FEE_DECISION_PENDING_REASON,
    };

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "nofee", [FakeBroadcastResult::Accept]).await;

    let result = execute_journaled_recovery_with_optional_fee_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        None,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await;

    assert!(matches!(
        result,
        Err(AppError::RecoveryNotAvailable(reason))
            if reason == BITCOIN_FEE_DECISION_PENDING_REASON
    ));
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
    assert_eq!(swap.status, "refund_due");
    assert!(swap.refund_txid.is_none());

    let txid = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        &harness.fee_decision,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .expect("a later accepted live decision must resume recovery construction");
    assert_eq!(txid, harness.expected_txid);
    assert_eq!(harness.builder.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.broadcaster.calls.lock().await.len(), 1);

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
        &harness.fee_decision,
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
        &harness.fee_decision,
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
        &harness.fee_decision,
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
        &harness.fee_decision,
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
async fn recovery_ambiguity_result_rejects_a_stale_broadcast_start_token() {
    use pay_service::chain_recovery::{execute_journaled_recovery_with_services, NoRecoveryFaults};

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let harness =
        seed_recovery_journal_harness(&pool, "stalebroadcast", [FakeBroadcastResult::Reject]).await;

    assert!(execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        &harness.fee_decision,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    )
    .await
    .is_err());
    let attempt = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();

    let stale_token = pay_service::db::mark_recovery_broadcast_started(&pool, attempt.id)
        .await
        .unwrap()
        .expect("ambiguous attempt must remain exactly redrivable");
    let current_token = pay_service::db::mark_recovery_broadcast_started(&pool, attempt.id)
        .await
        .unwrap()
        .expect("a concurrent exact-byte redrive must receive its own token");

    assert_eq!(
        pay_service::db::mark_recovery_broadcast_ambiguous(
            &pool,
            attempt.id,
            &stale_token,
            "stale broadcaster result",
        )
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        pay_service::db::mark_recovery_broadcast_ambiguous(
            &pool,
            attempt.id,
            &current_token,
            "current broadcaster result",
        )
        .await
        .unwrap(),
        1
    );
    let current = pay_service::db::get_bitcoin_recovery_attempt(&pool, harness.swap.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.broadcast_attempts, attempt.broadcast_attempts + 2);
    assert_eq!(
        current.last_broadcast_result.as_deref(),
        Some("current broadcaster result")
    );

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
        &harness.fee_decision,
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
        &harness.fee_decision,
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
        source_amount_sat: 100_000,
        calls: AtomicUsize::new(0),
        fee_rates: Mutex::new(Vec::new()),
    };

    let result = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        &bad_builder,
        &harness.fee_decision,
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
        &harness.fee_decision,
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
        &harness.fee_decision,
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
        &harness.fee_decision,
        harness.chain.as_ref(),
        harness.broadcaster.as_ref(),
        &NoRecoveryFaults,
    );
    let second = execute_journaled_recovery_with_services(
        &pool,
        harness.swap.id,
        harness.builder.as_ref(),
        &harness.fee_decision,
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
        &harness.fee_decision,
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
        &harness.fee_decision,
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
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(3),
        "read-only response exposes only items, count, and has_more"
    );
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
    set_test_refund_destination(&pool, swap.id, committed).await;

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
    set_test_refund_destination(&pool, done_swap.id, "bc1qdonedest0000000000000000000000000").await;
    pay_service::db::mark_chain_swap_refunding(&pool, done_swap.id)
        .await
        .unwrap();
    pay_service::db::mark_chain_swap_refunded(&pool, done_swap.id, &"bb".repeat(32))
        .await
        .unwrap();

    let invoice2 = insert_test_invoice(&pool, "recorder", &npub, "lq1recorder2", 3_600).await;
    let due_swap = record_pre_050_chain_fixture(
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
    set_test_refund_destination(&pool, swap.id, canary).await;

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
        assert!(body["bitcoin_chain_amount_sat"].is_null(), "stage {stage}");
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
async fn recoverable_list_skips_nymless_swap() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let app = test_app(test_state(pool.clone()));
    // Good swap (has nym) + a legacy NULL-nym swap on a second invoice of the
    // same merchant. The NULL-nym row has no attributable recovery policy and
    // must be silently skipped while the good one is still returned.
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
    let bad_swap = record_pre_050_chain_fixture(
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

// =====================================================================
// #87: append-only recovery-manifest delivery ledger.
// =====================================================================

fn manifest_envelope_sha256(envelope: &str) -> String {
    hex::encode(Sha256::digest(envelope.as_bytes()))
}

#[derive(serde::Serialize)]
struct StructuralManifestEnvelope<'a> {
    ciphertext_hex: String,
    encryption_algorithm: &'a str,
    encryption_key_id: &'a str,
    format: &'a str,
    nonce_hex: String,
    signature_algorithm: &'a str,
    signer_xonly_public_key: &'a str,
    version: u16,
}

fn manifest_delivery_envelope(byte: u8) -> EncryptedSwapManifestV1 {
    let encoded = serde_json::to_string(&StructuralManifestEnvelope {
        ciphertext_hex: format!("{byte:02x}").repeat(16),
        encryption_algorithm: "xchacha20poly1305",
        encryption_key_id: "manifest-key-delivery-test",
        format: "bullnym-chain-swap-manifest",
        nonce_hex: format!("{:02x}", byte.wrapping_add(1)).repeat(24),
        signature_algorithm: "bip340-secp256k1-sha256",
        signer_xonly_public_key: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        version: 1,
    })
    .unwrap();
    EncryptedSwapManifestV1::parse(encoded).unwrap()
}

struct InstrumentedManifestObjectStore {
    inner: Arc<InMemory>,
    io_calls: AtomicUsize,
    fail_next_put: AtomicBool,
    conflict_next_put: AtomicBool,
    pause_next_successful_put: AtomicBool,
    put_committed: Option<Arc<Barrier>>,
    release_put: Option<Arc<Barrier>>,
}

impl InstrumentedManifestObjectStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(InMemory::new()),
            io_calls: AtomicUsize::new(0),
            fail_next_put: AtomicBool::new(false),
            conflict_next_put: AtomicBool::new(false),
            pause_next_successful_put: AtomicBool::new(false),
            put_committed: None,
            release_put: None,
        })
    }

    fn pausing_after_first_put() -> (Arc<Self>, Arc<Barrier>, Arc<Barrier>) {
        let put_committed = Arc::new(Barrier::new(2));
        let release_put = Arc::new(Barrier::new(2));
        (
            Arc::new(Self {
                inner: Arc::new(InMemory::new()),
                io_calls: AtomicUsize::new(0),
                fail_next_put: AtomicBool::new(false),
                conflict_next_put: AtomicBool::new(false),
                pause_next_successful_put: AtomicBool::new(true),
                put_committed: Some(put_committed.clone()),
                release_put: Some(release_put.clone()),
            }),
            put_committed,
            release_put,
        )
    }

    fn failing_first_put() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(InMemory::new()),
            io_calls: AtomicUsize::new(0),
            fail_next_put: AtomicBool::new(true),
            conflict_next_put: AtomicBool::new(false),
            pause_next_successful_put: AtomicBool::new(false),
            put_committed: None,
            release_put: None,
        })
    }

    fn conflicting_first_put() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(InMemory::new()),
            io_calls: AtomicUsize::new(0),
            fail_next_put: AtomicBool::new(false),
            conflict_next_put: AtomicBool::new(true),
            pause_next_successful_put: AtomicBool::new(false),
            put_committed: None,
            release_put: None,
        })
    }

    fn io_calls(&self) -> usize {
        self.io_calls.load(Ordering::SeqCst)
    }

    fn record_io(&self) {
        self.io_calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for InstrumentedManifestObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstrumentedManifestObjectStore")
    }
}

impl std::fmt::Display for InstrumentedManifestObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("instrumented manifest object store")
    }
}

#[async_trait]
impl ObjectStore for InstrumentedManifestObjectStore {
    async fn put_opts(
        &self,
        location: &ObjectStorePath,
        payload: PutPayload,
        options: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.record_io();
        if self.fail_next_put.swap(false, Ordering::SeqCst) {
            return Err(object_store::Error::Generic {
                store: "instrumented manifest store",
                source: Box::new(std::io::Error::other("injected put failure")),
            });
        }
        if self.conflict_next_put.swap(false, Ordering::SeqCst) {
            let path = location.to_string();
            let conflicting = manifest_delivery_envelope(0xfe).into_encoded();
            let conflicting_digest = manifest_envelope_sha256(&conflicting);
            let mut conflicting_attributes = object_store::Attributes::new();
            conflicting_attributes.insert(
                object_store::Attribute::ContentType,
                "application/vnd.bullnym.chain-swap-manifest.v1+json".into(),
            );
            conflicting_attributes.insert(
                object_store::Attribute::Metadata(std::borrow::Cow::Borrowed(
                    "bullnym-manifest-format-version",
                )),
                "1".into(),
            );
            conflicting_attributes.insert(
                object_store::Attribute::Metadata(std::borrow::Cow::Borrowed("bullnym-sha256")),
                conflicting_digest.into(),
            );
            let mut conflicting_options = options;
            conflicting_options.attributes = conflicting_attributes;
            self.inner
                .put_opts(location, PutPayload::from(conflicting), conflicting_options)
                .await?;
            return Err(object_store::Error::AlreadyExists {
                path,
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "injected create conflict",
                )),
            });
        }
        let result = self.inner.put_opts(location, payload, options).await;
        if result.is_ok() && self.pause_next_successful_put.swap(false, Ordering::SeqCst) {
            self.put_committed
                .as_ref()
                .expect("paused store has a commit barrier")
                .wait()
                .await;
            self.release_put
                .as_ref()
                .expect("paused store has a release barrier")
                .wait()
                .await;
        }
        result
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjectStorePath,
        options: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.record_io();
        self.inner.put_multipart_opts(location, options).await
    }

    async fn get_opts(
        &self,
        location: &ObjectStorePath,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        self.record_io();
        self.inner.get_opts(location, options).await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<ObjectStorePath>>,
    ) -> BoxStream<'static, object_store::Result<ObjectStorePath>> {
        self.record_io();
        self.inner.delete_stream(locations)
    }

    fn list(
        &self,
        prefix: Option<&ObjectStorePath>,
    ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.record_io();
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(
        &self,
        prefix: Option<&ObjectStorePath>,
    ) -> object_store::Result<ListResult> {
        self.record_io();
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &ObjectStorePath,
        to: &ObjectStorePath,
        options: CopyOptions,
    ) -> object_store::Result<()> {
        self.record_io();
        self.inner.copy_opts(from, to, options).await
    }
}

fn coordinator_manifest_store(
    backend: Arc<InstrumentedManifestObjectStore>,
) -> pay_service::swap_manifest_store::RecoveryManifestStore {
    let backend: Arc<dyn ObjectStore> = backend;
    pay_service::swap_manifest_store::RecoveryManifestStore::from_object_store_for_integration_tests(
        backend,
        format!("bullnym/coordinator/{}", uuid::Uuid::new_v4()),
    )
    .unwrap()
}

async fn insert_pending_manifest_delivery_fixture(
    pool: &PgPool,
    nym: &str,
    envelope_byte: u8,
) -> pay_service::db::ChainSwapManifestDelivery {
    let boltz_swap_id = format!("manifest-coordinator-{nym}");
    let lockup_address = format!("bc1q{nym}");
    let (_, _, _, swap) =
        seed_merchant_invoice_swap(pool, nym, &boltz_swap_id, &lockup_address, 1_010, 1_000).await;
    let envelope = manifest_delivery_envelope(envelope_byte);
    let mut tx = pool.begin().await.unwrap();
    let reservation = pay_service::db::lock_manifest_delivery_tail(&mut tx)
        .await
        .unwrap();
    let identity = reservation.identity(uuid::Uuid::new_v4(), swap.id).unwrap();
    let delivery = pay_service::db::insert_manifest_delivery(&mut tx, &identity, &envelope)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    delivery
}

fn delivery_object_id(delivery: &pay_service::db::ChainSwapManifestDelivery) -> ManifestObjectId {
    ManifestObjectId::new(delivery.chain_swap_id, delivery.manifest_id).unwrap()
}

async fn replace_manifest_digest_without_constraint(
    pool: &PgPool,
    manifest_id: uuid::Uuid,
    replacement_digest: &str,
) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_manifest_deliveries \
         DROP CONSTRAINT chain_swap_manifest_digest_match_check",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chain_swap_manifest_deliveries \
            SET envelope_sha256 = $2 \
          WHERE manifest_id = $1",
    )
    .bind(manifest_id)
    .bind(replacement_digest)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn restore_manifest_digest_constraint(
    pool: &PgPool,
    manifest_id: uuid::Uuid,
    correct_digest: &str,
) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chain_swap_manifest_deliveries \
            SET envelope_sha256 = $2 \
          WHERE manifest_id = $1",
    )
    .bind(manifest_id)
    .bind(correct_digest)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "ALTER TABLE chain_swap_manifest_deliveries \
         ADD CONSTRAINT chain_swap_manifest_digest_match_check CHECK (\
             envelope_sha256 = encode(\
                 digest(convert_to(encrypted_envelope, 'UTF8'), 'sha256'),\
                 'hex'\
             )\
         )",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn replace_manifest_envelope_bypassing_update_trigger(
    pool: &PgPool,
    manifest_id: uuid::Uuid,
    replacement: &EncryptedSwapManifestV1,
) {
    let replacement_digest = manifest_envelope_sha256(replacement.encoded());
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chain_swap_manifest_deliveries \
            SET encrypted_envelope = $2, envelope_sha256 = $3 \
          WHERE manifest_id = $1",
    )
    .bind(manifest_id)
    .bind(replacement.encoded())
    .bind(replacement_digest)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

fn assert_sqlstate(error: &sqlx::Error, expected: &str) {
    let database = error
        .as_database_error()
        .unwrap_or_else(|| panic!("expected database error {expected}, got {error}"));
    assert_eq!(
        database.code().as_deref(),
        Some(expected),
        "unexpected database error: {database}"
    );
}

#[derive(Clone)]
struct StartupRestoreProviderState {
    records: &'static str,
    index: &'static str,
    calls: Arc<AtomicUsize>,
}

struct StartupRestoreProviderServer {
    base_url: String,
    chain_url: String,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl StartupRestoreProviderServer {
    async fn spawn(records: &'static str, index: &'static str) -> Self {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = StartupRestoreProviderState {
            records,
            index,
            calls: calls.clone(),
        };
        let app = Router::new()
            .route("/v2/swap/restore", post(startup_restore_provider_records))
            .route(
                "/v2/swap/restore/index",
                post(startup_restore_provider_index),
            )
            .route("/blocks/tip/height", get(startup_chain_tip_height))
            .route("/block-height/:height", get(startup_chain_block_hash))
            .route(
                "/address/:address/txs",
                get(startup_chain_empty_address_history),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            base_url: format!("http://{address}/v2"),
            chain_url: format!("http://{address}"),
            calls,
            task,
        }
    }
}

async fn startup_chain_tip_height() -> &'static str {
    "900000"
}

async fn startup_chain_block_hash() -> String {
    "11".repeat(32)
}

async fn startup_chain_empty_address_history() -> axum::Json<Value> {
    axum::Json(json!([]))
}

fn startup_chain_witness_adapter(
    server: &StartupRestoreProviderServer,
) -> pay_service::chain_lockup_witness_adapter::BitcoinLockupWitnessAdapterV1 {
    pay_service::chain_lockup_witness_adapter::BitcoinLockupWitnessAdapterV1::try_new(
        vec![server.chain_url.clone()],
        Duration::from_secs(2),
    )
    .unwrap()
}

impl Drop for StartupRestoreProviderServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn startup_restore_provider_records(
    State(state): State<StartupRestoreProviderState>,
) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    startup_restore_provider_response(state.records)
}

async fn startup_restore_provider_index(
    State(state): State<StartupRestoreProviderState>,
) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    startup_restore_provider_response(state.index)
}

fn startup_restore_provider_response(body: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn startup_reconciliation_master_key() -> SwapMasterKey {
    SwapMasterKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        Network::Mainnet,
    )
    .unwrap()
}

#[tokio::test]
async fn startup_provider_reconciliation_opens_only_on_exact_empty_source_agreement() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let server = StartupRestoreProviderServer::spawn("[]", r#"{"index":-1}"#).await;
    let fetcher =
        pay_service::boltz_restore_fetch::BoltzRestoreFetcher::from_loopback_for_integration_tests(
            &server.base_url,
        )
        .unwrap();
    let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(
        coordinator_manifest_store(InstrumentedManifestObjectStore::new()),
    );
    let master_key = startup_reconciliation_master_key();
    let chain_witness = startup_chain_witness_adapter(&server);

    let fact = pay_service::startup_provider_reconciliation::reconcile_startup_provider_state_v1(
        &pool,
        &runtime,
        &fetcher,
        &master_key,
        &chain_witness,
    )
    .await
    .unwrap();

    assert!(fact.exact_agreement());
    assert_eq!(fact.repaired_obligation_count(), 0);
    let report = fact.report();
    assert_eq!(report.manifest_count, 0);
    assert_eq!(report.local.local_record_count, 0);
    assert_eq!(report.boltz.validated_record_count, 0);
    assert_eq!(fact.reconstructed_chain_swap_count(), 0);
    assert_eq!(fact.reconstructed_delivery_count(), 0);
    assert_eq!(server.calls.load(Ordering::SeqCst), 2);
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn startup_provider_reconciliation_closes_on_provider_only_chain_orphan() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let server = StartupRestoreProviderServer::spawn(
        include_str!("fixtures/boltz-xpub-restore-v1.json"),
        include_str!("fixtures/boltz-xpub-restore-index-v1.json"),
    )
    .await;
    let fetcher =
        pay_service::boltz_restore_fetch::BoltzRestoreFetcher::from_loopback_for_integration_tests(
            &server.base_url,
        )
        .unwrap();
    let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(
        coordinator_manifest_store(InstrumentedManifestObjectStore::new()),
    );
    let master_key = startup_reconciliation_master_key();
    let chain_witness = startup_chain_witness_adapter(&server);

    let error = pay_service::startup_provider_reconciliation::reconcile_startup_provider_state_v1(
        &pool,
        &runtime,
        &fetcher,
        &master_key,
        &chain_witness,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        pay_service::startup_provider_reconciliation::StartupProviderReconciliationErrorV1::ThreeSourceAuditFailed,
        "a provider-only chain identity without an exact local inventory must fail closed"
    );
    assert_eq!(server.calls.load(Ordering::SeqCst), 2);
    let local_chain_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM chain_swap_records")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        local_chain_count, 0,
        "the failed audit must not reconstruct"
    );
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn startup_provider_reconciliation_repairs_then_requires_provider_match_without_restart() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture =
        AtomicManifestPersistenceFixture::seed(&pool, "startuprepairthenaudit", 30_001).await;
    let row = fixture.persist_manifestless_row(&pool).await;
    let store = coordinator_manifest_store(InstrumentedManifestObjectStore::new());
    let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(store);
    let server = StartupRestoreProviderServer::spawn("[]", r#"{"index":-1}"#).await;
    let fetcher =
        pay_service::boltz_restore_fetch::BoltzRestoreFetcher::from_loopback_for_integration_tests(
            &server.base_url,
        )
        .unwrap();
    let master_key = startup_reconciliation_master_key();
    let chain_witness = startup_chain_witness_adapter(&server);

    let error = pay_service::startup_provider_reconciliation::reconcile_startup_provider_state_v1(
        &pool,
        &runtime,
        &fetcher,
        &master_key,
        &chain_witness,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        pay_service::startup_provider_reconciliation::StartupProviderReconciliationErrorV1::ChainSwapReconstructionFailed,
        "the repaired manifest must fail before audit when no matching validated provider identity exists"
    );
    assert_eq!(server.calls.load(Ordering::SeqCst), 2);
    let deliveries = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].chain_swap_id, row.id);
    assert_eq!(deliveries[0].delivery_state, "delivered");
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn stale_restore_startup_reconstructs_authenticated_row_before_ledger_and_audit() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture =
        StaleRestoreReconstructionFixture::seed(&pool, "startupstalereconstruction").await;
    let backend = InstrumentedManifestObjectStore::new();
    let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(
        coordinator_manifest_store(backend),
    );
    let envelope =
        EncryptedSwapManifestV1::parse(runtime.seal_manifest_v1(&fixture.manifest).unwrap())
            .unwrap();
    let object_id = ManifestObjectId::new(
        fixture.manifest.restore_identity.chain_swap_id,
        fixture.manifest.restore_identity.manifest_id,
    )
    .unwrap();
    assert_eq!(
        runtime.store().put_v1(object_id, &envelope).await.unwrap(),
        ManifestWriteOutcome::Created
    );

    let all_records: Value =
        serde_json::from_str(include_str!("fixtures/boltz-xpub-restore-v1.json")).unwrap();
    let chain_only = Value::Array(vec![all_records.as_array().unwrap()[1].clone()]);
    let records: &'static str =
        Box::leak(serde_json::to_string(&chain_only).unwrap().into_boxed_str());
    let server = StartupRestoreProviderServer::spawn(
        records,
        include_str!("fixtures/boltz-xpub-restore-index-v1.json"),
    )
    .await;
    let fetcher =
        pay_service::boltz_restore_fetch::BoltzRestoreFetcher::from_loopback_for_integration_tests(
            &server.base_url,
        )
        .unwrap();
    let chain_witness = startup_chain_witness_adapter(&server);

    let first = pay_service::startup_provider_reconciliation::reconcile_startup_provider_state_v1(
        &pool,
        &runtime,
        &fetcher,
        &fixture.master,
        &chain_witness,
    )
    .await
    .unwrap();
    assert!(first.exact_agreement());
    assert_eq!(first.reconstructed_chain_swap_count(), 1);
    assert_eq!(first.reconstructed_delivery_count(), 1);
    assert_eq!(first.repaired_obligation_count(), 0);
    assert_eq!(first.chain_witness().missing_manifest_count, 1);
    let restored = pay_service::db::get_chain_swap_by_boltz_id(
        &pool,
        &fixture.manifest.restore_identity.boltz_swap_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(restored.id, fixture.manifest.restore_identity.chain_swap_id);
    assert_eq!(restored.claim_key_hex, fixture.expected_claim_key_hex);
    let deliveries = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(
        deliveries[0].manifest_id,
        fixture.manifest.restore_identity.manifest_id
    );
    assert_eq!(deliveries[0].chain_swap_id, restored.id);
    assert_eq!(deliveries[0].delivery_state, "delivered");
    assert_eq!(server.calls.load(Ordering::SeqCst), 4);

    let restarted =
        pay_service::startup_provider_reconciliation::reconcile_startup_provider_state_v1(
            &pool,
            &runtime,
            &fetcher,
            &fixture.master,
            &chain_witness,
        )
        .await
        .unwrap();
    assert!(restarted.exact_agreement());
    assert_eq!(restarted.reconstructed_chain_swap_count(), 0);
    assert_eq!(restarted.reconstructed_delivery_count(), 0);
    assert_eq!(server.calls.load(Ordering::SeqCst), 8);

    cleanup_db(&pool).await;
}

fn assert_corrupt_manifest_envelope(
    error: pay_service::db::ManifestDeliveryError,
    expected_manifest_id: uuid::Uuid,
    forbidden_envelope: &str,
) {
    assert!(matches!(
        &error,
        pay_service::db::ManifestDeliveryError::CorruptDatabaseEnvelope { manifest_id }
            if *manifest_id == expected_manifest_id
    ));
    let public_error = format!("{error:?} {error}");
    assert!(!public_error.contains(forbidden_envelope));
}

#[allow(clippy::too_many_arguments)]
async fn raw_insert_manifest_delivery(
    pool: &PgPool,
    manifest_id: uuid::Uuid,
    chain_swap_id: uuid::Uuid,
    manifest_sequence: i64,
    previous_manifest_id: Option<uuid::Uuid>,
    encrypted_envelope: &str,
    envelope_sha256: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO chain_swap_manifest_deliveries (\
             manifest_id, chain_swap_id, manifest_sequence, previous_manifest_id, \
             encrypted_envelope, envelope_sha256\
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(manifest_id)
    .bind(chain_swap_id)
    .bind(manifest_sequence)
    .bind(previous_manifest_id)
    .bind(encrypted_envelope)
    .bind(envelope_sha256)
    .execute(pool)
    .await?;
    Ok(())
}

async fn race_manifest_delivery_insert(
    pool: PgPool,
    start: Arc<Barrier>,
    manifest_id: uuid::Uuid,
    chain_swap_id: uuid::Uuid,
    encrypted_envelope: EncryptedSwapManifestV1,
) -> Result<pay_service::db::ChainSwapManifestDelivery, pay_service::db::ManifestDeliveryError> {
    let mut tx = pool.begin().await?;
    start.wait().await;
    let reservation = match pay_service::db::lock_manifest_delivery_tail(&mut tx).await {
        Ok(reservation) => reservation,
        Err(error) => {
            tx.rollback().await?;
            return Err(error);
        }
    };
    let identity = reservation.identity(manifest_id, chain_swap_id)?;
    let row =
        pay_service::db::insert_manifest_delivery(&mut tx, &identity, &encrypted_envelope).await?;
    tx.commit().await?;
    Ok(row)
}

#[tokio::test]
async fn manifest_delivery_ledger_api_resumes_marks_exactly_and_survives_source_cleanup() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (_, _, _, swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgerapi",
        "manifest-ledger-api",
        "bc1qmanifestledgerapi",
        1_010,
        1_000,
    )
    .await;
    let envelope = manifest_delivery_envelope(0x11);
    let manifest_id = uuid::Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    let reservation = pay_service::db::lock_manifest_delivery_tail(&mut tx)
        .await
        .unwrap();
    assert_eq!(reservation.manifest_sequence(), 1);
    assert_eq!(reservation.previous_manifest_id(), None);
    let identity = reservation.identity(manifest_id, swap.id).unwrap();
    let inserted = pay_service::db::insert_manifest_delivery(&mut tx, &identity, &envelope)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert_eq!(inserted.identity(), identity);
    assert_eq!(inserted.encrypted_envelope(), &envelope);
    assert_eq!(
        inserted.envelope_sha256,
        manifest_envelope_sha256(envelope.encoded())
    );
    assert_eq!(inserted.delivery_state, "pending");
    assert_eq!(inserted.delivered_at_unix, None);
    let debug = format!("{inserted:?}");
    assert!(debug.contains("encrypted_envelope: \"<redacted>\""));
    assert!(!debug.contains(envelope.encoded()));

    let pending = pay_service::db::list_pending_manifest_deliveries(&pool)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].identity(), identity);
    assert_eq!(pending[0].encrypted_envelope(), &envelope);

    let mut blocked = pool.begin().await.unwrap();
    let error = pay_service::db::lock_manifest_delivery_tail(&mut blocked)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        pay_service::db::ManifestDeliveryError::PendingDelivery {
            manifest_id: pending_id,
            chain_swap_id: pending_swap,
            manifest_sequence: 1,
        } if pending_id == manifest_id && pending_swap == swap.id
    ));
    blocked.rollback().await.unwrap();

    assert!(
        pay_service::db::mark_manifest_delivered(&pool, &identity, &"00".repeat(32),)
            .await
            .unwrap()
            .is_none()
    );
    let wrong_identity = pay_service::db::ManifestDeliveryIdentity {
        chain_swap_id: uuid::Uuid::new_v4(),
        ..identity
    };
    assert!(pay_service::db::mark_manifest_delivered(
        &pool,
        &wrong_identity,
        &inserted.envelope_sha256,
    )
    .await
    .unwrap()
    .is_none());

    let delivered =
        pay_service::db::mark_manifest_delivered(&pool, &identity, &inserted.envelope_sha256)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(delivered.delivery_state, "delivered");
    let delivered_at = delivered.delivered_at_unix.expect("delivery timestamp");
    let retry =
        pay_service::db::mark_manifest_delivered(&pool, &identity, &inserted.envelope_sha256)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(retry.delivered_at_unix, Some(delivered_at));
    assert!(pay_service::db::list_pending_manifest_deliveries(&pool)
        .await
        .unwrap()
        .is_empty());

    let audit = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].identity(), identity);
    assert!(matches!(
        pay_service::db::list_manifest_delivery_audit(&pool, 0, 0).await,
        Err(pay_service::db::ManifestDeliveryError::InvalidAuditLimit { .. })
    ));
    assert!(matches!(
        pay_service::db::list_manifest_delivery_audit(
            &pool,
            0,
            pay_service::db::MAX_MANIFEST_AUDIT_PAGE + 1,
        )
        .await,
        Err(pay_service::db::ManifestDeliveryError::InvalidAuditLimit {
            requested: 65,
            max: 64,
        })
    ));

    let deleted = sqlx::query("DELETE FROM chain_swap_records WHERE id = $1")
        .bind(swap.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(deleted.rows_affected(), 1);
    let preserved = pay_service::db::get_manifest_delivery(&pool, manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.identity(), identity);
    assert_eq!(preserved.encrypted_envelope(), &envelope);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_delivery_ledger_concurrency_serializes_genesis_and_pending_barrier() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (_, _, _, first_swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgerracea",
        "manifest-ledger-race-a",
        "bc1qmanifestledgerracea",
        1_010,
        1_000,
    )
    .await;
    let (_, _, _, second_swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgerraceb",
        "manifest-ledger-race-b",
        "bc1qmanifestledgerraceb",
        1_010,
        1_000,
    )
    .await;

    let start = Arc::new(Barrier::new(2));
    let first = tokio::spawn(race_manifest_delivery_insert(
        pool.clone(),
        start.clone(),
        uuid::Uuid::new_v4(),
        first_swap.id,
        manifest_delivery_envelope(0x21),
    ));
    let second = tokio::spawn(race_manifest_delivery_insert(
        pool.clone(),
        start,
        uuid::Uuid::new_v4(),
        second_swap.id,
        manifest_delivery_envelope(0x22),
    ));
    let results = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(pay_service::db::ManifestDeliveryError::PendingDelivery { .. })
            ))
            .count(),
        1
    );

    let rows = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].manifest_sequence, 1);
    assert_eq!(rows[0].previous_manifest_id, None);
    assert_eq!(rows[0].delivery_state, "pending");

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_delivery_ledger_refuses_gaps_branches_and_duplicate_predecessors() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (_, _, _, first_swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgertopa",
        "manifest-ledger-top-a",
        "bc1qmanifestledgertopa",
        1_010,
        1_000,
    )
    .await;
    let (_, _, _, second_swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgertopb",
        "manifest-ledger-top-b",
        "bc1qmanifestledgertopb",
        1_010,
        1_000,
    )
    .await;
    let (_, _, _, third_swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgertopc",
        "manifest-ledger-top-c",
        "bc1qmanifestledgertopc",
        1_010,
        1_000,
    )
    .await;

    let first_manifest = uuid::Uuid::new_v4();
    let first_envelope = manifest_delivery_envelope(0x31);
    let mut first_tx = pool.begin().await.unwrap();
    let first_reservation = pay_service::db::lock_manifest_delivery_tail(&mut first_tx)
        .await
        .unwrap();
    let first_identity = first_reservation
        .identity(first_manifest, first_swap.id)
        .unwrap();
    let first_row =
        pay_service::db::insert_manifest_delivery(&mut first_tx, &first_identity, &first_envelope)
            .await
            .unwrap();
    first_tx.commit().await.unwrap();
    pay_service::db::mark_manifest_delivered(&pool, &first_identity, &first_row.envelope_sha256)
        .await
        .unwrap()
        .unwrap();

    let second_manifest = uuid::Uuid::new_v4();
    let second_envelope = manifest_delivery_envelope(0x32);
    let second_digest = manifest_envelope_sha256(second_envelope.encoded());
    let gap = raw_insert_manifest_delivery(
        &pool,
        second_manifest,
        second_swap.id,
        3,
        Some(first_manifest),
        second_envelope.encoded(),
        &second_digest,
    )
    .await
    .unwrap_err();
    assert_sqlstate(&gap, "23514");

    let wrong_predecessor = raw_insert_manifest_delivery(
        &pool,
        second_manifest,
        second_swap.id,
        2,
        Some(uuid::Uuid::new_v4()),
        second_envelope.encoded(),
        &second_digest,
    )
    .await
    .unwrap_err();
    assert_sqlstate(&wrong_predecessor, "23514");

    let mut second_tx = pool.begin().await.unwrap();
    let second_reservation = pay_service::db::lock_manifest_delivery_tail(&mut second_tx)
        .await
        .unwrap();
    assert_eq!(second_reservation.manifest_sequence(), 2);
    assert_eq!(
        second_reservation.previous_manifest_id(),
        Some(first_manifest)
    );
    let second_identity = second_reservation
        .identity(second_manifest, second_swap.id)
        .unwrap();
    let second_row = pay_service::db::insert_manifest_delivery(
        &mut second_tx,
        &second_identity,
        &second_envelope,
    )
    .await
    .unwrap();
    second_tx.commit().await.unwrap();
    pay_service::db::mark_manifest_delivered(&pool, &second_identity, &second_row.envelope_sha256)
        .await
        .unwrap()
        .unwrap();

    let third_envelope = manifest_delivery_envelope(0x33);
    let third_digest = manifest_envelope_sha256(third_envelope.encoded());
    let branch = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        third_swap.id,
        3,
        Some(first_manifest),
        third_envelope.encoded(),
        &third_digest,
    )
    .await
    .unwrap_err();
    assert_sqlstate(&branch, "23514");

    let third_manifest = uuid::Uuid::new_v4();
    raw_insert_manifest_delivery(
        &pool,
        third_manifest,
        third_swap.id,
        3,
        Some(second_manifest),
        third_envelope.encoded(),
        &third_digest,
    )
    .await
    .unwrap();

    // Even a test-owner trigger bypass cannot create two successors for one
    // predecessor; the unique predecessor constraint is independent.
    let mut bypass = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *bypass)
        .await
        .unwrap();
    let duplicate_branch_envelope = manifest_delivery_envelope(0x34);
    let duplicate_predecessor = sqlx::query(
        "INSERT INTO chain_swap_manifest_deliveries (\
             manifest_id, chain_swap_id, manifest_sequence, previous_manifest_id, \
             encrypted_envelope, envelope_sha256, delivery_state, delivered_at\
         ) VALUES ($1, $2, 4, $3, $4, $5, 'delivered', NOW())",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(uuid::Uuid::new_v4())
    .bind(second_manifest)
    .bind(duplicate_branch_envelope.encoded())
    .bind(manifest_envelope_sha256(
        duplicate_branch_envelope.encoded(),
    ))
    .execute(&mut *bypass)
    .await
    .unwrap_err();
    assert_sqlstate(&duplicate_predecessor, "23505");
    assert_eq!(
        duplicate_predecessor
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_manifest_deliveries_previous_manifest_id_key")
    );
    bypass.rollback().await.unwrap();

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_delivery_ledger_enforces_bounds_digest_immutability_and_delete_refusal() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let (_, _, _, swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgerguard",
        "manifest-ledger-guard",
        "bc1qmanifestledgerguard",
        1_010,
        1_000,
    )
    .await;
    let (_, _, _, corrupt_swap) = seed_merchant_invoice_swap(
        &pool,
        "manifestledgercorrupt",
        "manifest-ledger-corrupt",
        "bc1qmanifestledgercorrupt",
        1_010,
        1_000,
    )
    .await;

    let envelope = manifest_delivery_envelope(0x41);
    let digest = manifest_envelope_sha256(envelope.encoded());
    let nonexistent = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        1,
        None,
        envelope.encoded(),
        &digest,
    )
    .await
    .unwrap_err();
    assert_sqlstate(&nonexistent, "23503");

    let empty = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        swap.id,
        1,
        None,
        "",
        &manifest_envelope_sha256(""),
    )
    .await
    .unwrap_err();
    assert_sqlstate(&empty, "23514");

    let oversized = "x".repeat(pay_service::db::MAX_MANIFEST_ENVELOPE_BYTES + 1);
    let oversized_error = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        swap.id,
        1,
        None,
        &oversized,
        &manifest_envelope_sha256(&oversized),
    )
    .await
    .unwrap_err();
    assert_sqlstate(&oversized_error, "23514");

    let uppercase_digest = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        swap.id,
        1,
        None,
        envelope.encoded(),
        &digest.to_uppercase(),
    )
    .await
    .unwrap_err();
    assert_sqlstate(&uppercase_digest, "23514");
    let mismatch = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        swap.id,
        1,
        None,
        envelope.encoded(),
        &"ab".repeat(32),
    )
    .await
    .unwrap_err();
    assert_sqlstate(&mismatch, "23514");
    let non_positive = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        swap.id,
        -1,
        None,
        envelope.encoded(),
        &digest,
    )
    .await
    .unwrap_err();
    assert_sqlstate(&non_positive, "23514");

    let manifest_id = uuid::Uuid::new_v4();
    let mut tx = pool.begin().await.unwrap();
    let reservation = pay_service::db::lock_manifest_delivery_tail(&mut tx)
        .await
        .unwrap();
    let identity = reservation.identity(manifest_id, swap.id).unwrap();
    assert!(EncryptedSwapManifestV1::parse("").is_err());
    assert!(EncryptedSwapManifestV1::parse(&oversized).is_err());
    let inserted = pay_service::db::insert_manifest_delivery(&mut tx, &identity, &envelope)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    for mutation_sql in [
        "UPDATE chain_swap_manifest_deliveries SET manifest_id = gen_random_uuid() WHERE manifest_id = $1",
        "UPDATE chain_swap_manifest_deliveries SET chain_swap_id = gen_random_uuid() WHERE manifest_id = $1",
        "UPDATE chain_swap_manifest_deliveries SET manifest_sequence = manifest_sequence + 1 WHERE manifest_id = $1",
        "UPDATE chain_swap_manifest_deliveries SET previous_manifest_id = gen_random_uuid() WHERE manifest_id = $1",
        "UPDATE chain_swap_manifest_deliveries SET envelope_sha256 = repeat('0', 64) WHERE manifest_id = $1",
        "UPDATE chain_swap_manifest_deliveries SET created_at = created_at + INTERVAL '1 second' WHERE manifest_id = $1",
    ] {
        let immutable = sqlx::query(mutation_sql)
            .bind(manifest_id)
            .execute(&pool)
            .await
            .unwrap_err();
        assert_sqlstate(&immutable, "55000");
    }

    let mutated_envelope = manifest_delivery_envelope(0x42);
    let mutation = sqlx::query(
        "UPDATE chain_swap_manifest_deliveries \
            SET encrypted_envelope = $2, envelope_sha256 = $3 \
          WHERE manifest_id = $1",
    )
    .bind(manifest_id)
    .bind(mutated_envelope.encoded())
    .bind(manifest_envelope_sha256(mutated_envelope.encoded()))
    .execute(&pool)
    .await
    .unwrap_err();
    assert_sqlstate(&mutation, "55000");

    let missing_timestamp = sqlx::query(
        "UPDATE chain_swap_manifest_deliveries \
            SET delivery_state = 'delivered' \
          WHERE manifest_id = $1",
    )
    .bind(manifest_id)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_sqlstate(&missing_timestamp, "55000");
    let delete = sqlx::query("DELETE FROM chain_swap_manifest_deliveries WHERE manifest_id = $1")
        .bind(manifest_id)
        .execute(&pool)
        .await
        .unwrap_err();
    assert_sqlstate(&delete, "55000");

    pay_service::db::mark_manifest_delivered(&pool, &identity, &inserted.envelope_sha256)
        .await
        .unwrap()
        .unwrap();
    let backwards = sqlx::query(
        "UPDATE chain_swap_manifest_deliveries \
            SET delivery_state = 'pending', delivered_at = NULL \
          WHERE manifest_id = $1",
    )
    .bind(manifest_id)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_sqlstate(&backwards, "55000");

    // Static uniqueness remains enforced even for the isolated test owner
    // with ordinary row triggers disabled.
    let duplicate_envelope = manifest_delivery_envelope(0x43);
    let duplicate_digest = manifest_envelope_sha256(duplicate_envelope.encoded());
    let mut duplicate_manifest_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *duplicate_manifest_tx)
        .await
        .unwrap();
    let duplicate_manifest = sqlx::query(
        "INSERT INTO chain_swap_manifest_deliveries (\
             manifest_id, chain_swap_id, manifest_sequence, previous_manifest_id, \
             encrypted_envelope, envelope_sha256, delivery_state, delivered_at\
         ) VALUES ($1, $2, 2, $3, $4, $5, 'delivered', NOW())",
    )
    .bind(manifest_id)
    .bind(uuid::Uuid::new_v4())
    .bind(uuid::Uuid::new_v4())
    .bind(duplicate_envelope.encoded())
    .bind(&duplicate_digest)
    .execute(&mut *duplicate_manifest_tx)
    .await
    .unwrap_err();
    assert_sqlstate(&duplicate_manifest, "23505");
    assert_eq!(
        duplicate_manifest
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_manifest_deliveries_pkey")
    );
    duplicate_manifest_tx.rollback().await.unwrap();

    let mut duplicate_sequence_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *duplicate_sequence_tx)
        .await
        .unwrap();
    let duplicate_sequence = sqlx::query(
        "INSERT INTO chain_swap_manifest_deliveries (\
             manifest_id, chain_swap_id, manifest_sequence, \
             encrypted_envelope, envelope_sha256, delivery_state, delivered_at\
         ) VALUES ($1, $2, 1, $3, $4, 'delivered', NOW())",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(uuid::Uuid::new_v4())
    .bind(duplicate_envelope.encoded())
    .bind(&duplicate_digest)
    .execute(&mut *duplicate_sequence_tx)
    .await
    .unwrap_err();
    assert_sqlstate(&duplicate_sequence, "23505");
    assert_eq!(
        duplicate_sequence
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_manifest_deliveries_manifest_sequence_key")
    );
    duplicate_sequence_tx.rollback().await.unwrap();

    let duplicate_chain_envelope = manifest_delivery_envelope(0x44);
    let duplicate_chain = raw_insert_manifest_delivery(
        &pool,
        uuid::Uuid::new_v4(),
        swap.id,
        2,
        Some(manifest_id),
        duplicate_chain_envelope.encoded(),
        &manifest_envelope_sha256(duplicate_chain_envelope.encoded()),
    )
    .await
    .unwrap_err();
    assert_sqlstate(&duplicate_chain, "23505");
    assert_eq!(
        duplicate_chain
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("chain_swap_manifest_deliveries_chain_swap_id_key")
    );

    // A privileged direct-SQL writer can satisfy the database's independent
    // size and digest constraints without producing a valid public envelope.
    // Every read/resume surface must reject that row before exposing bytes.
    let corrupt_manifest_id = uuid::Uuid::new_v4();
    let corrupt_envelope = "digest-valid-but-not-a-manifest-envelope";
    raw_insert_manifest_delivery(
        &pool,
        corrupt_manifest_id,
        corrupt_swap.id,
        2,
        Some(manifest_id),
        corrupt_envelope,
        &manifest_envelope_sha256(corrupt_envelope),
    )
    .await
    .unwrap();
    assert_corrupt_manifest_envelope(
        pay_service::db::list_pending_manifest_deliveries(&pool)
            .await
            .unwrap_err(),
        corrupt_manifest_id,
        corrupt_envelope,
    );
    assert_corrupt_manifest_envelope(
        pay_service::db::get_manifest_delivery(&pool, corrupt_manifest_id)
            .await
            .unwrap_err(),
        corrupt_manifest_id,
        corrupt_envelope,
    );
    assert_corrupt_manifest_envelope(
        pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
            .await
            .unwrap_err(),
        corrupt_manifest_id,
        corrupt_envelope,
    );

    cleanup_db(&pool).await;
}

// =====================================================================
// #87: unwired atomic chain-swap persistence + manifest delivery.
// =====================================================================

const ATOMIC_MANIFEST_LIQUID_DESTINATION: &str = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";
const ATOMIC_MANIFEST_EMERGENCY_ADDRESS: &str =
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

fn atomic_manifest_public_key(scalar: u8) -> boltz_client::PublicKey {
    let mut bytes = [0_u8; 32];
    bytes[31] = scalar;
    let secret = SecretKey::from_slice(&bytes).unwrap();
    boltz_client::PublicKey::new(secp256k1::PublicKey::from_secret_key(
        &Secp256k1::new(),
        &secret,
    ))
}

fn atomic_manifest_claim_script(
    hashlock: bitcoin::hashes::hash160::Hash,
    receiver: &boltz_client::PublicKey,
) -> bitcoin::ScriptBuf {
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_HASH160, OP_SIZE};
    use bitcoin::script::Builder;

    Builder::new()
        .push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_HASH160)
        .push_slice(hashlock.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&receiver.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn atomic_manifest_refund_script(
    sender: &boltz_client::PublicKey,
    timeout_height: u32,
) -> bitcoin::ScriptBuf {
    use bitcoin::absolute::LockTime;
    use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV};
    use bitcoin::script::Builder;

    Builder::new()
        .push_x_only_key(&sender.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_lock_time(LockTime::from_consensus(timeout_height))
        .push_opcode(OP_CLTV)
        .into_script()
}

fn atomic_manifest_provider_fixture(
    boltz_swap_id: &str,
    preimage: &boltz_client::util::secrets::Preimage,
    claim_public_key: boltz_client::PublicKey,
    refund_public_key: boltz_client::PublicKey,
) -> boltz_client::swaps::boltz::CreateChainResponse {
    use bitcoin::absolute::LockTime;
    use boltz_client::network::{BitcoinChain, LiquidChain};
    use boltz_client::swaps::boltz::{
        ChainSwapDetails, CreateChainResponse, Leaf, Side, SwapTree, SwapType,
    };
    use boltz_client::{BtcSwapScript, LBtcSwapScript, ZKKeyPair, ZKSecp256k1};

    const BLINDING_KEY: &str = "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";
    let bitcoin_server_key = boltz_client::PublicKey::from_str(
        "031c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8",
    )
    .unwrap();
    let liquid_server_key = boltz_client::PublicKey::from_str(
        "033009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01a",
    )
    .unwrap();
    let bitcoin_timeout = 958_033;
    let liquid_timeout = 3_972_215;
    let bitcoin_tree = SwapTree {
        claim_leaf: Leaf {
            output: hex::encode(atomic_manifest_claim_script(
                preimage.hash160,
                &bitcoin_server_key,
            )),
            version: 0xc0,
        },
        refund_leaf: Leaf {
            output: hex::encode(atomic_manifest_refund_script(
                &refund_public_key,
                bitcoin_timeout,
            )),
            version: 0xc0,
        },
        covenant_claim_leaf: None,
    };
    let liquid_tree = SwapTree {
        claim_leaf: Leaf {
            output: hex::encode(atomic_manifest_claim_script(
                preimage.hash160,
                &claim_public_key,
            )),
            version: 0xc4,
        },
        refund_leaf: Leaf {
            output: hex::encode(atomic_manifest_refund_script(
                &liquid_server_key,
                liquid_timeout,
            )),
            version: 0xc4,
        },
        covenant_claim_leaf: None,
    };
    let bitcoin_address = BtcSwapScript {
        swap_type: SwapType::Chain,
        side: Some(Side::Lockup),
        funding_addrs: None,
        hashlock: preimage.hash160,
        receiver_pubkey: bitcoin_server_key,
        locktime: LockTime::from_consensus(bitcoin_timeout),
        sender_pubkey: refund_public_key,
    }
    .to_address(BitcoinChain::Bitcoin)
    .unwrap()
    .to_string();
    let blinding_key = ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), BLINDING_KEY).unwrap();
    let liquid_address = LBtcSwapScript {
        swap_type: SwapType::Chain,
        side: Some(Side::Claim),
        funding_addrs: None,
        hashlock: preimage.hash160,
        receiver_pubkey: claim_public_key,
        locktime: boltz_client::elements::LockTime::from_consensus(liquid_timeout),
        sender_pubkey: liquid_server_key,
        blinding_key,
    }
    .to_address(LiquidChain::Liquid)
    .unwrap()
    .to_string();

    CreateChainResponse {
        id: boltz_swap_id.to_owned(),
        claim_details: ChainSwapDetails {
            swap_tree: liquid_tree,
            lockup_address: liquid_address,
            server_public_key: liquid_server_key,
            timeout_block_height: liquid_timeout,
            amount: 25_000,
            blinding_key: Some(BLINDING_KEY.into()),
            refund_address: None,
            claim_address: None,
            bip21: None,
        },
        lockup_details: ChainSwapDetails {
            swap_tree: bitcoin_tree,
            lockup_address: bitcoin_address,
            server_public_key: bitcoin_server_key,
            timeout_block_height: bitcoin_timeout,
            amount: 25_431,
            blinding_key: None,
            refund_address: None,
            claim_address: None,
            bip21: Some("bitcoin:provider-evidence-only?amount=999".into()),
        },
    }
}

fn atomic_manifest_sort_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut sorted = serde_json::Map::with_capacity(entries.len());
            for (key, value) in entries {
                sorted.insert(key, atomic_manifest_sort_json(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => {
            Value::Array(values.into_iter().map(atomic_manifest_sort_json).collect())
        }
        scalar => scalar,
    }
}

fn atomic_manifest_canonical_json<T: serde::Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).unwrap();
    serde_json::to_string(&atomic_manifest_sort_json(value)).unwrap()
}

fn atomic_manifest_leaf_sha256(leaf: &boltz_client::swaps::boltz::Leaf) -> String {
    hex::encode(Sha256::digest(hex::decode(&leaf.output).unwrap()))
}

struct StaleRestoreReconstructionFixture {
    master: SwapMasterKey,
    manifest: pay_service::swap_manifest::SwapManifestV1,
    provider: pay_service::boltz_restore::ValidatedBoltzRestoreSet,
    expected_preimage_hex: String,
    expected_claim_key_hex: String,
    expected_refund_key_hex: String,
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct StaleRestoreLineageRow {
    claim_key_index: Option<i64>,
    refund_key_index: Option<i64>,
    root_fingerprint: Option<String>,
    claim_key_allocation_id: Option<Uuid>,
    refund_key_allocation_id: Option<Uuid>,
}

impl StaleRestoreReconstructionFixture {
    async fn seed(pool: &PgPool, nym: &str) -> Self {
        use pay_service::boltz_restore::{
            BoltzRestoreKeyPurpose, BoltzRestoreKind, ValidatedBoltzRestoreKey,
            ValidatedBoltzRestoreRecord, ValidatedBoltzRestoreSet,
        };
        use pay_service::swap_manifest::{
            ImmutableChainSwapCreationV1, ManifestKeyAllocationV1, ManifestKeyPurposeV1,
            MerchantPolicyReferencesV1, SwapDerivationLineageV1, SwapManifestV1,
            SwapRestoreIdentityV1,
        };

        let npub = create_test_user(pool, nym).await;
        let recovery_address_commitment_id = insert_test_recovery_commitment(
            pool,
            &npub,
            ATOMIC_MANIFEST_EMERGENCY_ADDRESS,
            1,
            0x87,
        )
        .await;
        let invoice =
            insert_test_invoice(pool, nym, &npub, ATOMIC_MANIFEST_LIQUID_DESTINATION, 3_600).await;

        let master = startup_reconciliation_master_key();
        let claim_child_index = 101_u32;
        let refund_child_index = 102_u32;
        let claim_keypair = master.derive_swapkey(u64::from(claim_child_index)).unwrap();
        let refund_keypair = master
            .derive_swapkey(u64::from(refund_child_index))
            .unwrap();
        let claim_public_key = boltz_client::PublicKey::new(claim_keypair.public_key());
        let refund_public_key = boltz_client::PublicKey::new(refund_keypair.public_key());
        let preimage = Preimage::from_swap_key(&claim_keypair);
        let response = atomic_manifest_provider_fixture(
            "RstrChn00001",
            &preimage,
            claim_public_key,
            refund_public_key,
        );
        let canonical_provider_response = atomic_manifest_canonical_json(&response);
        let response_sha256 = hex::encode(Sha256::digest(canonical_provider_response.as_bytes()));
        let root_seed = master.derive_swapkey(0).unwrap();
        let root_digest = Sha256::digest(root_seed.public_key().serialize());
        let root_fingerprint = hex::encode(&root_digest[..8]);
        let claim_allocation_id = Uuid::new_v4();
        let refund_allocation_id = Uuid::new_v4();
        let chain_swap_id = Uuid::new_v4();
        let preimage_hash = preimage.sha256.to_string();
        let lockup_address = response.lockup_details.lockup_address.clone();
        let manifest = SwapManifestV1::new(
            SwapRestoreIdentityV1 {
                manifest_id: Uuid::new_v4(),
                manifest_sequence: 1,
                previous_manifest_id: None,
                chain_swap_id,
                boltz_swap_id: response.id.clone(),
                created_at_unix: 1_784_000_000,
            },
            SwapDerivationLineageV1 {
                root_fingerprint,
                key_epoch: 1,
                derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
                allocation_high_water_child_index: i64::from(refund_child_index),
                claim: ManifestKeyAllocationV1 {
                    allocation_id: claim_allocation_id,
                    child_index: i64::from(claim_child_index),
                    purpose: ManifestKeyPurposeV1::ChainClaim,
                    public_key_hex: claim_public_key.to_string(),
                    preimage_hash_hex: Some(preimage_hash.clone()),
                },
                refund: ManifestKeyAllocationV1 {
                    allocation_id: refund_allocation_id,
                    child_index: i64::from(refund_child_index),
                    purpose: ManifestKeyPurposeV1::ChainRefund,
                    public_key_hex: refund_public_key.to_string(),
                    preimage_hash_hex: None,
                },
            },
            ImmutableChainSwapCreationV1 {
                lockup_address: lockup_address.clone(),
                lockup_bip21: format!(
                    "bitcoin:{lockup_address}?amount=0.00025431&label=Restore%20payment"
                ),
                user_lock_amount_sat: 25_431,
                server_lock_amount_sat: 25_000,
                canonical_provider_response_json: canonical_provider_response,
                pinned_pair_hash: "22".repeat(32),
                canonical_pair_quote_json: format!(r#"{{"hash":"{}","rate":1}}"#, "22".repeat(32)),
                creation_response_sha256: response_sha256,
                btc_claim_script_sha256: atomic_manifest_leaf_sha256(
                    &response.lockup_details.swap_tree.claim_leaf,
                ),
                btc_refund_script_sha256: atomic_manifest_leaf_sha256(
                    &response.lockup_details.swap_tree.refund_leaf,
                ),
                liquid_claim_script_sha256: atomic_manifest_leaf_sha256(
                    &response.claim_details.swap_tree.claim_leaf,
                ),
                liquid_refund_script_sha256: atomic_manifest_leaf_sha256(
                    &response.claim_details.swap_tree.refund_leaf,
                ),
                btc_timeout_height: i64::from(response.lockup_details.timeout_block_height),
                liquid_timeout_height: i64::from(response.claim_details.timeout_block_height),
                btc_network: "bitcoin".into(),
                liquid_network: "liquid".into(),
                liquid_asset_id: boltz_client::elements::AssetId::LIQUID_BTC.to_string(),
                merchant_liquid_destination: ATOMIC_MANIFEST_LIQUID_DESTINATION.into(),
                merchant_emergency_btc_address: Some(ATOMIC_MANIFEST_EMERGENCY_ADDRESS.into()),
            },
            MerchantPolicyReferencesV1::new(
                invoice.id,
                nym,
                ATOMIC_MANIFEST_LIQUID_DESTINATION,
                Some((
                    recovery_address_commitment_id,
                    ATOMIC_MANIFEST_EMERGENCY_ADDRESS,
                )),
            ),
        )
        .unwrap();
        let provider = ValidatedBoltzRestoreSet {
            records: vec![ValidatedBoltzRestoreRecord {
                provider_swap_id: response.id,
                kind: BoltzRestoreKind::Chain,
                status: "transaction.server.mempool".into(),
                created_at: 1_784_000_000,
                keys: vec![
                    ValidatedBoltzRestoreKey {
                        purpose: BoltzRestoreKeyPurpose::ChainClaim,
                        child_index: claim_child_index,
                        public_key_hex: claim_public_key.to_string(),
                        preimage_sha256_hex: Some(preimage_hash),
                    },
                    ValidatedBoltzRestoreKey {
                        purpose: BoltzRestoreKeyPurpose::ChainRefund,
                        child_index: refund_child_index,
                        public_key_hex: refund_public_key.to_string(),
                        preimage_sha256_hex: None,
                    },
                ],
            }],
            max_child_index: Some(refund_child_index),
        };

        Self {
            master,
            manifest,
            provider,
            expected_preimage_hex: hex::encode(preimage.bytes.unwrap()),
            expected_claim_key_hex: hex::encode(claim_keypair.secret_bytes()),
            expected_refund_key_hex: hex::encode(refund_keypair.secret_bytes()),
        }
    }
}

#[tokio::test]
async fn stale_restore_reconstructs_exact_row_and_is_restart_idempotent() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture = StaleRestoreReconstructionFixture::seed(&pool, "stalerestoreexact").await;
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();

    let first =
        pay_service::chain_swap_stale_restore::reconstruct_validated_manifested_chain_swaps_v1(
            &pool,
            std::slice::from_ref(&fixture.manifest),
            &fixture.provider,
            &fixture.master,
        )
        .await
        .unwrap();
    assert_eq!(first.witnessed_records, 1);
    assert_eq!(first.reconstructed_records, 1);
    assert_eq!(first.verified_existing_records, 0);

    let row = pay_service::db::get_chain_swap_by_boltz_id(
        &pool,
        &fixture.manifest.restore_identity.boltz_swap_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.id, fixture.manifest.restore_identity.chain_swap_id);
    assert_eq!(row.invoice_id, fixture.manifest.merchant_policy.invoice_id);
    assert_eq!(row.nym.as_deref(), Some("stalerestoreexact"));
    assert_eq!(row.status, "pending");
    assert_eq!(row.preimage_hex, fixture.expected_preimage_hex);
    assert_eq!(row.claim_key_hex, fixture.expected_claim_key_hex);
    assert_eq!(row.refund_key_hex, fixture.expected_refund_key_hex);
    assert_eq!(
        row.created_at_unix,
        fixture.manifest.restore_identity.created_at_unix
    );
    assert_eq!(row.updated_at_unix, row.created_at_unix);
    let terms = row.creation_terms.unwrap();
    assert_eq!(
        terms.recovery_address_commitment_id,
        fixture
            .manifest
            .merchant_policy
            .emergency_bitcoin_commitment_id
    );
    assert_eq!(
        terms.merchant_liquid_destination,
        ATOMIC_MANIFEST_LIQUID_DESTINATION
    );

    let lineage: StaleRestoreLineageRow = sqlx::query_as(
        "SELECT claim_key_index, refund_key_index, root_fingerprint, \
                    claim_key_allocation_id, refund_key_allocation_id \
               FROM chain_swap_records WHERE id = $1",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        lineage,
        StaleRestoreLineageRow {
            claim_key_index: Some(fixture.manifest.derivation_lineage.claim.child_index),
            refund_key_index: Some(fixture.manifest.derivation_lineage.refund.child_index),
            root_fingerprint: Some(fixture.manifest.derivation_lineage.root_fingerprint.clone()),
            claim_key_allocation_id: Some(fixture.manifest.derivation_lineage.claim.allocation_id,),
            refund_key_allocation_id: Some(
                fixture.manifest.derivation_lineage.refund.allocation_id,
            ),
        }
    );
    let exact_allocation_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM swap_key_allocations WHERE id = $1 OR id = $2")
            .bind(fixture.manifest.derivation_lineage.claim.allocation_id)
            .bind(fixture.manifest.derivation_lineage.refund.allocation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(exact_allocation_count, 2);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before,
        "reconstruction must not consume or advance the allocator sequence"
    );

    sqlx::query("UPDATE chain_swap_records SET status = 'user_lock_mempool' WHERE id = $1")
        .bind(row.id)
        .execute(&pool)
        .await
        .unwrap();
    let restart =
        pay_service::chain_swap_stale_restore::reconstruct_validated_manifested_chain_swaps_v1(
            &pool,
            std::slice::from_ref(&fixture.manifest),
            &fixture.provider,
            &fixture.master,
        )
        .await
        .unwrap();
    assert_eq!(restart.witnessed_records, 1);
    assert_eq!(restart.reconstructed_records, 0);
    assert_eq!(restart.verified_existing_records, 1);
    let restarted = pay_service::db::get_chain_swap_by_boltz_id(
        &pool,
        &fixture.manifest.restore_identity.boltz_swap_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(restarted.status, "user_lock_mempool");

    let corrupt_claim_key = "fe".repeat(32);
    let mut corrupt = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    sqlx::query("UPDATE chain_swap_records SET claim_key_hex = $2 WHERE id = $1")
        .bind(row.id)
        .bind(&corrupt_claim_key)
        .execute(&mut *corrupt)
        .await
        .unwrap();
    corrupt.commit().await.unwrap();
    let conflict =
        pay_service::chain_swap_stale_restore::reconstruct_validated_manifested_chain_swaps_v1(
            &pool,
            std::slice::from_ref(&fixture.manifest),
            &fixture.provider,
            &fixture.master,
        )
        .await
        .unwrap_err();
    assert_eq!(
        conflict,
        pay_service::chain_swap_stale_restore::ChainSwapStaleRestoreErrorV1::ChainSwapConflict
    );
    let still_corrupt: String =
        sqlx::query_scalar("SELECT claim_key_hex FROM chain_swap_records WHERE id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        still_corrupt, corrupt_claim_key,
        "restore never overwrites a conflict"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn stale_restore_allocation_conflict_rolls_back_every_new_identity() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture = StaleRestoreReconstructionFixture::seed(&pool, "stalerestoreconflict").await;
    let conflicting_key = fixture.master.derive_swapkey(173).unwrap();
    let conflicting_public_key = boltz_client::PublicKey::new(conflicting_key.public_key());
    let conflicting_preimage = Preimage::from_swap_key(&conflicting_key);
    sqlx::query(
        "INSERT INTO swap_key_allocations (\
             id, root_fingerprint, key_epoch, derivation_scheme_version, child_index, \
             purpose, public_key_hex, preimage_hash_hex\
         ) VALUES ($1,$2,1,$3,173,'chain_claim',$4,$5)",
    )
    .bind(fixture.manifest.derivation_lineage.claim.allocation_id)
    .bind(&fixture.manifest.derivation_lineage.root_fingerprint)
    .bind(pay_service::db::DERIVATION_SCHEME_VERSION)
    .bind(conflicting_public_key.to_string())
    .bind(conflicting_preimage.sha256.to_string())
    .execute(&pool)
    .await
    .unwrap();
    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();

    let error =
        pay_service::chain_swap_stale_restore::reconstruct_validated_manifested_chain_swaps_v1(
            &pool,
            std::slice::from_ref(&fixture.manifest),
            &fixture.provider,
            &fixture.master,
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        pay_service::chain_swap_stale_restore::ChainSwapStaleRestoreErrorV1::AllocationConflict
    );
    assert!(pay_service::db::get_chain_swap_by_boltz_id(
        &pool,
        &fixture.manifest.restore_identity.boltz_swap_id,
    )
    .await
    .unwrap()
    .is_none());
    let refund_allocation_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM swap_key_allocations WHERE id = $1")
            .bind(fixture.manifest.derivation_lineage.refund.allocation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(refund_allocation_count, 0);
    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before
    );

    cleanup_db(&pool).await;
}

struct AtomicManifestPersistenceFixture {
    invoice_id: uuid::Uuid,
    nym: String,
    boltz_swap_id: String,
    lockup_address: String,
    lockup_bip21: String,
    canonical_provider_response: String,
    preimage_hex: String,
    claim_key_hex: String,
    refund_key_hex: String,
    root_fingerprint: String,
    claim_child_index: i64,
    refund_child_index: i64,
    claim_allocation_id: uuid::Uuid,
    refund_allocation_id: uuid::Uuid,
    claim_public_key_hex: String,
    refund_public_key_hex: String,
    preimage_hash_hex: String,
    creation_terms: pay_service::db::ChainSwapCreationTerms,
    policy: pay_service::swap_manifest::MerchantPolicyReferencesV1,
    encryption_key: [u8; 32],
    signing_key: Keypair,
    pinned_signer: secp256k1::XOnlyPublicKey,
}

impl AtomicManifestPersistenceFixture {
    async fn seed(pool: &PgPool, nym: &str, child_index: i64) -> Self {
        let npub = hex::encode(Sha256::digest(nym.as_bytes()));
        pay_service::db::create_user(pool, nym, &npub, TEST_DESCRIPTOR)
            .await
            .unwrap();
        let recovery_address_commitment_id = insert_test_recovery_commitment(
            pool,
            &npub,
            ATOMIC_MANIFEST_EMERGENCY_ADDRESS,
            1,
            0x87,
        )
        .await;
        let invoice =
            insert_test_invoice(pool, nym, &npub, &format!("lq1atomic{nym}"), 3_600).await;
        let boltz_swap_id = format!("AtomicManifest{child_index}");
        let claim_scalar = u8::try_from((child_index / 100).rem_euclid(100) + 1).unwrap();
        let preimage = boltz_client::util::secrets::Preimage::from_str(
            &format!("{claim_scalar:02x}").repeat(32),
        )
        .unwrap();
        let claim_public_key = atomic_manifest_public_key(claim_scalar);
        let refund_public_key = atomic_manifest_public_key(claim_scalar + 100);
        let provider = atomic_manifest_provider_fixture(
            &boltz_swap_id,
            &preimage,
            claim_public_key,
            refund_public_key,
        );
        let canonical_provider_response = atomic_manifest_canonical_json(&provider);
        let claim_public_key_hex = claim_public_key.to_string();
        let refund_public_key_hex = refund_public_key.to_string();
        let preimage_hash_hex = preimage.sha256.to_string();
        let root_fingerprint = format!("{:016x}", child_index as u64);
        let claim_allocation_id = pay_service::db::reserve_swap_key_allocation(
            pool,
            &pay_service::db::NewSwapKeyAllocation {
                root_fingerprint: &root_fingerprint,
                key_epoch: 1,
                derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
                child_index,
                purpose: pay_service::db::SwapKeyPurpose::ChainClaim,
                public_key_hex: &claim_public_key_hex,
                preimage_hash_hex: Some(&preimage_hash_hex),
            },
        )
        .await
        .unwrap();
        let refund_child_index = child_index + 1;
        let refund_allocation_id = pay_service::db::reserve_swap_key_allocation(
            pool,
            &pay_service::db::NewSwapKeyAllocation {
                root_fingerprint: &root_fingerprint,
                key_epoch: 1,
                derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
                child_index: refund_child_index,
                purpose: pay_service::db::SwapKeyPurpose::ChainRefund,
                public_key_hex: &refund_public_key_hex,
                preimage_hash_hex: None,
            },
        )
        .await
        .unwrap();
        let pinned_pair_hash = "22".repeat(32);
        let creation_terms = pay_service::db::ChainSwapCreationTerms {
            pinned_pair_hash: pinned_pair_hash.clone(),
            canonical_pair_quote_json: format!(r#"{{"hash":"{pinned_pair_hash}","rate":1}}"#),
            creation_response_sha256: hex::encode(Sha256::digest(
                canonical_provider_response.as_bytes(),
            )),
            btc_claim_script_sha256: atomic_manifest_leaf_sha256(
                &provider.lockup_details.swap_tree.claim_leaf,
            ),
            btc_refund_script_sha256: atomic_manifest_leaf_sha256(
                &provider.lockup_details.swap_tree.refund_leaf,
            ),
            liquid_claim_script_sha256: atomic_manifest_leaf_sha256(
                &provider.claim_details.swap_tree.claim_leaf,
            ),
            liquid_refund_script_sha256: atomic_manifest_leaf_sha256(
                &provider.claim_details.swap_tree.refund_leaf,
            ),
            btc_timeout_height: i64::from(provider.lockup_details.timeout_block_height),
            liquid_timeout_height: i64::from(provider.claim_details.timeout_block_height),
            btc_network: "bitcoin".into(),
            liquid_network: "liquid".into(),
            liquid_asset_id: boltz_client::elements::AssetId::LIQUID_BTC.to_string(),
            merchant_liquid_destination: ATOMIC_MANIFEST_LIQUID_DESTINATION.into(),
            merchant_emergency_btc_address: Some(ATOMIC_MANIFEST_EMERGENCY_ADDRESS.into()),
            recovery_address_commitment_id: Some(recovery_address_commitment_id),
        };
        let signing_key = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[0x11; 32]).unwrap(),
        );
        let pinned_signer = signing_key.x_only_public_key().0;
        let lockup_address = provider.lockup_details.lockup_address;
        let lockup_bip21 =
            format!("bitcoin:{lockup_address}?amount=0.00025431&label=Send%20to%20L-BTC%20address");

        Self {
            invoice_id: invoice.id,
            nym: nym.into(),
            boltz_swap_id,
            lockup_address,
            lockup_bip21,
            canonical_provider_response,
            preimage_hex: "aa".repeat(32),
            claim_key_hex: "bb".repeat(32),
            refund_key_hex: "cc".repeat(32),
            root_fingerprint,
            claim_child_index: child_index,
            refund_child_index,
            claim_allocation_id,
            refund_allocation_id,
            claim_public_key_hex,
            refund_public_key_hex,
            preimage_hash_hex,
            creation_terms,
            policy: pay_service::swap_manifest::MerchantPolicyReferencesV1::new(
                invoice.id,
                nym,
                ATOMIC_MANIFEST_LIQUID_DESTINATION,
                Some((
                    recovery_address_commitment_id,
                    ATOMIC_MANIFEST_EMERGENCY_ADDRESS,
                )),
            ),
            encryption_key: [0x42; 32],
            signing_key,
            pinned_signer,
        }
    }

    async fn persist(
        &self,
        pool: &PgPool,
        store: &RecoveryManifestStore,
        manifest_id: uuid::Uuid,
        policy: Option<&pay_service::swap_manifest::MerchantPolicyReferencesV1>,
    ) -> Result<
        pay_service::db::ChainSwapRecord,
        pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError,
    > {
        let faults = pay_service::swap_manifest_persistence::NoChainSwapPersistenceFaults;
        self.persist_with_faults(pool, store, manifest_id, policy, &faults)
            .await
    }

    async fn persist_with_faults(
        &self,
        pool: &PgPool,
        store: &RecoveryManifestStore,
        manifest_id: uuid::Uuid,
        policy: Option<&pay_service::swap_manifest::MerchantPolicyReferencesV1>,
        faults: &dyn pay_service::swap_manifest_persistence::ChainSwapPersistenceFaultInjector,
    ) -> Result<
        pay_service::db::ChainSwapRecord,
        pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError,
    > {
        let swap = pay_service::db::NewChainSwapRecord {
            invoice_id: self.invoice_id,
            nym: Some(&self.nym),
            boltz_swap_id: &self.boltz_swap_id,
            lockup_address: &self.lockup_address,
            lockup_bip21: Some(&self.lockup_bip21),
            user_lock_amount_sat: 25_431,
            server_lock_amount_sat: 25_000,
            preimage_hex: &self.preimage_hex,
            claim_key_hex: &self.claim_key_hex,
            refund_key_hex: &self.refund_key_hex,
            boltz_response_json: &self.canonical_provider_response,
            claim_key_index: Some(self.claim_child_index),
            refund_key_index: Some(self.refund_child_index),
            root_fingerprint: Some(&self.root_fingerprint),
        };
        let lineage = pay_service::db::ChainSwapLineage {
            claim_allocation_id: self.claim_allocation_id,
            refund_allocation_id: self.refund_allocation_id,
            key_epoch: 1,
            derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
            claim_public_key_hex: &self.claim_public_key_hex,
            refund_public_key_hex: &self.refund_public_key_hex,
            preimage_hash_hex: &self.preimage_hash_hex,
        };
        let terms = &self.creation_terms;
        let creation_terms = pay_service::db::NewChainSwapCreationTerms {
            pinned_pair_hash: &terms.pinned_pair_hash,
            canonical_pair_quote_json: &terms.canonical_pair_quote_json,
            creation_response_sha256: &terms.creation_response_sha256,
            btc_claim_script_sha256: &terms.btc_claim_script_sha256,
            btc_refund_script_sha256: &terms.btc_refund_script_sha256,
            liquid_claim_script_sha256: &terms.liquid_claim_script_sha256,
            liquid_refund_script_sha256: &terms.liquid_refund_script_sha256,
            btc_timeout_height: terms.btc_timeout_height,
            liquid_timeout_height: terms.liquid_timeout_height,
            btc_network: &terms.btc_network,
            liquid_network: &terms.liquid_network,
            liquid_asset_id: &terms.liquid_asset_id,
            merchant_liquid_destination: &terms.merchant_liquid_destination,
            merchant_emergency_btc_address: terms.merchant_emergency_btc_address.as_deref(),
        };
        pay_service::swap_manifest_persistence::persist_and_deliver_chain_swap_with_faults(
            pool,
            store,
            pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapRequest {
                swap: &swap,
                lineage: &lineage,
                creation_terms: &creation_terms,
                manifest_id,
                merchant_policy: policy.unwrap_or(&self.policy),
                crypto: pay_service::swap_manifest_staging::ManifestStagingCrypto::new(
                    "manifest-key-atomic-test",
                    &self.encryption_key,
                    &self.signing_key,
                    &self.pinned_signer,
                ),
            },
            faults,
        )
        .await
    }

    async fn persist_manifestless_row(&self, pool: &PgPool) -> pay_service::db::ChainSwapRecord {
        let terms = &self.creation_terms;
        pay_service::db::record_chain_swap_with_lineage_and_creation_evidence(
            pool,
            &pay_service::db::NewChainSwapRecord {
                invoice_id: self.invoice_id,
                nym: Some(&self.nym),
                boltz_swap_id: &self.boltz_swap_id,
                lockup_address: &self.lockup_address,
                lockup_bip21: Some(&self.lockup_bip21),
                user_lock_amount_sat: 25_431,
                server_lock_amount_sat: 25_000,
                preimage_hex: &self.preimage_hex,
                claim_key_hex: &self.claim_key_hex,
                refund_key_hex: &self.refund_key_hex,
                boltz_response_json: &self.canonical_provider_response,
                claim_key_index: Some(self.claim_child_index),
                refund_key_index: Some(self.refund_child_index),
                root_fingerprint: Some(&self.root_fingerprint),
            },
            &pay_service::db::ChainSwapLineage {
                claim_allocation_id: self.claim_allocation_id,
                refund_allocation_id: self.refund_allocation_id,
                key_epoch: 1,
                derivation_scheme_version: pay_service::db::DERIVATION_SCHEME_VERSION,
                claim_public_key_hex: &self.claim_public_key_hex,
                refund_public_key_hex: &self.refund_public_key_hex,
                preimage_hash_hex: &self.preimage_hash_hex,
            },
            &pay_service::db::NewChainSwapCreationEvidence {
                creation_terms: pay_service::db::NewChainSwapCreationTerms {
                    pinned_pair_hash: &terms.pinned_pair_hash,
                    canonical_pair_quote_json: &terms.canonical_pair_quote_json,
                    creation_response_sha256: &terms.creation_response_sha256,
                    btc_claim_script_sha256: &terms.btc_claim_script_sha256,
                    btc_refund_script_sha256: &terms.btc_refund_script_sha256,
                    liquid_claim_script_sha256: &terms.liquid_claim_script_sha256,
                    liquid_refund_script_sha256: &terms.liquid_refund_script_sha256,
                    btc_timeout_height: terms.btc_timeout_height,
                    liquid_timeout_height: terms.liquid_timeout_height,
                    btc_network: &terms.btc_network,
                    liquid_network: &terms.liquid_network,
                    liquid_asset_id: &terms.liquid_asset_id,
                    merchant_liquid_destination: &terms.merchant_liquid_destination,
                    merchant_emergency_btc_address: terms.merchant_emergency_btc_address.as_deref(),
                },
                recovery_address_commitment_id: terms.recovery_address_commitment_id,
            },
        )
        .await
        .unwrap()
    }
}

struct PausingChainSwapPersistenceFault {
    point: pay_service::swap_manifest_persistence::ChainSwapPersistenceFaultPoint,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl PausingChainSwapPersistenceFault {
    fn new(point: pay_service::swap_manifest_persistence::ChainSwapPersistenceFaultPoint) -> Self {
        Self {
            point,
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }

    async fn wait_until_reached(&self) {
        tokio::time::timeout(Duration::from_secs(30), self.reached.notified())
            .await
            .expect("chain-swap persistence did not reach the injected kill boundary");
    }
}

#[async_trait]
impl pay_service::swap_manifest_persistence::ChainSwapPersistenceFaultInjector
    for PausingChainSwapPersistenceFault
{
    async fn check(
        &self,
        point: pay_service::swap_manifest_persistence::ChainSwapPersistenceFaultPoint,
    ) -> Result<(), pay_service::swap_manifest_persistence::InjectedChainSwapPersistenceFault> {
        if point == self.point {
            self.reached.notify_one();
            self.release.notified().await;
        }
        Ok(())
    }
}

#[tokio::test]
async fn atomic_manifest_persistence_returns_only_after_exact_durable_delivery() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture = AtomicManifestPersistenceFixture::seed(&pool, "atomicmanifestok", 10_001).await;
    let manifest_id = uuid::Uuid::new_v4();
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);

    let persisted = fixture
        .persist(&pool, &store, manifest_id, None)
        .await
        .unwrap();
    let delivery = pay_service::db::get_manifest_delivery(&pool, manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivery.chain_swap_id, persisted.id);
    assert_eq!(delivery.delivery_state, "delivered");
    assert!(delivery.delivered_at_unix.is_some());
    assert_eq!(delivery.manifest_sequence, 1);
    assert_eq!(delivery.previous_manifest_id, None);
    assert_eq!(
        pay_service::db::latest_payer_exposable_chain_swap_for_invoice(
            &pool,
            fixture.invoice_id,
            25_000,
        )
        .await
        .unwrap()
        .map(|row| row.id),
        Some(persisted.id),
        "the payer address stayed hidden after exact durable manifest delivery"
    );
    let object_id = ManifestObjectId::new(persisted.id, manifest_id).unwrap();
    assert_eq!(
        store.get_v1(object_id).await.unwrap().encoded(),
        delivery.encrypted_envelope().encoded()
    );
    assert_eq!(
        resume_pending_manifest_delivery(&pool, &store)
            .await
            .unwrap(),
        ManifestDeliveryResumeOutcome::NoPending
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn chain_swap_creation_kill_restart_converges_at_every_persistence_boundary() {
    use pay_service::swap_manifest_persistence::ChainSwapPersistenceFaultPoint as Point;

    let cases = [
        (Point::AfterCanonicalSwapCommit, "killcanonical", 11_001),
        (
            Point::AfterManifestLedgerWriteBeforeCommit,
            "killledgerwrite",
            11_101,
        ),
        (
            Point::AfterManifestLedgerCommitBeforeDelivery,
            "killledgercommit",
            11_201,
        ),
        (
            Point::AfterManifestDeliveryAcknowledgedBeforeReturn,
            "killafterack",
            11_301,
        ),
    ];

    for (point, nym, child_index) in cases {
        let pool = test_pool().await;
        cleanup_db(&pool).await;
        let fixture =
            Arc::new(AtomicManifestPersistenceFixture::seed(&pool, nym, child_index).await);
        let manifest_id = uuid::Uuid::new_v4();
        let backend = InstrumentedManifestObjectStore::new();
        let store = coordinator_manifest_store(backend);
        let fault = Arc::new(PausingChainSwapPersistenceFault::new(point));

        let task_pool = pool.clone();
        let task_store = store.clone();
        let task_fixture = fixture.clone();
        let task_fault = fault.clone();
        let attempt = tokio::spawn(async move {
            task_fixture
                .persist_with_faults(
                    &task_pool,
                    &task_store,
                    manifest_id,
                    None,
                    task_fault.as_ref(),
                )
                .await
        });

        fault.wait_until_reached().await;
        attempt.abort();
        assert!(
            attempt.await.unwrap_err().is_cancelled(),
            "the injected process-loss task was not cancelled at {point:?}"
        );

        // Closing every old-pool connection models a process restart and also
        // makes a pre-commit cancellation's transaction rollback observable
        // before the restarted process reads any state.
        pool.close().await;
        let restarted = test_pool().await;
        let retained =
            pay_service::db::get_chain_swap_by_boltz_id(&restarted, &fixture.boltz_swap_id)
                .await
                .unwrap()
                .expect("a post-provider process kill erased the canonical swap");
        assert_eq!(retained.status, "pending");
        assert_eq!(
            retained.boltz_response_json,
            fixture.canonical_provider_response
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chain_swap_records")
                .fetch_one(&restarted)
                .await
                .unwrap(),
            1,
            "restart recovery duplicated the provider-created swap at {point:?}"
        );

        let deliveries_before = pay_service::db::list_manifest_delivery_audit(&restarted, 0, 10)
            .await
            .unwrap();
        match point {
            Point::AfterCanonicalSwapCommit | Point::AfterManifestLedgerWriteBeforeCommit => {
                assert!(
                    deliveries_before.is_empty(),
                    "an uncommitted ledger row survived process loss at {point:?}"
                );
            }
            Point::AfterManifestLedgerCommitBeforeDelivery => {
                assert_eq!(deliveries_before.len(), 1);
                assert_eq!(deliveries_before[0].manifest_id, manifest_id);
                assert_eq!(deliveries_before[0].delivery_state, "pending");
            }
            Point::AfterManifestDeliveryAcknowledgedBeforeReturn => {
                assert_eq!(deliveries_before.len(), 1);
                assert_eq!(deliveries_before[0].manifest_id, manifest_id);
                assert_eq!(deliveries_before[0].delivery_state, "delivered");
            }
        }

        let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(store.clone());
        let acquisition = ChainSwapCreationPermit::acquire(&restarted, &runtime).await;
        match point {
            Point::AfterManifestDeliveryAcknowledgedBeforeReturn => {
                acquisition
                    .expect("an acknowledged creation should need no restart repair")
                    .release()
                    .await
                    .unwrap();
            }
            _ => {
                assert_eq!(
                    acquisition.unwrap_err(),
                    ChainSwapCreationPermitError::ManifestRepairCompleted,
                    "restart must repair/resume without crossing the provider boundary"
                );
                ChainSwapCreationPermit::acquire(&restarted, &runtime)
                    .await
                    .expect("a clean attempt after restart repair should receive the permit")
                    .release()
                    .await
                    .unwrap();
            }
        }

        let deliveries = pay_service::db::list_manifest_delivery_audit(&restarted, 0, 10)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].chain_swap_id, retained.id);
        assert_eq!(deliveries[0].delivery_state, "delivered");
        assert!(deliveries[0].delivered_at_unix.is_some());
        assert_eq!(
            pay_service::db::latest_payer_exposable_chain_swap_for_invoice(
                &restarted,
                fixture.invoice_id,
                25_000,
            )
            .await
            .unwrap()
            .map(|candidate| candidate.id),
            Some(retained.id),
            "restart did not converge to one payer-exposable canonical swap"
        );
        assert!(
            pay_service::db::list_pending_manifest_deliveries(&restarted)
                .await
                .unwrap()
                .is_empty(),
            "restart left a pending manifest obligation at {point:?}"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chain_swap_records")
                .fetch_one(&restarted)
                .await
                .unwrap(),
            1
        );

        cleanup_db(&restarted).await;
        restarted.close().await;
    }
}

#[tokio::test]
async fn permit_repairs_manifestless_row_and_requires_a_fresh_creation_attempt() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture =
        AtomicManifestPersistenceFixture::seed(&pool, "repairmanifestlessok", 20_001).await;
    let row = fixture.persist_manifestless_row(&pool).await;
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);
    let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(store.clone());

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted,
        "the repair attempt must never return a new provider-creation permit"
    );
    let audit = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    let delivery = &audit[0];
    assert_eq!(delivery.chain_swap_id, row.id);
    assert_eq!(delivery.manifest_sequence, 1);
    assert_eq!(delivery.previous_manifest_id, None);
    assert_eq!(delivery.delivery_state, "delivered");
    let object_id = ManifestObjectId::new(row.id, delivery.manifest_id).unwrap();
    assert_eq!(
        store.get_v1(object_id).await.unwrap().encoded(),
        delivery.encrypted_envelope().encoded(),
        "the repaired object must pass the production read-verification path"
    );
    assert_eq!(
        pay_service::db::latest_payer_exposable_chain_swap_for_invoice(
            &pool,
            fixture.invoice_id,
            25_000,
        )
        .await
        .unwrap()
        .map(|candidate| candidate.id),
        Some(row.id)
    );

    let permit = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("a later clean attempt may receive the creation permit");
    permit.release().await.unwrap();
    assert_eq!(
        pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
            .await
            .unwrap()
            .len(),
        1,
        "repeat acquisition must not append another manifest"
    );
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn permit_repair_store_failure_retains_row_and_resumes_one_committed_identity() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture =
        AtomicManifestPersistenceFixture::seed(&pool, "repairmanifeststorefail", 20_101).await;
    let row = fixture.persist_manifestless_row(&pool).await;
    let backend = InstrumentedManifestObjectStore::failing_first_put();
    let store = coordinator_manifest_store(backend);
    let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(store.clone());

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairFailed
    );
    let retained = pay_service::db::get_chain_swap_by_id(&pool, row.id)
        .await
        .unwrap()
        .expect("canonical provider row must survive store failure");
    assert_eq!(retained.boltz_response_json, row.boltz_response_json);
    assert_eq!(retained.status, "pending");
    let pending = pay_service::db::list_pending_manifest_deliveries(&pool)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].chain_swap_id, row.id);
    let committed_manifest_id = pending[0].manifest_id;

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted,
        "resuming the pending repair must not return a creation permit"
    );
    let audit = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].manifest_id, committed_manifest_id);
    assert_eq!(audit[0].delivery_state, "delivered");
    let object_id = ManifestObjectId::new(row.id, committed_manifest_id).unwrap();
    assert_eq!(
        store.get_v1(object_id).await.unwrap().encoded(),
        audit[0].encrypted_envelope().encoded()
    );

    let permit = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("only the clean post-repair attempt receives a permit");
    permit.release().await.unwrap();
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn permit_repairs_multiple_rows_in_oldest_canonical_order() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let newer_fixture =
        AtomicManifestPersistenceFixture::seed(&pool, "repairmanifestnewer", 20_201).await;
    let newer = newer_fixture.persist_manifestless_row(&pool).await;
    let older_fixture =
        AtomicManifestPersistenceFixture::seed(&pool, "repairmanifestolder", 20_301).await;
    let older = older_fixture.persist_manifestless_row(&pool).await;
    sqlx::query("UPDATE chain_swap_records SET created_at = '2026-02-02T00:00:00Z' WHERE id = $1")
        .bind(newer.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE chain_swap_records SET created_at = '2026-02-01T00:00:00Z' WHERE id = $1")
        .bind(older.id)
        .execute(&pool)
        .await
        .unwrap();
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);
    let runtime = RecoveryManifestRuntimeV1::from_store_for_integration_tests(store);

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted
    );
    let first = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].chain_swap_id, older.id);
    assert_eq!(first[0].manifest_sequence, 1);

    assert_eq!(
        ChainSwapCreationPermit::acquire(&pool, &runtime)
            .await
            .unwrap_err(),
        ChainSwapCreationPermitError::ManifestRepairCompleted
    );
    let both = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(both.len(), 2);
    assert_eq!(both[0].chain_swap_id, older.id);
    assert_eq!(both[1].chain_swap_id, newer.id);
    assert_eq!(both[1].manifest_sequence, 2);
    assert_eq!(both[1].previous_manifest_id, Some(both[0].manifest_id));

    let permit = ChainSwapCreationPermit::acquire(&pool, &runtime)
        .await
        .expect("all older obligations are repaired");
    permit.release().await.unwrap();
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn post_provider_staging_failure_retains_canonical_pending_swap_and_withholds_payer_address()
{
    use pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError;

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture = AtomicManifestPersistenceFixture::seed(&pool, "atomicstagebad", 10_101).await;
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend.clone());
    let mut wrong_policy = fixture.policy.clone();
    wrong_policy.merchant_nym = "different-merchant".into();

    // Model the real create_bitcoin_chain_offer boundary: the provider has
    // already created the remote swap and returned its one canonical response,
    // but a later manifest-staging check refuses the payer instruction.
    let staging_error = fixture
        .persist(&pool, &store, uuid::Uuid::new_v4(), Some(&wrong_policy))
        .await
        .unwrap_err();
    assert_eq!(
        staging_error,
        PersistAndDeliverChainSwapError::ManifestStagingFailed
    );
    let retained = pay_service::db::get_chain_swap_by_boltz_id(&pool, &fixture.boltz_swap_id)
        .await
        .unwrap()
        .expect("post-provider staging failure erased the canonical swap record");
    assert_eq!(retained.invoice_id, fixture.invoice_id);
    assert_eq!(retained.nym.as_deref(), Some(fixture.nym.as_str()));
    assert_eq!(retained.lockup_address, fixture.lockup_address);
    assert_eq!(
        retained.lockup_bip21.as_deref(),
        Some(fixture.lockup_bip21.as_str())
    );
    assert_eq!(
        retained.boltz_response_json,
        fixture.canonical_provider_response
    );
    assert_eq!(retained.preimage_hex, fixture.preimage_hex);
    assert_eq!(retained.claim_key_hex, fixture.claim_key_hex);
    assert_eq!(retained.refund_key_hex, fixture.refund_key_hex);
    assert_eq!(
        retained.creation_terms.as_ref(),
        Some(&fixture.creation_terms)
    );
    assert_eq!(retained.status, "pending");
    let evidence = pay_service::db::load_manifest_staging_evidence(&pool, retained.id)
        .await
        .unwrap()
        .expect("retained provider record lost its recoverable public lineage");
    assert_eq!(
        evidence.persisted_lineage.claim.allocation_id,
        fixture.claim_allocation_id
    );
    assert_eq!(
        evidence.persisted_lineage.refund.allocation_id,
        fixture.refund_allocation_id
    );

    // The row remains an internal pending obligation, but public invoice reads
    // cannot expose its payer address until a delivered manifest exists.
    assert_eq!(
        pay_service::db::latest_payable_chain_swap_for_invoice(&pool, fixture.invoice_id, 25_000,)
            .await
            .unwrap()
            .map(|row| row.id),
        Some(retained.id)
    );
    assert!(
        pay_service::db::latest_payer_exposable_chain_swap_for_invoice(
            &pool,
            fixture.invoice_id,
            25_000,
        )
        .await
        .unwrap()
        .is_none(),
        "an undelivered recovery manifest exposed the payer address"
    );
    let npub = hex::encode(Sha256::digest(fixture.nym.as_bytes()));
    match pay_service::db::purge_user(&pool, &npub).await.unwrap() {
        pay_service::db::PurgeOutcome::InFlightSwaps(1) => {}
        _ => panic!("the retained pending chain swap did not block destructive purge"),
    }
    assert!(pay_service::db::list_pending_manifest_deliveries(&pool)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(backend.io_calls(), 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn atomic_manifest_persistence_retains_canonical_row_on_ledger_failure() {
    use pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError;

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);
    let retained_manifest_id = uuid::Uuid::new_v4();
    let first = AtomicManifestPersistenceFixture::seed(&pool, "atomicledgerfirst", 10_201).await;
    first
        .persist(&pool, &store, retained_manifest_id, None)
        .await
        .unwrap();
    let intermediate =
        AtomicManifestPersistenceFixture::seed(&pool, "atomicledgerbetween", 10_301).await;
    intermediate
        .persist(&pool, &store, uuid::Uuid::new_v4(), None)
        .await
        .unwrap();
    let rejected = AtomicManifestPersistenceFixture::seed(&pool, "atomicledgerbad", 10_401).await;
    let ledger_error = rejected
        .persist(&pool, &store, retained_manifest_id, None)
        .await
        .unwrap_err();
    assert_eq!(
        ledger_error,
        PersistAndDeliverChainSwapError::ManifestLedgerInsertFailed
    );
    let retained = pay_service::db::get_chain_swap_by_boltz_id(&pool, &rejected.boltz_swap_id)
        .await
        .unwrap()
        .expect("ledger failure erased the canonical provider-created swap");
    assert_eq!(retained.status, "pending");
    assert!(
        pay_service::db::latest_payer_exposable_chain_swap_for_invoice(
            &pool,
            rejected.invoice_id,
            25_000,
        )
        .await
        .unwrap()
        .is_none()
    );
    let ledger_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_manifest_deliveries")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ledger_count, 2);

    let duplicate_error = first
        .persist(&pool, &store, uuid::Uuid::new_v4(), None)
        .await
        .unwrap_err();
    assert_eq!(
        duplicate_error,
        PersistAndDeliverChainSwapError::ChainSwapPersistenceFailed
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM chain_swap_records")
            .fetch_one(&pool)
            .await
            .unwrap(),
        3
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn atomic_manifest_pending_barrier_blocks_concurrent_swap_and_success_waits_for_storage() {
    use pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError;

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let first =
        Arc::new(AtomicManifestPersistenceFixture::seed(&pool, "atomicblockedone", 10_301).await);
    let second = AtomicManifestPersistenceFixture::seed(&pool, "atomicblockedtwo", 10_401).await;
    let first_manifest_id = uuid::Uuid::new_v4();
    let (backend, put_committed, release_put) =
        InstrumentedManifestObjectStore::pausing_after_first_put();
    let store = coordinator_manifest_store(backend);
    let task_pool = pool.clone();
    let task_store = store.clone();
    let task_fixture = first.clone();
    let first_attempt = tokio::spawn(async move {
        task_fixture
            .persist(&task_pool, &task_store, first_manifest_id, None)
            .await
    });

    tokio::time::timeout(Duration::from_secs(30), put_committed.wait())
        .await
        .expect("atomic persistence did not reach its post-create barrier");
    assert!(
        !first_attempt.is_finished(),
        "a committed object is not success until read verification and acknowledgement"
    );
    let pending = pay_service::db::get_manifest_delivery(&pool, first_manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.delivery_state, "pending");
    assert!(
        pay_service::db::get_chain_swap_by_boltz_id(&pool, &first.boltz_swap_id)
            .await
            .unwrap()
            .is_some(),
        "canonical swap and pending ledger row must exist before off-host I/O"
    );

    let blocked = second
        .persist(&pool, &store, uuid::Uuid::new_v4(), None)
        .await
        .unwrap_err();
    assert_eq!(
        blocked,
        PersistAndDeliverChainSwapError::PendingManifestDelivery
    );
    let blocked_record = pay_service::db::get_chain_swap_by_boltz_id(&pool, &second.boltz_swap_id)
        .await
        .unwrap()
        .expect("the pending-manifest barrier erased a second provider-created swap");
    assert_eq!(blocked_record.status, "pending");
    assert!(
        pay_service::db::latest_payer_exposable_chain_swap_for_invoice(
            &pool,
            second.invoice_id,
            25_000,
        )
        .await
        .unwrap()
        .is_none(),
        "the blocked provider-created swap leaked a payer instruction"
    );

    tokio::time::timeout(Duration::from_secs(30), release_put.wait())
        .await
        .expect("atomic persistence did not leave its post-create barrier");
    let completed = tokio::time::timeout(Duration::from_secs(30), first_attempt)
        .await
        .expect("atomic persistence did not finish")
        .unwrap()
        .unwrap();
    assert_eq!(completed.boltz_swap_id, first.boltz_swap_id);
    assert_eq!(
        pay_service::db::get_manifest_delivery(&pool, first_manifest_id)
            .await
            .unwrap()
            .unwrap()
            .delivery_state,
        "delivered"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn atomic_manifest_storage_failure_commits_one_pending_row_and_resumes_exactly() {
    use pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError;

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture = AtomicManifestPersistenceFixture::seed(&pool, "atomicstorefail", 10_501).await;
    let manifest_id = uuid::Uuid::new_v4();
    let backend = InstrumentedManifestObjectStore::failing_first_put();
    let store = coordinator_manifest_store(backend);

    let error = fixture
        .persist(&pool, &store, manifest_id, None)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        PersistAndDeliverChainSwapError::ManifestDeliveryFailed
    );
    let public_error = format!("{error:?} {error}");
    for forbidden in [
        fixture.preimage_hex.as_str(),
        fixture.claim_key_hex.as_str(),
        fixture.refund_key_hex.as_str(),
        fixture.canonical_provider_response.as_str(),
        "injected put failure",
    ] {
        assert!(!public_error.contains(forbidden));
    }
    let pending = pay_service::db::get_manifest_delivery(&pool, manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.delivery_state, "pending");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM chain_swap_manifest_deliveries WHERE delivery_state = 'pending'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    assert_eq!(
        resume_pending_manifest_delivery(&pool, &store)
            .await
            .unwrap(),
        ManifestDeliveryResumeOutcome::Delivered {
            identity: pending.identity(),
            storage_outcome: ManifestWriteOutcome::Created,
        }
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn atomic_manifest_storage_conflict_never_acknowledges_or_returns_swap() {
    use pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError;

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let fixture =
        AtomicManifestPersistenceFixture::seed(&pool, "atomicstoreconflict", 10_601).await;
    let manifest_id = uuid::Uuid::new_v4();
    let backend = InstrumentedManifestObjectStore::conflicting_first_put();
    let store = coordinator_manifest_store(backend);

    let error = fixture
        .persist(&pool, &store, manifest_id, None)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        PersistAndDeliverChainSwapError::ManifestDeliveryFailed
    );
    let pending = pay_service::db::get_manifest_delivery(&pool, manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.delivery_state, "pending");
    let retry_error = resume_pending_manifest_delivery(&pool, &store)
        .await
        .unwrap_err();
    assert!(
        matches!(
            retry_error,
            ManifestDeliveryCoordinatorError::StorageConflict { .. }
        ),
        "unexpected retry error: {retry_error:?}"
    );
    assert_eq!(
        pay_service::db::get_manifest_delivery(&pool, manifest_id)
            .await
            .unwrap()
            .unwrap()
            .delivery_state,
        "pending"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn atomic_manifest_ack_failure_retries_read_verified_object_as_already_present() {
    use pay_service::swap_manifest_persistence::PersistAndDeliverChainSwapError;

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    sqlx::query(
        "DROP TRIGGER IF EXISTS bullnym_test_reject_manifest_ack ON chain_swap_manifest_deliveries",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS bullnym_test_reject_manifest_ack()")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE FUNCTION bullnym_test_reject_manifest_ack() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
             IF OLD.delivery_state = 'pending' AND NEW.delivery_state = 'delivered' THEN \
                 RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'injected ack failure'; \
             END IF; \
             RETURN NEW; \
         END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER bullnym_test_reject_manifest_ack \
         BEFORE UPDATE ON chain_swap_manifest_deliveries \
         FOR EACH ROW EXECUTE FUNCTION bullnym_test_reject_manifest_ack()",
    )
    .execute(&pool)
    .await
    .unwrap();

    let fixture = AtomicManifestPersistenceFixture::seed(&pool, "atomicackretry", 10_701).await;
    let manifest_id = uuid::Uuid::new_v4();
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);
    let error = fixture
        .persist(&pool, &store, manifest_id, None)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        PersistAndDeliverChainSwapError::ManifestDeliveryFailed
    );
    let pending = pay_service::db::get_manifest_delivery(&pool, manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.delivery_state, "pending");
    assert_eq!(
        store
            .get_v1(ManifestObjectId::new(pending.chain_swap_id, manifest_id).unwrap())
            .await
            .unwrap()
            .encoded(),
        pending.encrypted_envelope().encoded()
    );

    sqlx::query("DROP TRIGGER bullnym_test_reject_manifest_ack ON chain_swap_manifest_deliveries")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION bullnym_test_reject_manifest_ack()")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        resume_pending_manifest_delivery(&pool, &store)
            .await
            .unwrap(),
        ManifestDeliveryResumeOutcome::Delivered {
            identity: pending.identity(),
            storage_outcome: ManifestWriteOutcome::AlreadyPresent,
        }
    );

    cleanup_db(&pool).await;
}

// =====================================================================
// #87: unwired pending-manifest delivery coordinator.
// =====================================================================

#[tokio::test]
async fn manifest_delivery_coordinator_creates_verifies_and_acknowledges() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let delivery =
        insert_pending_manifest_delivery_fixture(&pool, "manifestcoordcreated", 0x81).await;
    let object_id = delivery_object_id(&delivery);
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);

    let outcome = resume_pending_manifest_delivery(&pool, &store)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ManifestDeliveryResumeOutcome::Delivered {
            identity: delivery.identity(),
            storage_outcome: ManifestWriteOutcome::Created,
        }
    );
    assert!(!format!("{outcome:?}").contains(delivery.encrypted_envelope().encoded()));
    let acknowledged = pay_service::db::get_manifest_delivery(&pool, delivery.manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acknowledged.delivery_state, "delivered");
    assert!(acknowledged.delivered_at_unix.is_some());
    assert_eq!(
        store.get_v1(object_id).await.unwrap().encoded(),
        delivery.encrypted_envelope().encoded()
    );
    assert_eq!(
        resume_pending_manifest_delivery(&pool, &store)
            .await
            .unwrap(),
        ManifestDeliveryResumeOutcome::NoPending
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_delivery_coordinator_retries_post_put_pre_ack_as_already_present() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let delivery =
        insert_pending_manifest_delivery_fixture(&pool, "manifestcoordretry", 0x82).await;
    let object_id = delivery_object_id(&delivery);
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);

    // Model a process disappearing after the durable write but before its
    // database acknowledgement.
    assert_eq!(
        store
            .put_v1(object_id, delivery.encrypted_envelope())
            .await
            .unwrap(),
        ManifestWriteOutcome::Created
    );
    assert_eq!(
        pay_service::db::list_pending_manifest_deliveries(&pool)
            .await
            .unwrap()
            .len(),
        1
    );

    assert_eq!(
        resume_pending_manifest_delivery(&pool, &store)
            .await
            .unwrap(),
        ManifestDeliveryResumeOutcome::Delivered {
            identity: delivery.identity(),
            storage_outcome: ManifestWriteOutcome::AlreadyPresent,
        }
    );
    assert_eq!(
        pay_service::db::get_manifest_delivery(&pool, delivery.manifest_id)
            .await
            .unwrap()
            .unwrap()
            .delivery_state,
        "delivered"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_delivery_coordinator_store_conflict_does_not_acknowledge() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let delivery =
        insert_pending_manifest_delivery_fixture(&pool, "manifestcoordconflict", 0x83).await;
    let object_id = delivery_object_id(&delivery);
    let conflicting_envelope = manifest_delivery_envelope(0x84);
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend);
    assert_eq!(
        store
            .put_v1(object_id, &conflicting_envelope)
            .await
            .unwrap(),
        ManifestWriteOutcome::Created
    );

    let error = resume_pending_manifest_delivery(&pool, &store)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ManifestDeliveryCoordinatorError::StorageConflict { object_id: stored_id }
            if stored_id == object_id
    ));
    let public_error = format!("{error:?} {error}");
    for forbidden in [
        delivery.encrypted_envelope().encoded(),
        conflicting_envelope.encoded(),
    ] {
        assert!(!public_error.contains(forbidden));
    }
    let still_pending = pay_service::db::get_manifest_delivery(&pool, delivery.manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_pending.delivery_state, "pending");
    assert_eq!(still_pending.delivered_at_unix, None);
    assert_eq!(
        store.get_v1(object_id).await.unwrap().encoded(),
        conflicting_envelope.encoded()
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_delivery_coordinator_digest_mismatch_performs_no_store_io() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let delivery =
        insert_pending_manifest_delivery_fixture(&pool, "manifestcoorddigest", 0x85).await;
    let backend = InstrumentedManifestObjectStore::new();
    let store = coordinator_manifest_store(backend.clone());
    let incorrect_digest = "00".repeat(32);
    assert_ne!(incorrect_digest, delivery.envelope_sha256);
    replace_manifest_digest_without_constraint(&pool, delivery.manifest_id, &incorrect_digest)
        .await;

    let result = resume_pending_manifest_delivery(&pool, &store).await;
    let observed_store_io = backend.io_calls();
    restore_manifest_digest_constraint(&pool, delivery.manifest_id, &delivery.envelope_sha256)
        .await;

    let error = result.unwrap_err();
    assert!(matches!(
        error,
        ManifestDeliveryCoordinatorError::EnvelopeDigestMismatch { manifest_id }
            if manifest_id == delivery.manifest_id
    ));
    assert_eq!(observed_store_io, 0);
    assert!(!format!("{error:?} {error}").contains(delivery.encrypted_envelope().encoded()));
    assert_eq!(
        pay_service::db::get_manifest_delivery(&pool, delivery.manifest_id)
            .await
            .unwrap()
            .unwrap()
            .delivery_state,
        "pending"
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn manifest_delivery_coordinator_exact_ack_mismatch_is_not_success() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let delivery = insert_pending_manifest_delivery_fixture(&pool, "manifestcoordack", 0x86).await;
    let original_envelope = delivery.encrypted_envelope().clone();
    let replacement_envelope = manifest_delivery_envelope(0x87);
    let object_id = delivery_object_id(&delivery);
    let (backend, put_committed, release_put) =
        InstrumentedManifestObjectStore::pausing_after_first_put();
    let store = coordinator_manifest_store(backend);
    let coordinator_pool = pool.clone();
    let coordinator_store = store.clone();
    let coordinator = tokio::spawn(async move {
        resume_pending_manifest_delivery(&coordinator_pool, &coordinator_store).await
    });

    tokio::time::timeout(Duration::from_secs(30), put_committed.wait())
        .await
        .expect("coordinator did not reach the post-put barrier");
    replace_manifest_envelope_bypassing_update_trigger(
        &pool,
        delivery.manifest_id,
        &replacement_envelope,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(30), release_put.wait())
        .await
        .expect("coordinator did not leave the post-put barrier");
    let error = tokio::time::timeout(Duration::from_secs(30), coordinator)
        .await
        .expect("coordinator did not finish")
        .unwrap()
        .unwrap_err();

    assert!(matches!(
        error,
        ManifestDeliveryCoordinatorError::AcknowledgementMismatch { manifest_id }
            if manifest_id == delivery.manifest_id
    ));
    let public_error = format!("{error:?} {error}");
    for forbidden in [original_envelope.encoded(), replacement_envelope.encoded()] {
        assert!(!public_error.contains(forbidden));
    }
    let still_pending = pay_service::db::get_manifest_delivery(&pool, delivery.manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_pending.delivery_state, "pending");
    assert_eq!(still_pending.encrypted_envelope(), &replacement_envelope);
    assert_eq!(
        store.get_v1(object_id).await.unwrap().encoded(),
        original_envelope.encoded()
    );

    cleanup_db(&pool).await;
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL + MinIO harness"]
async fn manifest_delivery_coordinator_real_postgres_minio_contract() {
    fn required_env(name: &str) -> String {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} must be supplied by the disposable harness"))
    }

    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let endpoint = required_env("BULLNYM_MINIO_ENDPOINT");
    let bucket = required_env("BULLNYM_MINIO_BUCKET");
    let access_key = required_env("BULLNYM_MINIO_ACCESS_KEY");
    let secret_key = required_env("BULLNYM_MINIO_SECRET_KEY");
    let prefix = required_env("BULLNYM_MINIO_DELIVERY_PREFIX");
    let store = RecoveryManifestStore::from_s3(S3ManifestStoreConfig::new(
        endpoint,
        "us-east-1",
        bucket,
        prefix,
        true,
        true,
        S3ManifestCredentials::new(access_key, secret_key, None),
    ))
    .unwrap();

    let created =
        insert_pending_manifest_delivery_fixture(&pool, "manifestrealcreated", 0x91).await;
    let created_id = delivery_object_id(&created);
    assert_eq!(
        resume_pending_manifest_delivery(&pool, &store)
            .await
            .unwrap(),
        ManifestDeliveryResumeOutcome::Delivered {
            identity: created.identity(),
            storage_outcome: ManifestWriteOutcome::Created,
        }
    );
    let created_ack = pay_service::db::get_manifest_delivery(&pool, created.manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created_ack.identity(), created.identity());
    assert_eq!(created_ack.envelope_sha256, created.envelope_sha256);
    assert_eq!(
        created_ack.encrypted_envelope(),
        created.encrypted_envelope()
    );
    assert_eq!(created_ack.delivery_state, "delivered");
    assert!(created_ack.delivered_at_unix.is_some());
    let created_readback = store.get_v1(created_id).await.unwrap();
    assert_eq!(
        created_readback.encoded(),
        created.encrypted_envelope().encoded()
    );
    assert_eq!(created_readback.sha256_hex(), created.envelope_sha256);

    let retry = insert_pending_manifest_delivery_fixture(&pool, "manifestrealretry", 0x92).await;
    let retry_id = delivery_object_id(&retry);
    // Model a process disappearing after the real durable write and before
    // the PostgreSQL acknowledgement. The coordinator must read-verify that
    // same retained object and acknowledge the still-pending exact identity.
    assert_eq!(
        store
            .put_v1(retry_id, retry.encrypted_envelope())
            .await
            .unwrap(),
        ManifestWriteOutcome::Created
    );
    assert_eq!(
        pay_service::db::list_pending_manifest_deliveries(&pool)
            .await
            .unwrap()
            .as_slice(),
        std::slice::from_ref(&retry)
    );
    assert_eq!(
        resume_pending_manifest_delivery(&pool, &store)
            .await
            .unwrap(),
        ManifestDeliveryResumeOutcome::Delivered {
            identity: retry.identity(),
            storage_outcome: ManifestWriteOutcome::AlreadyPresent,
        }
    );
    let retry_ack = pay_service::db::get_manifest_delivery(&pool, retry.manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry_ack.identity(), retry.identity());
    assert_eq!(retry_ack.envelope_sha256, retry.envelope_sha256);
    assert_eq!(retry_ack.encrypted_envelope(), retry.encrypted_envelope());
    assert_eq!(retry_ack.delivery_state, "delivered");
    assert!(retry_ack.delivered_at_unix.is_some());
    assert_eq!(
        store.get_v1(retry_id).await.unwrap().encoded(),
        retry.encrypted_envelope().encoded()
    );

    let conflict =
        insert_pending_manifest_delivery_fixture(&pool, "manifestrealconflict", 0x93).await;
    let conflict_id = delivery_object_id(&conflict);
    let conflicting_envelope = manifest_delivery_envelope(0x94);
    assert_eq!(
        store
            .put_v1(conflict_id, &conflicting_envelope)
            .await
            .unwrap(),
        ManifestWriteOutcome::Created
    );
    assert!(matches!(
        resume_pending_manifest_delivery(&pool, &store).await,
        Err(ManifestDeliveryCoordinatorError::StorageConflict { object_id })
            if object_id == conflict_id
    ));
    let conflict_pending = pay_service::db::get_manifest_delivery(&pool, conflict.manifest_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conflict_pending.delivery_state, "pending");
    assert_eq!(conflict_pending.delivered_at_unix, None);
    assert_eq!(
        store.get_v1(conflict_id).await.unwrap().encoded(),
        conflicting_envelope.encoded()
    );

    let mut observed_ids = store
        .list_v1(4)
        .await
        .unwrap()
        .objects
        .into_iter()
        .map(|object| object.id)
        .collect::<Vec<_>>();
    let mut expected_ids = vec![created_id, retry_id, conflict_id];
    observed_ids.sort_unstable();
    expected_ids.sort_unstable();
    assert_eq!(observed_ids, expected_ids);

    cleanup_db(&pool).await;
}

const RECOVERY_COMMITMENT_P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const RECOVERY_COMMITMENT_P2TR: &str =
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
const RECOVERY_COMMITMENT_P2PKH: &str = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
const RECOVERY_COMMITMENT_TESTNET: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

fn signed_recovery_address_registration(
    keypair: &Keypair,
    npub: &str,
    address: &str,
    timestamp: u64,
) -> recovery_address_registration::RecoveryAddressRegistrationRequest {
    let message = recovery_address_registration::build_recovery_address_registration_message(
        recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_VERSION,
        npub,
        address,
        timestamp,
    )
    .unwrap();
    recovery_address_registration::RecoveryAddressRegistrationRequest {
        version: recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_VERSION,
        npub: npub.to_string(),
        btc_address: address.to_string(),
        timestamp,
        signature: sign_with_keypair(keypair, &message),
    }
}

fn verified_recovery_commitment(
    keypair: &Keypair,
    npub: &str,
    address: &str,
    timestamp: u64,
) -> pay_service::recovery_address_registration::VerifiedRecoveryAddressRegistration {
    let request = signed_recovery_address_registration(keypair, npub, address, timestamp);
    pay_service::recovery_address_registration::verify_recovery_address_registration(&request)
        .unwrap()
}

const ISSUE84_CHAIN_AMOUNT_SAT: u64 = 25_000;
const ISSUE84_SWAP_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ISSUE84_BTC_TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;
const ISSUE84_LIQUID_TAPSCRIPT_LEAF_VERSION: u8 = 0xc4;

#[derive(Clone)]
struct Issue84ChainProviderState {
    pair_response: Value,
    height_response: Value,
    creation_response: Value,
    calls: Arc<AtomicUsize>,
    creation_calls: Arc<AtomicUsize>,
}

struct Issue84ChainProvider {
    base_url: String,
    calls: Arc<AtomicUsize>,
    creation_calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Issue84ChainProvider {
    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn issue84_chain_pairs_handler(
    axum::extract::State(state): axum::extract::State<Issue84ChainProviderState>,
) -> axum::Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    axum::Json(state.pair_response)
}

async fn issue84_chain_heights_handler(
    axum::extract::State(state): axum::extract::State<Issue84ChainProviderState>,
) -> axum::Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    axum::Json(state.height_response)
}

async fn issue84_chain_creation_handler(
    axum::extract::State(state): axum::extract::State<Issue84ChainProviderState>,
    axum::Json(_request): axum::Json<Value>,
) -> axum::Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    state.creation_calls.fetch_add(1, Ordering::SeqCst);
    axum::Json(state.creation_response)
}

fn issue84_claim_script(hashlock: hash160::Hash, receiver: &BoltzPublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_HASH160)
        .push_slice(hashlock.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&receiver.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn issue84_refund_script(sender: &BoltzPublicKey, timeout_height: u32) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&sender.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_lock_time(LockTime::from_consensus(timeout_height))
        .push_opcode(OP_CLTV)
        .into_script()
}

fn issue84_chain_pair() -> ChainPair {
    serde_json::from_value(json!({
        "hash": "014261b046f2045ddedd49fe291e0255afe002454c65a5aa7d6457a35cd32f19",
        "rate": 1.0,
        "limits": {
            "maximal": 25_000_000,
            "minimal": 25_000,
            "maximalZeroConf": 0
        },
        "fees": {
            "percentage": 0.1,
            "minerFees": {
                "server": 405,
                "user": {"claim": 20, "lockup": 385}
            }
        }
    }))
    .unwrap()
}

fn issue84_chain_heights() -> HeightResponse {
    serde_json::from_value(json!({
        "BTC": 957_817,
        "L-BTC": 3_970_775
    }))
    .unwrap()
}

fn issue84_chain_user_lock_amount(pair: &ChainPair, server_lock_amount_sat: u64) -> u64 {
    let numerator = server_lock_amount_sat
        .checked_add(pair.fees.miner_fees.server)
        .unwrap();
    (numerator as f64 / (1.0 - pair.fees.percentage / 100.0)).ceil() as u64
}

fn issue84_chain_creation_response(
    claim_key_index: u64,
    refund_key_index: u64,
    swap_id: &str,
) -> (ChainPair, HeightResponse, CreateChainResponse) {
    const BLINDING_KEY: &str = "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";
    let pair = issue84_chain_pair();
    let heights = issue84_chain_heights();
    let swap_master_key =
        SwapMasterKey::from_mnemonic(ISSUE84_SWAP_MNEMONIC, None, Network::Mainnet).unwrap();
    let claim_keypair = swap_master_key.derive_swapkey(claim_key_index).unwrap();
    let refund_keypair = swap_master_key.derive_swapkey(refund_key_index).unwrap();
    let claim_public_key = BoltzPublicKey::new(claim_keypair.public_key());
    let refund_public_key = BoltzPublicKey::new(refund_keypair.public_key());
    let hashlock = Preimage::from_swap_key(&claim_keypair).hash160;
    let bitcoin_server_key = BoltzPublicKey::from_str(
        "031c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8",
    )
    .unwrap();
    let liquid_server_key = BoltzPublicKey::from_str(
        "033009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01a",
    )
    .unwrap();
    let bitcoin_timeout = heights.btc + 144;
    let liquid_timeout = heights.lbtc + 720;
    let bitcoin_tree = SwapTree {
        claim_leaf: Leaf {
            output: hex::encode(issue84_claim_script(hashlock, &bitcoin_server_key)),
            version: ISSUE84_BTC_TAPSCRIPT_LEAF_VERSION,
        },
        refund_leaf: Leaf {
            output: hex::encode(issue84_refund_script(&refund_public_key, bitcoin_timeout)),
            version: ISSUE84_BTC_TAPSCRIPT_LEAF_VERSION,
        },
        covenant_claim_leaf: None,
    };
    let liquid_tree = SwapTree {
        claim_leaf: Leaf {
            output: hex::encode(issue84_claim_script(hashlock, &claim_public_key)),
            version: ISSUE84_LIQUID_TAPSCRIPT_LEAF_VERSION,
        },
        refund_leaf: Leaf {
            output: hex::encode(issue84_refund_script(&liquid_server_key, liquid_timeout)),
            version: ISSUE84_LIQUID_TAPSCRIPT_LEAF_VERSION,
        },
        covenant_claim_leaf: None,
    };
    let bitcoin_address = BtcSwapScript {
        swap_type: SwapType::Chain,
        side: Some(Side::Lockup),
        funding_addrs: None,
        hashlock,
        receiver_pubkey: bitcoin_server_key,
        locktime: LockTime::from_consensus(bitcoin_timeout),
        sender_pubkey: refund_public_key,
    }
    .to_address(BitcoinChain::Bitcoin)
    .unwrap()
    .to_string();
    let blinding_key = ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), BLINDING_KEY).unwrap();
    let liquid_address = LBtcSwapScript {
        swap_type: SwapType::Chain,
        side: Some(Side::Claim),
        funding_addrs: None,
        hashlock,
        receiver_pubkey: claim_public_key,
        locktime: boltz_client::elements::LockTime::from_consensus(liquid_timeout),
        sender_pubkey: liquid_server_key,
        blinding_key,
    }
    .to_address(LiquidChain::Liquid)
    .unwrap()
    .to_string();
    let response = CreateChainResponse {
        id: swap_id.to_string(),
        claim_details: ChainSwapDetails {
            swap_tree: liquid_tree,
            lockup_address: liquid_address,
            server_public_key: liquid_server_key,
            timeout_block_height: liquid_timeout,
            amount: ISSUE84_CHAIN_AMOUNT_SAT,
            blinding_key: Some(BLINDING_KEY.to_string()),
            refund_address: None,
            claim_address: None,
            bip21: None,
        },
        lockup_details: ChainSwapDetails {
            swap_tree: bitcoin_tree,
            lockup_address: bitcoin_address,
            server_public_key: bitcoin_server_key,
            timeout_block_height: bitcoin_timeout,
            amount: issue84_chain_user_lock_amount(&pair, ISSUE84_CHAIN_AMOUNT_SAT),
            blinding_key: None,
            refund_address: None,
            claim_address: None,
            bip21: Some("bitcoin:provider-controlled-and-never-forwarded?amount=999".into()),
        },
    };
    (pair, heights, response)
}

async fn spawn_issue84_chain_provider(
    claim_key_index: u64,
    refund_key_index: u64,
    swap_id: &str,
) -> Issue84ChainProvider {
    let (pair, heights, response) =
        issue84_chain_creation_response(claim_key_index, refund_key_index, swap_id);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let creation_calls = Arc::new(AtomicUsize::new(0));
    let state = Issue84ChainProviderState {
        pair_response: json!({"BTC": {"L-BTC": pair}, "L-BTC": {}}),
        height_response: serde_json::to_value(heights).unwrap(),
        creation_response: serde_json::to_value(response).unwrap(),
        calls: calls.clone(),
        creation_calls: creation_calls.clone(),
    };
    let app = Router::new()
        .route(
            "/swap/chain",
            get(issue84_chain_pairs_handler).post(issue84_chain_creation_handler),
        )
        .route("/chain/heights", get(issue84_chain_heights_handler))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Issue84ChainProvider {
        base_url: format!("http://{address}"),
        calls,
        creation_calls,
        task,
    }
}

async fn issue84_test_merchant(pool: &PgPool, nym: &str) -> (String, Keypair) {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(pool, nym, &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    (npub, keypair)
}

async fn issue84_chain_invoice(
    pool: &PgPool,
    nym: &str,
    npub: &str,
    liquid_address_index: u32,
) -> pay_service::db::Invoice {
    let liquid_address =
        pay_service::descriptor::derive_address(TEST_DESCRIPTOR, liquid_address_index).unwrap();
    let liquid_blinding_key_hex =
        pay_service::descriptor::derive_blinding_key_hex(TEST_DESCRIPTOR, &liquid_address).unwrap();
    pay_service::db::insert_invoice(
        pool,
        &pay_service::db::NewInvoice {
            nym_owner: Some(nym),
            public_slug: None,
            npub_owner: npub,
            origin: "checkout",
            fiat_amount_minor: None,
            fiat_currency: None,
            amount_sat: i64::try_from(ISSUE84_CHAIN_AMOUNT_SAT).unwrap(),
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
            liquid_address: Some(&liquid_address),
            liquid_blinding_key_hex: Some(&liquid_blinding_key_hex),
            expires_in_secs: 3_600,
        },
    )
    .await
    .unwrap()
}

async fn issue84_persist_recovery_commitment(
    pool: &PgPool,
    keypair: &Keypair,
    npub: &str,
    address: &str,
    timestamp: u64,
) -> Uuid {
    let evidence = verified_recovery_commitment(keypair, npub, address, timestamp);
    pay_service::db::persist_recovery_address_commitment(pool, &evidence)
        .await
        .unwrap()
        .commitment_id
}

#[tokio::test]
async fn issue84_chain_offer_missing_or_inactive_commitment_has_zero_mutation() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "issue84missing";
    let (npub, _) = issue84_test_merchant(&pool, nym).await;
    let mut invoice = issue84_chain_invoice(&pool, nym, &npub, 0).await;
    let (boltz_url, provider_calls, provider_task) = spawn_counting_http_server().await;
    let mut config = test_config();
    config.boltz.api_url = boltz_url;
    let state = test_state_with_config(pool.clone(), config);

    let sequence_before = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let chain_high_water_before =
        pay_service::db::max_persisted_chain_key_index(&pool, "0000000000000000")
            .await
            .unwrap();
    let allocations_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_key_allocations")
        .fetch_one(&pool)
        .await
        .unwrap();

    let mismatched = pay_service::invoice::exercise_bitcoin_chain_offer_creation(
        &state,
        Some("issue84differentowner"),
        ISSUE84_CHAIN_AMOUNT_SAT,
        &invoice,
    )
    .await
    .unwrap();
    assert!(mismatched.is_none());

    invoice.npub_owner = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into();
    let recipient_mismatched = pay_service::invoice::exercise_bitcoin_chain_offer_creation(
        &state,
        Some(nym),
        ISSUE84_CHAIN_AMOUNT_SAT,
        &invoice,
    )
    .await
    .unwrap();
    assert!(recipient_mismatched.is_none());
    invoice.npub_owner.clone_from(&npub);

    let missing = pay_service::invoice::exercise_bitcoin_chain_offer_creation(
        &state,
        Some(nym),
        ISSUE84_CHAIN_AMOUNT_SAT,
        &invoice,
    )
    .await
    .unwrap();
    assert!(missing.is_none());

    pay_service::db::deactivate_user(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    let inactive = pay_service::invoice::exercise_bitcoin_chain_offer_creation(
        &state,
        Some(nym),
        ISSUE84_CHAIN_AMOUNT_SAT,
        &invoice,
    )
    .await
    .unwrap();
    assert!(inactive.is_none());

    assert_eq!(
        pay_service::db::swap_key_seq_next_value(&pool)
            .await
            .unwrap(),
        sequence_before,
        "merchant recovery gating consumed a swap-key sequence value"
    );
    assert_eq!(
        pay_service::db::max_persisted_chain_key_index(&pool, "0000000000000000")
            .await
            .unwrap(),
        chain_high_water_before,
        "merchant recovery gating changed the persisted chain-key high water"
    );
    let allocations_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM swap_key_allocations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(allocations_after, allocations_before);
    let chain_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chain_swap_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(chain_rows, 0);
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "merchant recovery gating reached the provider"
    );

    provider_task.abort();
    let _ = provider_task.await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn issue84_chain_offer_copies_commitment_durably_before_return() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "issue84durable";
    let (npub, keypair) = issue84_test_merchant(&pool, nym).await;
    let recovery_commitment_id = issue84_persist_recovery_commitment(
        &pool,
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        auth_timestamp(),
    )
    .await;
    let invoice = issue84_chain_invoice(&pool, nym, &npub, 0).await;
    let next_key = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let provider = spawn_issue84_chain_provider(
        u64::try_from(next_key).unwrap(),
        u64::try_from(next_key + 1).unwrap(),
        "Issue84Durable1",
    )
    .await;
    let mut config = test_config();
    config.boltz.api_url = provider.base_url.clone();
    let mut state = test_state_with_config(pool.clone(), config);
    state.recovery_manifest_runtime_v1 = Some(in_memory_recovery_manifest_runtime());

    let returned = pay_service::invoice::exercise_bitcoin_chain_offer_creation(
        &state,
        Some(nym),
        ISSUE84_CHAIN_AMOUNT_SAT,
        &invoice,
    )
    .await
    .unwrap()
    .expect("registered merchant should receive a chain offer");

    let recorded: (Uuid, String, String, i64, i64) = sqlx::query_as(
        "SELECT recovery_address_commitment_id, merchant_emergency_btc_address, lockup_address, \
                claim_key_index, refund_key_index \
           FROM chain_swap_records WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recorded.0, recovery_commitment_id);
    assert_eq!(recorded.1, RECOVERY_COMMITMENT_P2WPKH);
    assert_eq!(recorded.2, returned.0);
    assert_eq!(recorded.3, next_key);
    assert_eq!(recorded.4, next_key + 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    assert_eq!(provider.creation_calls.load(Ordering::SeqCst), 1);

    provider.shutdown().await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn issue84_chain_offer_rotation_changes_only_future_swaps() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let nym = "issue84rotation";
    let (npub, keypair) = issue84_test_merchant(&pool, nym).await;
    let first_commitment_timestamp = auth_timestamp();
    let first_recovery_commitment_id = issue84_persist_recovery_commitment(
        &pool,
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        first_commitment_timestamp,
    )
    .await;
    let first_invoice = issue84_chain_invoice(&pool, nym, &npub, 0).await;
    let first_key = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let first_provider = spawn_issue84_chain_provider(
        u64::try_from(first_key).unwrap(),
        u64::try_from(first_key + 1).unwrap(),
        "Issue84RotationOld1",
    )
    .await;
    let mut first_config = test_config();
    first_config.boltz.api_url = first_provider.base_url.clone();
    let mut first_state = test_state_with_config(pool.clone(), first_config);
    first_state.recovery_manifest_runtime_v1 = Some(in_memory_recovery_manifest_runtime());
    pay_service::invoice::exercise_bitcoin_chain_offer_creation(
        &first_state,
        Some(nym),
        ISSUE84_CHAIN_AMOUNT_SAT,
        &first_invoice,
    )
    .await
    .unwrap()
    .expect("first registered commitment should admit creation");
    first_provider.shutdown().await;

    let second_recovery_commitment_id = issue84_persist_recovery_commitment(
        &pool,
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2TR,
        first_commitment_timestamp + 1,
    )
    .await;
    let first_after_rotation: (Uuid, String) = sqlx::query_as(
        "SELECT recovery_address_commitment_id, merchant_emergency_btc_address \
           FROM chain_swap_records WHERE invoice_id = $1",
    )
    .bind(first_invoice.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(first_after_rotation.0, first_recovery_commitment_id);
    assert_eq!(first_after_rotation.1, RECOVERY_COMMITMENT_P2WPKH);

    let second_invoice = issue84_chain_invoice(&pool, nym, &npub, 1).await;
    let second_key = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap();
    let second_provider = spawn_issue84_chain_provider(
        u64::try_from(second_key).unwrap(),
        u64::try_from(second_key + 1).unwrap(),
        "Issue84RotationNew1",
    )
    .await;
    let mut second_config = test_config();
    second_config.boltz.api_url = second_provider.base_url.clone();
    let mut second_state = test_state_with_config(pool.clone(), second_config);
    second_state.recovery_manifest_runtime_v1 = Some(in_memory_recovery_manifest_runtime());
    pay_service::invoice::exercise_bitcoin_chain_offer_creation(
        &second_state,
        Some(nym),
        ISSUE84_CHAIN_AMOUNT_SAT,
        &second_invoice,
    )
    .await
    .unwrap()
    .expect("rotated commitment should admit future creation");

    let recorded: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT invoice_id, recovery_address_commitment_id, merchant_emergency_btc_address \
           FROM chain_swap_records \
          WHERE invoice_id = ANY($1) \
          ORDER BY created_at, invoice_id",
    )
    .bind(vec![first_invoice.id, second_invoice.id])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(recorded.len(), 2);
    let first_evidence = recorded
        .iter()
        .find_map(|(invoice_id, commitment_id, address)| {
            (*invoice_id == first_invoice.id).then_some((*commitment_id, address.as_str()))
        })
        .unwrap();
    let second_evidence = recorded
        .iter()
        .find_map(|(invoice_id, commitment_id, address)| {
            (*invoice_id == second_invoice.id).then_some((*commitment_id, address.as_str()))
        })
        .unwrap();
    assert_eq!(first_evidence.0, first_recovery_commitment_id);
    assert_eq!(first_evidence.1, RECOVERY_COMMITMENT_P2WPKH);
    assert_eq!(second_evidence.0, second_recovery_commitment_id);
    assert_eq!(second_evidence.1, RECOVERY_COMMITMENT_P2TR);
    assert_eq!(second_provider.calls.load(Ordering::SeqCst), 3);
    assert_eq!(second_provider.creation_calls.load(Ordering::SeqCst), 1);

    second_provider.shutdown().await;
    cleanup_db(&pool).await;
}

async fn observe_recovery_lock_wait(
    pool: &PgPool,
    backend_pid: i32,
    query_pattern: &str,
) -> Result<bool, sqlx::Error> {
    match tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let observed = sqlx::query_scalar(
                "SELECT EXISTS (\
                     SELECT 1 \
                      FROM pg_stat_activity \
                      WHERE datname = current_database() \
                        AND pid = $1 \
                        AND wait_event_type = 'Lock' \
                        AND query LIKE $2\
                 )",
            )
            .bind(backend_pid)
            .bind(query_pattern)
            .fetch_one(pool)
            .await?;
            if observed {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    {
        Ok(result) => result.map(|()| true),
        Err(_) => Ok(false),
    }
}

async fn join_recovery_task_bounded<T>(mut task: tokio::task::JoinHandle<T>, label: &str) -> T {
    match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => panic!("{label} task failed: {error}"),
        Err(_) => {
            task.abort();
            let _ = task.await;
            panic!("{label} task did not finish within 10 seconds");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_address_registration_endpoint_first_retry_rotation_and_privacy() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, "recoveryendpoint", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let app = test_app(test_state(pool.clone()));
    let timestamp = auth_timestamp();
    let first_request = signed_recovery_address_registration(
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        timestamp,
    );
    let first_signature = first_request.signature.clone();

    let log_writer = CapturedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(log_writer.clone())
        .finish();
    let _subscriber_guard = tracing::subscriber::set_default(subscriber);

    let expected_response = json!({
        "version": recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_VERSION,
        "recovery_address_registered": true,
        "signed_at_unix": timestamp,
    });
    let (first_status, first_body) = put_json(
        &app,
        "/api/v1/recovery-address",
        serde_json::to_value(&first_request).unwrap(),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(first_body, expected_response);

    let first = pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.commitment_version, 1);

    let (retry_status, retry_body) = put_json(
        &app,
        "/api/v1/recovery-address",
        serde_json::to_value(&first_request).unwrap(),
    )
    .await;
    assert_eq!(retry_status, StatusCode::OK);
    assert_eq!(retry_body, expected_response);
    let exact_retry = pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exact_retry, first);

    let rotation_request =
        signed_recovery_address_registration(&keypair, &npub, RECOVERY_COMMITMENT_P2TR, timestamp);
    let rotation_signature = rotation_request.signature.clone();
    let (rotation_status, rotation_body) = put_json(
        &app,
        "/api/v1/recovery-address",
        serde_json::to_value(&rotation_request).unwrap(),
    )
    .await;
    assert_eq!(rotation_status, StatusCode::OK);
    assert_eq!(rotation_body, expected_response);
    let rotated = pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rotated.commitment_version, 2);
    assert_ne!(rotated.commitment_id, first.commitment_id);
    assert_eq!(rotated.canonical_btc_address(), RECOVERY_COMMITMENT_P2TR);
    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_address_commitments WHERE npub = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 2);

    let response_text = format!("{first_body} {retry_body} {rotation_body}");
    let response_debug = format!("{first_body:?} {retry_body:?} {rotation_body:?}");
    let logs = log_writer.contents();
    let first_commitment_id = first.commitment_id.to_string();
    let rotated_commitment_id = rotated.commitment_id.to_string();
    for forbidden in [
        npub.as_str(),
        RECOVERY_COMMITMENT_P2WPKH,
        RECOVERY_COMMITMENT_P2TR,
        first_signature.as_str(),
        rotation_signature.as_str(),
        first_commitment_id.as_str(),
        rotated_commitment_id.as_str(),
    ] {
        assert!(!response_text.contains(forbidden));
        assert!(!response_debug.contains(forbidden));
        assert!(!logs.contains(forbidden));
    }
    for forbidden_field in ["npub", "btc_address", "signature", "commitment_id"] {
        assert!(!response_text.contains(forbidden_field));
        assert!(!response_debug.contains(forbidden_field));
    }

    let (read_status, _, _) = get_json_with_headers(&app, "/api/v1/recovery-address").await;
    assert_eq!(read_status, StatusCode::METHOD_NOT_ALLOWED);

    cleanup_db(&pool).await;
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_address_registration_endpoint_refuses_missing_and_inactive_identically() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    let request = signed_recovery_address_registration(
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        auth_timestamp(),
    );
    let signature = request.signature.clone();
    let app = test_app(test_state(pool.clone()));

    let log_writer = CapturedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(log_writer.clone())
        .finish();
    let _subscriber_guard = tracing::subscriber::set_default(subscriber);

    let (missing_status, missing_body) = put_json(
        &app,
        "/api/v1/recovery-address",
        serde_json::to_value(&request).unwrap(),
    )
    .await;
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);

    pay_service::db::create_user(&pool, "recoveryinactiveendpoint", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let deactivated = pay_service::db::deactivate_user(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert!(!deactivated.is_active);
    let (inactive_status, inactive_body) = put_json(
        &app,
        "/api/v1/recovery-address",
        serde_json::to_value(&request).unwrap(),
    )
    .await;
    assert_eq!(inactive_status, StatusCode::UNAUTHORIZED);
    assert_eq!(inactive_body, missing_body);
    assert_eq!(
        missing_body,
        json!({
            "status": "ERROR",
            "code": "AuthError",
            "reason": "Wallet signature did not verify.",
        })
    );

    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_address_commitments WHERE npub = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 0);
    let public_output = format!(
        "{missing_body:?} {inactive_body:?} {}",
        log_writer.contents()
    );
    for forbidden in [
        npub.as_str(),
        RECOVERY_COMMITMENT_P2WPKH,
        signature.as_str(),
        "missing",
        "inactive",
        "SourceIdentityNotActive",
    ] {
        assert!(!public_output.contains(forbidden));
    }

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_address_registration_endpoint_rejects_signature_address_and_oversize_body() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, "recoverynegative", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let app = test_app(test_state(pool.clone()));
    let timestamp = auth_timestamp();

    let mut bad_signature = signed_recovery_address_registration(
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        timestamp,
    );
    bad_signature.signature = "00".repeat(64);
    let (signature_status, signature_body) = put_json(
        &app,
        "/api/v1/recovery-address",
        serde_json::to_value(&bad_signature).unwrap(),
    )
    .await;
    assert_eq!(signature_status, StatusCode::UNAUTHORIZED);
    assert_eq!(signature_body["code"], "AuthError");

    let invalid_address_message = pay_service::auth::build_la_v2_message(
        recovery_address_registration::ACTION_RECOVERY_ADDRESS_SET,
        &npub,
        "",
        &["1", RECOVERY_COMMITMENT_TESTNET],
        timestamp,
    );
    let invalid_address_request =
        recovery_address_registration::RecoveryAddressRegistrationRequest {
            version: recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_VERSION,
            npub: npub.clone(),
            btc_address: RECOVERY_COMMITMENT_TESTNET.to_string(),
            timestamp,
            signature: sign_with_keypair(&keypair, &invalid_address_message),
        };
    let (address_status, address_body) = put_json(
        &app,
        "/api/v1/recovery-address",
        serde_json::to_value(&invalid_address_request).unwrap(),
    )
    .await;
    assert_eq!(address_status, StatusCode::OK);
    assert_eq!(address_body["code"], "RecoveryAddressInvalid");

    let oversized_body = json!({
        "version": recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_VERSION,
        "npub": npub.clone(),
        "btc_address": RECOVERY_COMMITMENT_P2WPKH,
        "timestamp": timestamp,
        "signature": "a".repeat(
            recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_BODY_LIMIT_BYTES + 1
        ),
    })
    .to_string();
    let oversized_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/recovery-address")
                .header("content-type", "application/json")
                .body(Body::from(oversized_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized_response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_address_commitments WHERE npub = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_address_commitment_refuses_missing_and_inactive_sources() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    let evidence = verified_recovery_commitment(
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        auth_timestamp(),
    );

    let missing_error = pay_service::db::persist_recovery_address_commitment(&pool, &evidence)
        .await
        .unwrap_err();
    let missing_debug = format!("{missing_error:?}");
    assert_eq!(missing_debug, "SourceIdentityNotActive");
    assert!(!missing_debug.contains(&npub));
    assert!(matches!(
        missing_error,
        pay_service::db::RecoveryAddressCommitmentError::SourceIdentityNotActive
    ));

    pay_service::db::create_user(&pool, "recoveryinactive", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let deactivated = pay_service::db::deactivate_user(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert!(!deactivated.is_active);
    let inactive_error = pay_service::db::persist_recovery_address_commitment(&pool, &evidence)
        .await
        .unwrap_err();
    assert!(matches!(
        inactive_error,
        pay_service::db::RecoveryAddressCommitmentError::SourceIdentityNotActive
    ));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_address_commitment_deactivation_serializes_before_acceptance() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, "recoverylockorder", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let evidence = verified_recovery_commitment(
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        auth_timestamp(),
    );

    // Hold the deactivation row update open. A correct acceptance check uses a
    // conflicting row lock and must wait; FOR KEY SHARE would incorrectly run
    // concurrently with this non-key is_active update.
    let mut deactivation = pool.begin().await.unwrap();
    let deactivated =
        sqlx::query("UPDATE users SET is_active = FALSE WHERE npub = $1 AND is_active = TRUE")
            .bind(&npub)
            .execute(&mut *deactivation)
            .await
            .unwrap();
    assert_eq!(deactivated.rows_affected(), 1);

    let persist_pool = named_single_connection_test_pool("recovery-persistence-lock-test").await;
    let persist_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&persist_pool)
        .await
        .unwrap();
    let persistence_task_pool = persist_pool.clone();
    let persist_evidence = evidence.clone();
    let persistence = tokio::spawn(async move {
        pay_service::db::persist_recovery_address_commitment(
            &persistence_task_pool,
            &persist_evidence,
        )
        .await
    });

    let observed_row_lock_wait =
        match observe_recovery_lock_wait(&pool, persist_backend_pid, "%FROM users%FOR UPDATE%")
            .await
        {
            Ok(observed) => observed,
            Err(error) => {
                deactivation.rollback().await.unwrap();
                let task_result = join_recovery_task_bounded(persistence, "persistence").await;
                persist_pool.close().await;
                cleanup_db(&pool).await;
                panic!("persistence lock probe failed: {error}; task result: {task_result:?}");
            }
        };

    if !observed_row_lock_wait {
        deactivation.rollback().await.unwrap();
        let premature = join_recovery_task_bounded(persistence, "persistence").await;
        persist_pool.close().await;
        cleanup_db(&pool).await;
        panic!("persistence did not wait for deactivation row lock: {premature:?}");
    }

    deactivation.commit().await.unwrap();
    let error = join_recovery_task_bounded(persistence, "persistence")
        .await
        .unwrap_err();
    persist_pool.close().await;
    assert!(matches!(
        error,
        pay_service::db::RecoveryAddressCommitmentError::SourceIdentityNotActive
    ));
    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_address_commitments WHERE npub = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_address_commitment_trigger_serializes_deactivation_before_direct_insert() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, "recoverytriggerlock", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();

    let mut deactivation = pool.begin().await.unwrap();
    let deactivated =
        sqlx::query("UPDATE users SET is_active = FALSE WHERE npub = $1 AND is_active = TRUE")
            .bind(&npub)
            .execute(&mut *deactivation)
            .await
            .unwrap();
    assert_eq!(deactivated.rows_affected(), 1);

    let insert_pool = named_single_connection_test_pool("recovery-trigger-lock-test").await;
    let insert_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&insert_pool)
        .await
        .unwrap();
    let insertion_task_pool = insert_pool.clone();
    let insert_npub = npub.clone();
    let insertion = tokio::spawn(async move {
        sqlx::query(
            "INSERT INTO recovery_address_commitments (\
                 commitment_id, npub, contract_format_version, commitment_version, \
                 canonical_btc_address, original_signature, signed_at_unix\
             ) VALUES ($1, $2, 1, 1, $3, $4, $5)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(insert_npub)
        .bind(RECOVERY_COMMITMENT_P2WPKH)
        .bind("22".repeat(64))
        .bind(i64::try_from(auth_timestamp()).unwrap())
        .execute(&insertion_task_pool)
        .await
    });

    let observed_row_lock_wait = match observe_recovery_lock_wait(
        &pool,
        insert_backend_pid,
        "%INSERT INTO recovery_address_commitments%",
    )
    .await
    {
        Ok(observed) => observed,
        Err(error) => {
            deactivation.rollback().await.unwrap();
            let task_result = join_recovery_task_bounded(insertion, "trigger insertion").await;
            insert_pool.close().await;
            cleanup_db(&pool).await;
            panic!("trigger lock probe failed: {error}; task result: {task_result:?}");
        }
    };

    if !observed_row_lock_wait {
        deactivation.rollback().await.unwrap();
        let premature = join_recovery_task_bounded(insertion, "trigger insertion").await;
        insert_pool.close().await;
        cleanup_db(&pool).await;
        panic!("trigger insert did not wait for deactivation row lock: {premature:?}");
    }

    deactivation.commit().await.unwrap();
    let error = join_recovery_task_bounded(insertion, "trigger insertion")
        .await
        .unwrap_err();
    insert_pool.close().await;
    assert_sqlstate(&error, "23503");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database| database.constraint()),
        Some("recovery_address_commitment_source_exists")
    );
    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_address_commitments WHERE npub = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 0);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_address_commitment_exact_retry_preserves_identity_and_selects_current() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, "recoverycurrent", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let timestamp = auth_timestamp();
    let first_evidence =
        verified_recovery_commitment(&keypair, &npub, RECOVERY_COMMITMENT_P2WPKH, timestamp);

    let first = pay_service::db::persist_recovery_address_commitment(&pool, &first_evidence)
        .await
        .unwrap();
    let exact_retry = pay_service::db::persist_recovery_address_commitment(&pool, &first_evidence)
        .await
        .unwrap();
    assert_eq!(first, exact_retry);
    assert!(!first.commitment_id.is_nil());
    assert_eq!(first.npub, npub);
    assert_eq!(
        first.contract_format_version,
        pay_service::recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_VERSION
    );
    assert_eq!(first.commitment_version, 1);
    assert_eq!(first.canonical_btc_address(), RECOVERY_COMMITMENT_P2WPKH);
    assert_eq!(
        first.original_signature(),
        first_evidence.original_signature()
    );
    assert_eq!(first.signed_at_unix, timestamp);
    assert!(first.registered_at_unix > 0);
    let debug = format!("{first:?}");
    assert!(debug.contains("npub: \"<redacted>\""));
    assert!(debug.contains("canonical_btc_address: \"<redacted>\""));
    assert!(debug.contains("original_signature: \"<redacted>\""));
    assert!(!debug.contains(&npub));
    assert!(!debug.contains(RECOVERY_COMMITMENT_P2WPKH));
    assert!(!debug.contains(first_evidence.original_signature()));

    let signature_reuse_error = sqlx::query(
        "INSERT INTO recovery_address_commitments (\
             commitment_id, npub, contract_format_version, commitment_version, \
             canonical_btc_address, original_signature, signed_at_unix\
         ) VALUES ($1, $2, 1, 2, $3, $4, $5)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(&npub)
    .bind(RECOVERY_COMMITMENT_P2PKH)
    .bind(first_evidence.original_signature())
    .bind(i64::try_from(timestamp).unwrap() + 1)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_sqlstate(&signature_reuse_error, "23505");
    assert_eq!(
        signature_reuse_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("recovery_address_commitment_signature_once_key")
    );
    let raw_database_debug = format!("{signature_reuse_error:?}");
    assert!(raw_database_debug.contains(&npub));
    assert!(raw_database_debug.contains(first_evidence.original_signature()));
    let wrapped_database_error =
        pay_service::db::RecoveryAddressCommitmentError::Database(signature_reuse_error);
    let wrapped_database_debug = format!("{wrapped_database_error:?}");
    assert_eq!(wrapped_database_debug, "Database(<redacted>)");
    assert!(std::error::Error::source(&wrapped_database_error).is_none());
    assert!(!wrapped_database_debug.contains(&npub));
    assert!(!wrapped_database_debug.contains(RECOVERY_COMMITMENT_P2PKH));
    assert!(!wrapped_database_debug.contains(first_evidence.original_signature()));

    let second_evidence =
        verified_recovery_commitment(&keypair, &npub, RECOVERY_COMMITMENT_P2TR, timestamp);
    let second = pay_service::db::persist_recovery_address_commitment(&pool, &second_evidence)
        .await
        .unwrap();
    assert_eq!(second.commitment_version, 2);
    assert_ne!(second.commitment_id, first.commitment_id);

    let current = pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current, second);
    let mut tx = pool.begin().await.unwrap();
    let transactional_current =
        pay_service::db::select_current_recovery_address_commitment(&mut *tx, &npub)
            .await
            .unwrap()
            .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(transactional_current, second);

    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_address_commitments WHERE npub = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 2);

    let deactivated = pay_service::db::deactivate_user(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert!(!deactivated.is_active);
    let retained_current =
        pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(retained_current, second);
    let inactive_retry_error =
        pay_service::db::persist_recovery_address_commitment(&pool, &second_evidence)
            .await
            .unwrap_err();
    assert!(matches!(
        inactive_retry_error,
        pay_service::db::RecoveryAddressCommitmentError::SourceIdentityNotActive
    ));

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_address_commitment_concurrent_exact_retries_collapse_to_one_row() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, "recoveryretry", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let evidence = verified_recovery_commitment(
        &keypair,
        &npub,
        RECOVERY_COMMITMENT_P2WPKH,
        auth_timestamp(),
    );
    let start = Arc::new(Barrier::new(3));
    let first_pool = pool.clone();
    let first_start = start.clone();
    let first_evidence = evidence.clone();
    let first = tokio::spawn(async move {
        first_start.wait().await;
        pay_service::db::persist_recovery_address_commitment(&first_pool, &first_evidence).await
    });
    let second_pool = pool.clone();
    let second_start = start.clone();
    let second_evidence = evidence.clone();
    let second = tokio::spawn(async move {
        second_start.wait().await;
        pay_service::db::persist_recovery_address_commitment(&second_pool, &second_evidence).await
    });
    start.wait().await;

    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.commitment_version, 1);
    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_address_commitments WHERE npub = $1")
            .bind(&npub)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row_count, 1);

    cleanup_db(&pool).await;
}

#[tokio::test]
async fn recovery_address_commitment_concurrent_rotations_are_contiguous_and_immutable() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
    let (npub, _) = keypair.x_only_public_key();
    let npub = npub.to_string();
    pay_service::db::create_user(&pool, "recoveryrotate", &npub, TEST_DESCRIPTOR)
        .await
        .unwrap();
    let timestamp = auth_timestamp();
    let first_evidence =
        verified_recovery_commitment(&keypair, &npub, RECOVERY_COMMITMENT_P2WPKH, timestamp);
    let second_evidence =
        verified_recovery_commitment(&keypair, &npub, RECOVERY_COMMITMENT_P2PKH, timestamp);
    let start = Arc::new(Barrier::new(3));
    let first_pool = pool.clone();
    let first_start = start.clone();
    let first = tokio::spawn(async move {
        first_start.wait().await;
        pay_service::db::persist_recovery_address_commitment(&first_pool, &first_evidence).await
    });
    let second_pool = pool.clone();
    let second_start = start.clone();
    let second = tokio::spawn(async move {
        second_start.wait().await;
        pay_service::db::persist_recovery_address_commitment(&second_pool, &second_evidence).await
    });
    start.wait().await;

    let mut rotations = [
        first.await.unwrap().unwrap(),
        second.await.unwrap().unwrap(),
    ];
    rotations.sort_by_key(|row| row.commitment_version);
    assert_eq!(
        rotations
            .iter()
            .map(|row| row.commitment_version)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_ne!(rotations[0].commitment_id, rotations[1].commitment_id);
    let current = pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current, rotations[1]);

    let gap_error = sqlx::query(
        "INSERT INTO recovery_address_commitments (\
             commitment_id, npub, contract_format_version, commitment_version, \
             canonical_btc_address, original_signature, signed_at_unix\
         ) VALUES ($1, $2, 1, 4, $3, $4, $5)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(&npub)
    .bind(RECOVERY_COMMITMENT_P2TR)
    .bind("11".repeat(64))
    .bind(i64::try_from(timestamp).unwrap())
    .execute(&pool)
    .await
    .unwrap_err();
    assert_sqlstate(&gap_error, "23514");

    let update_error = sqlx::query(
        "UPDATE recovery_address_commitments \
            SET canonical_btc_address = $2 \
          WHERE commitment_id = $1",
    )
    .bind(rotations[1].commitment_id)
    .bind(RECOVERY_COMMITMENT_P2TR)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_sqlstate(&update_error, "55000");
    let delete_error =
        sqlx::query("DELETE FROM recovery_address_commitments WHERE commitment_id = $1")
            .bind(rotations[1].commitment_id)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_sqlstate(&delete_error, "55000");

    let still_current = pay_service::db::select_current_recovery_address_commitment(&pool, &npub)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_current, rotations[1]);

    cleanup_db(&pool).await;
}
// #87: invoice route -> atomic persistence + synchronous delivery.
// =====================================================================

#[derive(Clone, Copy)]
enum InvoiceRouteManifestStoreMode {
    Durable,
    RejectWrites,
}

#[derive(Clone)]
struct InvoiceRouteStoredManifest {
    body: Vec<u8>,
    content_type: String,
    format_version: String,
    sha256: String,
}

#[derive(Clone)]
struct InvoiceRouteManifestStoreState {
    mode: InvoiceRouteManifestStoreMode,
    objects: Arc<Mutex<HashMap<String, InvoiceRouteStoredManifest>>>,
    put_calls: Arc<AtomicUsize>,
}

struct InvoiceRouteManifestStoreFixture {
    endpoint: String,
    put_calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl InvoiceRouteManifestStoreFixture {
    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

fn invoice_route_s3_response(status: StatusCode, body: impl Into<Body>) -> Response {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    response
}

fn invoice_route_s3_object_response(object: &InvoiceRouteStoredManifest, head: bool) -> Response {
    let mut response = invoice_route_s3_response(
        StatusCode::OK,
        if head {
            Body::empty()
        } else {
            Body::from(object.body.clone())
        },
    );
    let headers = response.headers_mut();
    headers.insert(
        "content-length",
        object.body.len().to_string().parse().unwrap(),
    );
    headers.insert("content-type", object.content_type.parse().unwrap());
    headers.insert("etag", "\"invoice-route-manifest-etag\"".parse().unwrap());
    headers.insert(
        "last-modified",
        "Mon, 13 Jul 2026 12:00:00 GMT".parse().unwrap(),
    );
    headers.insert(
        "x-amz-meta-bullnym-manifest-format-version",
        object.format_version.parse().unwrap(),
    );
    headers.insert("x-amz-meta-bullnym-sha256", object.sha256.parse().unwrap());
    response
}

async fn invoice_route_s3_handler(
    axum::extract::State(state): axum::extract::State<InvoiceRouteManifestStoreState>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let key = parts.uri.path().to_owned();
    match parts.method {
        Method::PUT => {
            state.put_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(state.mode, InvoiceRouteManifestStoreMode::RejectWrites) {
                let mut response = invoice_route_s3_response(
                    StatusCode::FORBIDDEN,
                    Body::from("<Error><Code>AccessDenied</Code></Error>"),
                );
                response
                    .headers_mut()
                    .insert("content-type", "application/xml".parse().unwrap());
                return response;
            }

            let format_version = parts
                .headers
                .get("x-amz-meta-bullnym-manifest-format-version")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let sha256 = parts
                .headers
                .get("x-amz-meta-bullnym-sha256")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let content_type = parts
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = match body.collect().await {
                Ok(body) => body.to_bytes().to_vec(),
                Err(_) => return invoice_route_s3_response(StatusCode::BAD_REQUEST, Body::empty()),
            };
            state.objects.lock().await.insert(
                key,
                InvoiceRouteStoredManifest {
                    body,
                    content_type,
                    format_version,
                    sha256,
                },
            );
            let mut response = invoice_route_s3_response(StatusCode::OK, Body::empty());
            response
                .headers_mut()
                .insert("etag", "\"invoice-route-manifest-etag\"".parse().unwrap());
            response
        }
        Method::GET | Method::HEAD => {
            let object = state.objects.lock().await.get(&key).cloned();
            match object {
                Some(object) => {
                    invoice_route_s3_object_response(&object, parts.method == Method::HEAD)
                }
                None => {
                    let mut response = invoice_route_s3_response(
                        StatusCode::NOT_FOUND,
                        Body::from("<Error><Code>NoSuchKey</Code></Error>"),
                    );
                    response
                        .headers_mut()
                        .insert("content-type", "application/xml".parse().unwrap());
                    response
                }
            }
        }
        _ => invoice_route_s3_response(StatusCode::METHOD_NOT_ALLOWED, Body::empty()),
    }
}

async fn spawn_invoice_route_manifest_store(
    mode: InvoiceRouteManifestStoreMode,
) -> InvoiceRouteManifestStoreFixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let put_calls = Arc::new(AtomicUsize::new(0));
    let state = InvoiceRouteManifestStoreState {
        mode,
        objects: Arc::new(Mutex::new(HashMap::new())),
        put_calls: put_calls.clone(),
    };
    let app = Router::new()
        .fallback(any(invoice_route_s3_handler))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    InvoiceRouteManifestStoreFixture {
        endpoint: format!("http://{address}"),
        put_calls,
        task,
    }
}

#[derive(Clone)]
struct InvoiceRouteBoltzState {
    chain_response: Value,
    chain_calls: Arc<AtomicUsize>,
}

struct InvoiceRouteBoltzFixture {
    base_url: String,
    chain_calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl InvoiceRouteBoltzFixture {
    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn invoice_route_chain_pair(
    axum::extract::State(state): axum::extract::State<InvoiceRouteBoltzState>,
) -> axum::Json<Value> {
    state.chain_calls.fetch_add(1, Ordering::SeqCst);
    axum::Json(json!({
        "BTC": {
            "L-BTC": {
                "hash": "014261b046f2045ddedd49fe291e0255afe002454c65a5aa7d6457a35cd32f19",
                "rate": 1.0,
                "limits": {
                    "maximal": 25_000_000,
                    "minimal": 25_000,
                    "maximalZeroConf": 0
                },
                "fees": {
                    "percentage": 0.1,
                    "minerFees": {
                        "server": 405,
                        "user": {"claim": 20, "lockup": 385}
                    }
                }
            }
        },
        "L-BTC": {}
    }))
}

async fn invoice_route_chain_heights(
    axum::extract::State(state): axum::extract::State<InvoiceRouteBoltzState>,
) -> axum::Json<Value> {
    state.chain_calls.fetch_add(1, Ordering::SeqCst);
    axum::Json(json!({"BTC": 957_817, "L-BTC": 3_970_775}))
}

async fn invoice_route_create_chain(
    axum::extract::State(state): axum::extract::State<InvoiceRouteBoltzState>,
    axum::Json(_request): axum::Json<Value>,
) -> axum::Json<Value> {
    state.chain_calls.fetch_add(1, Ordering::SeqCst);
    axum::Json(state.chain_response)
}

async fn invoice_route_reject_reverse() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        axum::Json(json!({"error": "fixture"})),
    )
        .into_response()
}

async fn spawn_invoice_route_boltz(
    response: &boltz_client::swaps::boltz::CreateChainResponse,
) -> InvoiceRouteBoltzFixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let chain_calls = Arc::new(AtomicUsize::new(0));
    let state = InvoiceRouteBoltzState {
        chain_response: serde_json::to_value(response).unwrap(),
        chain_calls: chain_calls.clone(),
    };
    let app = Router::new()
        .route(
            "/swap/chain",
            get(invoice_route_chain_pair).post(invoice_route_create_chain),
        )
        .route("/chain/heights", get(invoice_route_chain_heights))
        .route("/swap/reverse", post(invoice_route_reject_reverse))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    InvoiceRouteBoltzFixture {
        base_url: format!("http://{address}"),
        chain_calls,
        task,
    }
}

fn invoice_route_chain_response(
    boltz_swap_id: &str,
    claim_child_index: u64,
    refund_child_index: u64,
) -> boltz_client::swaps::boltz::CreateChainResponse {
    let master = SwapMasterKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        Network::Mainnet,
    )
    .unwrap();
    let claim_keypair = master.derive_swapkey(claim_child_index).unwrap();
    let refund_keypair = master.derive_swapkey(refund_child_index).unwrap();
    let preimage = boltz_client::util::secrets::Preimage::from_swap_key(&claim_keypair);
    atomic_manifest_provider_fixture(
        boltz_swap_id,
        &preimage,
        boltz_client::PublicKey::new(claim_keypair.public_key()),
        boltz_client::PublicKey::new(refund_keypair.public_key()),
    )
}

fn invoice_route_manifest_runtime(
    endpoint: &str,
) -> Arc<pay_service::swap_manifest_runtime::RecoveryManifestRuntimeV1> {
    use pay_service::swap_manifest_runtime as runtime;

    let signing_secret = SecretKey::from_slice(&[0x61; 32]).unwrap();
    let signing_keypair = Keypair::from_secret_key(&Secp256k1::new(), &signing_secret);
    let values = HashMap::from([
        (runtime::S3_ENDPOINT_ENV.to_owned(), endpoint.to_owned()),
        (runtime::S3_REGION_ENV.to_owned(), "us-east-1".to_owned()),
        (
            runtime::S3_BUCKET_ENV.to_owned(),
            "bullnym-invoice-route".to_owned(),
        ),
        (
            runtime::S3_PREFIX_ENV.to_owned(),
            "invoice-route".to_owned(),
        ),
        (runtime::S3_PATH_STYLE_ENV.to_owned(), "true".to_owned()),
        (runtime::S3_ALLOW_HTTP_ENV.to_owned(), "true".to_owned()),
        (
            runtime::S3_ACCESS_KEY_ID_ENV.to_owned(),
            "invoice-route-access".to_owned(),
        ),
        (
            runtime::S3_SECRET_ACCESS_KEY_ENV.to_owned(),
            "invoice-route-secret".to_owned(),
        ),
        (
            runtime::ENCRYPTION_KEY_ID_ENV.to_owned(),
            "invoice-route-key-v1".to_owned(),
        ),
        (
            runtime::ENCRYPTION_KEY_HEX_ENV.to_owned(),
            hex::encode([0x51; 32]),
        ),
        (
            runtime::SIGNING_SECRET_KEY_HEX_ENV.to_owned(),
            hex::encode(signing_secret.secret_bytes()),
        ),
        (
            runtime::EXPECTED_SIGNER_XONLY_HEX_ENV.to_owned(),
            signing_keypair.x_only_public_key().0.to_string(),
        ),
    ]);
    Arc::new(
        runtime::RecoveryManifestRuntimeV1::from_lookup(|name| values.get(name).cloned()).unwrap(),
    )
}

async fn seed_invoice_route_page(pool: &PgPool, nym: &str) -> uuid::Uuid {
    let npub = create_test_user(pool, nym).await;
    let recovery_address_commitment_id =
        insert_test_recovery_commitment(pool, &npub, ATOMIC_MANIFEST_EMERGENCY_ADDRESS, 1, 0x88)
            .await;
    pay_service::db::upsert_donation_page(
        pool,
        &pay_service::db::UpsertDonationPage {
            nym,
            kind: pay_service::db::KIND_PAYMENT_PAGE,
            ct_descriptor: Some(TEST_DESCRIPTOR),
            header: "Atomic route",
            description: "Atomic chain-swap route fixture",
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
    recovery_address_commitment_id
}

async fn drop_invoice_route_staging_drift(pool: &PgPool) {
    sqlx::query("DROP TRIGGER IF EXISTS zz_invoice_route_staging_drift ON chain_swap_records")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION IF EXISTS invoice_route_staging_drift()")
        .execute(pool)
        .await
        .unwrap();
}

async fn install_invoice_route_staging_drift(pool: &PgPool) {
    drop_invoice_route_staging_drift(pool).await;
    sqlx::query(
        "CREATE FUNCTION invoice_route_staging_drift() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN NEW.nym := NEW.nym || '-persisted-drift'; RETURN NEW; END $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER zz_invoice_route_staging_drift \
         BEFORE INSERT ON chain_swap_records FOR EACH ROW \
         EXECUTE FUNCTION invoice_route_staging_drift()",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn invoice_route_test_state(
    pool: &PgPool,
    boltz_url: &str,
    manifest_endpoint: &str,
) -> AppState {
    let mut config = test_config();
    config.boltz.api_url = boltz_url.to_owned();
    let mut state = test_state_with_config(pool.clone(), config);
    state.recovery_manifest_runtime_v1 = Some(invoice_route_manifest_runtime(manifest_endpoint));
    state
}

#[tokio::test]
async fn invoice_chain_offer_returns_only_after_manifest_delivery() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    drop_invoice_route_staging_drift(&pool).await;
    let nym = "invoicemanifestdelivered";
    let recovery_address_commitment_id = seed_invoice_route_page(&pool, nym).await;

    let first_child_index = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap() as u64;
    let provider_response = invoice_route_chain_response(
        "InvoiceManifestDelivered1",
        first_child_index + 1,
        first_child_index + 2,
    );
    let expected_provider_json = atomic_manifest_canonical_json(&provider_response);
    let expected_lockup_address = provider_response.lockup_details.lockup_address.clone();
    let boltz = spawn_invoice_route_boltz(&provider_response).await;
    let store = spawn_invoice_route_manifest_store(InvoiceRouteManifestStoreMode::Durable).await;
    let state = invoice_route_test_state(&pool, &boltz.base_url, &store.endpoint).await;
    let app = test_app(state);

    let (status, body) = post_json(
        &app,
        &format!("/{nym}/invoice"),
        json!({"amount_sat": 25_000}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lightning_pr"], "");
    assert_eq!(body["bitcoin_chain_address"], expected_lockup_address);
    assert_eq!(body["bitcoin_chain_amount_sat"], 25_431);
    let payer_bip21 = body["bitcoin_chain_bip21"].as_str().unwrap();
    assert!(payer_bip21.starts_with(&format!(
        "bitcoin:{}?amount=0.00025431&",
        provider_response.lockup_details.lockup_address
    )));
    assert_ne!(
        payer_bip21,
        provider_response.lockup_details.bip21.as_deref().unwrap()
    );
    let invoice_id = body["invoice_id"].as_str().unwrap();
    let (status_code, status_body) =
        get_path(&app, &format!("/api/v1/invoices/{invoice_id}/status")).await;
    assert_eq!(status_code, StatusCode::OK, "{status_body}");
    assert_eq!(
        status_body["bitcoin_chain_address"],
        expected_lockup_address
    );
    assert_eq!(status_body["bitcoin_chain_bip21"], payer_bip21);
    assert_eq!(status_body["bitcoin_chain_amount_sat"], 25_431);
    assert_eq!(status_body["remaining_amount_sat"], 25_000);
    assert!(status_body["lightning_amount_sat"].is_null());
    assert_eq!(status_body["liquid_amount_sat"], 25_000);
    let (render_status, html) = get_text_path(&app, &format!("/{nym}/i/{invoice_id}")).await;
    assert_eq!(render_status, StatusCode::OK, "{html}");
    assert!(html.contains("INITIAL_BITCOIN_CHAIN_AMOUNT_SAT = 25431"));
    assert!(html.contains("currentBitcoinChainAmountSat"));
    assert!(
        html.contains("Includes ${new Intl.NumberFormat().format(swapCostSat)} sats in swap costs")
    );

    let row = pay_service::db::get_chain_swap_by_boltz_id(&pool, "InvoiceManifestDelivered1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "pending");
    assert_eq!(row.nym.as_deref(), Some(nym));
    assert_eq!(row.boltz_response_json, expected_provider_json);
    assert_eq!(row.lockup_bip21.as_deref(), Some(payer_bip21));
    let terms = row.creation_terms.as_ref().unwrap();
    assert_eq!(terms.merchant_liquid_destination, body["liquid_address"]);
    assert_eq!(
        terms.merchant_emergency_btc_address.as_deref(),
        Some(ATOMIC_MANIFEST_EMERGENCY_ADDRESS)
    );
    assert_eq!(
        terms.recovery_address_commitment_id,
        Some(recovery_address_commitment_id)
    );

    let audit = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert!(!audit[0].manifest_id.is_nil());
    assert_eq!(audit[0].chain_swap_id, row.id);
    assert_eq!(audit[0].delivery_state, "delivered");
    assert!(audit[0].delivered_at_unix.is_some());
    assert_eq!(store.put_calls.load(Ordering::SeqCst), 1);
    assert_eq!(boltz.chain_calls.load(Ordering::SeqCst), 3);

    boltz.shutdown().await;
    store.shutdown().await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_chain_offer_staging_failure_withholds_offer_and_retains_provider_row() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    install_invoice_route_staging_drift(&pool).await;
    let nym = "invoicemanifeststagingfailure";
    seed_invoice_route_page(&pool, nym).await;
    // Keep the deliberate post-validation nym drift database-valid so this
    // test reaches manifest staging after the canonical row commits.
    create_test_user(&pool, "invoicemanifeststagingfailure-persisted-drift").await;

    let first_child_index = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap() as u64;
    let provider_response = invoice_route_chain_response(
        "InvoiceManifestStagingFailure1",
        first_child_index + 1,
        first_child_index + 2,
    );
    let expected_provider_json = atomic_manifest_canonical_json(&provider_response);
    let boltz = spawn_invoice_route_boltz(&provider_response).await;
    let store = spawn_invoice_route_manifest_store(InvoiceRouteManifestStoreMode::Durable).await;
    let state = invoice_route_test_state(&pool, &boltz.base_url, &store.endpoint).await;
    let app = test_app(state);

    let (status, body) = post_json(
        &app,
        &format!("/{nym}/invoice"),
        json!({"amount_sat": 25_000}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["bitcoin_chain_address"].is_null(), "{body}");
    assert!(body["bitcoin_chain_bip21"].is_null(), "{body}");
    assert!(body["bitcoin_chain_amount_sat"].is_null(), "{body}");
    let row = pay_service::db::get_chain_swap_by_boltz_id(&pool, "InvoiceManifestStagingFailure1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "pending");
    assert_eq!(
        row.nym.as_deref(),
        Some("invoicemanifeststagingfailure-persisted-drift")
    );
    assert_eq!(row.boltz_response_json, expected_provider_json);
    assert_eq!(
        pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
            .await
            .unwrap(),
        Vec::new()
    );
    assert_eq!(store.put_calls.load(Ordering::SeqCst), 0);
    assert_eq!(boltz.chain_calls.load(Ordering::SeqCst), 3);

    boltz.shutdown().await;
    store.shutdown().await;
    drop_invoice_route_staging_drift(&pool).await;
    cleanup_db(&pool).await;
}

#[tokio::test]
async fn invoice_chain_offer_delivery_failure_withholds_offer_and_retains_provider_row() {
    let pool = test_pool().await;
    cleanup_db(&pool).await;
    drop_invoice_route_staging_drift(&pool).await;
    let nym = "invoicemanifestdeliveryfailure";
    seed_invoice_route_page(&pool, nym).await;

    let first_child_index = pay_service::db::swap_key_seq_next_value(&pool)
        .await
        .unwrap() as u64;
    let provider_response = invoice_route_chain_response(
        "InvoiceManifestDeliveryFailure1",
        first_child_index + 1,
        first_child_index + 2,
    );
    let expected_provider_json = atomic_manifest_canonical_json(&provider_response);
    let boltz = spawn_invoice_route_boltz(&provider_response).await;
    let store =
        spawn_invoice_route_manifest_store(InvoiceRouteManifestStoreMode::RejectWrites).await;
    let state = invoice_route_test_state(&pool, &boltz.base_url, &store.endpoint).await;
    let app = test_app(state);

    let (status, body) = post_json(
        &app,
        &format!("/{nym}/invoice"),
        json!({"amount_sat": 25_000}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["bitcoin_chain_address"].is_null(), "{body}");
    assert!(body["bitcoin_chain_bip21"].is_null(), "{body}");
    assert!(body["bitcoin_chain_amount_sat"].is_null(), "{body}");
    let row = pay_service::db::get_chain_swap_by_boltz_id(&pool, "InvoiceManifestDeliveryFailure1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "pending");
    assert_eq!(row.nym.as_deref(), Some(nym));
    assert_eq!(row.boltz_response_json, expected_provider_json);
    let audit = pay_service::db::list_manifest_delivery_audit(&pool, 0, 10)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert!(!audit[0].manifest_id.is_nil());
    assert_eq!(audit[0].chain_swap_id, row.id);
    assert_eq!(audit[0].delivery_state, "pending");
    assert_eq!(audit[0].delivered_at_unix, None);
    assert!(store.put_calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(boltz.chain_calls.load(Ordering::SeqCst), 3);

    boltz.shutdown().await;
    store.shutdown().await;
    cleanup_db(&pool).await;
}
