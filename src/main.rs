use axum::routing::{get, post, put};
use axum::Router;
use boltz_client::network::Network;
use boltz_client::util::secrets::SwapMasterKey;
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use pay_service::{boltz, claimer, config, dns, lnurl, nostr, registration, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pay_service=info,tower_http=info".into()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let config = config::Config::load(&config_path)?;
    tracing::info!("loaded config for domain: {}", config.domain);

    let pool = PgPoolOptions::new()
        .max_connections(config.pool_size)
        .connect(&config.database_url)
        .await
        .map_err(|e| format!("database connection failed: {e}"))?;
    tracing::info!("connected to database");

    let swap_master_key = SwapMasterKey::from_mnemonic(
        &config.swap_mnemonic,
        None,
        Network::Mainnet,
    )
    .map_err(|e| format!("invalid swap mnemonic: {e}"))?;

    let boltz_service = boltz::BoltzService::new(&config.boltz.api_url, swap_master_key);
    tracing::info!("boltz service initialized ({})", config.boltz.api_url);

    let dns = if config.dns_enabled() {
        tracing::info!("DNS record management enabled for {}", config.dns.zone_domain);
        Some(dns::EasyDnsClient::new(
            &config.dns.easydns_api_url,
            &config.dns.zone_domain,
            config.easydns_api_key.as_deref().unwrap(),
            config.easydns_api_token.as_deref().unwrap(),
        ))
    } else {
        tracing::info!("DNS record management disabled");
        None
    };

    let listen_addr = config.listen.clone();
    let config = std::sync::Arc::new(config);
    let boltz = std::sync::Arc::new(boltz_service);

    let state = AppState {
        db: pool.clone(),
        config: config.clone(),
        boltz: boltz.clone(),
        dns,
    };

    // Crash recovery: claim any swaps that were left in lockup_confirmed status
    let recovery_pool = pool.clone();
    let recovery_boltz = boltz.clone();
    let recovery_config = config.clone();
    tokio::spawn(async move {
        if let Err(e) = claimer::recover_unclaimed_swaps(
            &recovery_pool,
            &recovery_boltz,
            &recovery_config.boltz.electrum_url,
            &recovery_config.boltz.api_url,
        )
        .await
        {
            tracing::error!("crash recovery failed: {e}");
        }
    });

    let app = Router::new()
        .route("/.well-known/lnurlp/{nym}", get(lnurl::metadata))
        .route("/.well-known/nostr.json", get(nostr::nostr_json))
        .route("/lnurlp/callback/{nym}", get(lnurl::callback))
        .route("/register", post(registration::register))
        .route("/register", put(registration::update_registration))
        .route("/webhook/boltz", post(claimer::webhook))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("listening on {listen_addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("received shutdown signal");
}
