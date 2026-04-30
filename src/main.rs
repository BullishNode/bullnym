use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post, put};
use axum::Router;
use boltz_client::network::Network;
use boltz_client::util::secrets::SwapMasterKey;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use pay_service::{
    boltz, chain_watcher, claimer, config, gc, ip_whitelist, lnurl, nostr, rate_limit, registration,
    utxo::{self, UtxoBackend},
    AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    // rustls 0.23 panics if more than one CryptoProvider feature is linked
    // and no process-level default is selected. Both aws-lc-rs and ring come
    // in transitively (electrum-client + lwk + boltz-client), so install one
    // explicitly before any TLS handshake.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "rustls CryptoProvider already installed")?;

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

    let webhook_url = format!("https://{}/webhook/boltz", config.domain);
    let boltz_service = boltz::BoltzService::new(
        &config.boltz.api_url,
        swap_master_key,
        Some(webhook_url.clone()),
    );
    tracing::info!("boltz service initialized ({}) webhook={}", config.boltz.api_url, webhook_url);

    // IP whitelist (fail-closed on parse errors — a typo should surface loudly).
    let whitelist = ip_whitelist::IpWhitelist::parse(&config.rate_limit.ip_whitelist)
        .map_err(|e| format!("ip_whitelist parse error: {e}"))?;
    if !whitelist.is_empty() {
        tracing::info!(
            "ip_whitelist loaded ({} entries); whitelisted callers bypass proof + rate limits",
            config.rate_limit.ip_whitelist.len(),
        );
    }

    // Electrum backend for Liquid UTXO verification. The client is resilient
    // to stale TCP connections and rotates through `liquid_urls` on failure;
    // even if no URL is reachable at startup it constructs successfully and
    // reconnects lazily on the first PF request.
    let electrum_urls = config.electrum.urls();
    tracing::info!(
        "liquid electrum backend configured with {} url(s): {}",
        electrum_urls.len(),
        electrum_urls.join(", ")
    );
    let utxo_backend: Option<Arc<dyn UtxoBackend>> = match utxo::ElectrumClient::connect(
        electrum_urls,
        config.electrum.cache_ttl_secs,
        config.electrum.cache_max_entries,
    ) {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            tracing::error!("liquid electrum backend init failed: {e}");
            None
        }
    };

    let rate_limiter = Arc::new(rate_limit::RateLimiter::new(
        pool.clone(),
        config.rate_limit.clone(),
    ));

    let listen_addr = config.listen.clone();
    let config = Arc::new(config);
    let boltz = Arc::new(boltz_service);
    let whitelist = Arc::new(whitelist);

    let state = AppState {
        db: pool.clone(),
        config: config.clone(),
        boltz: boltz.clone(),
        ip_whitelist: whitelist.clone(),
        rate_limiter: rate_limiter.clone(),
        utxo_backend,
    };

    let cancel = CancellationToken::new();
    claimer::spawn_background_claimer(pool.clone(), config.clone(), cancel.clone());

    // Periodic GC of rate-limit tables. Without this, sliding-window
    // queries get progressively slower as inactive rows accumulate.
    {
        let pool = pool.clone();
        let cancel_gc = cancel.clone();
        tokio::spawn(async move {
            gc::run(pool, cancel_gc, gc::GcConfig::default()).await;
        });
        tracing::info!("rate-limit GC started (prune every 10 min, retention 24h)");
    }

    // Periodic in-memory sweep for the per-IP / register / metadata
    // sliding-window counters. Without this, one-shot bursts of unique
    // IPs would leave entries behind forever.
    {
        let rl = rate_limiter.clone();
        let cancel_sweep = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = cancel_sweep.cancelled() => return,
                    _ = tick.tick() => {
                        let evicted = rl.sweep_inmemory(std::time::Duration::from_secs(7200));
                        if evicted > 0 {
                            tracing::info!("rate-limit in-mem sweep: evicted {} idle entries", evicted);
                        }
                    }
                }
            }
        });
    }

    if let Some(backend) = state.utxo_backend.clone() {
        let pool = state.db.clone();
        let rl = rate_limiter.clone();
        let cancel_watcher = cancel.clone();
        let watcher_cfg =
            chain_watcher::ChainWatcherConfig::from_rate_limit_config(&config.rate_limit);
        let active = watcher_cfg.active_tick_secs;
        let idle = watcher_cfg.idle_tick_secs;
        tokio::spawn(async move {
            chain_watcher::run(pool, backend, rl, cancel_watcher, watcher_cfg).await;
        });
        tracing::info!(
            "chain watcher started (active tick {}s, idle tick {}s, lookahead 10)",
            active, idle,
        );
    } else {
        tracing::warn!("chain watcher NOT started: utxo backend unavailable");
    }

    let app = Router::new()
        .route("/.well-known/lnurlp/:nym", get(lnurl::metadata))
        .route("/.well-known/nostr.json", get(nostr::nostr_json))
        .route("/lnurlp/callback/:nym", get(lnurl::callback))
        .route("/register", post(registration::register))
        .route("/register", put(registration::update_registration))
        .route("/register", axum::routing::delete(registration::delete_registration))
        .route("/register/lookup", get(registration::lookup_by_npub))
        .route("/api/reservations/:nym", get(registration::list_reservations))
        .route("/webhook/boltz", post(claimer::webhook))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("listening on {listen_addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("received shutdown signal");
        cancel.cancel();
    })
    .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}
