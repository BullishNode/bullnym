use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use boltz_client::network::Network;
use boltz_client::util::secrets::SwapMasterKey;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use pay_service::{
    bitcoin_watcher, boltz, certification, chain_watcher, claimer, config, db, donation_page,
    donation_render, gc, invoice, ip_whitelist, lnurl, nostr, pricer, qr, rate_limit, readiness,
    reconciler, registration,
    utxo::{self, UtxoBackend},
    version, AppState,
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
    if config.rate_limit.trust_forwarded_for {
        tracing::warn!(
            "rate_limit.trust_forwarded_for=true; only run this behind a trusted reverse proxy \
             that overwrites X-Forwarded-For at the network boundary"
        );
    }
    if !config.boltz_webhook_url_secret_previous.is_empty() {
        tracing::warn!(
            "BOLTZ_WEBHOOK_URL_SECRET_PREVIOUS is set; webhook secret rotation overlap is active"
        );
    }
    tracing::info!(
        "features: lightning_address={} invoices={} payment_pages={} workers={}",
        config.features.lightning_address,
        config.features.invoices,
        config.features.payment_pages,
        config.workers.enabled,
    );

    let pool = PgPoolOptions::new()
        .max_connections(config.pool_size)
        .connect(&config.database_url)
        .await
        .map_err(|e| format!("database connection failed: {e}"))?;
    tracing::info!("connected to database");

    let swap_master_key =
        SwapMasterKey::from_mnemonic(&config.swap_mnemonic, None, Network::Mainnet)
            .map_err(|e| format!("invalid swap mnemonic: {e}"))?;

    // Boltz does not HMAC-sign webhook deliveries; the only viable
    // authenticator is the URL itself. Compatibility details live in
    // docs/compatibility-ledger.md.
    let webhook_url = if config.boltz_webhook_url_secret.is_empty() {
        tracing::warn!(
            "BOLTZ_WEBHOOK_URL_SECRET unset — registering unauthenticated webhook URL (DEV ONLY)"
        );
        format!("https://{}/webhook/boltz", config.domain)
    } else {
        format!(
            "https://{}/webhook/boltz/{}",
            config.domain, config.boltz_webhook_url_secret
        )
    };
    let boltz_service = boltz::BoltzService::new(
        &config.boltz.api_url,
        swap_master_key,
        Some(webhook_url.clone()),
    );
    // Log the sanitized URL — never log the secret. Production logs
    // pipe to multiple sinks; the secret is high-value.
    tracing::info!(
        "boltz service initialized ({}) webhook=https://{}/webhook/boltz/{}",
        config.boltz.api_url,
        config.domain,
        if config.boltz_webhook_url_secret.is_empty() {
            "<unauthenticated>"
        } else {
            "<redacted>"
        }
    );

    // IP whitelist (fail-closed on parse errors — a typo should surface loudly).
    let whitelist = ip_whitelist::IpWhitelist::parse(&config.rate_limit.ip_whitelist)
        .map_err(|e| format!("ip_whitelist parse error: {e}"))?;
    if !whitelist.is_empty() {
        tracing::info!(
            "ip_whitelist loaded ({} entries); whitelisted callers bypass proof + rate limits",
            config.rate_limit.ip_whitelist.len(),
        );
    }
    let certification_allowlist =
        certification::CertificationAllowlist::parse(&config.certification)
            .map_err(|e| format!("certification allowlist parse error: {e}"))?;
    if certification_allowlist.enabled() {
        tracing::warn!(
            scopes = ?certification_allowlist.configured_scopes(),
            "certification allowlist loaded; scoped bypasses require source allowlist and token"
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

    let pricer_client = Arc::new(
        pricer::PricerClient::new(config.pricer.clone())
            .map_err(|e| format!("pricer client init: {e}"))?,
    );
    tracing::info!(
        "pricer client configured (url={}, ttl={}s, timeout={}ms)",
        config.pricer.url,
        config.pricer.cache_ttl_secs,
        config.pricer.request_timeout_ms,
    );
    let pwa_shells = Arc::new(donation_render::PwaShells::load(&config.pwa.dist_dir));

    let listen_addr = config.listen.clone();
    let config = Arc::new(config);
    let boltz = Arc::new(boltz_service);
    let whitelist = Arc::new(whitelist);
    let certification_allowlist = Arc::new(certification_allowlist);

    let state = AppState {
        db: pool.clone(),
        config: config.clone(),
        boltz: boltz.clone(),
        ip_whitelist: whitelist.clone(),
        certification: certification_allowlist.clone(),
        rate_limiter: rate_limiter.clone(),
        utxo_backend,
        pricer: pricer_client,
        pwa_shells,
    };

    let cancel = CancellationToken::new();
    if config.workers.enabled {
        tracing::info!("background workers enabled");
        claimer::spawn_background_claimer(
            pool.clone(),
            config.clone(),
            state.utxo_backend.clone(),
            cancel.clone(),
        );

        // Reconciler: polls boltz_api.get_swap for every non-terminal swap
        // older than `min_age_secs` and patches our DB to match Boltz's
        // view. Closes the dropped-webhook gap (Boltz's webhook delivery
        // gives up after ~5 min) by querying state directly.
        reconciler::spawn(
            pool.clone(),
            config.boltz.api_url.clone(),
            Arc::new(config.reconciler.clone()),
            cancel.clone(),
        );
        tracing::info!(
            "reconciler started (interval={}s, min_age={}s, max_per_tick={})",
            config.reconciler.interval_secs,
            config.reconciler.min_age_secs,
            config.reconciler.max_per_tick,
        );

        // Periodic GC of rate-limit tables. Without this, sliding-window
        // queries get progressively slower as inactive rows accumulate.
        {
            let pool = pool.clone();
            let gc_cfg = gc::GcConfig {
                checkout_partial_terminal_grace_secs: config
                    .invoice_accounting
                    .checkout_partial_terminal_grace_secs,
                ..gc::GcConfig::default()
            };
            let cancel_gc = cancel.clone();
            tokio::spawn(async move {
                gc::run(pool, cancel_gc, gc_cfg).await;
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
            let accounting_tolerances =
                db::InvoiceAccountingTolerances::from(&config.invoice_accounting);
            let active = watcher_cfg.active_tick_secs;
            let idle = watcher_cfg.idle_tick_secs;
            tokio::spawn(async move {
                chain_watcher::run(
                    pool,
                    backend,
                    rl,
                    cancel_watcher,
                    watcher_cfg,
                    accounting_tolerances,
                )
                .await;
            });
            tracing::info!(
                "chain watcher started (active tick {}s, idle tick {}s, lookahead 10)",
                active,
                idle,
            );
        } else {
            tracing::warn!("chain watcher NOT started: utxo backend unavailable");
        }

        // Bitcoin watcher: polls mempool.bullbitcoin.com for invoice on-chain
        // BTC settlement. Independent of the Liquid chain watcher above —
        // separate API, separate rate-limit policy, separate cadence.
        if config.bitcoin_watcher.enabled {
            let pool = state.db.clone();
            let cancel_btc = cancel.clone();
            let btc_cfg = config.bitcoin_watcher.clone();
            let accounting_tolerances =
                db::InvoiceAccountingTolerances::from(&config.invoice_accounting);
            tokio::spawn(async move {
                bitcoin_watcher::run(btc_cfg, accounting_tolerances, pool, cancel_btc).await;
            });
        } else {
            tracing::info!("bitcoin watcher disabled by config");
        }
    } else {
        tracing::warn!(
            "background workers disabled by config; HTTP routes are active but claims, \
             reconciliation, watchers, and GC will not run in this process"
        );
    }

    let app = build_router(state);

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

fn build_router(state: AppState) -> Router {
    let features = state.config.features.clone();
    let invoice_sessions_enabled = features.invoices || features.payment_pages;
    let pwa_dist_dir = state.config.pwa.dist_dir.clone();

    let mut router: Router<AppState> = Router::new()
        .route(
            "/api/v1/supported-currencies",
            get(pricer::supported_currencies),
        )
        .route("/api/v1/rate", get(pricer::rate))
        .nest_service(
            "/pwa-assets",
            ServiceBuilder::new()
                .layer(middleware::from_fn(pwa_assets_headers))
                .service(ServeDir::new(pwa_dist_dir).precompressed_gzip()),
        )
        .route("/robots.txt", get(invoice::robots_txt))
        .route("/sw.js", get(donation_render::service_worker))
        .route("/qr.svg", get(qr::generate))
        // See docs/compatibility-ledger.md for webhook compatibility policy.
        .route("/webhook/boltz/:secret", post(claimer::webhook_with_secret))
        .route("/webhook/boltz", post(claimer::webhook_unauthenticated))
        .route("/health", get(health))
        .route("/ready", get(readiness::ready))
        .route("/version", get(version::version))
        .route("/certification/preflight", get(certification::preflight));

    if features.lightning_address {
        router = router
            .route("/.well-known/lnurlp/:nym", get(lnurl::metadata))
            .route("/.well-known/nostr.json", get(nostr::nostr_json))
            .route("/lnurlp/callback/:nym", get(lnurl::callback))
            .route("/register", post(registration::register))
            .route("/register", put(registration::update_registration))
            .route(
                "/register",
                axum::routing::delete(registration::delete_registration),
            )
            .route("/register/lookup", get(registration::lookup_by_npub))
            .route(
                "/api/reservations/:nym",
                get(registration::list_reservations),
            );
    }

    if features.payment_pages {
        // Tighter per-route body caps for the donation CRUD endpoints.
        // The global 64 KiB still applies; the smaller per-route limit wins.
        // Save body is JSON with all v1 fields ~ <2 KiB in practice; 8 KiB
        // is generous headroom. Archive carries only nym+npub+sig+ts.
        router = router
            .route(
                "/donation-page",
                put(donation_page::save).layer(DefaultBodyLimit::max(8 * 1024)),
            )
            .route(
                "/donation-page",
                axum::routing::delete(donation_page::archive).layer(DefaultBodyLimit::max(1024)),
            )
            .route("/donation-page/:nym", get(donation_page::get))
            .route("/:nym/manifest.webmanifest", get(donation_render::manifest))
            // Donation checkout now uses invoice sessions instead of the
            // removed donation callback/status endpoints.
            // Anonymous checkout invoice endpoints. The create route keeps a
            // tight body cap; status and offer routes are rate-limit gated.
            .route(
                "/:nym/invoice",
                post(invoice::create_anonymous).layer(DefaultBodyLimit::max(1024)),
            )
            .route("/:nym/i/:id", get(invoice::render_payment));

        // Donation-page image upload needs a 2 MiB body cap, well above the
        // 64 KiB global. Layers are per-router in axum 0.7+ — putting the
        // image route in its own sub-router with its own RequestBodyLimitLayer
        // keeps the global tight while letting this one path accept binaries.
        let image_upload_router: Router<AppState> = Router::new()
            .route("/donation-page/image", post(donation_page::upload_image))
            .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024));
        router = router.merge(image_upload_router);
    }

    if invoice_sessions_enabled {
        router = router
            .route("/api/v1/invoices/:id/status", get(invoice::status))
            .route(
                "/api/v1/invoices/:id/lightning",
                post(invoice::fetch_lightning_offer),
            )
            .route(
                "/api/v1/invoices/:id/liquid",
                post(invoice::fetch_liquid_offer),
            );
    }

    if features.invoices {
        // Schnorr-signed recipient invoice endpoints, linked + unlinked.
        // Body cap 8 KiB on signed POST to
        // bound a misbehaving client; DELETE carries only npub+ts+sig.
        // List uses GET + Query at the npub-keyed root.
        router = router
            .route(
                "/api/v1/:nym/invoices",
                post(invoice::create_signed_linked).layer(DefaultBodyLimit::max(8 * 1024)),
            )
            .route(
                "/api/v1/invoices",
                post(invoice::create_signed_unlinked).layer(DefaultBodyLimit::max(8 * 1024)),
            )
            .route(
                "/api/v1/:nym/invoices/:id",
                axum::routing::delete(invoice::cancel_linked).layer(DefaultBodyLimit::max(1024)),
            )
            .route(
                "/api/v1/invoices/:id",
                axum::routing::delete(invoice::cancel_unlinked).layer(DefaultBodyLimit::max(1024)),
            )
            .route("/api/v1/invoices", get(invoice::list_signed))
            // Public unlinked render path. Privacy headers + indexing posture
            // are applied via `invoice::html_response`; the parent fallback's
            // donation_render path is bypassed via explicit registration.
            .route("/invoice/:id", get(invoice::render_unlinked_payment));
    }

    let router = if features.payment_pages {
        router.fallback(donation_render::render_or_404)
    } else {
        router.fallback(not_found)
    };

    router
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn pwa_assets_headers(req: Request<Body>, next: Next) -> Response {
    let raw_path = req.uri().path();
    let path = raw_path
        .strip_prefix("/pwa-assets")
        .unwrap_or(raw_path)
        .to_string();
    if path.starts_with("/apps/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let mut resp = next.run(req).await;
    if !resp.status().is_success() {
        return resp;
    }
    let cache_control = if path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    resp
}

async fn health() -> &'static str {
    "ok"
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}
