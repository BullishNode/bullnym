use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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
    admission, bitcoin_watcher, boltz, certification, chain_watcher, claimer, config, db,
    derivation_guard, donation_page, donation_render, gc, invoice, ip_whitelist, lnurl, nostr,
    og_image, pricer, qr, rate_limit, readiness, reconciler, registration,
    utxo::{self, UtxoBackend},
    version, AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--build-info") {
        println!("{}", version::build_info_json()?);
        return Ok(());
    }

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

    let provenance = version::BuildProvenance::current();
    tracing::info!(
        bullnym_commit = provenance.build_commit,
        boltz_client_commit = provenance.boltz_client_commit,
        boltz_client_verification = provenance.boltz_client_verification,
        build_profile = provenance.build_profile,
        source_state = provenance.build_source_state,
        schema_marker = provenance.expected_schema_marker,
        pwa_content_sha256 = provenance.pwa_content_sha256,
        rustc_version = provenance.rustc_version,
        cargo_version = provenance.cargo_version,
        build_target = provenance.build_target,
        "build provenance"
    );

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
        "features: lightning_address={} invoices={} payment_pages={} nip05={} workers={}",
        config.features.lightning_address,
        config.features.invoices,
        config.features.payment_pages,
        config.features.nip05,
        config.workers.enabled,
    );
    if config.features.payment_pages && !config.workers.enabled {
        tracing::warn!(
            "Payment Pages are enabled while background workers are disabled; \
             OG generation still runs on save, but legacy backfill, retries, and \
             host-local missing-file verification will not run"
        );
    }

    let pool = PgPoolOptions::new()
        .max_connections(config.pool_size)
        .connect(&config.database_url)
        .await
        .map_err(|e| format!("database connection failed: {e}"))?;
    tracing::info!("connected to database");

    let schema_and_journal_ready = readiness::schema_and_journal_ready(&pool)
        .await
        .map_err(|e| format!("database schema verification failed: {e}"))?;
    if !schema_and_journal_ready {
        return Err(format!(
            "database is missing expected schema marker {} or writable recovery journal",
            version::EXPECTED_SCHEMA_MARKER
        )
        .into());
    }
    tracing::info!(
        schema_marker = version::EXPECTED_SCHEMA_MARKER,
        "database schema and recovery journal verified"
    );

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
    if boltz_service.client_ready() {
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
    } else {
        tracing::error!(
            event = "boltz_client_init_failed",
            "Boltz client URL is invalid; new swap admission is closed"
        );
    }

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
    let electrum_urls = config.electrum.urls_with_builtin_failover();
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

    let direct_liquid_settings_valid =
        config.electrum.explicit_urls_valid() && config.liquid_watcher.finality_valid();
    let liquid_claim_settings_valid = config.liquid_claim_settings_valid();
    let bitcoin_backend_settings_valid = config.bitcoin_watcher.explicit_endpoints_valid()
        && config.bitcoin_watcher.finality_valid();
    if !direct_liquid_settings_valid {
        tracing::error!(
            event = "direct_liquid_config_invalid",
            "Liquid backend/finality configuration is invalid; direct Liquid admission is closed"
        );
    }
    if !liquid_claim_settings_valid {
        tracing::error!(
            event = "liquid_claim_config_invalid",
            "explicit Liquid claim configuration is invalid; new swap admission is closed"
        );
    }
    if !bitcoin_backend_settings_valid {
        tracing::error!(
            event = "bitcoin_backend_config_invalid",
            "Bitcoin backend/finality configuration is invalid; dependent admission is closed"
        );
    }

    // Swap claim clients own blocking Electrum sockets and are created per
    // operation. Retain the exact validated factory used by those operations
    // so admission never mistakes the direct-Liquid UTXO backend for claim
    // capability. A factory failure closes only new swap admission.
    let liquid_claim_client_factory =
        match claimer::LiquidClaimClientFactory::try_new(config.claim_liquid_electrum_urls()) {
            Ok(factory) => Some(Arc::new(factory)),
            Err(error) => {
                tracing::error!(
                    event = "liquid_claim_client_init_failed",
                    error = %error,
                    "Liquid claim client factory is unavailable; new swap admission is closed"
                );
                None
            }
        };

    // Chain recovery uses this same initialized evidence object for every
    // journal reconciliation. Invalid rail-specific configuration is not a
    // process-readiness failure: HTTP and existing non-chain paths stay up.
    let bitcoin_recovery_backend =
        match pay_service::chain_recovery::BitcoinRecoveryBackend::try_new(
            config.bitcoin_watcher.effective_endpoints(),
        ) {
            Ok(backend) => Some(Arc::new(backend)),
            Err(error) => {
                tracing::error!(
                    event = "bitcoin_recovery_client_init_failed",
                    error = %error,
                    "Bitcoin recovery evidence client is unavailable; new chain-swap admission is closed"
                );
                None
            }
        };

    // Construct the direct-Bitcoin watcher before taking the admission
    // snapshot. Its reporter still owns startup/liveness evidence, while this
    // retained object proves the actual HTTP watcher client initialized.
    let initialized_bitcoin_watcher = if config.bitcoin_watcher.enabled {
        match bitcoin_watcher::BitcoinWatcher::new(
            config.bitcoin_watcher.clone(),
            db::InvoiceAccountingTolerances::from(&config.invoice_accounting),
            pool.clone(),
        ) {
            Ok(watcher) => Some(watcher),
            Err(error) => {
                tracing::error!(
                    event = "bitcoin_watcher_client_init_failed",
                    error = %error,
                    "Bitcoin watcher client is unavailable; direct Bitcoin admission is closed"
                );
                None
            }
        }
    } else {
        None
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

    // Fingerprint of the swap-key seed, persisted with every new swap so a
    // rewound key sequence (e.g. an older DB backup restored over live data) is
    // detectable. Compute it once at startup and check for a rewind. An
    // unverifiable or rewound lineage closes only new swap admission while
    // HTTP and existing-obligation recovery remain available. The periodic
    // supervised check below updates the same fail-closed fact. See
    // derivation_guard and migrations 044/050.
    let swap_key_root_fingerprint = boltz
        .derivation_root_fingerprint()
        .map_err(|e| format!("swap key fingerprint derivation failed: {e}"))?;
    tracing::info!(
        fingerprint = %swap_key_root_fingerprint,
        key_epoch = config.boltz.key_epoch,
        derivation_scheme_version = db::DERIVATION_SCHEME_VERSION,
        "swap key derivation fingerprint computed"
    );
    let swap_key_lineage_safe = match derivation_guard::check_rollback(
        &pool,
        &swap_key_root_fingerprint,
        config.boltz.key_epoch,
        db::DERIVATION_SCHEME_VERSION,
    )
    .await
    {
        Ok(true) => {
            tracing::error!(
                event = "swap_key_sequence_rollback",
                fingerprint = %swap_key_root_fingerprint,
                "swap_key_seq would next issue an index that is already durably reserved \
                 or attached to a legacy swap — the sequence may have been rewound by a database \
                 restore. New swap admission is closed; restore the correct backup \
                 or advance swap_key_seq past the highest persisted index."
            );
            false
        }
        Ok(false) => {
            tracing::info!(
                event = "swap_key_sequence_ok",
                "swap key sequence is ahead of all durable allocations and legacy indices"
            );
            true
        }
        Err(e) => {
            tracing::error!(
                event = "swap_key_sequence_check_failed",
                error = %e,
                "swap-key lineage could not be verified; new swap admission is closed"
            );
            false
        }
    };
    let swap_key_root_fingerprint = Arc::new(swap_key_root_fingerprint);

    let admission = admission::MoneyAdmission::new(
        admission::FoundationFacts {
            workers_enabled: config.workers.enabled,
            schema_ready: schema_and_journal_ready,
            direct_liquid_backend_ready: direct_liquid_settings_valid && utxo_backend.is_some(),
            direct_bitcoin_watcher_ready: bitcoin_backend_settings_valid
                && initialized_bitcoin_watcher.is_some(),
            liquid_claim_client_ready: liquid_claim_settings_valid
                && liquid_claim_client_factory.is_some(),
            bitcoin_evidence_client_ready: bitcoin_backend_settings_valid
                && bitcoin_recovery_backend.is_some(),
            boltz_client_ready: boltz.client_ready(),
            swap_key_lineage_safe,
            recovery_journal_ready: schema_and_journal_ready,
            // #64 owns live fee observation and persistence. Until it lands,
            // new reverse and chain swaps deliberately remain fail-closed.
            fee_policy_ready: false,
            // #84 owns the signed, merchant-specific recovery commitment.
            recovery_commitment_ready: false,
        },
        admission::WorkerCadences::from_runtime(
            Duration::from_secs(config.reconciler.interval_secs),
            Duration::from_secs(config.reconciler.slow_recovery_interval_secs),
            Duration::from_secs(u64::from(
                config.rate_limit.chain_watcher_active_user_tick_secs,
            )),
            Duration::from_secs(config.bitcoin_watcher.active_tick_secs),
        ),
    );

    let state = AppState {
        db: pool.clone(),
        config: config.clone(),
        admission,
        boltz: boltz.clone(),
        ip_whitelist: whitelist.clone(),
        certification: certification_allowlist.clone(),
        rate_limiter: rate_limiter.clone(),
        utxo_backend,
        liquid_claim_client_factory,
        bitcoin_recovery_backend,
        pricer: pricer_client,
        pwa_shells,
        swap_key_root_fingerprint: swap_key_root_fingerprint.clone(),
    };

    let cancel = CancellationToken::new();
    {
        let pool = pool.clone();
        let fingerprint = swap_key_root_fingerprint.clone();
        let key_epoch = state.config.boltz.key_epoch;
        let mut lineage_reporter = state.admission.swap_key_lineage_reporter();
        let cancel_lineage = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            // The synchronous startup check above supplied the initial fact.
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = cancel_lineage.cancelled() => {
                        lineage_reporter.intentional_shutdown();
                        return;
                    },
                    _ = tick.tick() => {
                        match derivation_guard::check_rollback(
                            &pool,
                            fingerprint.as_str(),
                            key_epoch,
                            db::DERIVATION_SCHEME_VERSION,
                        ).await {
                            Ok(rollback_detected) => {
                                lineage_reporter.observed_safe(!rollback_detected);
                            }
                            Err(error) => {
                                tracing::error!(
                                    event = "swap_key_sequence_monitor_failed",
                                    error = %error,
                                    "swap-key lineage cannot be verified; closing new swap admission"
                                );
                                lineage_reporter.observed_safe(false);
                            }
                        }
                    }
                }
            }
        });
    }
    if config.workers.enabled {
        tracing::info!("background workers enabled");
        if config.features.payment_pages {
            og_image::spawn_reconciler(
                pool.clone(),
                config.donation.image_root_path.clone(),
                cancel.clone(),
            );
            tracing::info!("Payment Page OG image reconciler started");
        }
        let _claimer_task = claimer::spawn_background_claimer(
            pool.clone(),
            config.clone(),
            state.liquid_claim_client_factory.clone(),
            state.utxo_backend.clone(),
            cancel.clone(),
            state.admission.reporter(admission::Worker::ReverseClaimer),
            state.admission.reporter(admission::Worker::ChainClaimer),
        );

        // Reconciler: polls boltz_api.get_swap for every non-terminal swap
        // older than `min_age_secs` and patches our DB to match Boltz's
        // view. Closes the dropped-webhook gap (Boltz's webhook delivery
        // gives up after ~5 min) by querying state directly.
        let _reverse_reconciler_task = reconciler::spawn(
            pool.clone(),
            config.boltz.api_url.clone(),
            Arc::new(config.reconciler.clone()),
            cancel.clone(),
            state
                .admission
                .reporter(admission::Worker::ReverseReconciler),
        );
        tracing::info!(
            "reconciler started (interval={}s, min_age={}s, max_per_tick={})",
            config.reconciler.interval_secs,
            config.reconciler.min_age_secs,
            config.reconciler.max_per_tick,
        );

        // Chain-swap reconciler: same dropped-webhook recovery as above, but for
        // `chain_swap_records` (which the reverse reconciler does not touch).
        // Without this a chain swap stranded by a missed webhook never recovers.
        let _chain_reconciler_task = reconciler::spawn_chain(
            state.clone(),
            Arc::new(config.reconciler.clone()),
            cancel.clone(),
            state.admission.reporter(admission::Worker::ChainReconciler),
        );
        tracing::info!("chain reconciler started (shares reconciler config)");

        // Settlement-repair: re-records invoice payment events for reverse
        // (Lightning) swaps that reached `claimed` but whose invoice flip never
        // completed (crash / transient failure between the claimed commit and
        // the flip). Closes the merchant-paid-but-invoice-unpaid gap; the flip
        // is idempotent so this is a safe no-op when the event already exists.
        let _settlement_repair_task = reconciler::spawn_settlement_repair(
            state.clone(),
            Arc::new(config.reconciler.clone()),
            cancel.clone(),
            state
                .admission
                .reporter(admission::Worker::SettlementRepair),
        );
        tracing::info!("settlement repair started (shares reconciler config)");

        // Slow recovery: revives funded `claim_stuck` swaps back into the claim
        // sweep on a long capped backoff so a transient-outage-stranded output
        // isn't abandoned once the retry budget is spent (issue #63).
        let _slow_recovery_task = reconciler::spawn_slow_recovery(
            state.clone(),
            Arc::new(config.reconciler.clone()),
            cancel.clone(),
            state.admission.reporter(admission::Worker::SlowRecovery),
        );
        tracing::info!("slow recovery started (shares reconciler config)");

        // Periodic GC of rate-limit tables. Without this, sliding-window
        // queries get progressively slower as inactive rows accumulate.
        {
            let pool = pool.clone();
            let gc_cfg = gc::GcConfig {
                checkout_partial_terminal_grace_secs: config
                    .invoice_accounting
                    .checkout_partial_terminal_grace_secs,
                payment_grace_secs: config.invoice_accounting.payment_grace_secs,
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
            let watcher_cfg = chain_watcher::ChainWatcherConfig::from_rate_limit_config(
                &config.rate_limit,
                config.liquid_watcher.finality_confirmations,
            );
            let accounting_tolerances =
                db::InvoiceAccountingTolerances::from(&config.invoice_accounting);
            let liquid_reporter = state.admission.reporter(admission::Worker::LiquidWatcher);
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
                    liquid_reporter,
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
        if let Some(watcher) = initialized_bitcoin_watcher {
            let cancel_btc = cancel.clone();
            let bitcoin_reporter = state.admission.reporter(admission::Worker::BitcoinWatcher);
            tokio::spawn(async move {
                watcher.run(cancel_btc, bitcoin_reporter).await;
            });
        } else {
            tracing::info!("bitcoin watcher disabled or its client failed to initialize");
        }
    } else {
        tracing::warn!(
            "background workers disabled by config; HTTP routes are active but claims, \
             reconciliation, watchers, and GC will not run in this process"
        );
    }

    // Axum may continue polling in-flight handlers during graceful shutdown.
    // Close new-money admission synchronously before worker cancellation so a
    // handler that reaches its final mutation boundary after shutdown begins
    // cannot publish an obligation whose worker has already exited.
    let shutdown_admission = state.admission.clone();
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
        shutdown_admission.set_workers_enabled(false);
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
        .route(og_image::FALLBACK_LIVE_PATH, get(og_image::fallback_live))
        .route(
            og_image::FALLBACK_UNAVAILABLE_PATH,
            get(og_image::fallback_unavailable),
        )
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

    // NIP-05 is opt-in and gated by its own flag (default off) so the server
    // never publishes `/.well-known/nostr.json` unless explicitly enabled.
    // Requires registration (`lightning_address`) since it resolves nyms.
    // See ISS-S-01 / ADR-004.
    if features.lightning_address && features.nip05 {
        router = router.route("/.well-known/nostr.json", get(nostr::nostr_json));
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
            .route(
                "/:nym/pos/manifest.webmanifest",
                get(donation_render::manifest_pos),
            )
            // Public POS terminal shell for the nym's POS surface (kind='pos').
            .route("/:nym/pos", get(donation_render::render_pos))
            // Donation checkout now uses invoice sessions instead of the
            // removed donation callback/status endpoints.
            // Anonymous checkout invoice endpoints. The create route keeps a
            // tight body cap; status and offer routes are rate-limit gated.
            // The POS surface reuses the same keyless flow, kind-scoped to the
            // POS descriptor (idx 103) with no Lightning-Address fallback.
            .route(
                "/:nym/invoice",
                post(invoice::create_anonymous).layer(DefaultBodyLimit::max(1024)),
            )
            .route(
                "/:nym/pos/invoice",
                post(invoice::create_anonymous_pos).layer(DefaultBodyLimit::max(1024)),
            )
            .route("/:nym/i/:id", get(invoice::render_payment))
            // Alias surfaces served at `/a/<slug>`, decoupled from the nym.
            // The literal `/a` first segment out-prioritises the `/:nym/...`
            // param routes, and the two-segment shape can never be claimed by
            // the single-segment donation-page fallback. One invoice route
            // serves both the alias Payment Page and POS (kind resolved from
            // the row); status/offer polling stays on the id-only
            // `/api/v1/invoices/:id/...` routes.
            .route("/a/:slug", get(donation_render::render_alias))
            .route("/a/:slug/", get(donation_render::render_alias))
            .route(
                "/a/:slug/manifest.webmanifest",
                get(donation_render::manifest_alias),
            )
            .route(
                "/a/:slug/invoice",
                post(invoice::create_anonymous_alias).layer(DefaultBodyLimit::max(1024)),
            )
            .route("/a/:slug/i/:id", get(invoice::render_payment_alias));
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

    // Merchant-authenticated chain-swap recovery (#44). Schnorr-signed by the
    // invoice-owning nym; linked-only (only nym invoices ever create a chain
    // swap). Gated SOLELY behind its own default-off flag — it signs and
    // broadcasts real BTC and stays off until the staged broadcast test. Kept
    // out of the `features.invoices` block: chain swaps are born under
    // `payment_pages` (checkout), so tying the recover route to `invoices`
    // could leave swaps in `refund_due` with the route silently absent.
    if features.chain_swap_merchant_recovery {
        if !features.payment_pages {
            tracing::warn!(
                "chain_swap_merchant_recovery is ON but payment_pages is OFF — no chain swaps are created, so nothing will ever be recoverable"
            );
        }
        router = router.route(
            "/api/v1/:nym/invoices/:id/recover",
            post(invoice::recover_chain_swap).layer(DefaultBodyLimit::max(1024)),
        );
    }

    // Signed, npub-keyed detection of stuck (recoverable) chain swaps. Read-only
    // and ALWAYS-ON — deliberately NOT gated by `chain_swap_merchant_recovery`
    // (that flag guards the dangerous broadcast path only): merchants must be
    // able to SEE stranded funds before the recover action is enabled. The
    // response carries `recovery_enabled` so the server drives the "Recover now"
    // vs "Contact support" UI. Guarded by `invoices || payment_pages` for the
    // same reason as the recover route: chain swaps are born under checkout
    // (`payment_pages`), so a merchant could have a `refund_due` swap even on a
    // deployment with `invoices` off — the detection route must not be absent.
    if features.invoices || features.payment_pages {
        router = router.route(
            "/api/v1/invoices/recoverable",
            get(invoice::list_recoverable_signed),
        );
    }

    let router = if features.payment_pages {
        router.fallback(donation_render::render_or_404)
    } else {
        router.fallback(not_found)
    };

    router
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(TraceLayer::new_for_http())
        // Signature-auth API (no cookies/ambient credentials), so CORS is not
        // itself a security boundary here — but `permissive()` echoes any
        // attacker-requested header via `Access-Control-Allow-Headers: *`
        // (SEC-09). Keep origin/methods open for the public read+create API,
        // but bound request headers to what the JSON API actually uses.
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers([axum::http::header::CONTENT_TYPE]),
        )
        .layer(middleware::from_fn(pwa_assets_vary_accept_encoding))
        .with_state(state)
}

async fn pwa_assets_vary_accept_encoding(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let mut resp = next.run(req).await;
    if resp.status().is_success() && path.starts_with("/pwa-assets/") {
        resp.headers_mut()
            .append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    resp
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
