use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, MatchedPath};
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
    admission, bitcoin_watcher, boltz, boltz_restore_fetch, bull_bitcoin_settlement, certification,
    chain_fallback, chain_lockup_witness_adapter, chain_watcher, claimer, config, db,
    derivation_guard, donation_page, donation_render, fee_runtime, fiat_settlement, gc,
    get_paid_transaction_history, invoice, ip_whitelist, lnurl, lnurl_comment_history, nostr,
    og_image, pricer, rate_limit, readiness, reconciler, recovery_address_registration,
    registration, startup_provider_reconciliation, swap_manifest_runtime,
    utxo::{self, UtxoBackend},
    version, wallet_backup, AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--build-info") {
        println!("{}", version::build_info_json()?);
        return Ok(());
    }

    dotenvy::from_path(".env").ok();

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
        "features: lightning_address={} invoices={} payment_pages={} nip05={} bull_bitcoin_fiat_settlement={} workers={}",
        config.features.lightning_address,
        config.features.invoices,
        config.features.payment_pages,
        config.features.nip05,
        config.features.bull_bitcoin_fiat_settlement,
        config.workers.enabled,
    );
    if config.features.payment_pages && !config.workers.enabled {
        tracing::warn!(
            "Payment Pages are enabled while background workers are disabled; \
             OG generation still runs on save, but legacy backfill, retries, and \
             host-local missing-file verification will not run"
        );
    }

    let recovery_manifest_runtime_v1 =
        swap_manifest_runtime::RecoveryManifestRuntimeV1::for_process_startup();

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
    let recovery_commitment_ready = match readiness::recovery_commitment_ready(&pool).await {
        Ok(true) => {
            tracing::info!(
                event = "recovery_commitment_foundation_ready",
                "private append-only recovery commitment binding verified"
            );
            true
        }
        Ok(false) => {
            tracing::error!(
                event = "recovery_commitment_foundation_unsafe",
                "recovery commitment schema, ACL, foreign key, or trigger verification failed; new chain admission remains closed"
            );
            false
        }
        Err(error) => {
            tracing::error!(
                event = "recovery_commitment_foundation_check_failed",
                error = %error,
                "recovery commitment foundation could not be verified; new chain admission remains closed"
            );
            false
        }
    };

    let fee_runtime = Arc::new(fee_runtime::FeeRuntime::from_config(
        &config.fee_policy,
        Arc::new(db::PgFeeRuntimePersistence::new(pool.clone())),
    )?);
    let fee_startup = fee_runtime.initialize().await;
    tracing::info!(
        event = "fee_runtime_initialized",
        bitcoin = ?fee_startup.refresh().bitcoin(),
        liquid = ?fee_startup.refresh().liquid(),
        bitcoin_persistence = ?fee_startup.bitcoin_persistence(),
        liquid_persistence = ?fee_startup.liquid_persistence(),
        ready = fee_startup.readiness().ready(),
        "runtime fee evidence initialized"
    );

    let swap_master_key =
        SwapMasterKey::from_mnemonic(&config.swap_mnemonic, None, Network::Mainnet)
            .map_err(|e| format!("invalid swap mnemonic: {e}"))?;

    // Compare the provider's validated xpub restore snapshot with both the
    // authenticated off-host witness and one coherent PostgreSQL snapshot
    // before moving the master key into the Boltz service. Failures close only
    // new Bitcoin chain-swap admission; HTTP and existing-obligation recovery
    // continue to start.
    let startup_chain_witness =
        chain_lockup_witness_adapter::BitcoinLockupWitnessAdapterV1::from_watcher_config(
            &config.bitcoin_watcher,
        )
        .ok()
        .map(Arc::new);
    let provider_recovery_reconciliation = match (
        recovery_manifest_runtime_v1.as_deref(),
        startup_chain_witness.as_ref(),
    ) {
        (Some(runtime), Some(chain_witness)) => {
            let fetcher = boltz_restore_fetch::BoltzRestoreFetcher::new(&config.boltz.api_url);
            match fetcher {
                Ok(fetcher) => {
                    match startup_provider_reconciliation::reconcile_startup_provider_state_v1(
                        &pool,
                        runtime,
                        &fetcher,
                        &swap_master_key,
                        chain_witness,
                    )
                    .await
                    {
                        Ok(fact) => {
                            let report = fact.report();
                            let exact_agreement = fact.exact_agreement();
                            let repaired_obligation_count = fact.repaired_obligation_count();
                            let reconstructed_chain_swap_count =
                                fact.reconstructed_chain_swap_count();
                            let reconstructed_delivery_count = fact.reconstructed_delivery_count();
                            let chain = fact.chain_witness();
                            if exact_agreement {
                                tracing::info!(
                                    event = "startup_provider_recovery_consistent",
                                    repaired_obligation_count,
                                    reconstructed_chain_swap_count,
                                    reconstructed_delivery_count,
                                    manifest_count = report.manifest_count,
                                    provider_record_count = report.boltz.validated_record_count,
                                    provider_chain_record_count = report.boltz.chain_record_count,
                                    provider_reverse_record_count =
                                        report.boltz.reverse_record_count,
                                    provider_local_high_water_relation =
                                        ?report.provider_local_high_water_relation,
                                    local_record_count = report.local.local_record_count,
                                    local_chain_inventory_count =
                                        report.chain_inventory.local_chain_record_count,
                                    current_v1_chain_record_count =
                                        report.chain_inventory.current_v1_record_count,
                                    complete_legacy_chain_record_count =
                                        report.chain_inventory.complete_legacy_record_count,
                                    local_lineage_count = report.local.local_lineage_count,
                                    local_lineage_equal_count =
                                        report.local.lineage_classifications.equal,
                                    local_lineage_ahead_count =
                                        report.local.lineage_classifications.local_ahead,
                                    local_lineage_behind_count =
                                        report.local.lineage_classifications.local_behind,
                                    local_lineage_missing_count =
                                        report.local.lineage_classifications.local_missing,
                                    manifest_lineage_missing_count =
                                        report.local.lineage_classifications.manifest_missing,
                                    chain_observation_count = chain.observation_count,
                                    chain_missing_manifest_count = chain.missing_manifest_count,
                                    chain_unconfirmed_manifest_count =
                                        chain.unconfirmed_manifest_count,
                                    chain_confirmed_manifest_count = chain.confirmed_manifest_count,
                                    chain_spent_manifest_count = chain.spent_manifest_count,
                                    chain_conflicting_manifest_count =
                                        chain.conflicting_manifest_count,
                                    chain_amount_mismatch_manifest_count =
                                        chain.amount_mismatch_manifest_count,
                                    "startup recovery sources agree exactly"
                                );
                            } else {
                                tracing::error!(
                                    event = "startup_provider_recovery_inconsistent",
                                    repaired_obligation_count,
                                    reconstructed_chain_swap_count,
                                    reconstructed_delivery_count,
                                    manifest_count = report.manifest_count,
                                    provider_record_count = report.boltz.validated_record_count,
                                    provider_chain_record_count = report.boltz.chain_record_count,
                                    provider_reverse_record_count =
                                        report.boltz.reverse_record_count,
                                    provider_only_chain_record_count =
                                        report.boltz.provider_only_chain_record_count,
                                    provider_local_high_water_relation =
                                        ?report.provider_local_high_water_relation,
                                    local_record_count = report.local.local_record_count,
                                    manifest_only_record_count =
                                        report.local.manifest_only_record_count,
                                    local_only_record_count = report.local.local_only_record_count,
                                    local_chain_inventory_count =
                                        report.chain_inventory.local_chain_record_count,
                                    current_v1_chain_record_count =
                                        report.chain_inventory.current_v1_record_count,
                                    complete_legacy_chain_record_count =
                                        report.chain_inventory.complete_legacy_record_count,
                                    local_lineage_count = report.local.local_lineage_count,
                                    local_lineage_equal_count =
                                        report.local.lineage_classifications.equal,
                                    local_lineage_ahead_count =
                                        report.local.lineage_classifications.local_ahead,
                                    local_lineage_behind_count =
                                        report.local.lineage_classifications.local_behind,
                                    local_lineage_missing_count =
                                        report.local.lineage_classifications.local_missing,
                                    manifest_lineage_missing_count =
                                        report.local.lineage_classifications.manifest_missing,
                                    chain_observation_count = chain.observation_count,
                                    chain_conflicting_manifest_count =
                                        chain.conflicting_manifest_count,
                                    chain_amount_mismatch_manifest_count =
                                        chain.amount_mismatch_manifest_count,
                                    chain_structural_conflicting_manifest_count =
                                        chain.structural_conflicting_manifest_count,
                                    "startup recovery sources differ; new Bitcoin chain-swap admission is closed"
                                );
                            }
                            Some(Ok(fact))
                        }
                        Err(error) => {
                            tracing::error!(
                                event = "startup_provider_recovery_unavailable",
                                error = %error,
                                "startup recovery evidence is unavailable or invalid; new Bitcoin chain-swap admission is closed"
                            );
                            Some(Err(error))
                        }
                    }
                }
                Err(_) => {
                    tracing::error!(
                        event = "startup_provider_recovery_configuration_invalid",
                        "startup recovery evidence configuration is invalid; new Bitcoin chain-swap admission is closed"
                    );
                    None
                }
            }
        }
        (Some(_), None) => {
            tracing::error!(
                event = "startup_chain_witness_configuration_invalid",
                "startup Bitcoin witness configuration is invalid; new Bitcoin chain-swap admission is closed"
            );
            None
        }
        (None, _) => {
            tracing::error!(
                event = "startup_provider_recovery_configuration_missing",
                "startup recovery evidence configuration is unavailable; new Bitcoin chain-swap admission is closed"
            );
            None
        }
    };

    // Boltz does not HMAC-sign webhook deliveries; every registered callback
    // therefore carries the required URL-path secret. Config validation rejects
    // an absent or empty secret in every runtime mode before startup reaches
    // this point.
    let webhook_url = format!(
        "https://{}/webhook/boltz/{}",
        config.domain, config.boltz_webhook_url_secret
    );
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
            "<redacted>"
        );
    } else {
        tracing::error!(
            event = "boltz_client_init_failed",
            "Boltz client URL is invalid; new swap admission is closed"
        );
    }
    match boltz_service.refresh_provider_limits().await {
        pay_service::provider_limits_runtime::ProviderLimitRefreshOutcome::Updated => {
            tracing::info!(event = "provider_limits_startup_updated");
        }
        pay_service::provider_limits_runtime::ProviderLimitRefreshOutcome::Invalid(error) => {
            tracing::error!(
                event = "provider_limits_startup_invalid",
                reason = %error,
                "Lightning Address provider-limit snapshot is invalid"
            );
        }
        pay_service::provider_limits_runtime::ProviderLimitRefreshOutcome::FetchFailed => {
            tracing::warn!(
                event = "provider_limits_startup_failed",
                "Lightning Address starts unavailable until a refresh succeeds"
            );
        }
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
        "pricer client configured (ttl={}s, max_freshness={}s, timeout={}ms)",
        config.pricer.cache_ttl_secs,
        config.pricer.max_freshness_secs,
        config.pricer.request_timeout_ms,
    );
    let initialized_bitcoin_watcher =
        initialized_bitcoin_watcher.map(|watcher| watcher.with_pricer(pricer_client.clone()));
    let pwa_shells = Arc::new(donation_render::PwaShells::load(&config.pwa.dist_dir));

    let listen_addr = config.listen.clone();
    let config = Arc::new(config);
    let bull_bitcoin = Arc::new(
        pay_service::bull_bitcoin::HttpBullBitcoinApi::new(&config.bull_bitcoin)
            .map_err(|error| format!("invalid Bull Bitcoin API client configuration: {error}"))?,
    );
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
            // Only the opaque reconciliation result below may open this
            // process-local fact. Missing or invalid configuration therefore
            // remains closed without inventing recovery evidence.
            provider_recovery_consistent: false,
            fee_policy_ready: fee_startup.readiness().ready(),
            recovery_commitment_ready,
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
    if let Some(result) = provider_recovery_reconciliation {
        admission.apply_provider_recovery_reconciliation_v1(result);
    }

    let state = AppState {
        db: pool.clone(),
        config: config.clone(),
        admission,
        boltz: boltz.clone(),
        bull_bitcoin,
        ip_whitelist: whitelist.clone(),
        certification: certification_allowlist.clone(),
        rate_limiter: rate_limiter.clone(),
        utxo_backend,
        liquid_claim_client_factory,
        bitcoin_recovery_backend,
        bitcoin_lockup_witness_adapter: startup_chain_witness,
        fee_runtime: fee_runtime.clone(),
        pricer: pricer_client,
        pwa_shells,
        recovery_manifest_runtime_v1,
        swap_key_root_fingerprint: swap_key_root_fingerprint.clone(),
    };

    let cancel = CancellationToken::new();
    let _fee_runtime_task = fee_runtime
        .clone()
        .spawn_background(state.admission.clone(), cancel.clone());
    let _provider_limits_refresh_task = boltz.spawn_provider_limits_refresh(cancel.clone());
    tracing::info!(
        event = "provider_limits_refresh_started",
        cadence_secs =
            pay_service::provider_limits_runtime::PROVIDER_LIMIT_REFRESH_CADENCE.as_secs(),
        maximum_age_secs =
            pay_service::provider_limits_runtime::PROVIDER_LIMIT_MAXIMUM_AGE.as_secs(),
        "provider-limit refresh started"
    );
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
    // Every HTTP process owns its in-memory rate-limit buckets, so every
    // process must sweep them. A separate worker instance can maintain shared
    // PostgreSQL state but cannot reclaim memory in a web-only process.
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
    // Signed backup gates and other HTTP controls persist cross-process rate
    // events even in web-only mode, so their retention loop cannot depend on
    // payment workers being enabled.
    {
        let rate_limit_gc_pool = pool.clone();
        let rate_limit_gc_cancel = cancel.clone();
        let rate_limit_gc_config = gc::GcConfig::default();
        let tick_secs = rate_limit_gc_config.tick_secs;
        let retention_secs = rate_limit_gc_config.retention_secs;
        tokio::spawn(async move {
            gc::run_rate_limit_gc(
                rate_limit_gc_pool,
                rate_limit_gc_cancel,
                tick_secs,
                retention_secs,
            )
            .await;
        });
        tracing::info!(tick_secs, retention_secs, "rate-limit GC started");
    }
    // Tombstones outlive the five-minute signed-request window, then become
    // disposable. Every HTTP process may run this bounded SKIP LOCKED sweep;
    // concurrent processes divide work without blocking request transactions.
    {
        let cleanup_pool = pool.clone();
        let cleanup_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = cleanup_cancel.cancelled() => return,
                    _ = tick.tick() => {
                        match db::cleanup_expired_wallet_backup_tombstones(
                            &cleanup_pool,
                            wallet_backup::TOMBSTONE_RETENTION_SECS,
                            500,
                        ).await {
                            Ok(removed) if removed > 0 => tracing::info!(
                                event = "wallet_backup_tombstones_cleaned",
                                removed,
                                "expired wallet backup tombstones removed"
                            ),
                            Ok(_) => {}
                            Err(error) => tracing::error!(
                                event = "wallet_backup_tombstone_cleanup_failed",
                                error_class = ?error.class(),
                                "wallet backup tombstone cleanup failed"
                            ),
                        }
                    }
                }
            }
        });
    }
    if config.workers.enabled {
        tracing::info!("background workers enabled");
        {
            // The rollout flag gates new fiat admission, not supervision of
            // already-exposed Bull Bitcoin destinations. Keep this worker
            // running whenever this process owns background work.
            let settlement_state = state.clone();
            let settlement_cancel = cancel.clone();
            tokio::spawn(async move {
                bull_bitcoin_settlement::run_reconciler(settlement_state, settlement_cancel).await;
            });
            tracing::info!(
                interval_secs = config.bull_bitcoin.reconcile_interval_secs,
                batch_size = config.bull_bitcoin.reconcile_batch_size,
                "Bull Bitcoin settlement reconciler started"
            );
        }
        if config.features.payment_pages {
            og_image::spawn_reconciler(
                pool.clone(),
                config.donation.image_root_path.clone(),
                cancel.clone(),
            );
            tracing::info!("Payment Page OG image reconciler started");
        }
        let _claimer_task = claimer::spawn_background_claimer(
            claimer::BackgroundClaimerDependencies::new(
                pool.clone(),
                config.clone(),
                state.liquid_claim_client_factory.clone(),
                state.utxo_backend.clone(),
                state.fee_runtime.clone(),
                state.clone(),
                cancel.clone(),
            ),
            claimer::BackgroundClaimerReporters::new(
                state.admission.reporter(admission::Worker::ReverseClaimer),
                state.admission.reporter(admission::Worker::ChainClaimer),
            ),
        );

        // Reconciler: polls boltz_api.get_swap for every non-terminal swap
        // older than `min_age_secs` and patches our DB to match Boltz's
        // view. Closes the dropped-webhook gap (Boltz's webhook delivery
        // gives up after ~5 min) by querying state directly.
        let _reverse_reconciler_task = reconciler::spawn(
            pool.clone(),
            state.boltz.clone(),
            state.pricer.clone(),
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

        // Automatic Bitcoin fallback is a distinct existing-obligation
        // executor. It consumes only #82-authorized due markers and remains
        // active when admission closes; provider polling never decides or
        // broadcasts from this task.
        let _automatic_fallback_task = chain_fallback::spawn_automatic_fallback_executor(
            state.clone(),
            Arc::new(config.reconciler.clone()),
            cancel.clone(),
            state
                .admission
                .reporter(admission::Worker::AutomaticFallback),
        );
        tracing::info!("automatic Bitcoin fallback executor started");

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

        // Payment-state cleanup remains worker-owned because it changes
        // invoice and reservation lifecycle state.
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
            tracing::info!("operational payment-state GC started");
        }

        if let Some(backend) = state.utxo_backend.clone() {
            let pool = state.db.clone();
            let rl = rate_limiter.clone();
            let pricer = state.pricer.clone();
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
                    pricer,
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
            "/api/v1/get-paid/transactions",
            get(get_paid_transaction_history::list_signed),
        )
        .route(
            "/api/v1/lnurl/comments",
            get(lnurl_comment_history::list_signed),
        )
        .route(
            "/api/v1/recovery-address",
            get(recovery_address_registration::lookup)
                .put(recovery_address_registration::register)
                .layer(DefaultBodyLimit::max(
                    recovery_address_registration::RECOVERY_ADDRESS_REGISTRATION_BODY_LIMIT_BYTES,
                )),
        )
        .route(
            "/api/v1/supported-currencies",
            get(pricer::supported_currencies),
        )
        .route(
            "/api/v1/fiat-settlement/options",
            get(fiat_settlement::options),
        )
        .route(
            "/api/v1/fiat-settlement",
            get(fiat_settlement::configuration),
        )
        .route(
            "/api/v1/fiat-settlements",
            get(fiat_settlement::settlements),
        )
        .route(
            "/api/v1/fiat-settlement/:product",
            put(fiat_settlement::set)
                .delete(fiat_settlement::delete_product)
                .layer(DefaultBodyLimit::max(fiat_settlement::BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/v1/bull-bitcoin-credential",
            axum::routing::delete(fiat_settlement::delete_credential)
                .layer(DefaultBodyLimit::max(fiat_settlement::BODY_LIMIT_BYTES)),
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
        .route("/webhook/boltz/:secret", post(claimer::webhook_with_secret))
        .route("/health", get(health))
        .route("/ready", get(readiness::ready))
        .route("/version", get(version::version))
        .route("/certification/preflight", get(certification::preflight));

    if features.lightning_address {
        router = router
            .route("/.well-known/lnurlp/:nym", get(lnurl::metadata))
            .route(
                "/lnurlp/callback/:nym/:comment_intent",
                get(lnurl::callback_with_comment_intent),
            )
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
            // Owner-level aliases select Page at `/a/<slug>` and POS at
            // `/a/<slug>/pos`, independently of Lightning Address status.
            // The literal `/a` first segment out-prioritises the `/:nym/...`
            // param routes and cannot fall into the donation-page fallback.
            .route("/a/:slug", get(donation_render::render_alias))
            .route("/a/:slug/", get(donation_render::render_alias))
            .route("/a/:slug/pos", get(donation_render::render_alias_pos))
            .route("/a/:slug/pos/", get(donation_render::render_alias_pos))
            .route(
                "/a/:slug/manifest.webmanifest",
                get(donation_render::manifest_alias),
            )
            .route(
                "/a/:slug/pos/manifest.webmanifest",
                get(donation_render::manifest_alias_pos),
            )
            .route(
                "/a/:slug/invoice",
                post(invoice::create_anonymous_alias).layer(DefaultBodyLimit::max(1024)),
            )
            .route(
                "/a/:slug/pos/invoice",
                post(invoice::create_anonymous_alias_pos).layer(DefaultBodyLimit::max(1024)),
            )
            .route("/a/:slug/i/:id", get(invoice::render_payment_alias))
            .route("/a/:slug/pos/i/:id", get(invoice::render_payment_alias));
    }

    if invoice_sessions_enabled {
        router = router
            .route("/api/v1/invoices/:id/status", get(invoice::status))
            .route(
                "/api/v1/invoices/:id/lightning",
                post(invoice::fetch_lightning_offer),
            )
            .route(
                "/api/v1/invoices/:id/quote",
                post(invoice::payer_demand_quote).layer(DefaultBodyLimit::max(1024)),
            );
    }

    if features.invoices {
        // Schnorr-signed recipient invoice endpoints, linked + unlinked.
        // Body cap 16 KiB on signed POST to accommodate the fixed 5.5 KiB
        // base64url private-presentation envelope while retaining a strict
        // upper bound. DELETE carries only npub+ts+sig.
        // List uses GET + Query at the npub-keyed root.
        router = router
            .route(
                "/api/v1/:nym/invoices",
                post(invoice::create_signed_linked).layer(DefaultBodyLimit::max(16 * 1024)),
            )
            .route(
                "/api/v1/invoices",
                post(invoice::create_signed_unlinked).layer(DefaultBodyLimit::max(16 * 1024)),
            )
            .route(
                "/api/v1/:nym/invoices/:id",
                axum::routing::delete(invoice::cancel_linked).layer(DefaultBodyLimit::max(1024)),
            )
            .route(
                "/api/v1/invoices/:id",
                axum::routing::delete(invoice::cancel_unlinked).layer(DefaultBodyLimit::max(1024)),
            )
            .route(
                "/api/v1/invoices/:id/presentation",
                get(invoice::private_presentation),
            )
            .route("/api/v1/invoices", get(invoice::list_signed))
            // Public unlinked render path. Privacy headers + indexing posture
            // are applied via `invoice::html_response`; the parent fallback's
            // donation_render path is bypassed via explicit registration.
            .route("/invoice/:id", get(invoice::render_unlinked_payment));
    }

    // Signed, npub-keyed read-only status for chain swaps in the recovery
    // lifecycle. Recovery execution is internal and automatic: this route
    // never accepts a destination or triggers a broadcast. Guarded by
    // `invoices || payment_pages` because chain swaps are born under checkout
    // (`payment_pages`), so status must remain available when `invoices` is off.
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

    let standard_router = router.layer(RequestBodyLimitLayer::new(64 * 1024));

    standard_router
        // Backup stores need a 3 MiB JSON envelope for a maximum 2 MiB
        // decoded object. Keeping this as a separately layered router leaves
        // the established 64 KiB ceiling intact for every other endpoint.
        .merge(wallet_backup::router())
        // Keep private invoice and invoice-API responses out of shared/browser
        // caches, search indexes, and outbound Referer headers. This applies to
        // success and error responses at the route boundary.
        .layer(middleware::from_fn(private_invoice_response_headers))
        // LNURL payer comments and proofs arrive in GET queries by protocol.
        // Record only Axum's static route template: never the raw URI, query,
        // nym, invoice id, comment-intent token, or webhook secret.
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                tracing::debug_span!(
                    "http_request",
                    method = %request.method(),
                    route = request_route_template(request)
                )
            }),
        )
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
    let cache_control = if matches!(path.as_str(), "/invoice-qr.js" | "/private-invoice.js") {
        // These stable module names are imported by the server-rendered
        // private invoice page. Always revalidate them; dependencies are
        // content-hashed.
        "public, max-age=0, must-revalidate"
    } else if path.starts_with("/assets/") {
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

fn request_route_template(request: &Request<Body>) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("<unmatched>")
}

fn is_private_invoice_route(route: &str) -> bool {
    route == "/api/v1/invoices"
        || route.starts_with("/api/v1/invoices/")
        || route == "/api/v1/:nym/invoices"
        || route.starts_with("/api/v1/:nym/invoices/")
        || matches!(
            route,
            "/:nym/invoice"
                | "/:nym/pos/invoice"
                | "/:nym/i/:id"
                | "/a/:slug/invoice"
                | "/a/:slug/pos/invoice"
                | "/a/:slug/i/:id"
                | "/a/:slug/pos/i/:id"
                | "/invoice/:id"
        )
}

fn apply_private_response_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
}

async fn private_invoice_response_headers(req: Request<Body>, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|route| route.as_str().to_owned());
    let is_private = route
        .as_deref()
        .is_some_and(is_private_invoice_route);
    let mut response = next.run(req).await;
    if is_private {
        apply_private_response_headers(&mut response);
    }
    if route
        .as_deref()
        .is_some_and(|route| route.starts_with("/api/v1/fiat-settlement"))
    {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store, max-age=0"),
        );
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        response.headers_mut().insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
    }
    response
}

async fn health() -> &'static str {
    "ok"
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn unmatched_trace_route_never_falls_back_to_the_raw_uri() {
        let request = Request::builder()
            .uri("/private/invoice-id?comment=do-not-log")
            .body(Body::empty())
            .unwrap();

        assert_eq!(request_route_template(&request), "<unmatched>");
    }

    #[test]
    fn private_invoice_route_set_excludes_public_pages() {
        assert!(is_private_invoice_route("/api/v1/invoices/:id/status"));
        assert!(is_private_invoice_route(
            "/api/v1/invoices/:id/presentation"
        ));
        assert!(is_private_invoice_route("/:nym/i/:id"));
        assert!(is_private_invoice_route("/a/:slug/pos/invoice"));
        assert!(is_private_invoice_route("/invoice/:id"));

        assert!(!is_private_invoice_route("/:nym"));
        assert!(!is_private_invoice_route("/a/:slug"));
        assert!(!is_private_invoice_route("/.well-known/lnurlp/:nym"));
    }

    #[test]
    fn private_response_headers_forbid_storage_and_referrers() {
        let mut response = StatusCode::OK.into_response();

        apply_private_response_headers(&mut response);

        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()["x-robots-tag"], "noindex, nofollow");
    }

    #[tokio::test]
    async fn private_header_middleware_uses_the_matched_route_template() {
        let app = Router::new()
            .route(
                "/api/v1/invoices/:id/status",
                get(|| async { StatusCode::OK }),
            )
            .route("/public/:id", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(private_invoice_response_headers));

        let private_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/invoices/private-id/status?proof=do-not-cache")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            private_response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            private_response.headers()[header::REFERRER_POLICY],
            "no-referrer"
        );

        let public_response = app
            .oneshot(
                Request::builder()
                    .uri("/public/page-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!public_response
            .headers()
            .contains_key(header::CACHE_CONTROL));
        assert!(!public_response
            .headers()
            .contains_key(header::REFERRER_POLICY));
    }
}
