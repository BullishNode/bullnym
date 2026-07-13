pub mod admission;
pub mod auth;
pub mod bitcoin_watcher;
pub mod boltz;
pub mod boltz_breaker;
pub mod boltz_restore;
pub mod boltz_restore_fetch;
pub(crate) mod canonical_json;
pub mod certification;
pub mod chain_recovery;
pub mod chain_swap_action;
pub mod chain_watcher;
pub mod claimer;
pub mod config;
pub mod db;
pub mod derivation_guard;
pub mod descriptor;
pub mod donation_page;
pub mod donation_render;
pub mod error;
pub mod esplora;
pub mod gc;
pub mod image_pipeline;
pub mod invoice;
pub mod ip_whitelist;
pub mod lnurl;
pub mod nostr;
pub mod og_image;
pub mod pricer;
pub mod provider_limits;
pub mod provider_limits_runtime;
pub mod qr;
pub mod rate_limit;
pub mod readiness;
pub mod reconciler;
pub mod registration;
pub mod reserved_nyms;
pub mod swap_manifest;
pub mod swap_manifest_delivery;
pub mod swap_manifest_persistence;
pub mod swap_manifest_runtime;
pub mod swap_manifest_staging;
pub mod swap_manifest_store;
pub mod swap_manifest_witness;
pub mod utxo;
pub mod validators;
pub mod version;
pub(crate) mod watcher_schedule;

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<config::Config>,
    pub admission: admission::MoneyAdmission,
    pub boltz: Arc<boltz::BoltzService>,
    pub ip_whitelist: Arc<ip_whitelist::IpWhitelist>,
    pub certification: Arc<certification::CertificationAllowlist>,
    pub rate_limiter: Arc<rate_limit::RateLimiter>,
    pub utxo_backend: Option<Arc<dyn utxo::UtxoBackend>>,
    pub liquid_claim_client_factory: Option<Arc<claimer::LiquidClaimClientFactory>>,
    pub bitcoin_recovery_backend: Option<Arc<chain_recovery::BitcoinRecoveryBackend>>,
    pub pricer: Arc<pricer::PricerClient>,
    pub pwa_shells: Arc<donation_render::PwaShells>,
    /// Fingerprint of the swap-key master seed (see [`derivation_guard`] and
    /// migrations 044/050). Persisted in the allocation registry before each
    /// provider call so a rewound key sequence is detectable even for orphans.
    pub swap_key_root_fingerprint: Arc<String>,
}

impl AppState {
    /// Private #68 operations view. Public `/ready` deliberately remains the
    /// DB/schema readiness contract and does not serialize these details.
    pub fn operations_snapshot(&self) -> admission::OperationsSnapshot {
        self.admission
            .operations_snapshot(self.boltz.creation_circuit_snapshot())
    }
}
