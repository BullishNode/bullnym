pub mod auth;
pub mod bitcoin_watcher;
pub mod boltz;
pub mod boltz_breaker;
pub mod certification;
pub mod chain_watcher;
pub mod chain_recovery;
pub mod claimer;
pub mod config;
pub mod db;
pub mod derivation_guard;
pub mod descriptor;
pub mod donation_page;
pub mod esplora;
pub mod donation_render;
pub mod error;
pub mod gc;
pub mod image_pipeline;
pub mod invoice;
pub mod ip_whitelist;
pub mod lnurl;
pub mod nostr;
pub mod og_image;
pub mod pricer;
pub mod qr;
pub mod rate_limit;
pub mod readiness;
pub mod reconciler;
pub mod registration;
pub mod reserved_nyms;
pub mod utxo;
pub mod validators;
pub mod version;

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<config::Config>,
    pub boltz: Arc<boltz::BoltzService>,
    pub ip_whitelist: Arc<ip_whitelist::IpWhitelist>,
    pub certification: Arc<certification::CertificationAllowlist>,
    pub rate_limiter: Arc<rate_limit::RateLimiter>,
    pub utxo_backend: Option<Arc<dyn utxo::UtxoBackend>>,
    pub pricer: Arc<pricer::PricerClient>,
    pub pwa_shells: Arc<donation_render::PwaShells>,
    /// Fingerprint of the swap-key master seed (see [`derivation_guard`] and
    /// migration 044). Persisted with each new swap so a rewound key sequence
    /// is detectable on the next startup.
    pub swap_key_root_fingerprint: Arc<String>,
}
