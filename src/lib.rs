pub mod auth;
pub mod bitcoin_watcher;
pub mod boltz;
pub mod chain_watcher;
pub mod claimer;
pub mod config;
pub mod db;
pub mod descriptor;
pub mod donation_callback;
pub mod donation_page;
pub mod donation_render;
pub mod error;
pub mod gc;
pub mod image_pipeline;
pub mod invoice;
pub mod ip_whitelist;
pub mod lnurl;
pub mod nostr;
pub mod pricer;
pub mod qr;
pub mod rate_limit;
pub mod reconciler;
pub mod registration;
pub mod reserved_nyms;
pub mod utxo;
pub mod validators;

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<config::Config>,
    pub boltz: Arc<boltz::BoltzService>,
    pub ip_whitelist: Arc<ip_whitelist::IpWhitelist>,
    pub rate_limiter: Arc<rate_limit::RateLimiter>,
    pub utxo_backend: Option<Arc<dyn utxo::UtxoBackend>>,
    pub pricer: Arc<pricer::PricerClient>,
}
