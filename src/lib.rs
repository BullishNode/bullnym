pub mod auth;
pub mod boltz;
pub mod chain_watcher;
pub mod claimer;
pub mod config;
pub mod db;
pub mod descriptor;
pub mod error;
pub mod ip_whitelist;
pub mod lnurl;
pub mod nostr;
pub mod rate_limit;
pub mod registration;
pub mod utxo;

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: Arc<config::Config>,
    pub boltz: Arc<boltz::BoltzService>,
    pub ip_whitelist: Arc<ip_whitelist::IpWhitelist>,
    pub rate_limiter: Arc<rate_limit::RateLimiter>,
    pub utxo_backend: Option<Arc<dyn utxo::UtxoBackend>>,
}
