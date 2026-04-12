pub mod auth;
pub mod boltz;
pub mod claimer;
pub mod config;
pub mod db;
pub mod descriptor;
pub mod error;
pub mod lnurl;
pub mod nostr;
pub mod registration;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: std::sync::Arc<config::Config>,
    pub boltz: std::sync::Arc<boltz::BoltzService>,
}
