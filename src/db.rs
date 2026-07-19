mod bitcoin_recovery_fee_authority;
mod chain_swap_attempts;
mod chain_swap_cooperative_signing;
mod chain_swap_renegotiations;
mod chain_swaps;
mod direct_payments;
mod donation_pages;
mod fee_observations;
mod fee_runtime_persistence;
mod fiat_settlement;
mod get_paid_transactions;
mod invoices;
mod liquid_claim_fee_authority;
mod lnurl_comments;
mod local_chain_swap_recovery_snapshot;
mod manifest_deliveries;
mod manifest_staging_evidence;
mod merchant_settlements;
mod public_names;
mod quote_provider_attempts;
mod rate_limits;
mod recovery_address_commitments;
mod reservations;
mod swap_lineage;
mod swaps;
mod users;
mod wallet_backups;
mod watcher;

pub use bitcoin_recovery_fee_authority::*;
pub use chain_swap_attempts::*;
pub use chain_swap_cooperative_signing::*;
pub use chain_swap_renegotiations::*;
pub use chain_swaps::*;
pub use direct_payments::*;
pub use donation_pages::*;
pub use fee_observations::*;
pub use fee_runtime_persistence::*;
pub use fiat_settlement::*;
pub use get_paid_transactions::*;
pub use invoices::*;
pub use liquid_claim_fee_authority::*;
pub use lnurl_comments::*;
pub use local_chain_swap_recovery_snapshot::*;
pub use manifest_deliveries::*;
pub use manifest_staging_evidence::*;
pub use merchant_settlements::*;
pub use public_names::*;
pub use quote_provider_attempts::*;
pub use rate_limits::*;
pub use recovery_address_commitments::*;
pub use reservations::*;
pub use swap_lineage::*;
pub use swaps::*;
pub use users::*;
pub use wallet_backups::*;
pub use watcher::*;

/// Shared advisory-lock namespace for exact invoice presentation value versus
/// Lightning offer creation. Direct reducers take the blocking form; offer
/// handlers use the try-lock form and retry rather than serving stale value.
pub fn invoice_lightning_lock_key(invoice_id: uuid::Uuid) -> String {
    format!("invoice-lightning:{invoice_id}")
}

#[cfg(test)]
mod tests;
