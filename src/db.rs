mod chain_swap_attempts;
mod chain_swaps;
mod direct_payments;
mod donation_pages;
mod invoices;
mod local_chain_swap_recovery_snapshot;
mod manifest_deliveries;
mod manifest_staging_evidence;
mod rate_limits;
mod reservations;
mod swap_lineage;
mod swaps;
mod users;
mod watcher;

pub use chain_swap_attempts::*;
pub use chain_swaps::*;
pub use direct_payments::*;
pub use donation_pages::*;
pub use invoices::*;
pub use local_chain_swap_recovery_snapshot::*;
pub use manifest_deliveries::*;
pub use manifest_staging_evidence::*;
pub use rate_limits::*;
pub use reservations::*;
pub use swap_lineage::*;
pub use swaps::*;
pub use users::*;
pub use watcher::*;

/// Shared advisory-lock namespace for exact invoice presentation value versus
/// Lightning offer creation. Direct reducers take the blocking form; offer
/// handlers use the try-lock form and retry rather than serving stale value.
pub fn invoice_lightning_lock_key(invoice_id: uuid::Uuid) -> String {
    format!("invoice-lightning:{invoice_id}")
}

#[cfg(test)]
mod tests;
