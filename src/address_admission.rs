use std::str::FromStr;
use std::sync::Arc;

use crate::config::BitcoinWatcherConfig;
use crate::error::AppError;
use crate::utxo::{LiquidHistorySnapshotLimits, LiquidHistorySnapshotOutcome, UtxoBackend};

fn require_empty_liquid_history(outcome: LiquidHistorySnapshotOutcome) -> Result<(), AppError> {
    match outcome {
        LiquidHistorySnapshotOutcome::Complete(snapshot) if snapshot.entries.is_empty() => Ok(()),
        LiquidHistorySnapshotOutcome::Complete(_) | LiquidHistorySnapshotOutcome::Incomplete(_) => {
            Err(AppError::LiquidAddressAlreadyUsed)
        }
    }
}

#[async_trait::async_trait]
pub trait InvoiceAddressAdmission: Send + Sync {
    async fn assert_fresh(
        &self,
        bitcoin_address: Option<&str>,
        liquid_address: Option<&str>,
    ) -> Result<(), AppError>;
}

pub struct ChainInvoiceAddressAdmission {
    bitcoin: BitcoinWatcherConfig,
    liquid: Option<Arc<dyn UtxoBackend>>,
}

impl ChainInvoiceAddressAdmission {
    pub fn new(bitcoin: BitcoinWatcherConfig, liquid: Option<Arc<dyn UtxoBackend>>) -> Self {
        Self { bitcoin, liquid }
    }
}

#[async_trait::async_trait]
impl InvoiceAddressAdmission for ChainInvoiceAddressAdmission {
    async fn assert_fresh(
        &self,
        bitcoin_address: Option<&str>,
        liquid_address: Option<&str>,
    ) -> Result<(), AppError> {
        if let Some(address) = bitcoin_address {
            crate::bitcoin_watcher::assert_fresh_invoice_address(&self.bitcoin, address).await?;
        }
        if let Some(address) = liquid_address {
            let parsed = lwk_wollet::elements::Address::from_str(address)
                .map_err(|_| AppError::MoneyAdmissionUnavailable)?;
            let backend = self
                .liquid
                .as_ref()
                .ok_or(AppError::MoneyAdmissionUnavailable)?;
            require_empty_liquid_history(
                backend
                    .automatic_fallback_liquid_history_snapshot(
                        &parsed.script_pubkey(),
                        &[],
                        LiquidHistorySnapshotLimits {
                            max_history_entries: 256,
                            max_block_heights: 256,
                        },
                    )
                    .await
                    .map_err(|_| AppError::MoneyAdmissionUnavailable)?,
            )?;
        }
        Ok(())
    }
}

/// Deterministic adapter for API/integration tests. Production constructs the
/// chain-backed implementation above; this type is deliberately not selected
/// by configuration.
pub struct AllowFreshInvoiceAddresses;

#[async_trait::async_trait]
impl InvoiceAddressAdmission for AllowFreshInvoiceAddresses {
    async fn assert_fresh(
        &self,
        _bitcoin_address: Option<&str>,
        _liquid_address: Option<&str>,
    ) -> Result<(), AppError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::{LiquidHistoryEntry, LiquidHistorySnapshot, LiquidHistorySnapshotLimit};
    use std::collections::BTreeMap;

    fn snapshot(entries: Vec<LiquidHistoryEntry>) -> LiquidHistorySnapshotOutcome {
        LiquidHistorySnapshotOutcome::Complete(LiquidHistorySnapshot {
            authority: "test".into(),
            tip_height: 1,
            tip_hash: "00".repeat(32),
            entries,
            anchored_block_hashes: BTreeMap::new(),
        })
    }

    #[test]
    fn liquid_invoice_address_admission_accepts_only_complete_empty_history() {
        assert!(require_empty_liquid_history(snapshot(Vec::new())).is_ok());
        assert!(matches!(
            require_empty_liquid_history(snapshot(vec![LiquidHistoryEntry {
                txid: "11".repeat(32),
                height: 1,
                block_hash: Some("22".repeat(32)),
            }])),
            Err(AppError::LiquidAddressAlreadyUsed)
        ));
        assert!(matches!(
            require_empty_liquid_history(LiquidHistorySnapshotOutcome::Incomplete(
                LiquidHistorySnapshotLimit::HistoryEntries {
                    observed: 257,
                    limit: 256,
                }
            )),
            Err(AppError::LiquidAddressAlreadyUsed)
        ));
    }
}
