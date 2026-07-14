//! Read-only Bitcoin-mainnet evidence adapter for chain-lockup audits.
//!
//! Each endpoint attempt is an isolated authority snapshot. A partial result is
//! discarded on any timeout, malformed response, pagination bound, chain-view
//! change, or validation failure; failover always restarts from the tip. An
//! empty observation set therefore means that one authority completed every
//! bounded address history, never that a backend failed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Address, Network, ScriptBuf, Transaction};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use uuid::Uuid;

use crate::chain_lockup_witness_audit::{
    audit_manifest_set_against_chain_lockup_witness_v1, ChainLockupInclusionV1, ChainLockupSpendV1,
    ChainLockupWitnessChainV1, PrevalidatedChainLockupObservationV1,
    MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1,
    MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_V1,
};
use crate::config::BitcoinWatcherConfig;
use crate::swap_manifest::{audit_append_only_manifest_set_v1, SwapManifestV1};

/// Operational cap below the pure audit's protocol cap. A recovery invocation
/// above this size must be split before issuing public-chain requests.
pub const MAX_BITCOIN_LOCKUP_WITNESS_MANIFESTS_V1: usize = 256;
/// Canonical Esplora confirmed-history page size.
pub const BITCOIN_LOCKUP_WITNESS_PAGE_SIZE_V1: usize = 25;
/// Bull's first address page may contain fifty confirmed transactions plus a
/// bounded mempool prefix; continuation pages remain canonical Esplora pages.
pub const MAX_BITCOIN_LOCKUP_WITNESS_FIRST_PAGE_TXS_V1: usize = 64;
/// Initial page plus at most fifteen cursor pages. A full final page is an
/// incomplete prefix and fails closed.
pub const MAX_BITCOIN_LOCKUP_WITNESS_PAGES_V1: usize = 16;
/// Maximum unique address-history transactions for one manifest.
pub const MAX_BITCOIN_LOCKUP_WITNESS_TXS_PER_MANIFEST_V1: usize =
    MAX_BITCOIN_LOCKUP_WITNESS_FIRST_PAGE_TXS_V1
        + (MAX_BITCOIN_LOCKUP_WITNESS_PAGES_V1 - 1) * BITCOIN_LOCKUP_WITNESS_PAGE_SIZE_V1;
/// Maximum configured failover authorities.
pub const MAX_BITCOIN_LOCKUP_WITNESS_ENDPOINTS_V1: usize = 8;

const EXTENDED_FIRST_CONFIRMED_PAGE_SIZE: usize = 50;
const MAX_ENDPOINT_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RAW_TRANSACTION_BYTES: usize = 4_000_000;
const MAX_TEXT_RESPONSE_BYTES: usize = 1024;
const MAX_ENDPOINT_REQUESTS: usize = 20_000;
const MAX_ENDPOINT_BYTES_U64: u64 = MAX_ENDPOINT_BYTES as u64;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BITCOIN_MONEY_SAT: u64 = 2_100_000_000_000_000;
const HASH_HEX_CHARS: usize = 64;
const REDACTED: &str = "<redacted>";

/// A complete, authority-scoped input for
/// `audit_manifest_set_against_chain_lockup_witness_v1`.
#[derive(Clone, PartialEq, Eq)]
pub struct BitcoinMainnetLockupWitnessSnapshotV1 {
    authority: String,
    pub tip_height: u32,
    pub tip_hash: String,
    pub observations: Vec<PrevalidatedChainLockupObservationV1>,
}

impl BitcoinMainnetLockupWitnessSnapshotV1 {
    /// Exact authority selected after failover. Callers may attach it to
    /// restricted operational telemetry; `Debug` deliberately redacts it.
    pub fn authority(&self) -> &str {
        &self.authority
    }
}

impl fmt::Debug for BitcoinMainnetLockupWitnessSnapshotV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinMainnetLockupWitnessSnapshotV1")
            .field("authority", &REDACTED)
            .field("tip_height", &self.tip_height)
            .field("tip_hash", &REDACTED)
            .field("observation_count", &self.observations.len())
            .finish()
    }
}

/// Fixed, source-free loader failures. No endpoint, address, script, txid,
/// block hash, amount, response body, or nested transport error is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinLockupWitnessAdapterError {
    InvalidConfiguration,
    TooManyManifestRecords,
    InvalidManifestSet,
    InvalidManifestTarget,
    NoCompleteAuthority,
}

impl fmt::Display for BitcoinLockupWitnessAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "Bitcoin lockup witness configuration is invalid",
            Self::TooManyManifestRecords => "Bitcoin lockup witness exceeds its manifest limit",
            Self::InvalidManifestSet => "Bitcoin lockup witness rejected the manifest set",
            Self::InvalidManifestTarget => "Bitcoin lockup witness rejected a manifest target",
            Self::NoCompleteAuthority => "Bitcoin lockup witness found no complete valid authority",
        })
    }
}

impl std::error::Error for BitcoinLockupWitnessAdapterError {}

/// Reusable, read-only Esplora adapter. Construction validates and normalizes
/// the immutable endpoint list and builds one bounded HTTP client.
pub struct BitcoinLockupWitnessAdapterV1 {
    endpoints: Vec<String>,
    client: reqwest::Client,
}

impl fmt::Debug for BitcoinLockupWitnessAdapterV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinLockupWitnessAdapterV1")
            .field("endpoint_count", &self.endpoints.len())
            .field("endpoints", &REDACTED)
            .finish_non_exhaustive()
    }
}

impl BitcoinLockupWitnessAdapterV1 {
    /// Use the watcher's validated ordering: explicit primary, explicit
    /// failovers, then built-in Bitcoin-mainnet Esplora authorities.
    pub fn from_watcher_config(
        config: &BitcoinWatcherConfig,
    ) -> Result<Self, BitcoinLockupWitnessAdapterError> {
        Self::try_new(
            config.effective_endpoints(),
            Duration::from_millis(config.request_timeout_ms),
        )
    }

    pub fn try_new(
        endpoints: Vec<String>,
        request_timeout: Duration,
    ) -> Result<Self, BitcoinLockupWitnessAdapterError> {
        if endpoints.is_empty()
            || endpoints.len() > MAX_BITCOIN_LOCKUP_WITNESS_ENDPOINTS_V1
            || request_timeout.is_zero()
            || request_timeout > MAX_REQUEST_TIMEOUT
        {
            return Err(BitcoinLockupWitnessAdapterError::InvalidConfiguration);
        }

        let mut normalized = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            if endpoint.len() > 2_048 || !crate::config::valid_http_endpoint(&endpoint) {
                return Err(BitcoinLockupWitnessAdapterError::InvalidConfiguration);
            }
            let endpoint = endpoint.trim_end_matches('/').to_owned();
            if endpoint.is_empty() {
                return Err(BitcoinLockupWitnessAdapterError::InvalidConfiguration);
            }
            if !normalized.contains(&endpoint) {
                normalized.push(endpoint);
            }
        }
        if normalized.is_empty() {
            return Err(BitcoinLockupWitnessAdapterError::InvalidConfiguration);
        }

        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidConfiguration)?;
        Ok(Self {
            endpoints: normalized,
            client,
        })
    }

    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Whether this snapshot came from the configured primary authority rather
    /// than a public failover. Only the primary carries the process contract
    /// required to prove an empty history by itself.
    pub fn is_primary_authority(&self, snapshot: &BitcoinMainnetLockupWitnessSnapshotV1) -> bool {
        self.endpoints
            .first()
            .is_some_and(|primary| primary == snapshot.authority())
    }

    /// Load a complete audit input. Every failed endpoint's partial vectors and
    /// caches are dropped before the next endpoint begins.
    pub async fn load_snapshot(
        &self,
        manifests: &[SwapManifestV1],
    ) -> Result<BitcoinMainnetLockupWitnessSnapshotV1, BitcoinLockupWitnessAdapterError> {
        let targets = preflight_manifests(manifests)?;
        for endpoint in &self.endpoints {
            let mut authority = AuthorityScan::new(self, endpoint);
            if let Ok(snapshot) = authority.scan(manifests, &targets).await {
                return Ok(snapshot);
            }
        }
        Err(BitcoinLockupWitnessAdapterError::NoCompleteAuthority)
    }

    /// Load one complete address history for an already-persisted chain swap.
    ///
    /// The caller supplies the immutable manifest/swap association from the
    /// delivered-manifest ledger. This avoids rescanning the full witness on
    /// every reconciler tick while retaining the exact same bounded raw-byte,
    /// inclusion, outspend, and stable-tip validation as startup recovery.
    pub async fn load_chain_swap_snapshot(
        &self,
        manifest_id: Uuid,
        chain_swap_id: Uuid,
        lockup_address: &str,
    ) -> Result<BitcoinMainnetLockupWitnessSnapshotV1, BitcoinLockupWitnessAdapterError> {
        if manifest_id.is_nil() || chain_swap_id.is_nil() {
            return Err(BitcoinLockupWitnessAdapterError::InvalidManifestTarget);
        }
        let canonical = crate::validators::canonical_btc_mainnet_address(lockup_address)
            .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidManifestTarget)?;
        if canonical != lockup_address {
            return Err(BitcoinLockupWitnessAdapterError::InvalidManifestTarget);
        }
        let address = Address::from_str(&canonical)
            .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidManifestTarget)?
            .require_network(Network::Bitcoin)
            .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidManifestTarget)?;
        let targets = [ManifestTarget {
            manifest_id,
            chain_swap_id,
            address: canonical,
            script_pubkey: address.script_pubkey(),
        }];
        for endpoint in &self.endpoints {
            let mut authority = AuthorityScan::new(self, endpoint);
            if let Ok(snapshot) = authority.scan_targets(&targets).await {
                return Ok(snapshot);
            }
        }
        Err(BitcoinLockupWitnessAdapterError::NoCompleteAuthority)
    }
}

#[derive(Clone)]
struct ManifestTarget {
    manifest_id: uuid::Uuid,
    chain_swap_id: uuid::Uuid,
    address: String,
    script_pubkey: ScriptBuf,
}

fn preflight_manifests(
    manifests: &[SwapManifestV1],
) -> Result<Vec<ManifestTarget>, BitcoinLockupWitnessAdapterError> {
    if manifests.len() > MAX_BITCOIN_LOCKUP_WITNESS_MANIFESTS_V1 {
        return Err(BitcoinLockupWitnessAdapterError::TooManyManifestRecords);
    }
    audit_append_only_manifest_set_v1(manifests)
        .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidManifestSet)?;

    let mut targets = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        if manifest.creation.btc_network != "bitcoin" {
            return Err(BitcoinLockupWitnessAdapterError::InvalidManifestTarget);
        }
        let canonical =
            crate::validators::canonical_btc_mainnet_address(&manifest.creation.lockup_address)
                .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidManifestTarget)?;
        if canonical != manifest.creation.lockup_address {
            return Err(BitcoinLockupWitnessAdapterError::InvalidManifestTarget);
        }
        let address = Address::from_str(&canonical)
            .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidManifestTarget)?
            .require_network(Network::Bitcoin)
            .map_err(|_| BitcoinLockupWitnessAdapterError::InvalidManifestTarget)?;
        u64::try_from(manifest.creation.user_lock_amount_sat)
            .ok()
            .filter(|amount| *amount > 0 && *amount <= MAX_BITCOIN_MONEY_SAT)
            .ok_or(BitcoinLockupWitnessAdapterError::InvalidManifestTarget)?;
        targets.push(ManifestTarget {
            manifest_id: manifest.restore_identity.manifest_id,
            chain_swap_id: manifest.restore_identity.chain_swap_id,
            address: canonical,
            script_pubkey: address.script_pubkey(),
        });
    }
    Ok(targets)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointError {
    RequestBound,
    ResponseBound,
    HistoryBound,
    Backend,
    InvalidEvidence,
    ChangedSnapshot,
}

#[derive(Default)]
struct RequestBudget {
    requests: usize,
    bytes: usize,
}

impl RequestBudget {
    fn begin_request(&mut self) -> Result<(), EndpointError> {
        self.requests = self
            .requests
            .checked_add(1)
            .ok_or(EndpointError::RequestBound)?;
        if self.requests > MAX_ENDPOINT_REQUESTS {
            return Err(EndpointError::RequestBound);
        }
        Ok(())
    }

    fn add_bytes(&mut self, count: usize) -> Result<(), EndpointError> {
        self.bytes = self
            .bytes
            .checked_add(count)
            .ok_or(EndpointError::ResponseBound)?;
        if self.bytes > MAX_ENDPOINT_BYTES {
            return Err(EndpointError::ResponseBound);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EsploraTxStatus {
    confirmed: bool,
    block_height: Option<u32>,
    block_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct AddressHistoryTransaction {
    txid: String,
    status: EsploraTxStatus,
}

#[derive(Debug, Deserialize)]
struct EsploraOutspend {
    spent: bool,
    txid: Option<String>,
    vin: Option<u32>,
    status: Option<EsploraTxStatus>,
}

#[derive(Clone, PartialEq, Eq)]
struct TipAnchor {
    height: u32,
    hash: String,
}

struct AuthorityScan<'a> {
    adapter: &'a BitcoinLockupWitnessAdapterV1,
    endpoint: &'a str,
    budget: RequestBudget,
    canonical_blocks: BTreeMap<u32, String>,
    raw_transactions: BTreeMap<String, Transaction>,
    transaction_inclusions: BTreeMap<String, ChainLockupInclusionV1>,
}

impl<'a> AuthorityScan<'a> {
    fn new(adapter: &'a BitcoinLockupWitnessAdapterV1, endpoint: &'a str) -> Self {
        Self {
            adapter,
            endpoint,
            budget: RequestBudget::default(),
            canonical_blocks: BTreeMap::new(),
            raw_transactions: BTreeMap::new(),
            transaction_inclusions: BTreeMap::new(),
        }
    }

    async fn scan(
        &mut self,
        manifests: &[SwapManifestV1],
        targets: &[ManifestTarget],
    ) -> Result<BitcoinMainnetLockupWitnessSnapshotV1, EndpointError> {
        let snapshot = self.scan_targets(targets).await?;
        audit_manifest_set_against_chain_lockup_witness_v1(manifests, &snapshot.observations)
            .map_err(|_| EndpointError::InvalidEvidence)?;
        Ok(snapshot)
    }

    async fn scan_targets(
        &mut self,
        targets: &[ManifestTarget],
    ) -> Result<BitcoinMainnetLockupWitnessSnapshotV1, EndpointError> {
        let tip = self.fetch_tip().await?;
        self.canonical_blocks.insert(tip.height, tip.hash.clone());
        let mut observations = Vec::new();
        for target in targets {
            let mut target_observation_count = 0usize;
            let history = self.fetch_complete_address_history(target).await?;
            for entry in history {
                let inclusion = self
                    .validated_transaction_inclusion(&entry.txid, &entry.status, &tip)
                    .await?;
                let transaction = self.validated_raw_transaction(&entry.txid).await?;
                for (vout, output) in transaction.output.iter().enumerate() {
                    if output.script_pubkey != target.script_pubkey {
                        continue;
                    }
                    if observations.len() >= MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_V1 {
                        return Err(EndpointError::HistoryBound);
                    }
                    if target_observation_count
                        >= MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1
                    {
                        return Err(EndpointError::HistoryBound);
                    }
                    let vout = u32::try_from(vout).map_err(|_| EndpointError::InvalidEvidence)?;
                    let amount_sat = output.value.to_sat();
                    if amount_sat == 0 || amount_sat > MAX_BITCOIN_MONEY_SAT {
                        return Err(EndpointError::InvalidEvidence);
                    }
                    let derived_address =
                        Address::from_script(&output.script_pubkey, Network::Bitcoin)
                            .map_err(|_| EndpointError::InvalidEvidence)?;
                    if derived_address.to_string() != target.address {
                        return Err(EndpointError::InvalidEvidence);
                    }
                    let spend = self.validated_outspend(&entry.txid, vout, &tip).await?;
                    observations.push(PrevalidatedChainLockupObservationV1 {
                        manifest_id: target.manifest_id,
                        chain_swap_id: target.chain_swap_id,
                        chain: ChainLockupWitnessChainV1::BitcoinMainnet,
                        lockup_address: target.address.clone(),
                        lockup_script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                        txid: entry.txid.clone(),
                        vout,
                        amount_sat,
                        inclusion: inclusion.clone(),
                        spend,
                    });
                    target_observation_count += 1;
                }
            }
        }

        self.revalidate_blocks().await?;
        if self.fetch_tip().await? != tip {
            return Err(EndpointError::ChangedSnapshot);
        }
        Ok(BitcoinMainnetLockupWitnessSnapshotV1 {
            authority: self.endpoint.to_owned(),
            tip_height: tip.height,
            tip_hash: tip.hash,
            observations,
        })
    }

    async fn fetch_tip(&mut self) -> Result<TipAnchor, EndpointError> {
        let height_text = self
            .get_text("blocks/tip/height", MAX_TEXT_RESPONSE_BYTES)
            .await?;
        let height = height_text
            .parse::<u32>()
            .ok()
            .filter(|height| *height > 0)
            .ok_or(EndpointError::InvalidEvidence)?;
        let hash = self.fetch_block_hash(height).await?;
        Ok(TipAnchor { height, hash })
    }

    async fn fetch_complete_address_history(
        &mut self,
        target: &ManifestTarget,
    ) -> Result<Vec<AddressHistoryTransaction>, EndpointError> {
        let path = format!("address/{}/txs", target.address);
        let first: Vec<AddressHistoryTransaction> = self.get_json(&path).await?;
        if first.len() > MAX_BITCOIN_LOCKUP_WITNESS_FIRST_PAGE_TXS_V1 {
            return Err(EndpointError::HistoryBound);
        }
        let mut history = Vec::with_capacity(first.len());
        let mut seen = BTreeSet::new();
        validate_history_page(&first, true, &mut seen)?;
        let first_confirmed = first.iter().filter(|entry| entry.status.confirmed).count();
        if first_confirmed > BITCOIN_LOCKUP_WITNESS_PAGE_SIZE_V1
            && first_confirmed != EXTENDED_FIRST_CONFIRMED_PAGE_SIZE
        {
            return Err(EndpointError::InvalidEvidence);
        }
        let mut page_confirmed = first_confirmed;
        let mut cursor = first
            .iter()
            .rev()
            .find(|entry| entry.status.confirmed)
            .map(|entry| entry.txid.clone());
        history.extend(first);
        let mut pages = 1usize;

        while matches!(
            page_confirmed,
            BITCOIN_LOCKUP_WITNESS_PAGE_SIZE_V1 | EXTENDED_FIRST_CONFIRMED_PAGE_SIZE
        ) {
            if pages >= MAX_BITCOIN_LOCKUP_WITNESS_PAGES_V1 {
                return Err(EndpointError::HistoryBound);
            }
            let cursor_txid = cursor.as_deref().ok_or(EndpointError::InvalidEvidence)?;
            let path = format!("address/{}/txs/chain/{cursor_txid}", target.address);
            let page: Vec<AddressHistoryTransaction> = self.get_json(&path).await?;
            if page.len() > BITCOIN_LOCKUP_WITNESS_PAGE_SIZE_V1 {
                return Err(EndpointError::HistoryBound);
            }
            validate_history_page(&page, false, &mut seen)?;
            if history.len().saturating_add(page.len())
                > MAX_BITCOIN_LOCKUP_WITNESS_TXS_PER_MANIFEST_V1
            {
                return Err(EndpointError::HistoryBound);
            }
            page_confirmed = page.len();
            cursor = page.last().map(|entry| entry.txid.clone());
            history.extend(page);
            pages += 1;
        }
        Ok(history)
    }

    async fn validated_raw_transaction(
        &mut self,
        requested_txid: &str,
    ) -> Result<Transaction, EndpointError> {
        if let Some(transaction) = self.raw_transactions.get(requested_txid) {
            return Ok(transaction.clone());
        }
        if !is_lower_hash(requested_txid) {
            return Err(EndpointError::InvalidEvidence);
        }
        let path = format!("tx/{requested_txid}/hex");
        let encoded = self
            .get_text(
                &path,
                MAX_RAW_TRANSACTION_BYTES
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(2))
                    .ok_or(EndpointError::ResponseBound)?,
            )
            .await?;
        if encoded.is_empty()
            || !encoded.len().is_multiple_of(2)
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EndpointError::InvalidEvidence);
        }
        let bytes = hex::decode(encoded).map_err(|_| EndpointError::InvalidEvidence)?;
        if bytes.len() > MAX_RAW_TRANSACTION_BYTES {
            return Err(EndpointError::ResponseBound);
        }
        let transaction: Transaction =
            deserialize(&bytes).map_err(|_| EndpointError::InvalidEvidence)?;
        if serialize(&transaction) != bytes
            || transaction.compute_txid().to_string() != requested_txid
        {
            return Err(EndpointError::InvalidEvidence);
        }
        self.raw_transactions
            .insert(requested_txid.to_owned(), transaction.clone());
        Ok(transaction)
    }

    async fn validated_transaction_inclusion(
        &mut self,
        txid: &str,
        history_status: &EsploraTxStatus,
        tip: &TipAnchor,
    ) -> Result<ChainLockupInclusionV1, EndpointError> {
        if let Some(inclusion) = self.transaction_inclusions.get(txid) {
            let repeated = inclusion_from_status(history_status, tip, &self.canonical_blocks)?;
            if inclusion != &repeated {
                return Err(EndpointError::InvalidEvidence);
            }
            return Ok(inclusion.clone());
        }
        let path = format!("tx/{txid}/status");
        let direct_status: EsploraTxStatus = self.get_json(&path).await?;
        if &direct_status != history_status {
            return Err(EndpointError::ChangedSnapshot);
        }
        self.validate_status_block(&direct_status, tip).await?;
        let inclusion = inclusion_from_status(&direct_status, tip, &self.canonical_blocks)?;
        self.transaction_inclusions
            .insert(txid.to_owned(), inclusion.clone());
        Ok(inclusion)
    }

    async fn validate_status_block(
        &mut self,
        status: &EsploraTxStatus,
        tip: &TipAnchor,
    ) -> Result<(), EndpointError> {
        validate_status_shape(status, tip)?;
        if let (Some(height), Some(claimed_hash)) = (status.block_height, &status.block_hash) {
            let canonical = if let Some(hash) = self.canonical_blocks.get(&height) {
                hash.clone()
            } else {
                let hash = self.fetch_block_hash(height).await?;
                self.canonical_blocks.insert(height, hash.clone());
                hash
            };
            if &canonical != claimed_hash {
                return Err(EndpointError::InvalidEvidence);
            }
        }
        Ok(())
    }

    async fn validated_outspend(
        &mut self,
        funding_txid: &str,
        funding_vout: u32,
        tip: &TipAnchor,
    ) -> Result<ChainLockupSpendV1, EndpointError> {
        let path = format!("tx/{funding_txid}/outspend/{funding_vout}");
        let outspend: EsploraOutspend = self.get_json(&path).await?;
        if !outspend.spent {
            if outspend.txid.is_some() || outspend.vin.is_some() || outspend.status.is_some() {
                return Err(EndpointError::InvalidEvidence);
            }
            return Ok(ChainLockupSpendV1::Unspent);
        }

        let spending_txid = outspend
            .txid
            .filter(|txid| is_lower_hash(txid) && txid != funding_txid)
            .ok_or(EndpointError::InvalidEvidence)?;
        let spending_vin = outspend.vin.ok_or(EndpointError::InvalidEvidence)?;
        let status = outspend.status.ok_or(EndpointError::InvalidEvidence)?;
        self.validate_status_block(&status, tip).await?;
        let spending_inclusion = inclusion_from_status(&status, tip, &self.canonical_blocks)?;

        if let Some(prior) = self.transaction_inclusions.get(&spending_txid) {
            if prior != &spending_inclusion {
                return Err(EndpointError::InvalidEvidence);
            }
        } else {
            self.transaction_inclusions
                .insert(spending_txid.clone(), spending_inclusion.clone());
        }
        let spending_tx = self.validated_raw_transaction(&spending_txid).await?;
        let spending_vin =
            usize::try_from(spending_vin).map_err(|_| EndpointError::InvalidEvidence)?;
        let input = spending_tx
            .input
            .get(spending_vin)
            .ok_or(EndpointError::InvalidEvidence)?;
        if input.previous_output.txid.to_string() != funding_txid
            || input.previous_output.vout != funding_vout
            || spending_tx
                .input
                .iter()
                .filter(|candidate| {
                    candidate.previous_output.txid.to_string() == funding_txid
                        && candidate.previous_output.vout == funding_vout
                })
                .count()
                != 1
        {
            return Err(EndpointError::InvalidEvidence);
        }

        Ok(ChainLockupSpendV1::Spent {
            spending_txid,
            inclusion: spending_inclusion,
        })
    }

    async fn revalidate_blocks(&mut self) -> Result<(), EndpointError> {
        let expected = self
            .canonical_blocks
            .iter()
            .map(|(height, hash)| (*height, hash.clone()))
            .collect::<Vec<_>>();
        for (height, hash) in expected {
            if self.fetch_block_hash(height).await? != hash {
                return Err(EndpointError::ChangedSnapshot);
            }
        }
        Ok(())
    }

    async fn fetch_block_hash(&mut self, height: u32) -> Result<String, EndpointError> {
        let path = format!("block-height/{height}");
        let hash = self.get_text(&path, MAX_TEXT_RESPONSE_BYTES).await?;
        if !is_lower_hash(&hash) {
            return Err(EndpointError::InvalidEvidence);
        }
        Ok(hash)
    }

    async fn get_json<T: DeserializeOwned>(&mut self, path: &str) -> Result<T, EndpointError> {
        let bytes = self.get_bytes(path, MAX_JSON_RESPONSE_BYTES).await?;
        serde_json::from_slice(&bytes).map_err(|_| EndpointError::InvalidEvidence)
    }

    async fn get_text(&mut self, path: &str, limit: usize) -> Result<String, EndpointError> {
        let bytes = self.get_bytes(path, limit).await?;
        let text = std::str::from_utf8(&bytes).map_err(|_| EndpointError::InvalidEvidence)?;
        let trimmed = text.trim_matches(|character: char| character.is_ascii_whitespace());
        if trimmed.is_empty() {
            return Err(EndpointError::InvalidEvidence);
        }
        Ok(trimmed.to_owned())
    }

    async fn get_bytes(&mut self, path: &str, limit: usize) -> Result<Vec<u8>, EndpointError> {
        self.budget.begin_request()?;
        let url = format!("{}/{}", self.endpoint, path.trim_start_matches('/'));
        let mut response = self
            .adapter
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| EndpointError::Backend)?;
        if !response.status().is_success() {
            return Err(EndpointError::Backend);
        }
        if response.content_length().is_some_and(|length| {
            length > u64::try_from(limit).unwrap_or(MAX_ENDPOINT_BYTES_U64)
                || length > MAX_ENDPOINT_BYTES_U64
        }) {
            return Err(EndpointError::ResponseBound);
        }

        let mut bytes = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(limit),
        );
        while let Some(chunk) = response.chunk().await.map_err(|_| EndpointError::Backend)? {
            if bytes.len().saturating_add(chunk.len()) > limit {
                return Err(EndpointError::ResponseBound);
            }
            bytes.extend_from_slice(&chunk);
        }
        self.budget.add_bytes(bytes.len())?;
        Ok(bytes)
    }
}

fn validate_history_page(
    page: &[AddressHistoryTransaction],
    allow_mempool: bool,
    seen: &mut BTreeSet<String>,
) -> Result<(), EndpointError> {
    let mut confirmed_seen = false;
    for entry in page {
        if !is_lower_hash(&entry.txid) || !seen.insert(entry.txid.clone()) {
            return Err(EndpointError::InvalidEvidence);
        }
        if entry.status.confirmed {
            confirmed_seen = true;
        } else if !allow_mempool || confirmed_seen {
            return Err(EndpointError::InvalidEvidence);
        }
        validate_status_shape_without_tip(&entry.status)?;
    }
    Ok(())
}

fn validate_status_shape_without_tip(status: &EsploraTxStatus) -> Result<(), EndpointError> {
    if status.confirmed {
        if status.block_height.is_none()
            || status.block_height == Some(0)
            || !status.block_hash.as_deref().is_some_and(is_lower_hash)
        {
            return Err(EndpointError::InvalidEvidence);
        }
    } else if status.block_height.is_some() || status.block_hash.is_some() {
        return Err(EndpointError::InvalidEvidence);
    }
    Ok(())
}

fn validate_status_shape(status: &EsploraTxStatus, tip: &TipAnchor) -> Result<(), EndpointError> {
    validate_status_shape_without_tip(status)?;
    if status
        .block_height
        .is_some_and(|height| height > tip.height)
    {
        return Err(EndpointError::InvalidEvidence);
    }
    Ok(())
}

fn inclusion_from_status(
    status: &EsploraTxStatus,
    tip: &TipAnchor,
    canonical_blocks: &BTreeMap<u32, String>,
) -> Result<ChainLockupInclusionV1, EndpointError> {
    validate_status_shape(status, tip)?;
    if !status.confirmed {
        return Ok(ChainLockupInclusionV1::Mempool);
    }
    let block_height = status.block_height.ok_or(EndpointError::InvalidEvidence)?;
    let block_hash = status
        .block_hash
        .as_ref()
        .ok_or(EndpointError::InvalidEvidence)?;
    if canonical_blocks.get(&block_height) != Some(block_hash) {
        return Err(EndpointError::InvalidEvidence);
    }
    let confirmations = tip
        .height
        .checked_sub(block_height)
        .and_then(|depth| depth.checked_add(1))
        .filter(|depth| *depth > 0)
        .ok_or(EndpointError::InvalidEvidence)?;
    Ok(ChainLockupInclusionV1::Confirmed {
        confirmations,
        block_height,
        block_hash: block_hash.clone(),
    })
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == HASH_HEX_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
