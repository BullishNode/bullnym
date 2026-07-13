//! Pure comparison of signed manifests with prevalidated Bitcoin lockup facts.
//!
//! This module is deliberately storage- and network-neutral. It performs no
//! SQL, RPC, provider request, reconstruction, admission decision, or mutation.
//! A caller must first finish an authoritative Bitcoin-mainnet scan and locally
//! validate raw transaction bytes, recomputed txids, output indexes, amounts,
//! scripts, inclusion proofs, and outspends. Backend failure or an incomplete
//! scan must never be represented as an empty observation set: `Missing` means
//! that a successful, complete adapter scan found no output for the manifest.
//!
//! Version 1 audits only the payer's Bitcoin user-lock output. Manifest v1 has
//! a complete immutable target for that leg: mainnet identity, canonical lockup
//! address/script, and the originally requested amount. It intentionally does
//! not infer the Liquid server-lock lifecycle, a renegotiated amount, or the
//! merchant settlement output. Those require the later persisted #83 exact-
//! output lifecycle rather than fields invented inside recovery code.
//!
//! Amount mismatches are classified as conflicting with the original payer
//! instruction, not discarded. A later obligation reducer may still classify
//! underpayment, overpayment, or repeated funding. This audit never decides
//! whether to recover funds or admit new swaps.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use bitcoin::{Address, Network};
use uuid::Uuid;

use crate::swap_manifest::{
    audit_append_only_manifest_set_v1, SwapManifestSetAuditV1, SwapManifestV1,
};

/// Maximum signed records accepted by one in-memory chain-witness audit.
pub const MAX_CHAIN_LOCKUP_WITNESS_MANIFESTS_V1: usize = 10_000;
/// Maximum public output records accepted by one audit.
pub const MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_V1: usize = 50_000;
/// Maximum funding outputs associated with one manifest in one snapshot.
pub const MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1: usize = 64;
/// Maximum canonical address bytes accepted before substantive validation.
pub const MAX_CHAIN_LOCKUP_WITNESS_ADDRESS_BYTES_V1: usize = 512;
/// Bitcoin's consensus script-size ceiling, represented as lowercase hex chars.
pub const MAX_CHAIN_LOCKUP_WITNESS_SCRIPT_HEX_CHARS_V1: usize = 20_000;

const MAX_BITCOIN_MONEY_SAT: u64 = 2_100_000_000_000_000;
const HASH_HEX_CHARS: usize = 64;
const REDACTED: &str = "<redacted>";

/// Public chain namespace claimed by a prevalidated observation.
///
/// Manifest-v1 user-lock evidence expects [`Self::BitcoinMainnet`]. The Liquid
/// variant exists so a misrouted but otherwise canonical observation is
/// classified as a chain conflict instead of being silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainLockupWitnessChainV1 {
    BitcoinMainnet,
    LiquidMainnet,
}

/// Canonical inclusion facts for one public transaction.
#[derive(Clone, PartialEq, Eq)]
pub enum ChainLockupInclusionV1 {
    Mempool,
    Confirmed {
        confirmations: u32,
        block_height: u32,
        block_hash: String,
    },
}

impl fmt::Debug for ChainLockupInclusionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mempool => f.write_str("Mempool"),
            Self::Confirmed {
                confirmations,
                block_height,
                ..
            } => f
                .debug_struct("Confirmed")
                .field("confirmations", confirmations)
                .field("block_height", block_height)
                .field("block_hash", &REDACTED)
                .finish(),
        }
    }
}

/// Independently observed outspend state for one funding output.
#[derive(Clone, PartialEq, Eq)]
pub enum ChainLockupSpendV1 {
    Unspent,
    Spent {
        spending_txid: String,
        inclusion: ChainLockupInclusionV1,
    },
}

impl fmt::Debug for ChainLockupSpendV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspent => f.write_str("Unspent"),
            Self::Spent { inclusion, .. } => f
                .debug_struct("Spent")
                .field("spending_txid", &REDACTED)
                .field("inclusion", inclusion)
                .finish(),
        }
    }
}

/// One storage-neutral public observation produced by a chain adapter.
///
/// `manifest_id` and `chain_swap_id` are both required association tags. The
/// audit independently resolves both and rejects unknown, partial, or crossed
/// identities. They are not asserted to be encoded in the Bitcoin transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct PrevalidatedChainLockupObservationV1 {
    pub manifest_id: Uuid,
    pub chain_swap_id: Uuid,
    pub chain: ChainLockupWitnessChainV1,
    pub lockup_address: String,
    pub lockup_script_pubkey_hex: String,
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub inclusion: ChainLockupInclusionV1,
    pub spend: ChainLockupSpendV1,
}

impl fmt::Debug for PrevalidatedChainLockupObservationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrevalidatedChainLockupObservationV1")
            .field("manifest_id", &self.manifest_id)
            .field("chain_swap_id", &self.chain_swap_id)
            .field("chain", &self.chain)
            .field("lockup_address", &REDACTED)
            .field("lockup_script_pubkey_hex", &REDACTED)
            .field("txid", &REDACTED)
            .field("vout", &self.vout)
            .field("amount_sat", &REDACTED)
            .field("inclusion", &self.inclusion)
            .field("spend", &self.spend)
            .finish()
    }
}

/// Exact immutable-target fields on which public evidence can disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainLockupConflictFieldV1 {
    Chain,
    LockupAddress,
    LockupScriptPubkey,
    ExpectedAmount,
}

/// Classification of one observed funding outpoint.
#[derive(Clone, PartialEq, Eq)]
pub enum ChainLockupFindingClassificationV1 {
    Unconfirmed,
    Confirmed,
    Spent,
    Conflicting {
        fields: Vec<ChainLockupConflictFieldV1>,
    },
}

impl fmt::Debug for ChainLockupFindingClassificationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unconfirmed => f.write_str("Unconfirmed"),
            Self::Confirmed => f.write_str("Confirmed"),
            Self::Spent => f.write_str("Spent"),
            Self::Conflicting { fields } => f
                .debug_struct("Conflicting")
                .field("fields", fields)
                .finish(),
        }
    }
}

/// Compact audited copy of one outpoint and its public lifecycle facts.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainLockupWitnessFindingV1 {
    pub txid: String,
    pub vout: u32,
    pub observed_amount_sat: u64,
    pub inclusion: ChainLockupInclusionV1,
    pub spend: ChainLockupSpendV1,
    pub classification: ChainLockupFindingClassificationV1,
}

impl fmt::Debug for ChainLockupWitnessFindingV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainLockupWitnessFindingV1")
            .field("txid", &REDACTED)
            .field("vout", &self.vout)
            .field("observed_amount_sat", &REDACTED)
            .field("inclusion", &self.inclusion)
            .field("spend", &self.spend)
            .field("classification", &self.classification)
            .finish()
    }
}

/// Highest-evidence summary for one manifest.
///
/// Priority is `Conflicting > Spent > Confirmed > Unconfirmed > Missing`. The
/// complete deterministic finding list remains available, so the summary does
/// not erase simultaneous or repeated funding facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainLockupManifestClassificationV1 {
    Missing,
    Unconfirmed,
    Confirmed,
    Spent,
    Conflicting,
}

/// Bitcoin user-lock findings for one signed manifest.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainLockupManifestWitnessAuditV1 {
    pub manifest_sequence: u64,
    pub manifest_id: Uuid,
    pub chain_swap_id: Uuid,
    pub expected_amount_sat: u64,
    pub classification: ChainLockupManifestClassificationV1,
    pub findings: Vec<ChainLockupWitnessFindingV1>,
}

impl fmt::Debug for ChainLockupManifestWitnessAuditV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainLockupManifestWitnessAuditV1")
            .field("manifest_sequence", &self.manifest_sequence)
            .field("manifest_id", &self.manifest_id)
            .field("chain_swap_id", &self.chain_swap_id)
            .field("expected_amount_sat", &REDACTED)
            .field("classification", &self.classification)
            .field("finding_count", &self.findings.len())
            .finish()
    }
}

/// Deterministic result of one manifest/Bitcoin-witness comparison.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainLockupWitnessAuditV1 {
    pub manifest_set: SwapManifestSetAuditV1,
    pub manifests: Vec<ChainLockupManifestWitnessAuditV1>,
    pub observation_count: usize,
    pub missing_manifest_count: usize,
    pub unconfirmed_manifest_count: usize,
    pub confirmed_manifest_count: usize,
    pub spent_manifest_count: usize,
    pub conflicting_manifest_count: usize,
}

impl fmt::Debug for ChainLockupWitnessAuditV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainLockupWitnessAuditV1")
            .field("manifest_count", &self.manifests.len())
            .field("observation_count", &self.observation_count)
            .field("missing_manifest_count", &self.missing_manifest_count)
            .field(
                "unconfirmed_manifest_count",
                &self.unconfirmed_manifest_count,
            )
            .field("confirmed_manifest_count", &self.confirmed_manifest_count)
            .field("spent_manifest_count", &self.spent_manifest_count)
            .field(
                "conflicting_manifest_count",
                &self.conflicting_manifest_count,
            )
            .finish()
    }
}

/// Fail-closed input failures. Variants intentionally retain no addresses,
/// scripts, txids, block hashes, amounts, provider ids, or nested error source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainLockupWitnessAuditError {
    TooManyManifestRecords,
    TooManyObservationRecords,
    ObservationStringLimitExceeded,
    InvalidManifestSet,
    InvalidPublicObservation,
    UnknownObservationIdentity,
    PartialObservationIdentity,
    DuplicateObservationOutpoint,
    ConflictingTransactionInclusion,
    TooManyObservationsForManifest,
    InvalidManifestLockupTarget,
}

impl fmt::Display for ChainLockupWitnessAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooManyManifestRecords => "chain lockup audit exceeds the manifest record limit",
            Self::TooManyObservationRecords => {
                "chain lockup audit exceeds the observation record limit"
            }
            Self::ObservationStringLimitExceeded => {
                "chain lockup audit observation exceeds a string limit"
            }
            Self::InvalidManifestSet => "chain lockup audit rejected the signed manifest set",
            Self::InvalidPublicObservation => "chain lockup audit received invalid public evidence",
            Self::UnknownObservationIdentity => {
                "chain lockup audit received an unknown observation identity"
            }
            Self::PartialObservationIdentity => {
                "chain lockup audit identities only partially agree"
            }
            Self::DuplicateObservationOutpoint => "chain lockup audit repeats an observed outpoint",
            Self::ConflictingTransactionInclusion => {
                "chain lockup audit has conflicting transaction inclusion"
            }
            Self::TooManyObservationsForManifest => {
                "chain lockup audit exceeds the per-manifest output limit"
            }
            Self::InvalidManifestLockupTarget => {
                "chain lockup audit could not derive the signed lockup target"
            }
        })
    }
}

impl std::error::Error for ChainLockupWitnessAuditError {}

struct ExpectedBitcoinLockupTarget<'a> {
    manifest: &'a SwapManifestV1,
    script_pubkey_hex: String,
    expected_amount_sat: u64,
}

/// Compare one complete append-only manifest set with one complete public
/// Bitcoin lockup snapshot.
///
/// Record counts and every attacker-controlled string length are checked before
/// any internal collection is allocated. The manifest set is then validated as
/// append-only before observation semantics or identities are considered.
/// Input order is irrelevant; output is sorted by manifest sequence and then by
/// `(txid, vout)`. Duplicate outpoints and partial/crossed association tags are
/// rejected rather than coalesced.
pub fn audit_manifest_set_against_chain_lockup_witness_v1(
    manifests: &[SwapManifestV1],
    observations: &[PrevalidatedChainLockupObservationV1],
) -> Result<ChainLockupWitnessAuditV1, ChainLockupWitnessAuditError> {
    preflight_limits(manifests, observations)?;

    let manifest_set = audit_append_only_manifest_set_v1(manifests)
        .map_err(|_| ChainLockupWitnessAuditError::InvalidManifestSet)?;

    for observation in observations {
        validate_public_observation(observation)?;
    }

    let mut targets = manifests
        .iter()
        .map(expected_bitcoin_lockup_target)
        .collect::<Result<Vec<_>, _>>()?;
    targets.sort_unstable_by_key(|target| target.manifest.restore_identity.manifest_sequence);

    let mut by_manifest_id = BTreeMap::new();
    let mut by_chain_swap_id = BTreeMap::new();
    for (index, target) in targets.iter().enumerate() {
        by_manifest_id.insert(target.manifest.restore_identity.manifest_id, index);
        by_chain_swap_id.insert(target.manifest.restore_identity.chain_swap_id, index);
    }

    let mut observations_by_manifest = vec![Vec::new(); targets.len()];
    let mut seen_outpoints = BTreeSet::new();
    let mut transaction_inclusions = BTreeMap::new();
    for observation in observations {
        let by_manifest = by_manifest_id.get(&observation.manifest_id).copied();
        let by_swap = by_chain_swap_id.get(&observation.chain_swap_id).copied();
        let target_index = match (by_manifest, by_swap) {
            (Some(manifest), Some(swap)) if manifest == swap => manifest,
            (None, None) => return Err(ChainLockupWitnessAuditError::UnknownObservationIdentity),
            _ => return Err(ChainLockupWitnessAuditError::PartialObservationIdentity),
        };

        if !seen_outpoints.insert((
            observation.chain,
            observation.txid.as_str(),
            observation.vout,
        )) {
            return Err(ChainLockupWitnessAuditError::DuplicateObservationOutpoint);
        }
        register_transaction_inclusion(
            &mut transaction_inclusions,
            observation.chain,
            &observation.txid,
            &observation.inclusion,
        )?;
        if let ChainLockupSpendV1::Spent {
            spending_txid,
            inclusion,
        } = &observation.spend
        {
            register_transaction_inclusion(
                &mut transaction_inclusions,
                observation.chain,
                spending_txid,
                inclusion,
            )?;
        }
        let target_observations = &mut observations_by_manifest[target_index];
        if target_observations.len() >= MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_PER_MANIFEST_V1 {
            return Err(ChainLockupWitnessAuditError::TooManyObservationsForManifest);
        }
        target_observations.push(observation);
    }

    let mut audited_manifests = Vec::with_capacity(targets.len());
    for (target, mut target_observations) in targets.into_iter().zip(observations_by_manifest) {
        target_observations.sort_unstable_by(|left, right| {
            left.txid
                .cmp(&right.txid)
                .then_with(|| left.vout.cmp(&right.vout))
        });
        let findings = target_observations
            .into_iter()
            .map(|observation| classify_observation(&target, observation))
            .collect::<Vec<_>>();
        let classification = summarize_findings(&findings);
        audited_manifests.push(ChainLockupManifestWitnessAuditV1 {
            manifest_sequence: target.manifest.restore_identity.manifest_sequence,
            manifest_id: target.manifest.restore_identity.manifest_id,
            chain_swap_id: target.manifest.restore_identity.chain_swap_id,
            expected_amount_sat: target.expected_amount_sat,
            classification,
            findings,
        });
    }

    let mut missing_manifest_count = 0;
    let mut unconfirmed_manifest_count = 0;
    let mut confirmed_manifest_count = 0;
    let mut spent_manifest_count = 0;
    let mut conflicting_manifest_count = 0;
    for manifest in &audited_manifests {
        match manifest.classification {
            ChainLockupManifestClassificationV1::Missing => missing_manifest_count += 1,
            ChainLockupManifestClassificationV1::Unconfirmed => unconfirmed_manifest_count += 1,
            ChainLockupManifestClassificationV1::Confirmed => confirmed_manifest_count += 1,
            ChainLockupManifestClassificationV1::Spent => spent_manifest_count += 1,
            ChainLockupManifestClassificationV1::Conflicting => {
                conflicting_manifest_count += 1;
            }
        }
    }

    Ok(ChainLockupWitnessAuditV1 {
        manifest_set,
        manifests: audited_manifests,
        observation_count: observations.len(),
        missing_manifest_count,
        unconfirmed_manifest_count,
        confirmed_manifest_count,
        spent_manifest_count,
        conflicting_manifest_count,
    })
}

fn register_transaction_inclusion<'a>(
    inclusions: &mut BTreeMap<(ChainLockupWitnessChainV1, &'a str), &'a ChainLockupInclusionV1>,
    chain: ChainLockupWitnessChainV1,
    txid: &'a str,
    inclusion: &'a ChainLockupInclusionV1,
) -> Result<(), ChainLockupWitnessAuditError> {
    if let Some(previous) = inclusions.insert((chain, txid), inclusion) {
        if previous != inclusion {
            return Err(ChainLockupWitnessAuditError::ConflictingTransactionInclusion);
        }
    }
    Ok(())
}

fn preflight_limits(
    manifests: &[SwapManifestV1],
    observations: &[PrevalidatedChainLockupObservationV1],
) -> Result<(), ChainLockupWitnessAuditError> {
    if manifests.len() > MAX_CHAIN_LOCKUP_WITNESS_MANIFESTS_V1 {
        return Err(ChainLockupWitnessAuditError::TooManyManifestRecords);
    }
    if observations.len() > MAX_CHAIN_LOCKUP_WITNESS_OBSERVATIONS_V1 {
        return Err(ChainLockupWitnessAuditError::TooManyObservationRecords);
    }
    for observation in observations {
        if observation.lockup_address.len() > MAX_CHAIN_LOCKUP_WITNESS_ADDRESS_BYTES_V1
            || observation.lockup_script_pubkey_hex.len()
                > MAX_CHAIN_LOCKUP_WITNESS_SCRIPT_HEX_CHARS_V1
            || observation.txid.len() > HASH_HEX_CHARS
            || inclusion_hash_too_long(&observation.inclusion)
            || match &observation.spend {
                ChainLockupSpendV1::Unspent => false,
                ChainLockupSpendV1::Spent {
                    spending_txid,
                    inclusion,
                } => spending_txid.len() > HASH_HEX_CHARS || inclusion_hash_too_long(inclusion),
            }
        {
            return Err(ChainLockupWitnessAuditError::ObservationStringLimitExceeded);
        }
    }
    Ok(())
}

fn inclusion_hash_too_long(inclusion: &ChainLockupInclusionV1) -> bool {
    matches!(
        inclusion,
        ChainLockupInclusionV1::Confirmed { block_hash, .. }
            if block_hash.len() > HASH_HEX_CHARS
    )
}

fn validate_public_observation(
    observation: &PrevalidatedChainLockupObservationV1,
) -> Result<(), ChainLockupWitnessAuditError> {
    if observation.manifest_id.is_nil()
        || observation.chain_swap_id.is_nil()
        || !is_lower_hash(&observation.txid)
        || observation.amount_sat == 0
        || observation.amount_sat > MAX_BITCOIN_MONEY_SAT
        || observation.lockup_address.is_empty()
        || observation.lockup_address.chars().any(char::is_whitespace)
        || !is_lower_even_hex(&observation.lockup_script_pubkey_hex)
    {
        return Err(ChainLockupWitnessAuditError::InvalidPublicObservation);
    }

    let canonical_script = canonical_observation_script(observation)?;
    if canonical_script != observation.lockup_script_pubkey_hex {
        return Err(ChainLockupWitnessAuditError::InvalidPublicObservation);
    }
    validate_inclusion(&observation.inclusion)?;

    if let ChainLockupSpendV1::Spent {
        spending_txid,
        inclusion,
    } = &observation.spend
    {
        if !is_lower_hash(spending_txid) || spending_txid == &observation.txid {
            return Err(ChainLockupWitnessAuditError::InvalidPublicObservation);
        }
        validate_inclusion(inclusion)?;
        validate_spend_order(&observation.inclusion, inclusion)?;
    }
    Ok(())
}

fn canonical_observation_script(
    observation: &PrevalidatedChainLockupObservationV1,
) -> Result<String, ChainLockupWitnessAuditError> {
    match observation.chain {
        ChainLockupWitnessChainV1::BitcoinMainnet => {
            let canonical =
                crate::validators::canonical_btc_mainnet_address(&observation.lockup_address)
                    .map_err(|_| ChainLockupWitnessAuditError::InvalidPublicObservation)?;
            if canonical != observation.lockup_address {
                return Err(ChainLockupWitnessAuditError::InvalidPublicObservation);
            }
            let address = Address::from_str(&canonical)
                .map_err(|_| ChainLockupWitnessAuditError::InvalidPublicObservation)?
                .require_network(Network::Bitcoin)
                .map_err(|_| ChainLockupWitnessAuditError::InvalidPublicObservation)?;
            Ok(hex::encode(address.script_pubkey().as_bytes()))
        }
        ChainLockupWitnessChainV1::LiquidMainnet => {
            let canonical =
                crate::validators::canonical_liquid_mainnet_address(&observation.lockup_address)
                    .map_err(|_| ChainLockupWitnessAuditError::InvalidPublicObservation)?;
            if canonical != observation.lockup_address {
                return Err(ChainLockupWitnessAuditError::InvalidPublicObservation);
            }
            let address = boltz_client::elements::Address::from_str(&canonical)
                .map_err(|_| ChainLockupWitnessAuditError::InvalidPublicObservation)?;
            Ok(hex::encode(address.script_pubkey().as_bytes()))
        }
    }
}

fn validate_inclusion(
    inclusion: &ChainLockupInclusionV1,
) -> Result<(), ChainLockupWitnessAuditError> {
    if let ChainLockupInclusionV1::Confirmed {
        confirmations,
        block_height,
        block_hash,
    } = inclusion
    {
        if *confirmations == 0 || *block_height == 0 || !is_lower_hash(block_hash) {
            return Err(ChainLockupWitnessAuditError::InvalidPublicObservation);
        }
    }
    Ok(())
}

fn validate_spend_order(
    funding: &ChainLockupInclusionV1,
    spend: &ChainLockupInclusionV1,
) -> Result<(), ChainLockupWitnessAuditError> {
    match (funding, spend) {
        (ChainLockupInclusionV1::Mempool, ChainLockupInclusionV1::Confirmed { .. }) => {
            Err(ChainLockupWitnessAuditError::InvalidPublicObservation)
        }
        (
            ChainLockupInclusionV1::Confirmed {
                confirmations: funding_confirmations,
                block_height: funding_height,
                block_hash: funding_block_hash,
            },
            ChainLockupInclusionV1::Confirmed {
                confirmations: spend_confirmations,
                block_height: spend_height,
                block_hash: spend_block_hash,
            },
        ) if spend_height < funding_height
            || spend_confirmations > funding_confirmations
            || u64::from(*funding_height) + u64::from(*funding_confirmations)
                != u64::from(*spend_height) + u64::from(*spend_confirmations)
            || (spend_height == funding_height && spend_block_hash != funding_block_hash) =>
        {
            Err(ChainLockupWitnessAuditError::InvalidPublicObservation)
        }
        _ => Ok(()),
    }
}

fn expected_bitcoin_lockup_target(
    manifest: &SwapManifestV1,
) -> Result<ExpectedBitcoinLockupTarget<'_>, ChainLockupWitnessAuditError> {
    if manifest.creation.btc_network != "bitcoin" {
        return Err(ChainLockupWitnessAuditError::InvalidManifestLockupTarget);
    }
    let canonical =
        crate::validators::canonical_btc_mainnet_address(&manifest.creation.lockup_address)
            .map_err(|_| ChainLockupWitnessAuditError::InvalidManifestLockupTarget)?;
    if canonical != manifest.creation.lockup_address {
        return Err(ChainLockupWitnessAuditError::InvalidManifestLockupTarget);
    }
    let address = Address::from_str(&canonical)
        .map_err(|_| ChainLockupWitnessAuditError::InvalidManifestLockupTarget)?
        .require_network(Network::Bitcoin)
        .map_err(|_| ChainLockupWitnessAuditError::InvalidManifestLockupTarget)?;
    let expected_amount_sat = u64::try_from(manifest.creation.user_lock_amount_sat)
        .ok()
        .filter(|amount| *amount > 0 && *amount <= MAX_BITCOIN_MONEY_SAT)
        .ok_or(ChainLockupWitnessAuditError::InvalidManifestLockupTarget)?;
    Ok(ExpectedBitcoinLockupTarget {
        manifest,
        script_pubkey_hex: hex::encode(address.script_pubkey().as_bytes()),
        expected_amount_sat,
    })
}

fn classify_observation(
    target: &ExpectedBitcoinLockupTarget<'_>,
    observation: &PrevalidatedChainLockupObservationV1,
) -> ChainLockupWitnessFindingV1 {
    let mut conflicts = Vec::with_capacity(4);
    if observation.chain != ChainLockupWitnessChainV1::BitcoinMainnet {
        conflicts.push(ChainLockupConflictFieldV1::Chain);
    }
    if observation.lockup_address != target.manifest.creation.lockup_address {
        conflicts.push(ChainLockupConflictFieldV1::LockupAddress);
    }
    if observation.lockup_script_pubkey_hex != target.script_pubkey_hex {
        conflicts.push(ChainLockupConflictFieldV1::LockupScriptPubkey);
    }
    if observation.amount_sat != target.expected_amount_sat {
        conflicts.push(ChainLockupConflictFieldV1::ExpectedAmount);
    }

    let classification = if conflicts.is_empty() {
        match (&observation.inclusion, &observation.spend) {
            (_, ChainLockupSpendV1::Spent { .. }) => ChainLockupFindingClassificationV1::Spent,
            (ChainLockupInclusionV1::Confirmed { .. }, ChainLockupSpendV1::Unspent) => {
                ChainLockupFindingClassificationV1::Confirmed
            }
            (ChainLockupInclusionV1::Mempool, ChainLockupSpendV1::Unspent) => {
                ChainLockupFindingClassificationV1::Unconfirmed
            }
        }
    } else {
        ChainLockupFindingClassificationV1::Conflicting { fields: conflicts }
    };

    ChainLockupWitnessFindingV1 {
        txid: observation.txid.clone(),
        vout: observation.vout,
        observed_amount_sat: observation.amount_sat,
        inclusion: observation.inclusion.clone(),
        spend: observation.spend.clone(),
        classification,
    }
}

fn summarize_findings(
    findings: &[ChainLockupWitnessFindingV1],
) -> ChainLockupManifestClassificationV1 {
    if findings.is_empty() {
        return ChainLockupManifestClassificationV1::Missing;
    }
    if findings.iter().any(|finding| {
        matches!(
            finding.classification,
            ChainLockupFindingClassificationV1::Conflicting { .. }
        )
    }) {
        return ChainLockupManifestClassificationV1::Conflicting;
    }
    if findings.iter().any(|finding| {
        matches!(
            finding.classification,
            ChainLockupFindingClassificationV1::Spent
        )
    }) {
        return ChainLockupManifestClassificationV1::Spent;
    }
    if findings.iter().any(|finding| {
        matches!(
            finding.classification,
            ChainLockupFindingClassificationV1::Confirmed
        )
    }) {
        return ChainLockupManifestClassificationV1::Confirmed;
    }
    ChainLockupManifestClassificationV1::Unconfirmed
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == HASH_HEX_CHARS && is_lower_hex(value)
}

fn is_lower_even_hex(value: &str) -> bool {
    !value.is_empty() && value.len().is_multiple_of(2) && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
