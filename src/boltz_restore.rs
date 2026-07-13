//! Offline validation for the exact Boltz xpub-restore response pinned by Bullnym.
//!
//! The transport is deliberately not wired here. The bounded sibling
//! `boltz_restore_fetch` adapter feeds the pinned response types through this
//! module, but no startup, admission, persistence, or manifest comparison is
//! connected yet.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

use boltz_client::bitcoin::absolute::LockTime;
use boltz_client::bitcoin::hashes::{hash160, Hash};
use boltz_client::bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
};
use boltz_client::bitcoin::script::Builder;
use boltz_client::bitcoin::ScriptBuf;
use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::boltz::{
    ChainSwapDetails, ClaimDetails, CreateChainResponse, CreateReverseResponse, RefundDetails,
    SwapRestoreIndexResponse, SwapRestoreResponse, SwapRestoreType, SwapTree,
};
use boltz_client::util::secrets::{Preimage, SwapMasterKey};
use boltz_client::PublicKey;

/// BIP32 bit 31 denotes hardened derivation and cannot be derived from the xpub
/// submitted to Boltz. The pinned client parses `m/{index}` as a normal child.
pub const MAX_UNHARDENED_BOLTZ_CHILD_INDEX: u32 = (1_u32 << 31) - 1;

const BTC_LEAF_VERSION: u8 = 0xc0;
const LIQUID_LEAF_VERSION: u8 = 0xc4;
const MAX_PROVIDER_ID_BYTES: usize = 128;
const MAX_STATUS_BYTES: usize = 128;
const MAX_SCRIPT_HEX_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoltzRestoreKind {
    Reverse,
    Chain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoltzRestoreKeyPurpose {
    ReverseClaim,
    ChainClaim,
    ChainRefund,
}

impl BoltzRestoreKeyPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReverseClaim => "reverse_claim",
            Self::ChainClaim => "chain_claim",
            Self::ChainRefund => "chain_refund",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBoltzRestoreKey {
    pub purpose: BoltzRestoreKeyPurpose,
    pub child_index: u32,
    /// Compressed public key derived by the pinned
    /// `SwapMasterKey::derive_swapkey(child_index)` implementation.
    pub public_key_hex: String,
    /// Present for deterministic claim keys and absent for refund keys.
    pub preimage_sha256_hex: Option<String>,
}

impl ValidatedBoltzRestoreKey {
    pub fn derivation_path(&self) -> String {
        format!("m/{}", self.child_index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBoltzRestoreRecord {
    pub provider_swap_id: String,
    pub kind: BoltzRestoreKind,
    pub status: String,
    pub created_at: u64,
    pub keys: Vec<ValidatedBoltzRestoreKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBoltzRestoreSet {
    pub records: Vec<ValidatedBoltzRestoreRecord>,
    pub max_child_index: Option<u32>,
}

impl ValidatedBoltzRestoreSet {
    /// Cross-check the pinned `/swap/restore/index` response against the actual
    /// validated record set. This prevents callers from merely advancing their
    /// allocator from an unaudited provider integer.
    pub fn validate_reported_high_water(
        &self,
        response: &SwapRestoreIndexResponse,
    ) -> Result<Option<u32>, BoltzRestoreValidationError> {
        let reported = validate_restore_index(response)?;
        if reported != self.max_child_index {
            return Err(BoltzRestoreValidationError::InvalidReportedIndex(format!(
                "reported high-water {reported:?} does not equal validated record high-water {:?}",
                self.max_child_index
            )));
        }
        Ok(reported)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoltzRestoreValidationError {
    InvalidRecord {
        provider_swap_id: String,
        reason: String,
    },
    UnsupportedRecord {
        provider_swap_id: String,
        reason: String,
    },
    DuplicateProviderId(String),
    ConflictingKeyIndex {
        child_index: u32,
        first_provider_swap_id: String,
        first_purpose: BoltzRestoreKeyPurpose,
        second_provider_swap_id: String,
        second_purpose: BoltzRestoreKeyPurpose,
    },
    InvalidReportedIndex(String),
}

impl fmt::Display for BoltzRestoreValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRecord {
                provider_swap_id,
                reason,
            } => write!(
                formatter,
                "invalid Boltz restore record {provider_swap_id:?}: {reason}"
            ),
            Self::UnsupportedRecord {
                provider_swap_id,
                reason,
            } => write!(
                formatter,
                "unsupported Boltz restore record {provider_swap_id:?}: {reason}"
            ),
            Self::DuplicateProviderId(provider_swap_id) => {
                write!(formatter, "duplicate Boltz provider id {provider_swap_id:?}")
            }
            Self::ConflictingKeyIndex {
                child_index,
                first_provider_swap_id,
                first_purpose,
                second_provider_swap_id,
                second_purpose,
            } => write!(
                formatter,
                "Boltz child index {child_index} conflicts between {first_provider_swap_id:?}/{} and {second_provider_swap_id:?}/{}",
                first_purpose.as_str(),
                second_purpose.as_str()
            ),
            Self::InvalidReportedIndex(reason) => {
                write!(formatter, "invalid Boltz restore index: {reason}")
            }
        }
    }
}

impl std::error::Error for BoltzRestoreValidationError {}

/// Validate and normalize records returned by the pinned
/// `BoltzApiClientV2::post_swap_restore` API.
///
/// Bullnym currently creates only BTC-Lightning to L-BTC reverse swaps and
/// BTC-to-L-BTC chain swaps. Every other type or direction is rejected instead
/// of being guessed into a local obligation.
pub fn validate_restore_records(
    swap_master_key: &SwapMasterKey,
    provider_records: &[SwapRestoreResponse],
) -> Result<ValidatedBoltzRestoreSet, BoltzRestoreValidationError> {
    let mut provider_ids = HashSet::with_capacity(provider_records.len());
    let mut indexes: HashMap<u32, (String, BoltzRestoreKeyPurpose)> = HashMap::new();
    let mut records = Vec::with_capacity(provider_records.len());

    for record in provider_records {
        validate_record_header(record)?;
        if !provider_ids.insert(record.id.clone()) {
            return Err(BoltzRestoreValidationError::DuplicateProviderId(
                record.id.clone(),
            ));
        }

        let validated = match &record.swap_type {
            SwapRestoreType::Reverse => validate_reverse_record(swap_master_key, record)?,
            SwapRestoreType::Chain => validate_chain_record(swap_master_key, record)?,
            SwapRestoreType::Submarine => {
                return unsupported(record, "submarine swaps are not created by Bullnym")
            }
        };

        for key in &validated.keys {
            if let Some((first_id, first_purpose)) = indexes.get(&key.child_index) {
                return Err(BoltzRestoreValidationError::ConflictingKeyIndex {
                    child_index: key.child_index,
                    first_provider_swap_id: first_id.clone(),
                    first_purpose: *first_purpose,
                    second_provider_swap_id: validated.provider_swap_id.clone(),
                    second_purpose: key.purpose,
                });
            }
            indexes.insert(
                key.child_index,
                (validated.provider_swap_id.clone(), key.purpose),
            );
        }
        records.push(validated);
    }

    Ok(ValidatedBoltzRestoreSet {
        max_child_index: indexes.keys().copied().max(),
        records,
    })
}

/// The pinned endpoint uses `-1` for an empty result and otherwise returns the
/// highest direct unhardened child index present in its matching records.
pub fn validate_restore_index(
    response: &SwapRestoreIndexResponse,
) -> Result<Option<u32>, BoltzRestoreValidationError> {
    match response.index {
        -1 => Ok(None),
        index if (0..=i64::from(MAX_UNHARDENED_BOLTZ_CHILD_INDEX)).contains(&index) => {
            Ok(Some(index as u32))
        }
        index => Err(BoltzRestoreValidationError::InvalidReportedIndex(format!(
            "{index} is outside -1 or 0..={MAX_UNHARDENED_BOLTZ_CHILD_INDEX}"
        ))),
    }
}

fn validate_record_header(record: &SwapRestoreResponse) -> Result<(), BoltzRestoreValidationError> {
    if record.id.is_empty()
        || record.id.len() > MAX_PROVIDER_ID_BYTES
        || !record.id.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return invalid(record, "provider id is malformed");
    }
    if record.status.is_empty()
        || record.status.len() > MAX_STATUS_BYTES
        || !record
            .status
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return invalid(record, "status is malformed");
    }
    if record.created_at == 0 {
        return invalid(record, "creation timestamp must be positive");
    }
    Ok(())
}

fn validate_reverse_record(
    swap_master_key: &SwapMasterKey,
    record: &SwapRestoreResponse,
) -> Result<ValidatedBoltzRestoreRecord, BoltzRestoreValidationError> {
    require_direction(record, "BTC", "L-BTC")?;
    let claim = record
        .claim_details
        .as_ref()
        .ok_or_else(|| invalid_error(record, "reverse claim details are missing"))?;
    if record.refund_details.is_some() {
        return invalid(record, "reverse record unexpectedly has refund details");
    }
    validate_claim_details(record, claim, LIQUID_LEAF_VERSION, true)?;

    let amount = claim
        .amount
        .filter(|amount| *amount > 0)
        .ok_or_else(|| invalid_error(record, "reverse claim amount is missing or zero"))?;
    let (claim_keypair, claim_key) = derive_restore_key(
        swap_master_key,
        record,
        claim.key_index,
        BoltzRestoreKeyPurpose::ReverseClaim,
        true,
    )?;
    let preimage = Preimage::from_swap_key(&claim_keypair);
    if claim.preimage_hash != preimage.sha256.to_string() {
        return invalid(
            record,
            "reverse claim key_index does not derive the reported preimage hash",
        );
    }
    let server_public_key = parse_public_key(record, &claim.server_public_key)?;
    validate_exact_tree(
        record,
        "reverse",
        &claim.tree,
        preimage.hash160,
        &PublicKey::new(claim_keypair.public_key()),
        &server_public_key,
        claim.timeout_block_height,
    )?;
    let reconstructed = CreateReverseResponse {
        id: record.id.clone(),
        invoice: None,
        swap_tree: claim.tree.clone(),
        lockup_address: claim.lockup_address.clone(),
        refund_public_key: server_public_key,
        timeout_block_height: claim.timeout_block_height,
        onchain_amount: amount,
        blinding_key: claim.blinding_key.clone(),
    };
    reconstructed
        .validate(
            &preimage,
            &PublicKey::new(claim_keypair.public_key()),
            Chain::Liquid(LiquidChain::Liquid),
        )
        .map_err(|error| {
            invalid_error(
                record,
                format!("reverse contract does not bind the derived claim key: {error}"),
            )
        })?;

    Ok(ValidatedBoltzRestoreRecord {
        provider_swap_id: record.id.clone(),
        kind: BoltzRestoreKind::Reverse,
        status: record.status.clone(),
        created_at: record.created_at,
        keys: vec![claim_key],
    })
}

fn validate_chain_record(
    swap_master_key: &SwapMasterKey,
    record: &SwapRestoreResponse,
) -> Result<ValidatedBoltzRestoreRecord, BoltzRestoreValidationError> {
    require_direction(record, "BTC", "L-BTC")?;
    let claim = record
        .claim_details
        .as_ref()
        .ok_or_else(|| invalid_error(record, "chain claim details are missing"))?;
    let refund = record
        .refund_details
        .as_ref()
        .ok_or_else(|| invalid_error(record, "chain refund details are missing"))?;
    validate_claim_details(record, claim, LIQUID_LEAF_VERSION, true)?;
    validate_refund_details(record, refund, BTC_LEAF_VERSION, false)?;
    if claim.key_index == refund.key_index {
        return invalid(record, "chain claim and refund key indexes are identical");
    }

    let amount = claim
        .amount
        .filter(|amount| *amount > 0)
        .ok_or_else(|| invalid_error(record, "chain claim amount is missing or zero"))?;
    let (claim_keypair, claim_key) = derive_restore_key(
        swap_master_key,
        record,
        claim.key_index,
        BoltzRestoreKeyPurpose::ChainClaim,
        true,
    )?;
    let (refund_keypair, refund_key) = derive_restore_key(
        swap_master_key,
        record,
        refund.key_index,
        BoltzRestoreKeyPurpose::ChainRefund,
        false,
    )?;
    let preimage = Preimage::from_swap_key(&claim_keypair);
    if claim.preimage_hash != preimage.sha256.to_string() {
        return invalid(
            record,
            "chain claim key_index does not derive the reported preimage hash",
        );
    }

    let liquid_server_public_key = parse_public_key(record, &claim.server_public_key)?;
    let bitcoin_server_public_key = parse_public_key(record, &refund.server_public_key)?;
    validate_exact_tree(
        record,
        "Liquid claim-side",
        &claim.tree,
        preimage.hash160,
        &PublicKey::new(claim_keypair.public_key()),
        &liquid_server_public_key,
        claim.timeout_block_height,
    )?;
    validate_exact_tree(
        record,
        "Bitcoin refund-side",
        &refund.tree,
        preimage.hash160,
        &bitcoin_server_public_key,
        &PublicKey::new(refund_keypair.public_key()),
        refund.timeout_block_height,
    )?;

    let reconstructed = CreateChainResponse {
        id: record.id.clone(),
        claim_details: restore_claim_to_chain_details(record, claim, amount)?,
        lockup_details: restore_refund_to_chain_details(record, refund)?,
    };
    reconstructed
        .validate(
            &PublicKey::new(claim_keypair.public_key()),
            &PublicKey::new(refund_keypair.public_key()),
            Chain::Bitcoin(BitcoinChain::Bitcoin),
            Chain::Liquid(LiquidChain::Liquid),
        )
        .map_err(|error| {
            invalid_error(
                record,
                format!("chain contracts do not bind the derived role keys: {error}"),
            )
        })?;

    Ok(ValidatedBoltzRestoreRecord {
        provider_swap_id: record.id.clone(),
        kind: BoltzRestoreKind::Chain,
        status: record.status.clone(),
        created_at: record.created_at,
        keys: vec![claim_key, refund_key],
    })
}

fn derive_restore_key(
    swap_master_key: &SwapMasterKey,
    record: &SwapRestoreResponse,
    child_index: u32,
    purpose: BoltzRestoreKeyPurpose,
    include_preimage: bool,
) -> Result<
    (
        boltz_client::bitcoin::secp256k1::Keypair,
        ValidatedBoltzRestoreKey,
    ),
    BoltzRestoreValidationError,
> {
    if child_index > MAX_UNHARDENED_BOLTZ_CHILD_INDEX {
        return invalid(
            record,
            format!(
                "{} key_index {child_index} is outside 0..={MAX_UNHARDENED_BOLTZ_CHILD_INDEX}",
                purpose.as_str()
            ),
        );
    }
    let keypair = swap_master_key
        .derive_swapkey(u64::from(child_index))
        .map_err(|error| {
            invalid_error(
                record,
                format!(
                    "{} key_index {child_index} cannot be derived as m/{child_index}: {error}",
                    purpose.as_str()
                ),
            )
        })?;
    let preimage_sha256_hex =
        include_preimage.then(|| Preimage::from_swap_key(&keypair).sha256.to_string());
    let identity = ValidatedBoltzRestoreKey {
        purpose,
        child_index,
        public_key_hex: PublicKey::new(keypair.public_key()).to_string(),
        preimage_sha256_hex,
    };
    Ok((keypair, identity))
}

fn validate_claim_details(
    record: &SwapRestoreResponse,
    details: &ClaimDetails,
    leaf_version: u8,
    require_blinding_key: bool,
) -> Result<(), BoltzRestoreValidationError> {
    validate_common_details(
        record,
        &details.tree,
        details.key_index,
        &details.lockup_address,
        details.timeout_block_height,
        details.blinding_key.as_deref(),
        leaf_version,
        require_blinding_key,
    )?;
    require_lower_hex(record, "preimage hash", &details.preimage_hash, 32)
}

fn validate_refund_details(
    record: &SwapRestoreResponse,
    details: &RefundDetails,
    leaf_version: u8,
    require_blinding_key: bool,
) -> Result<(), BoltzRestoreValidationError> {
    validate_common_details(
        record,
        &details.tree,
        details.key_index,
        &details.lockup_address,
        details.timeout_block_height,
        details.blinding_key.as_deref(),
        leaf_version,
        require_blinding_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_common_details(
    record: &SwapRestoreResponse,
    tree: &SwapTree,
    key_index: u32,
    lockup_address: &str,
    timeout_block_height: u32,
    blinding_key: Option<&str>,
    leaf_version: u8,
    require_blinding_key: bool,
) -> Result<(), BoltzRestoreValidationError> {
    if key_index > MAX_UNHARDENED_BOLTZ_CHILD_INDEX {
        return invalid(
            record,
            format!("key_index {key_index} is outside the unhardened derivation domain"),
        );
    }
    if lockup_address.is_empty() || lockup_address.len() > 256 {
        return invalid(record, "lockup address is malformed");
    }
    if timeout_block_height == 0 {
        return invalid(record, "timeout block height must be positive");
    }
    if require_blinding_key {
        let blinding_key =
            blinding_key.ok_or_else(|| invalid_error(record, "Liquid blinding key is missing"))?;
        require_lower_hex(record, "Liquid blinding key", blinding_key, 32)?;
    } else if blinding_key.is_some() {
        return invalid(record, "Bitcoin details unexpectedly have a blinding key");
    }
    validate_tree(record, tree, leaf_version)
}

fn validate_tree(
    record: &SwapRestoreResponse,
    tree: &SwapTree,
    expected_leaf_version: u8,
) -> Result<(), BoltzRestoreValidationError> {
    if tree.covenant_claim_leaf.is_some() {
        return invalid(record, "covenant restore trees are unsupported");
    }
    for (name, leaf) in [("claim", &tree.claim_leaf), ("refund", &tree.refund_leaf)] {
        if leaf.version != expected_leaf_version {
            return invalid(
                record,
                format!("{name} leaf version is not {expected_leaf_version:#04x}"),
            );
        }
        if leaf.output.is_empty()
            || leaf.output.len() > MAX_SCRIPT_HEX_BYTES * 2
            || !leaf.output.len().is_multiple_of(2)
            || !leaf
                .output
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return invalid(record, format!("{name} leaf script is malformed"));
        }
    }
    Ok(())
}

fn validate_exact_tree(
    record: &SwapRestoreResponse,
    name: &str,
    tree: &SwapTree,
    hashlock: hash160::Hash,
    receiver_public_key: &PublicKey,
    sender_public_key: &PublicKey,
    timeout_block_height: u32,
) -> Result<(), BoltzRestoreValidationError> {
    let expected_claim = expected_claim_script(hashlock, receiver_public_key);
    if tree.claim_leaf.output != hex::encode(expected_claim) {
        return invalid(
            record,
            format!("{name} claim leaf does not match the derived key role"),
        );
    }
    let expected_refund = expected_refund_script(sender_public_key, timeout_block_height);
    if tree.refund_leaf.output != hex::encode(expected_refund) {
        return invalid(
            record,
            format!("{name} refund leaf does not match the derived key role"),
        );
    }
    Ok(())
}

fn expected_claim_script(hashlock: hash160::Hash, receiver: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_HASH160)
        .push_slice(hashlock.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&receiver.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn expected_refund_script(sender: &PublicKey, timeout_block_height: u32) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&sender.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_lock_time(LockTime::from_consensus(timeout_block_height))
        .push_opcode(OP_CLTV)
        .into_script()
}

fn restore_claim_to_chain_details(
    record: &SwapRestoreResponse,
    details: &ClaimDetails,
    amount: u64,
) -> Result<ChainSwapDetails, BoltzRestoreValidationError> {
    Ok(ChainSwapDetails {
        swap_tree: details.tree.clone(),
        lockup_address: details.lockup_address.clone(),
        server_public_key: parse_public_key(record, &details.server_public_key)?,
        timeout_block_height: details.timeout_block_height,
        amount,
        blinding_key: details.blinding_key.clone(),
        refund_address: None,
        claim_address: None,
        bip21: None,
    })
}

fn restore_refund_to_chain_details(
    record: &SwapRestoreResponse,
    details: &RefundDetails,
) -> Result<ChainSwapDetails, BoltzRestoreValidationError> {
    Ok(ChainSwapDetails {
        swap_tree: details.tree.clone(),
        lockup_address: details.lockup_address.clone(),
        server_public_key: parse_public_key(record, &details.server_public_key)?,
        timeout_block_height: details.timeout_block_height,
        amount: 0,
        blinding_key: details.blinding_key.clone(),
        refund_address: None,
        claim_address: None,
        bip21: None,
    })
}

fn parse_public_key(
    record: &SwapRestoreResponse,
    value: &str,
) -> Result<PublicKey, BoltzRestoreValidationError> {
    PublicKey::from_str(value).map_err(|_| invalid_error(record, "server public key is malformed"))
}

fn require_direction(
    record: &SwapRestoreResponse,
    expected_from: &str,
    expected_to: &str,
) -> Result<(), BoltzRestoreValidationError> {
    if record.from != expected_from || record.to != expected_to {
        return unsupported(
            record,
            format!(
                "direction {} -> {} is not Bullnym's supported {} -> {} direction",
                record.from, record.to, expected_from, expected_to
            ),
        );
    }
    Ok(())
}

fn require_lower_hex(
    record: &SwapRestoreResponse,
    name: &str,
    value: &str,
    bytes: usize,
) -> Result<(), BoltzRestoreValidationError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(record, format!("{name} must be {bytes}-byte lowercase hex"));
    }
    Ok(())
}

fn invalid<T>(
    record: &SwapRestoreResponse,
    reason: impl Into<String>,
) -> Result<T, BoltzRestoreValidationError> {
    Err(invalid_error(record, reason))
}

fn invalid_error(
    record: &SwapRestoreResponse,
    reason: impl Into<String>,
) -> BoltzRestoreValidationError {
    BoltzRestoreValidationError::InvalidRecord {
        provider_swap_id: record.id.clone(),
        reason: reason.into(),
    }
}

fn unsupported<T>(
    record: &SwapRestoreResponse,
    reason: impl Into<String>,
) -> Result<T, BoltzRestoreValidationError> {
    Err(BoltzRestoreValidationError::UnsupportedRecord {
        provider_swap_id: record.id.clone(),
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltz_client::network::Network;
    use boltz_client::swaps::boltz::{Leaf, Side, SwapType};
    use boltz_client::{BtcSwapScript, LBtcSwapScript, ZKKeyPair, ZKSecp256k1};

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const BLINDING_KEY: &str = "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";

    fn master_key() -> SwapMasterKey {
        SwapMasterKey::from_mnemonic(TEST_MNEMONIC, None, Network::Mainnet).unwrap()
    }

    fn tree(
        preimage: &Preimage,
        receiver: &PublicKey,
        sender: &PublicKey,
        timeout: u32,
        version: u8,
    ) -> SwapTree {
        SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(expected_claim_script(preimage.hash160, receiver)),
                version,
            },
            refund_leaf: Leaf {
                output: hex::encode(expected_refund_script(sender, timeout)),
                version,
            },
            covenant_claim_leaf: None,
        }
    }

    fn realistic_records(
        reverse_index: u32,
        chain_claim_index: u32,
        chain_refund_index: u32,
    ) -> Vec<SwapRestoreResponse> {
        let master = master_key();
        let reverse_keypair = master.derive_swapkey(u64::from(reverse_index)).unwrap();
        let reverse_key = PublicKey::new(reverse_keypair.public_key());
        let reverse_preimage = Preimage::from_swap_key(&reverse_keypair);
        let chain_claim_keypair = master.derive_swapkey(u64::from(chain_claim_index)).unwrap();
        let chain_claim_key = PublicKey::new(chain_claim_keypair.public_key());
        let chain_preimage = Preimage::from_swap_key(&chain_claim_keypair);
        let chain_refund_keypair = master
            .derive_swapkey(u64::from(chain_refund_index))
            .unwrap();
        let chain_refund_key = PublicKey::new(chain_refund_keypair.public_key());
        let bitcoin_server_key = PublicKey::from_str(
            "031c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8",
        )
        .unwrap();
        let liquid_server_key = PublicKey::from_str(
            "033009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01a",
        )
        .unwrap();
        let reverse_server_key = PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
        let reverse_timeout = 3_972_100;
        let bitcoin_timeout = 958_033;
        let liquid_timeout = 3_972_215;
        let blinding_key = ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), BLINDING_KEY).unwrap();

        let reverse_tree = tree(
            &reverse_preimage,
            &reverse_key,
            &reverse_server_key,
            reverse_timeout,
            LIQUID_LEAF_VERSION,
        );
        let reverse_address = LBtcSwapScript {
            swap_type: SwapType::ReverseSubmarine,
            side: None,
            funding_addrs: None,
            hashlock: reverse_preimage.hash160,
            receiver_pubkey: reverse_key,
            locktime: boltz_client::elements::LockTime::from_consensus(reverse_timeout),
            sender_pubkey: reverse_server_key,
            blinding_key,
        }
        .to_address(LiquidChain::Liquid)
        .unwrap()
        .to_string();

        let bitcoin_tree = tree(
            &chain_preimage,
            &bitcoin_server_key,
            &chain_refund_key,
            bitcoin_timeout,
            BTC_LEAF_VERSION,
        );
        let bitcoin_address = BtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Lockup),
            funding_addrs: None,
            hashlock: chain_preimage.hash160,
            receiver_pubkey: bitcoin_server_key,
            locktime: boltz_client::bitcoin::absolute::LockTime::from_consensus(bitcoin_timeout),
            sender_pubkey: chain_refund_key,
        }
        .to_address(BitcoinChain::Bitcoin)
        .unwrap()
        .to_string();
        let liquid_tree = tree(
            &chain_preimage,
            &chain_claim_key,
            &liquid_server_key,
            liquid_timeout,
            LIQUID_LEAF_VERSION,
        );
        let liquid_address = LBtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Claim),
            funding_addrs: None,
            hashlock: chain_preimage.hash160,
            receiver_pubkey: chain_claim_key,
            locktime: boltz_client::elements::LockTime::from_consensus(liquid_timeout),
            sender_pubkey: liquid_server_key,
            blinding_key,
        }
        .to_address(LiquidChain::Liquid)
        .unwrap()
        .to_string();

        vec![
            SwapRestoreResponse {
                id: "RstrRev00001".into(),
                swap_type: SwapRestoreType::Reverse,
                status: "transaction.mempool".into(),
                created_at: 1_784_000_000,
                from: "BTC".into(),
                to: "L-BTC".into(),
                claim_details: Some(ClaimDetails {
                    tree: reverse_tree,
                    amount: Some(21_000),
                    key_index: reverse_index,
                    lockup_address: reverse_address,
                    server_public_key: reverse_server_key.to_string(),
                    timeout_block_height: reverse_timeout,
                    blinding_key: Some(BLINDING_KEY.into()),
                    preimage_hash: reverse_preimage.sha256.to_string(),
                }),
                refund_details: None,
            },
            SwapRestoreResponse {
                id: "RstrChn00001".into(),
                swap_type: SwapRestoreType::Chain,
                status: "transaction.server.mempool".into(),
                created_at: 1_784_000_100,
                from: "BTC".into(),
                to: "L-BTC".into(),
                claim_details: Some(ClaimDetails {
                    tree: liquid_tree,
                    amount: Some(25_000),
                    key_index: chain_claim_index,
                    lockup_address: liquid_address,
                    server_public_key: liquid_server_key.to_string(),
                    timeout_block_height: liquid_timeout,
                    blinding_key: Some(BLINDING_KEY.into()),
                    preimage_hash: chain_preimage.sha256.to_string(),
                }),
                refund_details: Some(RefundDetails {
                    tree: bitcoin_tree,
                    key_index: chain_refund_index,
                    lockup_address: bitcoin_address,
                    server_public_key: bitcoin_server_key.to_string(),
                    timeout_block_height: bitcoin_timeout,
                    blinding_key: None,
                }),
            },
        ]
    }

    fn serialized_fixture() -> Vec<SwapRestoreResponse> {
        serde_json::from_str(include_str!("../tests/fixtures/boltz-xpub-restore-v1.json")).unwrap()
    }

    fn assert_error_contains(records: &[SwapRestoreResponse], expected: &str) {
        let error = validate_restore_records(&master_key(), records).unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error}"
        );
    }

    #[test]
    fn realistic_serialized_fixture_maps_each_key_index_to_exact_direct_child() {
        let fixture = serialized_fixture();
        assert_eq!(
            serde_json::to_value(&fixture).unwrap(),
            serde_json::to_value(realistic_records(100, 101, 102)).unwrap(),
            "the checked-in wire fixture must remain generated by the pinned Boltz types"
        );

        let master = master_key();
        let validated = validate_restore_records(&master, &fixture).unwrap();
        assert_eq!(validated.records.len(), 2);
        assert_eq!(validated.max_child_index, Some(102));
        let keys: Vec<_> = validated
            .records
            .iter()
            .flat_map(|record| record.keys.iter())
            .collect();
        assert_eq!(
            keys.iter().map(|key| key.child_index).collect::<Vec<_>>(),
            [100, 101, 102]
        );
        for key in keys {
            let expected = master.derive_swapkey(u64::from(key.child_index)).unwrap();
            assert_eq!(
                key.public_key_hex,
                PublicKey::new(expected.public_key()).to_string()
            );
            assert_eq!(key.derivation_path(), format!("m/{}", key.child_index));
            match key.purpose {
                BoltzRestoreKeyPurpose::ReverseClaim | BoltzRestoreKeyPurpose::ChainClaim => {
                    let expected_hash = Preimage::from_swap_key(&expected).sha256.to_string();
                    assert_eq!(
                        key.preimage_sha256_hex.as_deref(),
                        Some(expected_hash.as_str())
                    );
                }
                BoltzRestoreKeyPurpose::ChainRefund => {
                    assert_eq!(key.preimage_sha256_hex, None);
                }
            }
        }

        let reported: SwapRestoreIndexResponse = serde_json::from_str(include_str!(
            "../tests/fixtures/boltz-xpub-restore-index-v1.json"
        ))
        .unwrap();
        assert_eq!(
            validated.validate_reported_high_water(&reported).unwrap(),
            Some(102)
        );
    }

    #[test]
    fn exact_maximum_unhardened_index_is_reconstructable_for_every_role() {
        let mut reverse = realistic_records(MAX_UNHARDENED_BOLTZ_CHILD_INDEX, 1, 2);
        reverse.truncate(1);
        let restored = validate_restore_records(&master_key(), &reverse).unwrap();
        assert_eq!(
            restored.max_child_index,
            Some(MAX_UNHARDENED_BOLTZ_CHILD_INDEX)
        );

        let mut chain_claim = realistic_records(1, MAX_UNHARDENED_BOLTZ_CHILD_INDEX, 2);
        chain_claim.remove(0);
        let restored = validate_restore_records(&master_key(), &chain_claim).unwrap();
        assert_eq!(
            restored.max_child_index,
            Some(MAX_UNHARDENED_BOLTZ_CHILD_INDEX)
        );

        let mut chain_refund = realistic_records(1, 2, MAX_UNHARDENED_BOLTZ_CHILD_INDEX);
        chain_refund.remove(0);
        let restored = validate_restore_records(&master_key(), &chain_refund).unwrap();
        assert_eq!(
            restored.max_child_index,
            Some(MAX_UNHARDENED_BOLTZ_CHILD_INDEX)
        );
    }

    #[test]
    fn bit_31_and_larger_are_rejected_for_every_restore_role() {
        for invalid_index in [MAX_UNHARDENED_BOLTZ_CHILD_INDEX + 1, u32::MAX] {
            let mut reverse = serialized_fixture();
            reverse[0].claim_details.as_mut().unwrap().key_index = invalid_index;
            assert_error_contains(&reverse, "outside the unhardened derivation domain");

            let mut claim = serialized_fixture();
            claim[1].claim_details.as_mut().unwrap().key_index = invalid_index;
            assert_error_contains(&claim, "outside the unhardened derivation domain");

            let mut refund = serialized_fixture();
            refund[1].refund_details.as_mut().unwrap().key_index = invalid_index;
            assert_error_contains(&refund, "outside the unhardened derivation domain");
        }
    }

    #[test]
    fn provider_key_indexes_must_bind_the_derived_preimage_and_contract_role() {
        let mut reverse = serialized_fixture();
        reverse[0].claim_details.as_mut().unwrap().key_index = 103;
        assert_error_contains(&reverse, "does not derive the reported preimage hash");

        let mut chain_claim = serialized_fixture();
        chain_claim[1].claim_details.as_mut().unwrap().key_index = 103;
        assert_error_contains(&chain_claim, "does not derive the reported preimage hash");

        let mut chain_refund = serialized_fixture();
        chain_refund[1].refund_details.as_mut().unwrap().key_index = 103;
        assert_error_contains(
            &chain_refund,
            "Bitcoin refund-side refund leaf does not match the derived key role",
        );
    }

    #[test]
    fn duplicate_provider_ids_and_conflicting_global_indexes_fail_closed() {
        let mut duplicate_id = serialized_fixture();
        duplicate_id.push(duplicate_id[0].clone());
        assert_error_contains(&duplicate_id, "duplicate Boltz provider id");

        let mut conflicting_index = serialized_fixture();
        let mut duplicate_key_record = conflicting_index[0].clone();
        duplicate_key_record.id = "RstrRev00002".into();
        conflicting_index.push(duplicate_key_record);
        assert_error_contains(&conflicting_index, "child index 100 conflicts");

        let mut same_chain_index = serialized_fixture();
        same_chain_index[1]
            .refund_details
            .as_mut()
            .unwrap()
            .key_index = 101;
        assert_error_contains(
            &same_chain_index,
            "chain claim and refund key indexes are identical",
        );
    }

    #[test]
    fn malformed_restore_records_fail_before_becoming_domain_records() {
        let mut malformed_id = serialized_fixture();
        malformed_id[0].id = "bad provider id".into();
        assert_error_contains(&malformed_id, "provider id is malformed");

        let mut missing_details = serialized_fixture();
        missing_details[0].claim_details = None;
        assert_error_contains(&missing_details, "reverse claim details are missing");

        let mut malformed_key = serialized_fixture();
        malformed_key[1]
            .claim_details
            .as_mut()
            .unwrap()
            .server_public_key = "not-a-public-key".into();
        assert_error_contains(&malformed_key, "server public key is malformed");

        let mut malformed_preimage = serialized_fixture();
        malformed_preimage[0]
            .claim_details
            .as_mut()
            .unwrap()
            .preimage_hash = "AA".repeat(32);
        assert_error_contains(&malformed_preimage, "32-byte lowercase hex");

        let mut malformed_contract = serialized_fixture();
        malformed_contract[1]
            .refund_details
            .as_mut()
            .unwrap()
            .lockup_address = "bc1pinvented".into();
        assert_error_contains(&malformed_contract, "do not bind the derived role keys");

        let mut parser_ignored_suffix = serialized_fixture();
        parser_ignored_suffix[0]
            .claim_details
            .as_mut()
            .unwrap()
            .tree
            .claim_leaf
            .output
            .push_str("51");
        assert_error_contains(
            &parser_ignored_suffix,
            "reverse claim leaf does not match the derived key role",
        );
    }

    #[test]
    fn unsupported_types_directions_and_contract_variants_fail_closed() {
        let mut submarine = serialized_fixture();
        submarine[0].swap_type = SwapRestoreType::Submarine;
        assert_error_contains(&submarine, "submarine swaps are not created by Bullnym");

        let mut reverse_direction = serialized_fixture();
        reverse_direction[1].from = "L-BTC".into();
        reverse_direction[1].to = "BTC".into();
        assert_error_contains(&reverse_direction, "direction L-BTC -> BTC");

        let mut covenant = serialized_fixture();
        let claim = covenant[0].claim_details.as_mut().unwrap();
        claim.tree.covenant_claim_leaf = Some(claim.tree.claim_leaf.clone());
        assert_error_contains(&covenant, "covenant restore trees are unsupported");
    }

    #[test]
    fn pinned_wire_types_reject_negative_indexes_and_unknown_swap_types() {
        let fixture = include_str!("../tests/fixtures/boltz-xpub-restore-v1.json");
        let negative = fixture.replacen("\"keyIndex\": 100", "\"keyIndex\": -1", 1);
        assert!(serde_json::from_str::<Vec<SwapRestoreResponse>>(&negative).is_err());

        let unknown = fixture.replacen("\"type\": \"reverse\"", "\"type\": \"future\"", 1);
        assert!(serde_json::from_str::<Vec<SwapRestoreResponse>>(&unknown).is_err());
    }

    #[test]
    fn restore_index_has_only_empty_or_unhardened_high_water_semantics() {
        assert_eq!(
            validate_restore_index(&SwapRestoreIndexResponse { index: -1 }).unwrap(),
            None
        );
        assert_eq!(
            validate_restore_index(&SwapRestoreIndexResponse {
                index: i64::from(MAX_UNHARDENED_BOLTZ_CHILD_INDEX),
            })
            .unwrap(),
            Some(MAX_UNHARDENED_BOLTZ_CHILD_INDEX)
        );
        for invalid in [
            -2,
            i64::from(MAX_UNHARDENED_BOLTZ_CHILD_INDEX) + 1,
            i64::MAX,
        ] {
            let error =
                validate_restore_index(&SwapRestoreIndexResponse { index: invalid }).unwrap_err();
            assert!(error.to_string().contains("outside -1 or"));
        }
    }

    #[test]
    fn reported_high_water_cannot_replace_or_disagree_with_record_reconciliation() {
        let restored = validate_restore_records(&master_key(), &serialized_fixture()).unwrap();
        let error = restored
            .validate_reported_high_water(&SwapRestoreIndexResponse { index: 101 })
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not equal validated record high-water"));

        let empty = validate_restore_records(&master_key(), &[]).unwrap();
        assert_eq!(
            empty
                .validate_reported_high_water(&SwapRestoreIndexResponse { index: -1 })
                .unwrap(),
            None
        );
    }
}
