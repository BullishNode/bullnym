//! Pure staging boundary for one already-persisted chain-swap manifest.
//!
//! This module deliberately performs no database, object-store, provider, or
//! runtime work. The caller must obtain an authoritative chain-swap row, its
//! public migration-050 lineage projection, both exact allocation-journal
//! rows, and a migration-052 sequence reservation before entering this seam.
//! Private preimages and private claim/refund keys remain borrowed inside the
//! [`crate::db::ChainSwapRecord`] and are never read, copied, formatted, or
//! included in the staged result.

use std::fmt;

use secp256k1::{Keypair, XOnlyPublicKey};
use uuid::Uuid;

use crate::db::{ChainSwapRecord, ManifestSequenceReservation, SwapKeyPurpose};
use crate::swap_manifest::{
    EncryptedSwapManifestV1, ImmutableChainSwapCreationV1, ManifestKeyAllocationV1,
    ManifestKeyPurposeV1, MerchantPolicyReferencesV1, SwapDerivationLineageV1, SwapManifestV1,
    SwapRestoreIdentityV1,
};

/// Public lineage columns persisted on the chain-swap row by migration 050.
///
/// `ChainSwapRecord` intentionally omits these columns from its ordinary
/// secret-bearing projection. A read boundary can populate this non-secret
/// type without widening access to the row's preimage or private keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedChainSwapLineageEvidence {
    pub chain_swap_id: Uuid,
    pub root_fingerprint: String,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub claim: PersistedChainSwapKeyReference,
    pub refund: PersistedChainSwapKeyReference,
}

/// One key reference copied from the persisted chain-swap row, never from its
/// private key columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedChainSwapKeyReference {
    pub allocation_id: Uuid,
    pub child_index: i64,
    pub public_key_hex: String,
    pub preimage_hash_hex: Option<String>,
}

/// Exact public evidence read from one append-only `swap_key_allocations` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSwapKeyAllocationEvidence {
    pub allocation_id: Uuid,
    pub root_fingerprint: String,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub child_index: i64,
    pub purpose: SwapKeyPurpose,
    pub public_key_hex: String,
    pub preimage_hash_hex: Option<String>,
}

/// Exact allocator high-water together with the namespace it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSwapKeyAllocationHighWaterEvidence {
    pub root_fingerprint: String,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub child_index: i64,
}

/// Borrowed cryptographic inputs for staging.
///
/// This type intentionally implements neither `Clone` nor `Debug`; its key
/// references cannot accidentally become part of a formatted request value.
pub struct ManifestStagingCrypto<'a> {
    encryption_key_id: &'a str,
    encryption_key: &'a [u8; 32],
    signing_key: &'a Keypair,
    pinned_signer: &'a XOnlyPublicKey,
}

impl<'a> ManifestStagingCrypto<'a> {
    pub fn new(
        encryption_key_id: &'a str,
        encryption_key: &'a [u8; 32],
        signing_key: &'a Keypair,
        pinned_signer: &'a XOnlyPublicKey,
    ) -> Self {
        Self {
            encryption_key_id,
            encryption_key,
            signing_key,
            pinned_signer,
        }
    }
}

/// Complete borrowed input for the pure manifest-staging boundary.
///
/// This type intentionally implements neither `Clone` nor `Debug` because it
/// borrows the secret-bearing database row. Staging reads only its public
/// identity, creation, instruction, amount, and policy fields.
pub struct ManifestStagingRequest<'a> {
    pub chain_swap: &'a ChainSwapRecord,
    pub persisted_lineage: &'a PersistedChainSwapLineageEvidence,
    pub claim_allocation: &'a PublicSwapKeyAllocationEvidence,
    pub refund_allocation: &'a PublicSwapKeyAllocationEvidence,
    pub sequence_reservation: ManifestSequenceReservation,
    pub manifest_id: Uuid,
    pub allocation_high_water: &'a PublicSwapKeyAllocationHighWaterEvidence,
    pub merchant_policy: &'a MerchantPolicyReferencesV1,
    pub crypto: ManifestStagingCrypto<'a>,
}

/// Validated plaintext and authenticated encrypted envelope produced together.
#[derive(Clone, PartialEq, Eq)]
pub struct StagedSwapManifestV1 {
    pub manifest: SwapManifestV1,
    pub encrypted_envelope: EncryptedSwapManifestV1,
}

impl fmt::Debug for StagedSwapManifestV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedSwapManifestV1")
            .field("manifest_id", &self.manifest.restore_identity.manifest_id)
            .field(
                "chain_swap_id",
                &self.manifest.restore_identity.chain_swap_id,
            )
            .field(
                "manifest_sequence",
                &self.manifest.restore_identity.manifest_sequence,
            )
            .field(
                "encrypted_envelope_bytes",
                &self.encrypted_envelope.encoded().len(),
            )
            .field("encrypted_envelope", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestStagingError {
    IncompleteRecord { field: &'static str },
    RecordLineageMismatch { field: &'static str },
    ClaimAllocationMismatch { field: &'static str },
    RefundAllocationMismatch { field: &'static str },
    AllocationHighWaterMismatch { field: &'static str },
    MerchantPolicyMismatch { field: &'static str },
    UnexpectedSigner,
    InvalidManifest,
    EnvelopeCreationFailed,
    EnvelopeValidationFailed,
}

impl fmt::Display for ManifestStagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteRecord { field } => {
                write!(f, "chain-swap record lacks required public field {field}")
            }
            Self::RecordLineageMismatch { field } => {
                write!(f, "chain-swap lineage does not match record field {field}")
            }
            Self::ClaimAllocationMismatch { field } => {
                write!(
                    f,
                    "claim allocation does not match persisted lineage field {field}"
                )
            }
            Self::RefundAllocationMismatch { field } => {
                write!(
                    f,
                    "refund allocation does not match persisted lineage field {field}"
                )
            }
            Self::AllocationHighWaterMismatch { field } => write!(
                f,
                "allocation high-water does not match persisted lineage field {field}"
            ),
            Self::MerchantPolicyMismatch { field } => {
                write!(
                    f,
                    "merchant policy does not match persisted record field {field}"
                )
            }
            Self::UnexpectedSigner => {
                f.write_str("manifest signing key does not match the pinned signer")
            }
            Self::InvalidManifest => {
                f.write_str("persisted evidence cannot form a valid recovery manifest")
            }
            Self::EnvelopeCreationFailed => {
                f.write_str("recovery-manifest envelope creation failed")
            }
            Self::EnvelopeValidationFailed => {
                f.write_str("recovery-manifest envelope self-validation failed")
            }
        }
    }
}

// Deliberately source-free: lower-layer validation errors can include
// untrusted provider or address details and must not escape this staging seam.
impl std::error::Error for ManifestStagingError {}

/// Build, validate, sign, encrypt, and authenticate one manifest without I/O.
pub fn stage_swap_manifest_v1(
    request: ManifestStagingRequest<'_>,
) -> Result<StagedSwapManifestV1, ManifestStagingError> {
    let ManifestStagingRequest {
        chain_swap,
        persisted_lineage,
        claim_allocation,
        refund_allocation,
        sequence_reservation,
        manifest_id,
        allocation_high_water,
        merchant_policy,
        crypto,
    } = request;

    let nym = required_record_text(chain_swap.nym.as_deref(), "nym")?;
    let lockup_bip21 = required_record_text(chain_swap.lockup_bip21.as_deref(), "lockup_bip21")?;
    let creation_terms =
        chain_swap
            .creation_terms
            .as_ref()
            .ok_or(ManifestStagingError::IncompleteRecord {
                field: "creation_terms",
            })?;

    if chain_swap.from_chain != "BTC" {
        return Err(ManifestStagingError::IncompleteRecord {
            field: "from_chain",
        });
    }
    if chain_swap.to_chain != "L-BTC" {
        return Err(ManifestStagingError::IncompleteRecord { field: "to_chain" });
    }
    if persisted_lineage.chain_swap_id != chain_swap.id {
        return Err(ManifestStagingError::RecordLineageMismatch {
            field: "chain_swap_id",
        });
    }

    cross_check_allocation(
        persisted_lineage,
        &persisted_lineage.claim,
        claim_allocation,
        SwapKeyPurpose::ChainClaim,
        true,
    )
    .map_err(|field| ManifestStagingError::ClaimAllocationMismatch { field })?;
    cross_check_allocation(
        persisted_lineage,
        &persisted_lineage.refund,
        refund_allocation,
        SwapKeyPurpose::ChainRefund,
        false,
    )
    .map_err(|field| ManifestStagingError::RefundAllocationMismatch { field })?;
    cross_check_high_water(persisted_lineage, allocation_high_water)
        .map_err(|field| ManifestStagingError::AllocationHighWaterMismatch { field })?;

    if merchant_policy.invoice_id != chain_swap.invoice_id {
        return Err(ManifestStagingError::MerchantPolicyMismatch {
            field: "invoice_id",
        });
    }
    if merchant_policy.merchant_nym != nym {
        return Err(ManifestStagingError::MerchantPolicyMismatch {
            field: "merchant_nym",
        });
    }
    if merchant_policy.merchant_liquid_destination != creation_terms.merchant_liquid_destination {
        return Err(ManifestStagingError::MerchantPolicyMismatch {
            field: "merchant_liquid_destination",
        });
    }
    if merchant_policy.merchant_emergency_btc_address
        != creation_terms.merchant_emergency_btc_address
    {
        return Err(ManifestStagingError::MerchantPolicyMismatch {
            field: "merchant_emergency_btc_address",
        });
    }
    if merchant_policy.emergency_bitcoin_commitment_id
        != creation_terms.recovery_address_commitment_id
    {
        return Err(ManifestStagingError::MerchantPolicyMismatch {
            field: "emergency_bitcoin_commitment_id",
        });
    }

    let actual_signer = crypto.signing_key.x_only_public_key().0;
    if &actual_signer != crypto.pinned_signer {
        return Err(ManifestStagingError::UnexpectedSigner);
    }

    let manifest = SwapManifestV1::new(
        SwapRestoreIdentityV1 {
            manifest_id,
            manifest_sequence: sequence_reservation.manifest_sequence(),
            previous_manifest_id: sequence_reservation.previous_manifest_id(),
            chain_swap_id: chain_swap.id,
            boltz_swap_id: chain_swap.boltz_swap_id.clone(),
            created_at_unix: chain_swap.created_at_unix,
        },
        SwapDerivationLineageV1 {
            root_fingerprint: persisted_lineage.root_fingerprint.clone(),
            key_epoch: persisted_lineage.key_epoch,
            derivation_scheme_version: persisted_lineage.derivation_scheme_version,
            allocation_high_water_child_index: allocation_high_water.child_index,
            claim: manifest_allocation(claim_allocation, ManifestKeyPurposeV1::ChainClaim),
            refund: manifest_allocation(refund_allocation, ManifestKeyPurposeV1::ChainRefund),
        },
        ImmutableChainSwapCreationV1::from_persisted_terms(
            creation_terms,
            chain_swap.lockup_address.clone(),
            lockup_bip21.to_owned(),
            chain_swap.user_lock_amount_sat,
            chain_swap.server_lock_amount_sat,
            chain_swap.boltz_response_json.clone(),
        ),
        merchant_policy.clone(),
    )
    .map_err(|_| ManifestStagingError::InvalidManifest)?;

    let encoded = manifest
        .seal(
            crypto.encryption_key_id,
            crypto.encryption_key,
            crypto.signing_key,
        )
        .map_err(|_| ManifestStagingError::EnvelopeCreationFailed)?;
    let encrypted_envelope = EncryptedSwapManifestV1::parse(encoded)
        .map_err(|_| ManifestStagingError::EnvelopeValidationFailed)?;
    let reopened = SwapManifestV1::open(
        encrypted_envelope.encoded(),
        crypto.encryption_key_id,
        crypto.encryption_key,
        crypto.pinned_signer,
    )
    .map_err(|_| ManifestStagingError::EnvelopeValidationFailed)?;
    if reopened != manifest {
        return Err(ManifestStagingError::EnvelopeValidationFailed);
    }

    Ok(StagedSwapManifestV1 {
        manifest,
        encrypted_envelope,
    })
}

fn required_record_text<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, ManifestStagingError> {
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(ManifestStagingError::IncompleteRecord { field }),
    }
}

fn cross_check_allocation(
    lineage: &PersistedChainSwapLineageEvidence,
    persisted: &PersistedChainSwapKeyReference,
    allocation: &PublicSwapKeyAllocationEvidence,
    expected_purpose: SwapKeyPurpose,
    requires_preimage_hash: bool,
) -> Result<(), &'static str> {
    if allocation.allocation_id != persisted.allocation_id {
        return Err("allocation_id");
    }
    if allocation.root_fingerprint != lineage.root_fingerprint {
        return Err("root_fingerprint");
    }
    if allocation.key_epoch != lineage.key_epoch {
        return Err("key_epoch");
    }
    if allocation.derivation_scheme_version != lineage.derivation_scheme_version {
        return Err("derivation_scheme_version");
    }
    if allocation.child_index != persisted.child_index {
        return Err("child_index");
    }
    if allocation.purpose != expected_purpose {
        return Err("purpose");
    }
    if allocation.public_key_hex != persisted.public_key_hex {
        return Err("public_key_hex");
    }
    if allocation.preimage_hash_hex != persisted.preimage_hash_hex {
        return Err("preimage_hash_hex");
    }
    if allocation.preimage_hash_hex.is_some() != requires_preimage_hash {
        return Err("preimage_hash_presence");
    }
    Ok(())
}

fn manifest_allocation(
    allocation: &PublicSwapKeyAllocationEvidence,
    purpose: ManifestKeyPurposeV1,
) -> ManifestKeyAllocationV1 {
    ManifestKeyAllocationV1 {
        allocation_id: allocation.allocation_id,
        child_index: allocation.child_index,
        purpose,
        public_key_hex: allocation.public_key_hex.clone(),
        preimage_hash_hex: allocation.preimage_hash_hex.clone(),
    }
}

fn cross_check_high_water(
    lineage: &PersistedChainSwapLineageEvidence,
    high_water: &PublicSwapKeyAllocationHighWaterEvidence,
) -> Result<(), &'static str> {
    if high_water.root_fingerprint != lineage.root_fingerprint {
        return Err("root_fingerprint");
    }
    if high_water.key_epoch != lineage.key_epoch {
        return Err("key_epoch");
    }
    if high_water.derivation_scheme_version != lineage.derivation_scheme_version {
        return Err("derivation_scheme_version");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;
    use std::str::FromStr;

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{hash160, Hash as _};
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
    };
    use bitcoin::script::Builder;
    use bitcoin::ScriptBuf;
    use boltz_client::network::{BitcoinChain, LiquidChain};
    use boltz_client::swaps::boltz::{
        ChainSwapDetails, CreateChainResponse, Leaf, Side, SwapTree, SwapType,
    };
    use boltz_client::util::secrets::Preimage;
    use boltz_client::{
        BtcSwapScript, LBtcSwapScript, PublicKey as BoltzPublicKey, ZKKeyPair, ZKSecp256k1,
    };
    use secp256k1::{Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    use crate::db::{ChainSwapCreationTerms, ManifestSequenceReservation};
    use crate::swap_manifest::MAX_UNHARDENED_SWAP_CHILD_INDEX;

    const ENCRYPTION_KEY: [u8; 32] = [0x42; 32];
    const PRIVATE_PREIMAGE_SENTINEL: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PRIVATE_CLAIM_KEY_SENTINEL: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PRIVATE_REFUND_KEY_SENTINEL: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const LIQUID_DESTINATION: &str = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";
    const EMERGENCY_ADDRESS: &str =
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

    struct Fixture {
        record: ChainSwapRecord,
        persisted_lineage: PersistedChainSwapLineageEvidence,
        claim_allocation: PublicSwapKeyAllocationEvidence,
        refund_allocation: PublicSwapKeyAllocationEvidence,
        policy: MerchantPolicyReferencesV1,
        reservation: ManifestSequenceReservation,
        manifest_id: Uuid,
        high_water: PublicSwapKeyAllocationHighWaterEvidence,
        encryption_key_id: String,
        encryption_key: [u8; 32],
        signing_key: Keypair,
        pinned_signer: XOnlyPublicKey,
    }

    impl Fixture {
        fn stage(&self) -> Result<StagedSwapManifestV1, ManifestStagingError> {
            stage_swap_manifest_v1(ManifestStagingRequest {
                chain_swap: &self.record,
                persisted_lineage: &self.persisted_lineage,
                claim_allocation: &self.claim_allocation,
                refund_allocation: &self.refund_allocation,
                sequence_reservation: self.reservation,
                manifest_id: self.manifest_id,
                allocation_high_water: &self.high_water,
                merchant_policy: &self.policy,
                crypto: ManifestStagingCrypto::new(
                    &self.encryption_key_id,
                    &self.encryption_key,
                    &self.signing_key,
                    &self.pinned_signer,
                ),
            })
        }
    }

    fn signing_key(byte: u8) -> Keypair {
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
    }

    fn public_key_from_scalar(scalar: u8) -> BoltzPublicKey {
        let mut bytes = [0_u8; 32];
        bytes[31] = scalar;
        let secret = SecretKey::from_slice(&bytes).unwrap();
        BoltzPublicKey::new(secp256k1::PublicKey::from_secret_key(
            &Secp256k1::new(),
            &secret,
        ))
    }

    fn expected_claim_script(hashlock: hash160::Hash, receiver: &BoltzPublicKey) -> ScriptBuf {
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

    fn expected_refund_script(sender: &BoltzPublicKey, timeout_height: u32) -> ScriptBuf {
        Builder::new()
            .push_x_only_key(&sender.inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_lock_time(LockTime::from_consensus(timeout_height))
            .push_opcode(OP_CLTV)
            .into_script()
    }

    fn provider_fixture() -> (
        CreateChainResponse,
        Preimage,
        BoltzPublicKey,
        BoltzPublicKey,
    ) {
        const BLINDING_KEY: &str =
            "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";
        let preimage = Preimage::from_str(&"11".repeat(32)).unwrap();
        let claim_public_key = public_key_from_scalar(1);
        let refund_public_key = public_key_from_scalar(2);
        let bitcoin_server_key = BoltzPublicKey::from_str(
            "031c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8",
        )
        .unwrap();
        let liquid_server_key = BoltzPublicKey::from_str(
            "033009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01a",
        )
        .unwrap();
        let bitcoin_timeout = 958_033;
        let liquid_timeout = 3_972_215;
        let bitcoin_tree = SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(expected_claim_script(preimage.hash160, &bitcoin_server_key)),
                version: 0xc0,
            },
            refund_leaf: Leaf {
                output: hex::encode(expected_refund_script(&refund_public_key, bitcoin_timeout)),
                version: 0xc0,
            },
            covenant_claim_leaf: None,
        };
        let liquid_tree = SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(expected_claim_script(preimage.hash160, &claim_public_key)),
                version: 0xc4,
            },
            refund_leaf: Leaf {
                output: hex::encode(expected_refund_script(&liquid_server_key, liquid_timeout)),
                version: 0xc4,
            },
            covenant_claim_leaf: None,
        };
        let bitcoin_address = BtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Lockup),
            funding_addrs: None,
            hashlock: preimage.hash160,
            receiver_pubkey: bitcoin_server_key,
            locktime: LockTime::from_consensus(bitcoin_timeout),
            sender_pubkey: refund_public_key,
        }
        .to_address(BitcoinChain::Bitcoin)
        .unwrap()
        .to_string();
        let blinding_key = ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), BLINDING_KEY).unwrap();
        let liquid_address = LBtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Claim),
            funding_addrs: None,
            hashlock: preimage.hash160,
            receiver_pubkey: claim_public_key,
            locktime: boltz_client::elements::LockTime::from_consensus(liquid_timeout),
            sender_pubkey: liquid_server_key,
            blinding_key,
        }
        .to_address(LiquidChain::Liquid)
        .unwrap()
        .to_string();

        (
            CreateChainResponse {
                id: "ManifestStaging01".into(),
                claim_details: ChainSwapDetails {
                    swap_tree: liquid_tree,
                    lockup_address: liquid_address,
                    server_public_key: liquid_server_key,
                    timeout_block_height: liquid_timeout,
                    amount: 25_000,
                    blinding_key: Some(BLINDING_KEY.into()),
                    refund_address: None,
                    claim_address: None,
                    bip21: None,
                },
                lockup_details: ChainSwapDetails {
                    swap_tree: bitcoin_tree,
                    lockup_address: bitcoin_address,
                    server_public_key: bitcoin_server_key,
                    timeout_block_height: bitcoin_timeout,
                    amount: 25_431,
                    blinding_key: None,
                    refund_address: None,
                    claim_address: None,
                    bip21: Some("bitcoin:untrusted-provider-instruction?amount=999".into()),
                },
            },
            preimage,
            claim_public_key,
            refund_public_key,
        )
    }

    fn leaf_sha256(leaf: &Leaf) -> String {
        hex::encode(Sha256::digest(hex::decode(&leaf.output).unwrap()))
    }

    fn fixture() -> Fixture {
        let (provider, preimage, claim_public_key, refund_public_key) = provider_fixture();
        let lockup_address = provider.lockup_details.lockup_address.clone();
        let (canonical_response, response_sha256) =
            crate::canonical_json::canonical_json_and_sha256(&provider).unwrap();
        let creation_terms = ChainSwapCreationTerms {
            pinned_pair_hash: "22".repeat(32),
            canonical_pair_quote_json: format!(r#"{{"hash":"{}","rate":1}}"#, "22".repeat(32)),
            creation_response_sha256: response_sha256,
            btc_claim_script_sha256: leaf_sha256(&provider.lockup_details.swap_tree.claim_leaf),
            btc_refund_script_sha256: leaf_sha256(&provider.lockup_details.swap_tree.refund_leaf),
            liquid_claim_script_sha256: leaf_sha256(&provider.claim_details.swap_tree.claim_leaf),
            liquid_refund_script_sha256: leaf_sha256(&provider.claim_details.swap_tree.refund_leaf),
            btc_timeout_height: i64::from(provider.lockup_details.timeout_block_height),
            liquid_timeout_height: i64::from(provider.claim_details.timeout_block_height),
            btc_network: "bitcoin".into(),
            liquid_network: "liquid".into(),
            liquid_asset_id: boltz_client::elements::AssetId::LIQUID_BTC.to_string(),
            merchant_liquid_destination: LIQUID_DESTINATION.into(),
            merchant_emergency_btc_address: Some(EMERGENCY_ADDRESS.into()),
            recovery_address_commitment_id: Some(Uuid::from_u128(6)),
        };
        let chain_swap_id = Uuid::from_u128(2);
        let invoice_id = Uuid::from_u128(5);
        let claim_reference = PersistedChainSwapKeyReference {
            allocation_id: Uuid::from_u128(3),
            child_index: 430,
            public_key_hex: claim_public_key.to_string(),
            preimage_hash_hex: Some(preimage.sha256.to_string()),
        };
        let refund_reference = PersistedChainSwapKeyReference {
            allocation_id: Uuid::from_u128(4),
            child_index: 431,
            public_key_hex: refund_public_key.to_string(),
            preimage_hash_hex: None,
        };
        let persisted_lineage = PersistedChainSwapLineageEvidence {
            chain_swap_id,
            root_fingerprint: "0011223344556677".into(),
            key_epoch: 1,
            derivation_scheme_version: 1,
            claim: claim_reference.clone(),
            refund: refund_reference.clone(),
        };
        let claim_allocation = PublicSwapKeyAllocationEvidence {
            allocation_id: claim_reference.allocation_id,
            root_fingerprint: persisted_lineage.root_fingerprint.clone(),
            key_epoch: persisted_lineage.key_epoch,
            derivation_scheme_version: persisted_lineage.derivation_scheme_version,
            child_index: claim_reference.child_index,
            purpose: SwapKeyPurpose::ChainClaim,
            public_key_hex: claim_reference.public_key_hex,
            preimage_hash_hex: claim_reference.preimage_hash_hex,
        };
        let refund_allocation = PublicSwapKeyAllocationEvidence {
            allocation_id: refund_reference.allocation_id,
            root_fingerprint: persisted_lineage.root_fingerprint.clone(),
            key_epoch: persisted_lineage.key_epoch,
            derivation_scheme_version: persisted_lineage.derivation_scheme_version,
            child_index: refund_reference.child_index,
            purpose: SwapKeyPurpose::ChainRefund,
            public_key_hex: refund_reference.public_key_hex,
            preimage_hash_hex: refund_reference.preimage_hash_hex,
        };
        let signing_key = signing_key(0x11);
        let pinned_signer = signing_key.x_only_public_key().0;

        Fixture {
            record: ChainSwapRecord {
                id: chain_swap_id,
                invoice_id,
                nym: Some("restore-nym".into()),
                boltz_swap_id: provider.id,
                from_chain: "BTC".into(),
                to_chain: "L-BTC".into(),
                lockup_address: lockup_address.clone(),
                lockup_bip21: Some(format!(
                    "bitcoin:{lockup_address}?amount=0.00025431&label=Send%20to%20L-BTC%20address"
                )),
                user_lock_amount_sat: 25_431,
                server_lock_amount_sat: 25_000,
                preimage_hex: PRIVATE_PREIMAGE_SENTINEL.into(),
                claim_key_hex: PRIVATE_CLAIM_KEY_SENTINEL.into(),
                refund_key_hex: PRIVATE_REFUND_KEY_SENTINEL.into(),
                boltz_response_json: canonical_response,
                status: "pending".into(),
                claim_txid: None,
                claim_tx_hex: None,
                claim_fee_authority: crate::db::LiquidClaimFeeAuthority::Legacy,
                claim_attempts: 0,
                last_claim_error: None,
                cooperative_refused: false,
                creation_terms: Some(creation_terms),
                renegotiated_server_lock_amount_sat: None,
                refund_address: None,
                refund_txid: None,
                created_at_unix: 1_784_000_000,
                updated_at_unix: 1_784_000_000,
            },
            persisted_lineage,
            claim_allocation,
            refund_allocation,
            policy: MerchantPolicyReferencesV1::new(
                invoice_id,
                "restore-nym",
                LIQUID_DESTINATION,
                Some((Uuid::from_u128(6), EMERGENCY_ADDRESS)),
            ),
            reservation: ManifestSequenceReservation::for_manifest_staging_test(
                2,
                Some(Uuid::from_u128(7)),
            ),
            manifest_id: Uuid::from_u128(1),
            high_water: PublicSwapKeyAllocationHighWaterEvidence {
                root_fingerprint: "0011223344556677".into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                child_index: 431,
            },
            encryption_key_id: "manifest-key-2026-01".into(),
            encryption_key: ENCRYPTION_KEY,
            signing_key,
            pinned_signer,
        }
    }

    #[test]
    fn stages_and_self_authenticates_complete_public_evidence() {
        let fixture = fixture();
        let staged = fixture.stage().unwrap();

        assert_eq!(
            staged.manifest.restore_identity.manifest_id,
            fixture.manifest_id
        );
        assert_eq!(
            staged.manifest.restore_identity.chain_swap_id,
            fixture.record.id
        );
        assert_eq!(staged.manifest.restore_identity.manifest_sequence, 2);
        assert_eq!(
            staged.manifest.derivation_lineage.claim.allocation_id,
            fixture.claim_allocation.allocation_id
        );
        assert_eq!(
            staged.manifest.derivation_lineage.refund.allocation_id,
            fixture.refund_allocation.allocation_id
        );
        assert_eq!(
            SwapManifestV1::open(
                staged.encrypted_envelope.encoded(),
                &fixture.encryption_key_id,
                &fixture.encryption_key,
                &fixture.pinned_signer,
            )
            .unwrap(),
            staged.manifest
        );
    }

    #[test]
    fn stages_without_optional_emergency_commitment_only_as_an_exact_pair() {
        let mut fixture = fixture();
        fixture
            .record
            .creation_terms
            .as_mut()
            .unwrap()
            .merchant_emergency_btc_address = None;
        fixture
            .record
            .creation_terms
            .as_mut()
            .unwrap()
            .recovery_address_commitment_id = None;
        fixture.policy.emergency_bitcoin_commitment_id = None;
        fixture.policy.merchant_emergency_btc_address = None;

        let staged = fixture.stage().unwrap();
        assert_eq!(
            staged
                .manifest
                .merchant_policy
                .emergency_bitcoin_commitment_id,
            None
        );
        assert_eq!(
            staged.manifest.creation.merchant_emergency_btc_address,
            None
        );
    }

    #[test]
    fn stages_the_genesis_reservation_without_a_predecessor() {
        let mut fixture = fixture();
        fixture.reservation = ManifestSequenceReservation::for_manifest_staging_test(1, None);

        let staged = fixture.stage().unwrap();
        assert_eq!(staged.manifest.restore_identity.manifest_sequence, 1);
        assert_eq!(staged.manifest.restore_identity.previous_manifest_id, None);
    }

    #[test]
    fn rejects_legacy_or_incomplete_record_projections() {
        let mut missing_nym = fixture();
        missing_nym.record.nym = None;
        assert_eq!(
            missing_nym.stage(),
            Err(ManifestStagingError::IncompleteRecord { field: "nym" })
        );

        let mut empty_nym = fixture();
        empty_nym.record.nym = Some(String::new());
        assert_eq!(
            empty_nym.stage(),
            Err(ManifestStagingError::IncompleteRecord { field: "nym" })
        );

        let mut missing_bip21 = fixture();
        missing_bip21.record.lockup_bip21 = None;
        assert_eq!(
            missing_bip21.stage(),
            Err(ManifestStagingError::IncompleteRecord {
                field: "lockup_bip21"
            })
        );

        let mut missing_terms = fixture();
        missing_terms.record.creation_terms = None;
        assert_eq!(
            missing_terms.stage(),
            Err(ManifestStagingError::IncompleteRecord {
                field: "creation_terms"
            })
        );

        let mut wrong_source = fixture();
        wrong_source.record.from_chain = "L-BTC".into();
        assert_eq!(
            wrong_source.stage(),
            Err(ManifestStagingError::IncompleteRecord {
                field: "from_chain"
            })
        );

        let mut wrong_destination = fixture();
        wrong_destination.record.to_chain = "BTC".into();
        assert_eq!(
            wrong_destination.stage(),
            Err(ManifestStagingError::IncompleteRecord { field: "to_chain" })
        );
    }

    #[test]
    fn rejects_drift_from_the_records_immutable_creation_boundary() {
        let mut provider_id = fixture();
        provider_id.record.boltz_swap_id = "DifferentProviderId".into();
        assert_eq!(
            provider_id.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut lockup_address = fixture();
        lockup_address.record.lockup_address =
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".into();
        assert_eq!(
            lockup_address.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut user_amount = fixture();
        user_amount.record.user_lock_amount_sat += 1;
        assert_eq!(
            user_amount.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut server_amount = fixture();
        server_amount.record.server_lock_amount_sat += 1;
        assert_eq!(
            server_amount.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut response_bytes = fixture();
        response_bytes.record.boltz_response_json.push(' ');
        assert_eq!(
            response_bytes.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut pair_hash = fixture();
        pair_hash
            .record
            .creation_terms
            .as_mut()
            .unwrap()
            .pinned_pair_hash = "33".repeat(32);
        assert_eq!(
            pair_hash.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );
    }

    fn assert_claim_mismatch(
        expected_field: &'static str,
        mutate: impl FnOnce(&mut PublicSwapKeyAllocationEvidence),
    ) {
        let mut fixture = fixture();
        mutate(&mut fixture.claim_allocation);
        assert_eq!(
            fixture.stage(),
            Err(ManifestStagingError::ClaimAllocationMismatch {
                field: expected_field
            })
        );
    }

    fn assert_refund_mismatch(
        expected_field: &'static str,
        mutate: impl FnOnce(&mut PublicSwapKeyAllocationEvidence),
    ) {
        let mut fixture = fixture();
        mutate(&mut fixture.refund_allocation);
        assert_eq!(
            fixture.stage(),
            Err(ManifestStagingError::RefundAllocationMismatch {
                field: expected_field
            })
        );
    }

    #[test]
    fn cross_checks_every_claim_allocation_field_exactly() {
        assert_claim_mismatch("allocation_id", |value| {
            value.allocation_id = Uuid::from_u128(99)
        });
        assert_claim_mismatch("root_fingerprint", |value| {
            value.root_fingerprint = "1011223344556677".into()
        });
        assert_claim_mismatch("key_epoch", |value| value.key_epoch += 1);
        assert_claim_mismatch("derivation_scheme_version", |value| {
            value.derivation_scheme_version += 1
        });
        assert_claim_mismatch("child_index", |value| value.child_index += 1);
        assert_claim_mismatch("purpose", |value| {
            value.purpose = SwapKeyPurpose::ChainRefund
        });
        assert_claim_mismatch("public_key_hex", |value| value.public_key_hex.push('0'));
        assert_claim_mismatch("preimage_hash_hex", |value| {
            value.preimage_hash_hex = Some("00".repeat(32))
        });
        let mut missing_claim_hash = fixture();
        missing_claim_hash.persisted_lineage.claim.preimage_hash_hex = None;
        missing_claim_hash.claim_allocation.preimage_hash_hex = None;
        assert_eq!(
            missing_claim_hash.stage(),
            Err(ManifestStagingError::ClaimAllocationMismatch {
                field: "preimage_hash_presence"
            })
        );
    }

    #[test]
    fn cross_checks_every_refund_allocation_field_exactly() {
        assert_refund_mismatch("allocation_id", |value| {
            value.allocation_id = Uuid::from_u128(99)
        });
        assert_refund_mismatch("root_fingerprint", |value| {
            value.root_fingerprint = "1011223344556677".into()
        });
        assert_refund_mismatch("key_epoch", |value| value.key_epoch += 1);
        assert_refund_mismatch("derivation_scheme_version", |value| {
            value.derivation_scheme_version += 1
        });
        assert_refund_mismatch("child_index", |value| value.child_index += 1);
        assert_refund_mismatch("purpose", |value| {
            value.purpose = SwapKeyPurpose::ReverseClaim
        });
        assert_refund_mismatch("public_key_hex", |value| value.public_key_hex.push('0'));
        assert_refund_mismatch("preimage_hash_hex", |value| {
            value.preimage_hash_hex = Some("00".repeat(32))
        });
        let mut unexpected_refund_hash = fixture();
        unexpected_refund_hash
            .persisted_lineage
            .refund
            .preimage_hash_hex = Some("00".repeat(32));
        unexpected_refund_hash.refund_allocation.preimage_hash_hex = Some("00".repeat(32));
        assert_eq!(
            unexpected_refund_hash.stage(),
            Err(ManifestStagingError::RefundAllocationMismatch {
                field: "preimage_hash_presence"
            })
        );
    }

    #[test]
    fn binds_allocator_high_water_to_the_exact_lineage_namespace() {
        for (field, selector) in [
            ("root_fingerprint", 0_u8),
            ("key_epoch", 1_u8),
            ("derivation_scheme_version", 2_u8),
        ] {
            let mut fixture = fixture();
            match selector {
                0 => fixture.high_water.root_fingerprint = "1011223344556677".into(),
                1 => fixture.high_water.key_epoch += 1,
                2 => fixture.high_water.derivation_scheme_version += 1,
                _ => unreachable!(),
            }
            assert_eq!(
                fixture.stage(),
                Err(ManifestStagingError::AllocationHighWaterMismatch { field })
            );
        }
    }

    #[test]
    fn binds_public_lineage_to_the_exact_chain_swap_record() {
        let mut fixture = fixture();
        fixture.persisted_lineage.chain_swap_id = Uuid::from_u128(99);
        assert_eq!(
            fixture.stage(),
            Err(ManifestStagingError::RecordLineageMismatch {
                field: "chain_swap_id"
            })
        );
    }

    #[test]
    fn cross_checks_every_duplicated_merchant_policy_field() {
        let mut invoice = fixture();
        invoice.policy.invoice_id = Uuid::from_u128(99);
        assert_eq!(
            invoice.stage(),
            Err(ManifestStagingError::MerchantPolicyMismatch {
                field: "invoice_id"
            })
        );

        let mut nym = fixture();
        nym.policy.merchant_nym = "other-nym".into();
        assert_eq!(
            nym.stage(),
            Err(ManifestStagingError::MerchantPolicyMismatch {
                field: "merchant_nym"
            })
        );

        let mut liquid = fixture();
        liquid.policy.merchant_liquid_destination.push('x');
        assert_eq!(
            liquid.stage(),
            Err(ManifestStagingError::MerchantPolicyMismatch {
                field: "merchant_liquid_destination"
            })
        );

        let mut emergency_address = fixture();
        emergency_address.policy.merchant_emergency_btc_address = None;
        assert_eq!(
            emergency_address.stage(),
            Err(ManifestStagingError::MerchantPolicyMismatch {
                field: "merchant_emergency_btc_address"
            })
        );

        let mut emergency_commitment = fixture();
        emergency_commitment.policy.emergency_bitcoin_commitment_id = None;
        assert_eq!(
            emergency_commitment.stage(),
            Err(ManifestStagingError::MerchantPolicyMismatch {
                field: "emergency_bitcoin_commitment_id"
            })
        );
    }

    #[test]
    fn rejects_invalid_emergency_commitment_even_when_presence_is_paired() {
        let mut fixture = fixture();
        fixture.policy.emergency_bitcoin_commitment_id = Some(Uuid::nil());
        fixture
            .record
            .creation_terms
            .as_mut()
            .unwrap()
            .recovery_address_commitment_id = Some(Uuid::nil());
        assert_eq!(fixture.stage(), Err(ManifestStagingError::InvalidManifest));
    }

    #[test]
    fn rejects_a_different_recovery_commitment_id_even_when_both_are_present() {
        let mut fixture = fixture();
        fixture.policy.emergency_bitcoin_commitment_id = Some(Uuid::from_u128(7));
        assert_eq!(
            fixture.stage(),
            Err(ManifestStagingError::MerchantPolicyMismatch {
                field: "emergency_bitcoin_commitment_id"
            })
        );
    }

    #[test]
    fn rejects_a_recovery_commitment_id_absent_from_creation_terms() {
        let mut fixture = fixture();
        fixture
            .record
            .creation_terms
            .as_mut()
            .unwrap()
            .recovery_address_commitment_id = None;
        assert_eq!(
            fixture.stage(),
            Err(ManifestStagingError::MerchantPolicyMismatch {
                field: "emergency_bitcoin_commitment_id"
            })
        );
    }

    #[test]
    fn requires_the_exact_pinned_bip340_signer() {
        let mut fixture = fixture();
        fixture.pinned_signer = signing_key(0x12).x_only_public_key().0;
        assert_eq!(fixture.stage(), Err(ManifestStagingError::UnexpectedSigner));
    }

    #[test]
    fn maps_manifest_and_envelope_bounds_to_source_free_errors() {
        let mut nil_manifest = fixture();
        nil_manifest.manifest_id = Uuid::nil();
        assert_eq!(
            nil_manifest.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut missing_predecessor = fixture();
        missing_predecessor.reservation =
            ManifestSequenceReservation::for_manifest_staging_test(2, None);
        assert_eq!(
            missing_predecessor.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut trailing_high_water = fixture();
        trailing_high_water.high_water.child_index = 430;
        assert_eq!(
            trailing_high_water.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut excessive_high_water = fixture();
        excessive_high_water.high_water.child_index = MAX_UNHARDENED_SWAP_CHILD_INDEX + 1;
        assert_eq!(
            excessive_high_water.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut oversized_nym = fixture();
        let oversized = "n".repeat(129);
        oversized_nym.record.nym = Some(oversized.clone());
        oversized_nym.policy.merchant_nym = oversized;
        assert_eq!(
            oversized_nym.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut oversized_bip21 = fixture();
        oversized_bip21.record.lockup_bip21 = Some("b".repeat(2_049));
        assert_eq!(
            oversized_bip21.stage(),
            Err(ManifestStagingError::InvalidManifest)
        );

        let mut bad_key_id = fixture();
        bad_key_id.encryption_key_id = "x".repeat(65);
        assert_eq!(
            bad_key_id.stage(),
            Err(ManifestStagingError::EnvelopeCreationFailed)
        );
    }

    #[test]
    fn validation_failures_do_not_expose_lower_layer_or_private_material() {
        let mut fixture = fixture();
        fixture.record.boltz_response_json.push(' ');
        let error = fixture.stage().unwrap_err();
        assert_eq!(error, ManifestStagingError::InvalidManifest);
        assert!(error.source().is_none());

        let rendered = format!("{error:?} {error}");
        for secret in [
            PRIVATE_PREIMAGE_SENTINEL,
            PRIVATE_CLAIM_KEY_SENTINEL,
            PRIVATE_REFUND_KEY_SENTINEL,
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn staged_debug_and_plaintext_never_contain_private_row_material() {
        let fixture = fixture();
        let staged = fixture.stage().unwrap();
        let manifest_json = serde_json::to_string(&staged.manifest).unwrap();
        let rendered = format!("{staged:?} {:?}", staged.encrypted_envelope);

        for secret in [
            PRIVATE_PREIMAGE_SENTINEL,
            PRIVATE_CLAIM_KEY_SENTINEL,
            PRIVATE_REFUND_KEY_SENTINEL,
        ] {
            assert!(!manifest_json.contains(secret));
            assert!(!rendered.contains(secret));
            assert!(!staged.encrypted_envelope.encoded().contains(secret));
        }
        assert!(rendered.contains("<redacted>"));
    }
}
