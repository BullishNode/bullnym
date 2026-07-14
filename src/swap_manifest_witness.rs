//! Bounded, authenticated loading of one passive recovery-manifest witness.
//!
//! This module deliberately stops after opening a quiescent external set and
//! checking its append-only topology. The generic object-store stream is not
//! ordered, so it is consumed once to EOF and sorted only after the hard bound
//! and duplicate checks pass. The caller must stop or serialize deliveries for
//! the entire scan. This module does not compare database state, reconstruct
//! records, alter admission, or own runtime configuration.

use std::fmt;

use secp256k1::XOnlyPublicKey;

use crate::swap_manifest::{
    audit_append_only_manifest_set_v1, EncryptedSwapManifestV1, SwapManifestSetAuditV1,
    SwapManifestV1,
};
use crate::swap_manifest_store::{
    ManifestObjectId, ManifestStoreError, RecoveryManifestStore, MAX_MANIFEST_FULL_SCAN_RESULTS,
};

/// Absolute number of records one witness load will authenticate and retain.
pub const MAX_RECOVERY_WITNESS_RECORDS_V1: usize = MAX_MANIFEST_FULL_SCAN_RESULTS;

/// Exact key material and signer pin used to open one configured witness.
///
/// The encryption key identifier is part of the authenticated envelope header,
/// but is still treated as configuration-sensitive here. No field is exposed
/// through `Debug`.
pub struct RecoveryWitnessOpenSecretsV1 {
    encryption_key_id: String,
    encryption_key: [u8; 32],
    expected_signer: XOnlyPublicKey,
}

impl RecoveryWitnessOpenSecretsV1 {
    pub fn new(
        encryption_key_id: impl Into<String>,
        encryption_key: [u8; 32],
        expected_signer: XOnlyPublicKey,
    ) -> Result<Self, RecoveryWitnessLoadError> {
        let encryption_key_id = encryption_key_id.into();
        if !valid_encryption_key_id(&encryption_key_id) {
            return Err(RecoveryWitnessLoadError::InvalidOpeningConfiguration);
        }
        Ok(Self {
            encryption_key_id,
            encryption_key,
            expected_signer,
        })
    }
}

impl fmt::Debug for RecoveryWitnessOpenSecretsV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryWitnessOpenSecretsV1")
            .field("encryption_key_id", &"<redacted>")
            .field("encryption_key", &"<redacted>")
            .field("expected_signer", &"<redacted>")
            .finish()
    }
}

/// Complete, authenticated contents of one quiescent append-only witness.
///
/// Manifests are returned in signed sequence order, independent of S3 object
/// key order. The audit summarizes the same complete set.
#[derive(Clone, PartialEq, Eq)]
pub struct LoadedRecoveryWitnessV1 {
    manifests: Vec<SwapManifestV1>,
    audit: SwapManifestSetAuditV1,
}

/// One exact, authenticated external object reacquired for reconstruction.
///
/// The envelope is the original create-only byte string read from the witness,
/// not a resealed copy. A stale-restore reconciler can therefore recreate the
/// local delivery-ledger evidence and read-verify the same external object.
/// Formatting is intentionally identity- and content-free.
pub struct LoadedRecoveryWitnessRecordV1 {
    manifest: SwapManifestV1,
    encrypted_envelope: EncryptedSwapManifestV1,
}

impl LoadedRecoveryWitnessRecordV1 {
    pub fn manifest(&self) -> &SwapManifestV1 {
        &self.manifest
    }

    pub fn encrypted_envelope(&self) -> &EncryptedSwapManifestV1 {
        &self.encrypted_envelope
    }

    pub fn into_parts(self) -> (SwapManifestV1, EncryptedSwapManifestV1) {
        (self.manifest, self.encrypted_envelope)
    }
}

impl fmt::Debug for LoadedRecoveryWitnessRecordV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedRecoveryWitnessRecordV1")
            .field("manifest", &"<authenticated recovery evidence>")
            .field("encrypted_envelope", &"<redacted>")
            .finish()
    }
}

impl LoadedRecoveryWitnessV1 {
    pub fn manifests(&self) -> &[SwapManifestV1] {
        &self.manifests
    }

    pub fn audit(&self) -> &SwapManifestSetAuditV1 {
        &self.audit
    }

    pub fn into_parts(self) -> (Vec<SwapManifestV1>, SwapManifestSetAuditV1) {
        (self.manifests, self.audit)
    }
}

impl fmt::Debug for LoadedRecoveryWitnessV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedRecoveryWitnessV1")
            .field("manifest_count", &self.manifests.len())
            .field("manifests", &"<authenticated recovery evidence>")
            .field("audit", &"<validated>")
            .finish()
    }
}

/// Fixed, non-nesting failure classes for a witness load.
///
/// Variants intentionally retain no store or cryptographic source error and no
/// object/configuration identity. `Display` and `Debug` are therefore bounded
/// and safe for operational logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryWitnessLoadError {
    InvalidOpeningConfiguration,
    StoreListFailed,
    RecordLimitExceeded,
    StoreReadFailed,
    StoreObjectChanged,
    EnvelopeAuthenticationFailed,
    ObjectIdentityMismatch,
    AuditedManifestChanged,
    AppendOnlySetInvalid,
}

impl fmt::Display for RecoveryWitnessLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidOpeningConfiguration => {
                "recovery witness opening configuration is invalid"
            }
            Self::StoreListFailed => "recovery witness listing failed",
            Self::RecordLimitExceeded => "recovery witness exceeds the record limit",
            Self::StoreReadFailed => "recovery witness object read failed",
            Self::StoreObjectChanged => "recovery witness object changed during the load",
            Self::EnvelopeAuthenticationFailed => "recovery witness envelope authentication failed",
            Self::ObjectIdentityMismatch => {
                "recovery witness object identity does not match its signed manifest"
            }
            Self::AuditedManifestChanged => {
                "recovery witness object no longer matches the audited manifest"
            }
            Self::AppendOnlySetInvalid => "recovery witness append-only set is invalid",
        })
    }
}

impl std::error::Error for RecoveryWitnessLoadError {}

/// Bounded loader for one configured passive manifest witness.
pub struct RecoveryManifestWitnessLoaderV1 {
    store: RecoveryManifestStore,
    secrets: RecoveryWitnessOpenSecretsV1,
    max_records: usize,
}

impl RecoveryManifestWitnessLoaderV1 {
    pub fn new(store: RecoveryManifestStore, secrets: RecoveryWitnessOpenSecretsV1) -> Self {
        Self {
            store,
            secrets,
            max_records: MAX_RECOVERY_WITNESS_RECORDS_V1,
        }
    }

    /// Load, exact-read, authenticate, and globally audit a quiescent witness.
    ///
    /// The caller must prevent new witness objects for the full duration of
    /// this call. A single object-store stream cannot provide a coherent
    /// snapshot while that set is changing. This API intentionally does not
    /// claim to detect or manufacture quiescence.
    pub async fn load_quiescent(
        &self,
    ) -> Result<LoadedRecoveryWitnessV1, RecoveryWitnessLoadError> {
        self.load_bounded().await
    }

    /// Reacquire one exact object after a complete witness audit.
    ///
    /// The caller supplies a manifest returned by [`Self::load_quiescent`] and
    /// must preserve the same creation-quiescent interval while stale-restore
    /// reconstruction is in progress. The create-only store is read again,
    /// the envelope is authenticated again, and the opened manifest must equal
    /// the audited value byte-for-byte at the typed boundary. This retains one
    /// exact envelope instead of multiplying peak startup memory by retaining
    /// every encrypted object during the complete audit.
    pub async fn load_exact_authenticated_record(
        &self,
        audited_manifest: &SwapManifestV1,
    ) -> Result<LoadedRecoveryWitnessRecordV1, RecoveryWitnessLoadError> {
        let object_id = ManifestObjectId::new(
            audited_manifest.restore_identity.chain_swap_id,
            audited_manifest.restore_identity.manifest_id,
        )
        .map_err(|_| RecoveryWitnessLoadError::ObjectIdentityMismatch)?;
        let stored = self
            .store
            .get_v1(object_id)
            .await
            .map_err(|_| RecoveryWitnessLoadError::StoreReadFailed)?;
        let encrypted_envelope = EncryptedSwapManifestV1::parse(stored.into_encoded())
            .map_err(|_| RecoveryWitnessLoadError::EnvelopeAuthenticationFailed)?;
        let manifest = SwapManifestV1::open(
            encrypted_envelope.encoded(),
            &self.secrets.encryption_key_id,
            &self.secrets.encryption_key,
            &self.secrets.expected_signer,
        )
        .map_err(|_| RecoveryWitnessLoadError::EnvelopeAuthenticationFailed)?;
        if manifest.restore_identity.chain_swap_id != object_id.chain_swap_id()
            || manifest.restore_identity.manifest_id != object_id.manifest_id()
        {
            return Err(RecoveryWitnessLoadError::ObjectIdentityMismatch);
        }
        if manifest != *audited_manifest {
            return Err(RecoveryWitnessLoadError::AuditedManifestChanged);
        }
        Ok(LoadedRecoveryWitnessRecordV1 {
            manifest,
            encrypted_envelope,
        })
    }

    async fn load_bounded(&self) -> Result<LoadedRecoveryWitnessV1, RecoveryWitnessLoadError> {
        if self.max_records == 0 || self.max_records > MAX_RECOVERY_WITNESS_RECORDS_V1 {
            return Err(RecoveryWitnessLoadError::InvalidOpeningConfiguration);
        }

        let objects = match self.store.list_all_v1_bounded(self.max_records).await {
            Ok(objects) => objects,
            Err(ManifestStoreError::ListResultLimitExceeded { .. }) => {
                return Err(RecoveryWitnessLoadError::RecordLimitExceeded);
            }
            Err(_) => return Err(RecoveryWitnessLoadError::StoreListFailed),
        };
        let mut manifests = Vec::with_capacity(objects.len());
        for summary in objects {
            let stored = self
                .store
                .get_v1(summary.id)
                .await
                .map_err(|_| RecoveryWitnessLoadError::StoreReadFailed)?;
            if u64::try_from(stored.encoded().len()).ok() != Some(summary.encoded_bytes) {
                return Err(RecoveryWitnessLoadError::StoreObjectChanged);
            }
            let manifest = SwapManifestV1::open(
                stored.encoded(),
                &self.secrets.encryption_key_id,
                &self.secrets.encryption_key,
                &self.secrets.expected_signer,
            )
            .map_err(|_| RecoveryWitnessLoadError::EnvelopeAuthenticationFailed)?;
            if manifest.restore_identity.chain_swap_id != summary.id.chain_swap_id()
                || manifest.restore_identity.manifest_id != summary.id.manifest_id()
            {
                return Err(RecoveryWitnessLoadError::ObjectIdentityMismatch);
            }
            manifests.push(manifest);
        }

        let audit = audit_append_only_manifest_set_v1(&manifests)
            .map_err(|_| RecoveryWitnessLoadError::AppendOnlySetInvalid)?;
        manifests.sort_unstable_by_key(|manifest| manifest.restore_identity.manifest_sequence);
        Ok(LoadedRecoveryWitnessV1 { manifests, audit })
    }

    #[cfg(test)]
    fn with_test_limits(
        store: RecoveryManifestStore,
        secrets: RecoveryWitnessOpenSecretsV1,
        max_records: usize,
    ) -> Self {
        Self {
            store,
            secrets,
            max_records,
        }
    }
}

impl fmt::Debug for RecoveryManifestWitnessLoaderV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryManifestWitnessLoaderV1")
            .field("store", &"<redacted>")
            .field("secrets", &"<redacted>")
            .field("limits", &"<redacted>")
            .finish()
    }
}

fn valid_encryption_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::io;
    use std::str::FromStr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
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
    use futures_util::stream::{self, BoxStream};
    use futures_util::{StreamExt, TryStreamExt};
    use object_store::memory::InMemory;
    use object_store::path::Path;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
        PutMultipartOptions, PutOptions, PutPayload, PutResult,
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;
    use crate::swap_manifest::{
        EncryptedSwapManifestV1, ImmutableChainSwapCreationV1, ManifestKeyAllocationV1,
        ManifestKeyPurposeV1, MerchantPolicyReferencesV1, SwapDerivationLineageV1,
        SwapRestoreIdentityV1,
    };
    use crate::swap_manifest_store::{
        CorruptReadKind, ManifestObjectId, ManifestStoreError, ManifestWriteOutcome,
    };

    const KEY_ID: &str = "private-manifest-key-2026-07";
    const ENCRYPTION_KEY: [u8; 32] = [0x42; 32];
    const WRONG_ENCRYPTION_KEY: [u8; 32] = [0x24; 32];
    const BTC_TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;
    const LIQUID_TAPSCRIPT_LEAF_VERSION: u8 = 0xc4;
    const PREFIX: &str = "private/witness/config-marker";
    const BACKEND_SECRET_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BACKEND_SECRET_OBJECT_KEY: &str =
        "private/witness/v1/secret-chain-id/secret-manifest-id.json";
    const BACKEND_SECRET_PROVIDER_ID: &str = "SecretProviderIdentifier";

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

    fn expected_claim_script(
        hashlock: bitcoin::hashes::hash160::Hash,
        receiver: &BoltzPublicKey,
    ) -> ScriptBuf {
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

    fn provider_fixture(
        id: String,
        claim_scalar: u8,
        refund_scalar: u8,
        preimage_byte: u8,
    ) -> (
        CreateChainResponse,
        Preimage,
        BoltzPublicKey,
        BoltzPublicKey,
    ) {
        const BLINDING_KEY: &str =
            "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";
        let preimage = Preimage::from_str(&format!("{preimage_byte:02x}").repeat(32)).unwrap();
        let claim_public_key = public_key_from_scalar(claim_scalar);
        let refund_public_key = public_key_from_scalar(refund_scalar);
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
                version: BTC_TAPSCRIPT_LEAF_VERSION,
            },
            refund_leaf: Leaf {
                output: hex::encode(expected_refund_script(&refund_public_key, bitcoin_timeout)),
                version: BTC_TAPSCRIPT_LEAF_VERSION,
            },
            covenant_claim_leaf: None,
        };
        let liquid_tree = SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(expected_claim_script(preimage.hash160, &claim_public_key)),
                version: LIQUID_TAPSCRIPT_LEAF_VERSION,
            },
            refund_leaf: Leaf {
                output: hex::encode(expected_refund_script(&liquid_server_key, liquid_timeout)),
                version: LIQUID_TAPSCRIPT_LEAF_VERSION,
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
                id,
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
                    bip21: Some("bitcoin:provider-evidence-only?amount=999".into()),
                },
            },
            preimage,
            claim_public_key,
            refund_public_key,
        )
    }

    fn canonical_json<T: Serialize>(value: &T) -> String {
        crate::canonical_json::canonical_json_and_sha256(value)
            .unwrap()
            .0
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn leaf_sha256(leaf: &Leaf) -> String {
        sha256_hex(&hex::decode(&leaf.output).unwrap())
    }

    #[allow(clippy::too_many_arguments)]
    fn manifest_fixture(
        sequence: u64,
        previous_manifest_id: Option<Uuid>,
        discriminator: u128,
        claim_child_index: i64,
        refund_child_index: i64,
        high_water: i64,
        claim_scalar: u8,
        refund_scalar: u8,
        preimage_byte: u8,
    ) -> SwapManifestV1 {
        let boltz_swap_id = format!("WitnessProvider{discriminator}");
        let (provider_response, preimage, claim_public_key, refund_public_key) = provider_fixture(
            boltz_swap_id.clone(),
            claim_scalar,
            refund_scalar,
            preimage_byte,
        );
        let canonical_response = canonical_json(&provider_response);
        let lockup_address = provider_response.lockup_details.lockup_address.clone();
        let liquid_destination = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";
        let emergency_address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        SwapManifestV1::new(
            SwapRestoreIdentityV1 {
                manifest_id: Uuid::from_u128(1_000 + discriminator),
                manifest_sequence: sequence,
                previous_manifest_id,
                chain_swap_id: Uuid::from_u128(2_000 + discriminator),
                boltz_swap_id,
                created_at_unix: 1_784_000_000 + i64::try_from(discriminator).unwrap(),
            },
            SwapDerivationLineageV1 {
                root_fingerprint: "0011223344556677".into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                allocation_high_water_child_index: high_water,
                claim: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(3_000 + discriminator * 2),
                    child_index: claim_child_index,
                    purpose: ManifestKeyPurposeV1::ChainClaim,
                    public_key_hex: claim_public_key.to_string(),
                    preimage_hash_hex: Some(preimage.sha256.to_string()),
                },
                refund: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(3_001 + discriminator * 2),
                    child_index: refund_child_index,
                    purpose: ManifestKeyPurposeV1::ChainRefund,
                    public_key_hex: refund_public_key.to_string(),
                    preimage_hash_hex: None,
                },
            },
            ImmutableChainSwapCreationV1 {
                lockup_address: lockup_address.clone(),
                lockup_bip21: format!(
                    "bitcoin:{lockup_address}?amount=0.00025431&label=Send%20to%20L-BTC%20address"
                ),
                user_lock_amount_sat: 25_431,
                server_lock_amount_sat: 25_000,
                canonical_provider_response_json: canonical_response.clone(),
                pinned_pair_hash: "22".repeat(32),
                canonical_pair_quote_json: r#"{"hash":"2222222222222222222222222222222222222222222222222222222222222222","rate":1}"#.into(),
                creation_response_sha256: sha256_hex(canonical_response.as_bytes()),
                btc_claim_script_sha256: leaf_sha256(
                    &provider_response.lockup_details.swap_tree.claim_leaf,
                ),
                btc_refund_script_sha256: leaf_sha256(
                    &provider_response.lockup_details.swap_tree.refund_leaf,
                ),
                liquid_claim_script_sha256: leaf_sha256(
                    &provider_response.claim_details.swap_tree.claim_leaf,
                ),
                liquid_refund_script_sha256: leaf_sha256(
                    &provider_response.claim_details.swap_tree.refund_leaf,
                ),
                btc_timeout_height: i64::from(
                    provider_response.lockup_details.timeout_block_height,
                ),
                liquid_timeout_height: i64::from(
                    provider_response.claim_details.timeout_block_height,
                ),
                btc_network: "bitcoin".into(),
                liquid_network: "liquid".into(),
                liquid_asset_id: boltz_client::elements::AssetId::LIQUID_BTC.to_string(),
                merchant_liquid_destination: liquid_destination.into(),
                merchant_emergency_btc_address: Some(emergency_address.into()),
            },
            MerchantPolicyReferencesV1::new(
                Uuid::from_u128(4_000 + discriminator),
                format!("witness-nym-{discriminator}"),
                liquid_destination,
                Some((Uuid::from_u128(5_000 + discriminator), emergency_address)),
            ),
        )
        .unwrap()
    }

    fn three_manifest_chain() -> [SwapManifestV1; 3] {
        let first = manifest_fixture(1, None, 30, 10, 11, 11, 1, 2, 0x21);
        let second = manifest_fixture(
            2,
            Some(first.restore_identity.manifest_id),
            10,
            12,
            13,
            13,
            3,
            4,
            0x22,
        );
        let third = manifest_fixture(
            3,
            Some(second.restore_identity.manifest_id),
            20,
            14,
            15,
            15,
            5,
            6,
            0x23,
        );
        [first, second, third]
    }

    fn object_id(manifest: &SwapManifestV1) -> ManifestObjectId {
        ManifestObjectId::new(
            manifest.restore_identity.chain_swap_id,
            manifest.restore_identity.manifest_id,
        )
        .unwrap()
    }

    fn seal(
        manifest: &SwapManifestV1,
        key_id: &str,
        key: &[u8; 32],
        signer: &Keypair,
    ) -> EncryptedSwapManifestV1 {
        EncryptedSwapManifestV1::parse(manifest.seal(key_id, key, signer).unwrap()).unwrap()
    }

    fn memory_store(backend: Arc<dyn ObjectStore>, prefix: &str) -> RecoveryManifestStore {
        RecoveryManifestStore::from_object_store_for_integration_tests(backend, prefix).unwrap()
    }

    fn secrets(key_id: &str, key: [u8; 32], signer: &Keypair) -> RecoveryWitnessOpenSecretsV1 {
        RecoveryWitnessOpenSecretsV1::new(key_id, key, signer.x_only_public_key().0).unwrap()
    }

    async fn store_manifest(
        store: &RecoveryManifestStore,
        manifest: &SwapManifestV1,
        signer: &Keypair,
    ) -> EncryptedSwapManifestV1 {
        let envelope = seal(manifest, KEY_ID, &ENCRYPTION_KEY, signer);
        assert_eq!(
            store.put_v1(object_id(manifest), &envelope).await.unwrap(),
            ManifestWriteOutcome::Created
        );
        envelope
    }

    #[tokio::test]
    async fn unordered_generic_stream_is_consumed_to_eof_before_sorting() {
        let inner = Arc::new(InMemory::new());
        let population_store = memory_store(inner.clone(), PREFIX);
        let signer = signing_key(0x11);
        let chain = three_manifest_chain();
        let mut expected_envelopes = Vec::with_capacity(chain.len());
        for manifest in &chain {
            expected_envelopes.push(
                store_manifest(&population_store, manifest, &signer)
                    .await
                    .into_encoded(),
            );
        }

        let list_prefix = Path::from(format!("{PREFIX}/v1"));
        let mut metadata: Vec<_> = inner.list(Some(&list_prefix)).try_collect().await.unwrap();
        metadata.sort_unstable_by_key(|meta| meta.location.clone());
        let deliberately_unordered = vec![
            metadata[2].clone(),
            metadata[0].clone(),
            metadata[1].clone(),
        ];
        let backend: Arc<dyn ObjectStore> = Arc::new(TestObjectStore {
            inner,
            mode: BackendMode::ScriptedList(deliberately_unordered),
        });
        let store = memory_store(backend, PREFIX);

        // The legacy diagnostic pager takes limit+1 before sorting. With this
        // legal unordered stream it advances to the largest key and skips two
        // objects, proving why restore must not build completeness from it.
        let diagnostic = store.list_v1(1).await.unwrap();
        assert!(diagnostic.truncated);
        let skipped = store.list_v1_after(diagnostic.next_after, 1).await.unwrap();
        assert!(skipped.objects.is_empty());

        // No writes occur after population: this is the required quiescent
        // interval around the one-stream complete loader.
        let loader =
            RecoveryManifestWitnessLoaderV1::new(store, secrets(KEY_ID, ENCRYPTION_KEY, &signer));
        let loaded = loader.load_quiescent().await.unwrap();
        let sequences: Vec<_> = loaded
            .manifests()
            .iter()
            .map(|manifest| manifest.restore_identity.manifest_sequence)
            .collect();
        assert_eq!(sequences, [1, 2, 3]);
        for (offset, manifest) in loaded.manifests().iter().enumerate() {
            let record = loader
                .load_exact_authenticated_record(manifest)
                .await
                .unwrap();
            assert_eq!(record.manifest(), manifest);
            assert_eq!(
                record.encrypted_envelope().encoded(),
                expected_envelopes[offset]
            );
            let debug = format!("{record:?}");
            assert!(!debug.contains(&expected_envelopes[offset]));
            assert!(!debug.contains(&record.manifest().restore_identity.boltz_swap_id));
        }

        let mut changed_after_audit = loaded.manifests()[1].clone();
        changed_after_audit
            .merchant_policy
            .merchant_nym
            .push_str("-different");
        let error = loader
            .load_exact_authenticated_record(&changed_after_audit)
            .await
            .unwrap_err();
        assert_eq!(error, RecoveryWitnessLoadError::AuditedManifestChanged);
        assert!(error.source().is_none());
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(&changed_after_audit.merchant_policy.merchant_nym));
        assert!(!rendered.contains(&changed_after_audit.restore_identity.boltz_swap_id));
        assert_eq!(loaded.audit().manifest_count, 3);
        assert_eq!(loaded.audit().last_manifest_sequence, Some(3));
        assert_eq!(
            loaded.audit().last_manifest_id,
            Some(chain[2].restore_identity.manifest_id)
        );
    }

    #[tokio::test]
    async fn empty_quiescent_witness_is_a_complete_authenticated_result() {
        let backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = memory_store(backend, PREFIX);
        let signer = signing_key(0x11);
        let loaded =
            RecoveryManifestWitnessLoaderV1::new(store, secrets(KEY_ID, ENCRYPTION_KEY, &signer))
                .load_quiescent()
                .await
                .unwrap();
        assert!(loaded.manifests().is_empty());
        assert_eq!(loaded.audit().manifest_count, 0);
        assert_eq!(loaded.audit().last_manifest_sequence, None);
        assert_eq!(loaded.audit().last_manifest_id, None);
    }

    #[tokio::test]
    async fn requires_both_signed_object_identity_fields_to_match() {
        let signer = signing_key(0x11);
        let manifest = manifest_fixture(1, None, 1, 10, 11, 11, 1, 2, 0x21);

        let matching_backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let matching_store = memory_store(matching_backend, "matching/witness");
        store_manifest(&matching_store, &manifest, &signer).await;
        assert_eq!(
            RecoveryManifestWitnessLoaderV1::new(
                matching_store,
                secrets(KEY_ID, ENCRYPTION_KEY, &signer),
            )
            .load_quiescent()
            .await
            .unwrap()
            .manifests()
            .len(),
            1
        );

        for mismatched_id in [
            ManifestObjectId::new(
                Uuid::from_u128(90_001),
                manifest.restore_identity.manifest_id,
            )
            .unwrap(),
            ManifestObjectId::new(
                manifest.restore_identity.chain_swap_id,
                Uuid::from_u128(90_002),
            )
            .unwrap(),
        ] {
            let backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
            let store = memory_store(
                backend,
                &format!("mismatch/{}", mismatched_id.manifest_id()),
            );
            let envelope = seal(&manifest, KEY_ID, &ENCRYPTION_KEY, &signer);
            store.put_v1(mismatched_id, &envelope).await.unwrap();
            assert_eq!(
                RecoveryManifestWitnessLoaderV1::new(
                    store,
                    secrets(KEY_ID, ENCRYPTION_KEY, &signer),
                )
                .load_quiescent()
                .await
                .unwrap_err(),
                RecoveryWitnessLoadError::ObjectIdentityMismatch
            );
        }
    }

    #[tokio::test]
    async fn rejects_tamper_and_wrong_key_signer_or_key_id() {
        let signer = signing_key(0x11);
        let other_signer = signing_key(0x12);
        let manifest = manifest_fixture(1, None, 2, 10, 11, 11, 1, 2, 0x21);
        let envelope = seal(&manifest, KEY_ID, &ENCRYPTION_KEY, &signer);

        let cases = [
            secrets(KEY_ID, WRONG_ENCRYPTION_KEY, &signer),
            secrets(KEY_ID, ENCRYPTION_KEY, &other_signer),
            secrets("different-valid-key-id", ENCRYPTION_KEY, &signer),
        ];
        for (index, opening) in cases.into_iter().enumerate() {
            let backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
            let store = memory_store(backend, &format!("wrong-opening/{index}"));
            store.put_v1(object_id(&manifest), &envelope).await.unwrap();
            assert_eq!(
                RecoveryManifestWitnessLoaderV1::new(store, opening)
                    .load_quiescent()
                    .await
                    .unwrap_err(),
                RecoveryWitnessLoadError::EnvelopeAuthenticationFailed
            );
        }

        let mut value: serde_json::Value = serde_json::from_str(envelope.encoded()).unwrap();
        let ciphertext = value["ciphertext_hex"].as_str().unwrap();
        let replacement = if ciphertext.starts_with('0') {
            "1"
        } else {
            "0"
        };
        let tampered_ciphertext = format!("{replacement}{}", &ciphertext[1..]);
        value["ciphertext_hex"] = tampered_ciphertext.into();
        let tampered = EncryptedSwapManifestV1::parse(canonical_json(&value)).unwrap();
        let backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = memory_store(backend, "tampered/witness");
        store.put_v1(object_id(&manifest), &tampered).await.unwrap();
        assert_eq!(
            RecoveryManifestWitnessLoaderV1::new(store, secrets(KEY_ID, ENCRYPTION_KEY, &signer),)
                .load_quiescent()
                .await
                .unwrap_err(),
            RecoveryWitnessLoadError::EnvelopeAuthenticationFailed
        );
    }

    #[tokio::test]
    async fn rejects_gap_duplicate_and_broken_predecessor_topology() {
        let signer = signing_key(0x11);
        let valid_first = manifest_fixture(1, None, 1, 10, 11, 11, 1, 2, 0x21);

        let gap = manifest_fixture(
            3,
            Some(valid_first.restore_identity.manifest_id),
            2,
            12,
            13,
            13,
            3,
            4,
            0x22,
        );
        let broken_predecessor =
            manifest_fixture(2, Some(Uuid::from_u128(99_999)), 3, 12, 13, 13, 3, 4, 0x22);
        let mut duplicate = manifest_fixture(
            2,
            Some(valid_first.restore_identity.manifest_id),
            4,
            12,
            13,
            13,
            3,
            4,
            0x22,
        );
        duplicate.restore_identity.chain_swap_id = valid_first.restore_identity.chain_swap_id;

        for (name, second) in [
            ("gap", gap),
            ("predecessor", broken_predecessor),
            ("duplicate", duplicate),
        ] {
            let backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
            let store = memory_store(backend, &format!("invalid-set/{name}"));
            store_manifest(&store, &valid_first, &signer).await;
            store_manifest(&store, &second, &signer).await;
            assert_eq!(
                RecoveryManifestWitnessLoaderV1::new(
                    store,
                    secrets(KEY_ID, ENCRYPTION_KEY, &signer),
                )
                .load_quiescent()
                .await
                .unwrap_err(),
                RecoveryWitnessLoadError::AppendOnlySetInvalid,
                "case {name}"
            );
        }
    }

    #[tokio::test]
    async fn complete_scan_enforces_overflow_and_duplicate_identity_bounds() {
        let signer = signing_key(0x11);
        let chain = three_manifest_chain();
        let backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = memory_store(backend, "record-bound/witness");
        for manifest in &chain {
            store_manifest(&store, manifest, &signer).await;
        }
        let overflow = store.list_all_v1_bounded(2).await.unwrap_err();
        assert_eq!(
            overflow,
            ManifestStoreError::ListResultLimitExceeded { max: 2 }
        );
        let overflow_rendered = format!("{overflow:?} {overflow}");
        for manifest in &chain {
            assert!(
                !overflow_rendered.contains(&manifest.restore_identity.chain_swap_id.to_string())
            );
            assert!(!overflow_rendered.contains(&manifest.restore_identity.manifest_id.to_string()));
        }
        assert!(overflow_rendered.len() < 180);
        assert_eq!(
            RecoveryManifestWitnessLoaderV1::with_test_limits(
                store,
                secrets(KEY_ID, ENCRYPTION_KEY, &signer),
                2,
            )
            .load_quiescent()
            .await
            .unwrap_err(),
            RecoveryWitnessLoadError::RecordLimitExceeded
        );

        let inner = Arc::new(InMemory::new());
        let population_store = memory_store(inner.clone(), "duplicate/witness");
        store_manifest(&population_store, &chain[0], &signer).await;
        let list_prefix = Path::from("duplicate/witness/v1");
        let metadata: Vec<_> = inner.list(Some(&list_prefix)).try_collect().await.unwrap();
        assert_eq!(metadata.len(), 1);
        let backend: Arc<dyn ObjectStore> = Arc::new(TestObjectStore {
            inner,
            mode: BackendMode::ScriptedList(vec![metadata[0].clone(), metadata[0].clone()]),
        });
        let duplicate_store = memory_store(backend, "duplicate/witness");
        assert!(matches!(
            duplicate_store.list_all_v1_bounded(10).await,
            Err(ManifestStoreError::CorruptRead {
                id: None,
                kind: CorruptReadKind::DuplicateObjectIdentity,
            })
        ));
        assert_eq!(
            RecoveryManifestWitnessLoaderV1::new(
                duplicate_store,
                secrets(KEY_ID, ENCRYPTION_KEY, &signer),
            )
            .load_quiescent()
            .await
            .unwrap_err(),
            RecoveryWitnessLoadError::StoreListFailed
        );
    }

    #[tokio::test]
    async fn collapses_list_and_get_backend_errors_without_sources() {
        let signer = signing_key(0x11);
        let manifest = manifest_fixture(1, None, 8, 10, 11, 11, 1, 2, 0x21);
        let inner = Arc::new(InMemory::new());
        let population_store = memory_store(inner.clone(), "backend-errors/witness");
        let envelope = store_manifest(&population_store, &manifest, &signer).await;

        for (mode, expected) in [
            (
                BackendMode::FailList,
                RecoveryWitnessLoadError::StoreListFailed,
            ),
            (
                BackendMode::FailGet,
                RecoveryWitnessLoadError::StoreReadFailed,
            ),
        ] {
            let backend: Arc<dyn ObjectStore> = Arc::new(TestObjectStore {
                inner: inner.clone(),
                mode,
            });
            let store = memory_store(backend, "backend-errors/witness");
            let error = RecoveryManifestWitnessLoaderV1::new(
                store,
                secrets(KEY_ID, ENCRYPTION_KEY, &signer),
            )
            .load_quiescent()
            .await
            .unwrap_err();
            assert_eq!(error, expected);
            assert!(error.source().is_none());
            let rendered = format!("{error:?} {error}");
            for forbidden in [
                "classified-backend-source",
                "https://secret-store.invalid",
                BACKEND_SECRET_HASH,
                BACKEND_SECRET_OBJECT_KEY,
                BACKEND_SECRET_PROVIDER_ID,
                KEY_ID,
                envelope.encoded(),
                &manifest.restore_identity.chain_swap_id.to_string(),
                &manifest.restore_identity.manifest_id.to_string(),
                &manifest.restore_identity.boltz_swap_id,
                PREFIX,
            ] {
                assert!(!rendered.contains(forbidden), "leaked {forbidden:?}");
            }
        }
    }

    #[test]
    fn secret_loader_result_and_errors_have_bounded_redacted_debug() {
        let signer = signing_key(0x11);
        let signer_hex = signer.x_only_public_key().0.to_string();
        let key_hex = hex::encode(ENCRYPTION_KEY);
        let opening = secrets(KEY_ID, ENCRYPTION_KEY, &signer);
        let opening_debug = format!("{opening:?}");
        for forbidden in [KEY_ID, key_hex.as_str(), signer_hex.as_str()] {
            assert!(!opening_debug.contains(forbidden));
        }
        assert!(opening_debug.matches("<redacted>").count() >= 3);

        let backend: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let loader = RecoveryManifestWitnessLoaderV1::new(memory_store(backend, PREFIX), opening);
        let loader_debug = format!("{loader:?}");
        for forbidden in [KEY_ID, key_hex.as_str(), signer_hex.as_str(), PREFIX] {
            assert!(!loader_debug.contains(forbidden));
        }
        assert!(loader_debug.contains("store: \"<redacted>\""));
        assert!(loader_debug.contains("secrets: \"<redacted>\""));

        let malformed = RecoveryWitnessOpenSecretsV1::new(
            "forbidden key id with spaces",
            ENCRYPTION_KEY,
            signer.x_only_public_key().0,
        )
        .unwrap_err();
        assert_eq!(
            malformed,
            RecoveryWitnessLoadError::InvalidOpeningConfiguration
        );
        let rendered = format!("{malformed:?} {malformed}");
        assert!(!rendered.contains("forbidden key id with spaces"));
        assert!(rendered.len() < 160);
    }

    enum BackendMode {
        FailList,
        FailGet,
        ScriptedList(Vec<ObjectMeta>),
    }

    struct TestObjectStore {
        inner: Arc<InMemory>,
        mode: BackendMode,
    }

    impl fmt::Debug for TestObjectStore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("TestObjectStore(<redacted>)")
        }
    }

    impl fmt::Display for TestObjectStore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("test object store")
        }
    }

    fn backend_error() -> object_store::Error {
        object_store::Error::Generic {
            store: "witness-test",
            source: Box::new(io::Error::other(
                "classified-backend-source https://secret-store.invalid \
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
                 private/witness/v1/secret-chain-id/secret-manifest-id.json \
                 SecretProviderIdentifier",
            )),
        }
    }

    #[async_trait]
    impl ObjectStore for TestObjectStore {
        async fn put_opts(
            &self,
            location: &Path,
            payload: PutPayload,
            options: PutOptions,
        ) -> object_store::Result<PutResult> {
            self.inner.put_opts(location, payload, options).await
        }

        async fn put_multipart_opts(
            &self,
            location: &Path,
            options: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(location, options).await
        }

        async fn get_opts(
            &self,
            location: &Path,
            options: GetOptions,
        ) -> object_store::Result<GetResult> {
            if matches!(&self.mode, BackendMode::FailGet) {
                Err(backend_error())
            } else {
                self.inner.get_opts(location, options).await
            }
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, object_store::Result<Path>>,
        ) -> BoxStream<'static, object_store::Result<Path>> {
            self.inner.delete_stream(locations)
        }

        fn list(
            &self,
            prefix: Option<&Path>,
        ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
            match &self.mode {
                BackendMode::FailList => stream::once(async { Err(backend_error()) }).boxed(),
                BackendMode::ScriptedList(metadata) => {
                    stream::iter(metadata.clone().into_iter().map(Ok)).boxed()
                }
                BackendMode::FailGet => self.inner.list(prefix),
            }
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&Path>,
        ) -> object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy_opts(
            &self,
            from: &Path,
            to: &Path,
            options: CopyOptions,
        ) -> object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }
}
