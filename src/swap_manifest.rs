//! Versioned, authenticated off-host evidence for exposed chain swaps.
//!
//! A manifest contains only the public derivation lineage and immutable policy
//! evidence needed to identify a missing database obligation. It deliberately
//! has no generic extension map and no fields for a preimage or private claim /
//! refund keys. The canonical payload is signed before the signed packet is
//! encrypted, so possession of the storage-encryption key is not sufficient to
//! forge Bullnym restore evidence.
//!
//! This module defines the format only. Export-before-exposure, external
//! storage durability, and restore reconciliation are separate #87 packages.

use std::fmt;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{hash160, Hash as _};
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
};
use bitcoin::script::Builder;
use bitcoin::ScriptBuf;
use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::boltz::{CreateChainResponse, Leaf, Side};
use boltz_client::util::secrets::Preimage;
use boltz_client::{BtcSwapScript, LBtcSwapScript, PublicKey as BoltzPublicKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secp256k1::rand::RngCore;
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SWAP_MANIFEST_FORMAT: &str = "bullnym-chain-swap-manifest";
pub const SWAP_MANIFEST_VERSION: u16 = 1;
/// Largest child index accepted by unhardened BIP32 derivation (`m/{index}`).
pub const MAX_UNHARDENED_SWAP_CHILD_INDEX: i64 = (1_i64 << 31) - 1;

const ENCRYPTION_ALGORITHM: &str = "xchacha20poly1305";
const SIGNATURE_ALGORITHM: &str = "bip340-secp256k1-sha256";
const SIGNING_DOMAIN: &[u8] = b"bullnym-chain-swap-manifest\0v1\0payload";
const SIGNING_AUX_DOMAIN: &[u8] = b"bullnym-chain-swap-manifest\0v1\0signing-aux";
const MAX_ENCODED_MANIFEST_BYTES: usize = 1_048_576;
const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_PAIR_QUOTE_BYTES: usize = 64 * 1024;
const XCHACHA_NONCE_BYTES: usize = 24;
const POLY1305_TAG_BYTES: usize = 16;
const BTC_TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;
const LIQUID_TAPSCRIPT_LEAF_VERSION: u8 = 0xc4;

/// Stable identities used to correlate an external record with a restored
/// database and the provider's xpub restore output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapRestoreIdentityV1 {
    pub manifest_id: Uuid,
    /// Monotonic position in the single configured append-only witness.
    pub manifest_sequence: u64,
    /// `None` only for sequence 1; otherwise the preceding manifest UUID.
    pub previous_manifest_id: Option<Uuid>,
    pub chain_swap_id: Uuid,
    pub boltz_swap_id: String,
    pub created_at_unix: i64,
}

/// One non-secret allocation from the global derivation registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestKeyAllocationV1 {
    pub allocation_id: Uuid,
    pub child_index: i64,
    pub purpose: ManifestKeyPurposeV1,
    pub public_key_hex: String,
    /// Present only for the chain-claim allocation. This is a hash, never the
    /// preimage itself.
    pub preimage_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKeyPurposeV1 {
    ChainClaim,
    ChainRefund,
}

/// Complete public lineage for the two keys allocated to one chain swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapDerivationLineageV1 {
    pub root_fingerprint: String,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    /// Allocator high-water observed by this signed record. It may exceed this
    /// swap's indexes when allocations are concurrent, but may never trail
    /// either allocation carried by the record.
    pub allocation_high_water_child_index: i64,
    pub claim: ManifestKeyAllocationV1,
    pub refund: ManifestKeyAllocationV1,
}

/// The exact creation boundary approved by #80 plus the locally constructed
/// payer instruction. All hashes are lowercase SHA-256 hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableChainSwapCreationV1 {
    pub lockup_address: String,
    pub lockup_bip21: String,
    pub user_lock_amount_sat: i64,
    pub server_lock_amount_sat: i64,
    pub canonical_provider_response_json: String,
    pub pinned_pair_hash: String,
    pub canonical_pair_quote_json: String,
    pub creation_response_sha256: String,
    pub btc_claim_script_sha256: String,
    pub btc_refund_script_sha256: String,
    pub liquid_claim_script_sha256: String,
    pub liquid_refund_script_sha256: String,
    pub btc_timeout_height: i64,
    pub liquid_timeout_height: i64,
    pub btc_network: String,
    pub liquid_network: String,
    pub liquid_asset_id: String,
    pub merchant_liquid_destination: String,
    pub merchant_emergency_btc_address: Option<String>,
}

impl ImmutableChainSwapCreationV1 {
    /// Copy the immutable #80 packet into the frozen manifest-v1 schema.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_terms(
        terms: &crate::db::ChainSwapCreationTerms,
        lockup_address: String,
        lockup_bip21: String,
        user_lock_amount_sat: i64,
        server_lock_amount_sat: i64,
        canonical_provider_response_json: String,
    ) -> Self {
        Self {
            lockup_address,
            lockup_bip21,
            user_lock_amount_sat,
            server_lock_amount_sat,
            canonical_provider_response_json,
            pinned_pair_hash: terms.pinned_pair_hash.clone(),
            canonical_pair_quote_json: terms.canonical_pair_quote_json.clone(),
            creation_response_sha256: terms.creation_response_sha256.clone(),
            btc_claim_script_sha256: terms.btc_claim_script_sha256.clone(),
            btc_refund_script_sha256: terms.btc_refund_script_sha256.clone(),
            liquid_claim_script_sha256: terms.liquid_claim_script_sha256.clone(),
            liquid_refund_script_sha256: terms.liquid_refund_script_sha256.clone(),
            btc_timeout_height: terms.btc_timeout_height,
            liquid_timeout_height: terms.liquid_timeout_height,
            btc_network: terms.btc_network.clone(),
            liquid_network: terms.liquid_network.clone(),
            liquid_asset_id: terms.liquid_asset_id.clone(),
            merchant_liquid_destination: terms.merchant_liquid_destination.clone(),
            merchant_emergency_btc_address: terms.merchant_emergency_btc_address.clone(),
        }
    }
}

/// References that let restore code verify the manifest's concrete merchant
/// destinations against their owning invoice and append-only recovery policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantPolicyReferencesV1 {
    pub invoice_id: Uuid,
    pub merchant_nym: String,
    pub merchant_liquid_destination: String,
    pub emergency_bitcoin_commitment_id: Option<Uuid>,
    pub merchant_emergency_btc_address: Option<String>,
}

impl MerchantPolicyReferencesV1 {
    pub fn new(
        invoice_id: Uuid,
        merchant_nym: impl Into<String>,
        liquid_destination: &str,
        emergency_bitcoin: Option<(Uuid, &str)>,
    ) -> Self {
        let (emergency_bitcoin_commitment_id, merchant_emergency_btc_address) =
            match emergency_bitcoin {
                Some((commitment_id, address)) => (Some(commitment_id), Some(address.to_owned())),
                None => (None, None),
            };
        Self {
            invoice_id,
            merchant_nym: merchant_nym.into(),
            merchant_liquid_destination: liquid_destination.to_owned(),
            emergency_bitcoin_commitment_id,
            merchant_emergency_btc_address,
        }
    }
}

/// Manifest-v1 signed plaintext. The schema marker is part of the signed bytes
/// as well as the authenticated envelope header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapManifestV1 {
    format: String,
    version: u16,
    pub restore_identity: SwapRestoreIdentityV1,
    pub derivation_lineage: SwapDerivationLineageV1,
    pub creation: ImmutableChainSwapCreationV1,
    pub merchant_policy: MerchantPolicyReferencesV1,
}

impl SwapManifestV1 {
    pub fn new(
        restore_identity: SwapRestoreIdentityV1,
        derivation_lineage: SwapDerivationLineageV1,
        creation: ImmutableChainSwapCreationV1,
        merchant_policy: MerchantPolicyReferencesV1,
    ) -> Result<Self, SwapManifestError> {
        let manifest = Self {
            format: SWAP_MANIFEST_FORMAT.to_owned(),
            version: SWAP_MANIFEST_VERSION,
            restore_identity,
            derivation_lineage,
            creation,
            merchant_policy,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn format(&self) -> &str {
        &self.format
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    /// Seal with a fresh 192-bit nonce. Determinism applies to canonical
    /// encoding and fixed-nonce fixtures, never to production nonce reuse.
    pub fn seal(
        &self,
        encryption_key_id: &str,
        encryption_key: &[u8; 32],
        signing_key: &Keypair,
    ) -> Result<String, SwapManifestError> {
        let mut nonce = [0_u8; XCHACHA_NONCE_BYTES];
        secp256k1::rand::thread_rng().fill_bytes(&mut nonce);
        self.seal_with_nonce(encryption_key_id, encryption_key, signing_key, &nonce)
    }

    fn seal_with_nonce(
        &self,
        encryption_key_id: &str,
        encryption_key: &[u8; 32],
        signing_key: &Keypair,
        nonce: &[u8; XCHACHA_NONCE_BYTES],
    ) -> Result<String, SwapManifestError> {
        self.validate()?;
        validate_key_id(encryption_key_id)?;

        let canonical_manifest = canonical_json(self)?;
        let manifest_sha256 = sha256_hex(canonical_manifest.as_bytes());
        let signing_digest = signing_digest(canonical_manifest.as_bytes());
        let message = Message::from_digest(signing_digest);
        let secp = Secp256k1::new();
        // The already-random envelope nonce supplies fresh BIP340 auxiliary
        // randomness without introducing a second fallible RNG boundary. A
        // fixed injected nonce still gives byte-stable protocol fixtures.
        let signing_aux = signing_aux(nonce);
        let signature = secp.sign_schnorr_with_aux_rand(&message, signing_key, &signing_aux);
        let (signer_xonly_public_key, _) = signing_key.x_only_public_key();

        let signed = SignedManifestV1 {
            manifest: self.clone(),
            manifest_sha256,
            signature_hex: signature.to_string(),
        };
        let signed_bytes = canonical_json(&signed)?.into_bytes();
        if signed_bytes.len() > MAX_CIPHERTEXT_BYTES - POLY1305_TAG_BYTES {
            return Err(SwapManifestError::TooLarge);
        }

        let header = EnvelopeHeaderV1 {
            format: SWAP_MANIFEST_FORMAT.to_owned(),
            version: SWAP_MANIFEST_VERSION,
            encryption_algorithm: ENCRYPTION_ALGORITHM.to_owned(),
            signature_algorithm: SIGNATURE_ALGORITHM.to_owned(),
            encryption_key_id: encryption_key_id.to_owned(),
            signer_xonly_public_key: signer_xonly_public_key.to_string(),
            nonce_hex: hex::encode(nonce),
        };
        let associated_data = canonical_json(&header)?;
        let cipher = XChaCha20Poly1305::new_from_slice(encryption_key)
            .map_err(|_| SwapManifestError::EncryptionFailed)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: &signed_bytes,
                    aad: associated_data.as_bytes(),
                },
            )
            .map_err(|_| SwapManifestError::EncryptionFailed)?;

        let envelope = EncryptedEnvelopeV1 {
            header,
            ciphertext_hex: hex::encode(ciphertext),
        };
        let encoded = canonical_json(&envelope)?;
        if encoded.len() > MAX_ENCODED_MANIFEST_BYTES {
            return Err(SwapManifestError::TooLarge);
        }
        Ok(encoded)
    }

    /// Authenticate, decrypt, verify the expected signer, and validate every
    /// version-1 semantic cross-reference before returning restore evidence.
    pub fn open(
        encoded: &str,
        expected_encryption_key_id: &str,
        encryption_key: &[u8; 32],
        expected_signer: &XOnlyPublicKey,
    ) -> Result<Self, SwapManifestError> {
        validate_key_id(expected_encryption_key_id)?;
        let envelope = parse_envelope(encoded)?;
        validate_envelope_header(&envelope.header)?;
        if envelope.header.encryption_key_id != expected_encryption_key_id {
            return Err(SwapManifestError::UnexpectedEncryptionKeyId);
        }
        if envelope.header.signer_xonly_public_key != expected_signer.to_string() {
            return Err(SwapManifestError::UnexpectedSigner);
        }

        let nonce =
            decode_fixed_hex::<XCHACHA_NONCE_BYTES>("envelope nonce", &envelope.header.nonce_hex)?;
        if envelope.ciphertext_hex.len() < POLY1305_TAG_BYTES * 2
            || envelope.ciphertext_hex.len() > MAX_CIPHERTEXT_BYTES * 2
        {
            return Err(SwapManifestError::InvalidField(
                "envelope ciphertext length is invalid".into(),
            ));
        }
        let ciphertext = decode_hex("envelope ciphertext", &envelope.ciphertext_hex)?;

        let associated_data = canonical_json(&envelope.header)?;
        let cipher = XChaCha20Poly1305::new_from_slice(encryption_key)
            .map_err(|_| SwapManifestError::AuthenticationFailed)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: associated_data.as_bytes(),
                },
            )
            .map_err(|_| SwapManifestError::AuthenticationFailed)?;

        let signed: SignedManifestV1 = serde_json::from_slice(&plaintext)
            .map_err(|_| SwapManifestError::MalformedSignedPayload)?;
        let canonical_signed = canonical_json(&signed)?;
        if canonical_signed.as_bytes() != plaintext {
            return Err(SwapManifestError::NonCanonicalEncoding);
        }
        if signed.manifest.format != SWAP_MANIFEST_FORMAT {
            return Err(SwapManifestError::InvalidField(
                "signed manifest format marker is invalid".into(),
            ));
        }
        if signed.manifest.version != SWAP_MANIFEST_VERSION {
            return Err(SwapManifestError::UnsupportedVersion(
                signed.manifest.version,
            ));
        }

        let canonical_manifest = canonical_json(&signed.manifest)?;
        require_lower_hex("signed manifest digest", &signed.manifest_sha256, 32)?;
        require_lower_hex("manifest signature", &signed.signature_hex, 64)?;
        if signed.manifest_sha256 != sha256_hex(canonical_manifest.as_bytes()) {
            return Err(SwapManifestError::DigestMismatch);
        }
        let signature = secp256k1::schnorr::Signature::from_str(&signed.signature_hex)
            .map_err(|_| SwapManifestError::SignatureVerificationFailed)?;
        let message = Message::from_digest(signing_digest(canonical_manifest.as_bytes()));
        Secp256k1::verification_only()
            .verify_schnorr(&signature, &message, expected_signer)
            .map_err(|_| SwapManifestError::SignatureVerificationFailed)?;

        signed.manifest.validate()?;
        Ok(signed.manifest)
    }

    fn validate(&self) -> Result<(), SwapManifestError> {
        if self.format != SWAP_MANIFEST_FORMAT {
            return invalid("manifest format marker is invalid");
        }
        if self.version != SWAP_MANIFEST_VERSION {
            return Err(SwapManifestError::UnsupportedVersion(self.version));
        }

        let identity = &self.restore_identity;
        require_non_nil("manifest id", identity.manifest_id)?;
        match (identity.manifest_sequence, identity.previous_manifest_id) {
            (0, _) => return invalid("manifest sequence must be positive"),
            (1, None) => {}
            (1, Some(_)) => return invalid("genesis manifest must not name a predecessor"),
            (_, None) => return invalid("non-genesis manifest must name its predecessor"),
            (_, Some(previous)) => {
                require_non_nil("previous manifest id", previous)?;
                if previous == identity.manifest_id {
                    return invalid("manifest must not name itself as its predecessor");
                }
            }
        }
        require_non_nil("chain swap id", identity.chain_swap_id)?;
        if identity.boltz_swap_id.is_empty()
            || identity.boltz_swap_id.len() > 128
            || !identity
                .boltz_swap_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        {
            return invalid("Boltz swap id is malformed");
        }
        if identity.created_at_unix <= 0 {
            return invalid("creation timestamp must be positive");
        }

        let lineage = &self.derivation_lineage;
        require_lower_hex("root fingerprint", &lineage.root_fingerprint, 8)?;
        if lineage.key_epoch <= 0 || lineage.derivation_scheme_version <= 0 {
            return invalid("derivation epoch and scheme version must be positive");
        }
        let claim_public_key =
            validate_allocation(&lineage.claim, ManifestKeyPurposeV1::ChainClaim)?;
        let refund_public_key =
            validate_allocation(&lineage.refund, ManifestKeyPurposeV1::ChainRefund)?;
        if lineage.claim.allocation_id == lineage.refund.allocation_id
            || lineage.claim.child_index == lineage.refund.child_index
            || claim_public_key.x_only_public_key().0 == refund_public_key.x_only_public_key().0
        {
            return invalid("claim and refund derivation identities must be distinct");
        }
        if !(0..=MAX_UNHARDENED_SWAP_CHILD_INDEX)
            .contains(&lineage.allocation_high_water_child_index)
        {
            return invalid("allocation high-water is outside the unhardened derivation domain");
        }
        if lineage.allocation_high_water_child_index
            < lineage.claim.child_index.max(lineage.refund.child_index)
        {
            return invalid("allocation high-water trails a manifest allocation");
        }

        let creation = &self.creation;
        require_bounded_no_whitespace("lockup address", &creation.lockup_address, 128)?;
        if creation.lockup_bip21.is_empty() || creation.lockup_bip21.len() > 2048 {
            return invalid("local BIP21 length is invalid");
        }
        validate_local_bip21(creation)?;
        if creation.server_lock_amount_sat <= 0
            || creation.user_lock_amount_sat < creation.server_lock_amount_sat
        {
            return invalid("chain-swap amounts are invalid");
        }
        let provider_response = validate_canonical_object(
            "provider response",
            &creation.canonical_provider_response_json,
            MAX_PROVIDER_RESPONSE_BYTES,
        )?;
        let pair_quote = validate_canonical_object(
            "pair quote",
            &creation.canonical_pair_quote_json,
            MAX_PAIR_QUOTE_BYTES,
        )?;
        for (name, hash) in [
            ("pinned pair hash", &creation.pinned_pair_hash),
            ("creation response hash", &creation.creation_response_sha256),
            (
                "Bitcoin claim script hash",
                &creation.btc_claim_script_sha256,
            ),
            (
                "Bitcoin refund script hash",
                &creation.btc_refund_script_sha256,
            ),
            (
                "Liquid claim script hash",
                &creation.liquid_claim_script_sha256,
            ),
            (
                "Liquid refund script hash",
                &creation.liquid_refund_script_sha256,
            ),
        ] {
            require_lower_hex(name, hash, 32)?;
        }
        if creation.creation_response_sha256
            != sha256_hex(creation.canonical_provider_response_json.as_bytes())
        {
            return invalid("creation response digest does not match canonical bytes");
        }
        validate_provider_creation_cross_references(
            self,
            &provider_response,
            &pair_quote,
            claim_public_key,
            refund_public_key,
        )?;
        if creation.btc_timeout_height <= 0 || creation.liquid_timeout_height <= 0 {
            return invalid("swap timeout heights must be positive");
        }
        validate_network_name("Bitcoin network", &creation.btc_network)?;
        validate_network_name("Liquid network", &creation.liquid_network)?;
        if creation.btc_network != "bitcoin" || creation.liquid_network != "liquid" {
            return invalid("manifest-v1 requires the Bitcoin and Liquid mainnet networks");
        }
        require_lower_hex("Liquid asset id", &creation.liquid_asset_id, 32)?;
        if creation.liquid_asset_id != boltz_client::elements::AssetId::LIQUID_BTC.to_string() {
            return invalid("manifest-v1 requires the Liquid Bitcoin asset id");
        }
        require_bounded_no_whitespace(
            "merchant Liquid destination",
            &creation.merchant_liquid_destination,
            512,
        )?;
        require_canonical_liquid_mainnet_address(
            "merchant Liquid destination",
            &creation.merchant_liquid_destination,
        )?;
        if let Some(address) = creation.merchant_emergency_btc_address.as_deref() {
            require_bounded_no_whitespace("merchant emergency Bitcoin address", address, 128)?;
            require_canonical_bitcoin_mainnet_address(
                "merchant emergency Bitcoin address",
                address,
            )?;
        }

        let policy = &self.merchant_policy;
        require_non_nil("invoice id", policy.invoice_id)?;
        require_bounded_no_whitespace("merchant nym", &policy.merchant_nym, 128)?;
        require_bounded_no_whitespace(
            "policy Liquid destination",
            &policy.merchant_liquid_destination,
            512,
        )?;
        require_canonical_liquid_mainnet_address(
            "policy Liquid destination",
            &policy.merchant_liquid_destination,
        )?;
        if policy.merchant_liquid_destination != creation.merchant_liquid_destination {
            return invalid("Liquid destination policy reference does not match creation evidence");
        }
        match (
            creation.merchant_emergency_btc_address.as_deref(),
            policy.emergency_bitcoin_commitment_id,
            policy.merchant_emergency_btc_address.as_deref(),
        ) {
            (None, None, None) => {}
            (Some(address), Some(commitment_id), Some(policy_address)) => {
                require_non_nil("emergency Bitcoin commitment id", commitment_id)?;
                require_bounded_no_whitespace(
                    "policy emergency Bitcoin address",
                    policy_address,
                    128,
                )?;
                require_canonical_bitcoin_mainnet_address(
                    "policy emergency Bitcoin address",
                    policy_address,
                )?;
                if policy_address != address {
                    return invalid(
                        "emergency Bitcoin policy reference does not match creation evidence",
                    );
                }
            }
            _ => {
                return invalid(
                    "emergency Bitcoin address and policy reference must be present together",
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifestV1 {
    manifest: SwapManifestV1,
    manifest_sha256: String,
    signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeHeaderV1 {
    format: String,
    version: u16,
    encryption_algorithm: String,
    signature_algorithm: String,
    encryption_key_id: String,
    signer_xonly_public_key: String,
    nonce_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedEnvelopeV1 {
    #[serde(flatten)]
    header: EnvelopeHeaderV1,
    ciphertext_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapManifestError {
    TooLarge,
    MalformedEnvelope,
    MalformedSignedPayload,
    NonCanonicalEncoding,
    UnsupportedVersion(u16),
    InvalidField(String),
    UnexpectedEncryptionKeyId,
    UnexpectedSigner,
    AuthenticationFailed,
    DigestMismatch,
    SignatureVerificationFailed,
    EncryptionFailed,
    Serialization(String),
}

impl fmt::Display for SwapManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("swap manifest exceeds the format size limit"),
            Self::MalformedEnvelope => f.write_str("swap manifest envelope is malformed"),
            Self::MalformedSignedPayload => {
                f.write_str("swap manifest signed payload is malformed")
            }
            Self::NonCanonicalEncoding => f.write_str("swap manifest encoding is not canonical"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported swap manifest version {version}")
            }
            Self::InvalidField(reason) => write!(f, "invalid swap manifest field: {reason}"),
            Self::UnexpectedEncryptionKeyId => {
                f.write_str("swap manifest encryption key id is not the expected id")
            }
            Self::UnexpectedSigner => {
                f.write_str("swap manifest signer is not the expected signer")
            }
            Self::AuthenticationFailed => f.write_str("swap manifest authentication failed"),
            Self::DigestMismatch => f.write_str("swap manifest payload digest does not match"),
            Self::SignatureVerificationFailed => {
                f.write_str("swap manifest signature verification failed")
            }
            Self::EncryptionFailed => f.write_str("swap manifest encryption failed"),
            Self::Serialization(reason) => {
                write!(f, "swap manifest serialization failed: {reason}")
            }
        }
    }
}

impl std::error::Error for SwapManifestError {}

fn parse_envelope(encoded: &str) -> Result<EncryptedEnvelopeV1, SwapManifestError> {
    if encoded.len() > MAX_ENCODED_MANIFEST_BYTES {
        return Err(SwapManifestError::TooLarge);
    }
    let envelope: EncryptedEnvelopeV1 =
        serde_json::from_str(encoded).map_err(|_| SwapManifestError::MalformedEnvelope)?;
    if canonical_json(&envelope)? != encoded {
        return Err(SwapManifestError::NonCanonicalEncoding);
    }
    Ok(envelope)
}

fn validate_envelope_header(header: &EnvelopeHeaderV1) -> Result<(), SwapManifestError> {
    if header.format != SWAP_MANIFEST_FORMAT {
        return invalid("envelope format marker is invalid");
    }
    if header.version != SWAP_MANIFEST_VERSION {
        return Err(SwapManifestError::UnsupportedVersion(header.version));
    }
    if header.encryption_algorithm != ENCRYPTION_ALGORITHM {
        return invalid("envelope encryption algorithm is invalid");
    }
    if header.signature_algorithm != SIGNATURE_ALGORITHM {
        return invalid("envelope signature algorithm is invalid");
    }
    validate_key_id(&header.encryption_key_id)?;
    XOnlyPublicKey::from_str(&header.signer_xonly_public_key)
        .map_err(|_| SwapManifestError::InvalidField("envelope signer is malformed".into()))?;
    decode_fixed_hex::<XCHACHA_NONCE_BYTES>("envelope nonce", &header.nonce_hex)?;
    Ok(())
}

fn validate_allocation(
    allocation: &ManifestKeyAllocationV1,
    expected_purpose: ManifestKeyPurposeV1,
) -> Result<secp256k1::PublicKey, SwapManifestError> {
    require_non_nil("allocation id", allocation.allocation_id)?;
    if !(0..=MAX_UNHARDENED_SWAP_CHILD_INDEX).contains(&allocation.child_index) {
        return invalid("derivation child index is outside the unhardened derivation domain");
    }
    if allocation.purpose != expected_purpose {
        return invalid("derivation allocation purpose is incorrect");
    }
    if allocation.public_key_hex.len() != 66
        || !matches!(allocation.public_key_hex.get(..2), Some("02" | "03"))
    {
        return invalid("derivation public key is not compressed secp256k1 hex");
    }
    require_lower_hex("derivation public key", &allocation.public_key_hex, 33)?;
    let public_key = secp256k1::PublicKey::from_str(&allocation.public_key_hex)
        .map_err(|_| SwapManifestError::InvalidField("derivation public key is invalid".into()))?;
    match (allocation.purpose, allocation.preimage_hash_hex.as_deref()) {
        (ManifestKeyPurposeV1::ChainClaim, Some(hash)) => {
            require_lower_hex("claim preimage hash", hash, 32)?;
        }
        (ManifestKeyPurposeV1::ChainRefund, None) => {}
        _ => return invalid("preimage hash does not match derivation purpose"),
    }
    Ok(public_key)
}

fn validate_local_bip21(creation: &ImmutableChainSwapCreationV1) -> Result<(), SwapManifestError> {
    let suffix = creation
        .lockup_bip21
        .strip_prefix("bitcoin:")
        .ok_or_else(|| SwapManifestError::InvalidField("local BIP21 scheme is invalid".into()))?;
    let (address, query) = suffix
        .split_once('?')
        .ok_or_else(|| SwapManifestError::InvalidField("local BIP21 has no query".into()))?;
    if address != creation.lockup_address {
        return invalid("local BIP21 address does not match creation evidence");
    }
    let expected_amount = format_btc_amount(creation.user_lock_amount_sat)?;
    let amounts: Vec<_> = query
        .split('&')
        .filter_map(|field| field.strip_prefix("amount="))
        .collect();
    if amounts.as_slice() != [expected_amount.as_str()] {
        return invalid("local BIP21 amount does not match creation evidence");
    }
    Ok(())
}

fn format_btc_amount(amount_sat: i64) -> Result<String, SwapManifestError> {
    let amount_sat = u64::try_from(amount_sat)
        .map_err(|_| SwapManifestError::InvalidField("payer amount is invalid".into()))?;
    Ok(format!(
        "{}.{:08}",
        amount_sat / 100_000_000,
        amount_sat % 100_000_000
    ))
}

fn validate_canonical_object(
    name: &str,
    encoded: &str,
    max_bytes: usize,
) -> Result<Value, SwapManifestError> {
    if encoded.len() > max_bytes {
        return invalid(format!("{name} exceeds its size limit"));
    }
    let value: Value = serde_json::from_str(encoded)
        .map_err(|_| SwapManifestError::InvalidField(format!("{name} is not valid JSON")))?;
    if !value.is_object() {
        return invalid(format!("{name} must be a JSON object"));
    }
    if canonical_json(&value)? != encoded {
        return invalid(format!("{name} is not canonical JSON"));
    }
    Ok(value)
}

fn validate_provider_creation_cross_references(
    manifest: &SwapManifestV1,
    response_value: &Value,
    pair_quote: &Value,
    claim_public_key: secp256k1::PublicKey,
    refund_public_key: secp256k1::PublicKey,
) -> Result<(), SwapManifestError> {
    let creation = &manifest.creation;
    let response: CreateChainResponse =
        serde_json::from_value(response_value.clone()).map_err(|error| {
            SwapManifestError::InvalidField(format!(
                "provider response does not match the pinned chain-response schema: {error}"
            ))
        })?;
    if response.id != manifest.restore_identity.boltz_swap_id {
        return invalid("provider response id does not match restore identity");
    }
    if response.lockup_details.lockup_address != creation.lockup_address {
        return invalid("provider lockup address does not match creation evidence");
    }
    if u64::try_from(creation.user_lock_amount_sat).ok() != Some(response.lockup_details.amount) {
        return invalid("provider user-lock amount does not match creation evidence");
    }
    if u64::try_from(creation.server_lock_amount_sat).ok() != Some(response.claim_details.amount) {
        return invalid("provider server-lock amount does not match creation evidence");
    }
    if pair_quote.get("hash").and_then(Value::as_str) != Some(creation.pinned_pair_hash.as_str()) {
        return invalid("pair quote hash does not match the pinned pair hash");
    }

    validate_provider_swap_contract(
        manifest,
        &response,
        BoltzPublicKey::new(claim_public_key),
        BoltzPublicKey::new(refund_public_key),
    )?;
    Ok(())
}

fn validate_provider_swap_contract(
    manifest: &SwapManifestV1,
    response: &CreateChainResponse,
    claim_public_key: BoltzPublicKey,
    refund_public_key: BoltzPublicKey,
) -> Result<(), SwapManifestError> {
    if response
        .lockup_details
        .swap_tree
        .covenant_claim_leaf
        .is_some()
        || response
            .claim_details
            .swap_tree
            .covenant_claim_leaf
            .is_some()
    {
        return invalid("provider response contains an unexpected covenant leaf");
    }

    let claim_preimage_sha256 = manifest
        .derivation_lineage
        .claim
        .preimage_hash_hex
        .as_deref()
        .ok_or_else(|| {
            SwapManifestError::InvalidField("claim preimage SHA-256 is missing".into())
        })?;
    // The pinned client deliberately derives HASH160 from an already-hashed
    // preimage as RIPEMD160(SHA256(preimage)); no secret preimage is needed.
    let expected_preimage = Preimage::from_sha256_str(claim_preimage_sha256).map_err(|error| {
        SwapManifestError::InvalidField(format!(
            "claim preimage SHA-256 cannot derive a hashlock: {error}"
        ))
    })?;

    let bitcoin_script = BtcSwapScript::chain_from_swap_resp(
        Side::Lockup,
        response.lockup_details.clone(),
        refund_public_key,
    )
    .map_err(|error| {
        SwapManifestError::InvalidField(format!("provider Bitcoin swap tree is invalid: {error}"))
    })?;
    let liquid_script = LBtcSwapScript::chain_from_swap_resp(
        Side::Claim,
        response.claim_details.clone(),
        claim_public_key,
    )
    .map_err(|error| {
        SwapManifestError::InvalidField(format!("provider Liquid swap tree is invalid: {error}"))
    })?;

    if bitcoin_script.hashlock.to_byte_array() != expected_preimage.hash160.to_byte_array()
        || liquid_script.hashlock.to_byte_array() != expected_preimage.hash160.to_byte_array()
        || bitcoin_script.hashlock.to_byte_array() != liquid_script.hashlock.to_byte_array()
    {
        return invalid("Bitcoin and Liquid hashlocks do not match the claim preimage SHA-256");
    }
    if bitcoin_script.sender_pubkey != refund_public_key
        || bitcoin_script.receiver_pubkey != response.lockup_details.server_public_key
        || liquid_script.sender_pubkey != response.claim_details.server_public_key
        || liquid_script.receiver_pubkey != claim_public_key
    {
        return invalid("claim/refund allocation keys do not match provider script roles");
    }
    if !x_only_role_keys_are_distinct(&[
        &claim_public_key,
        &refund_public_key,
        &response.lockup_details.server_public_key,
        &response.claim_details.server_public_key,
    ]) {
        return invalid("provider and allocation x-only role keys must be distinct");
    }

    let creation = &manifest.creation;
    let bitcoin_timeout = response.lockup_details.timeout_block_height;
    let liquid_timeout = response.claim_details.timeout_block_height;
    if creation.btc_timeout_height != i64::from(bitcoin_timeout) {
        return invalid("Bitcoin timeout does not match provider response");
    }
    if creation.liquid_timeout_height != i64::from(liquid_timeout) {
        return invalid("Liquid timeout does not match provider response");
    }
    if bitcoin_script.locktime.to_consensus_u32() != bitcoin_timeout {
        return invalid("Bitcoin refund script does not match provider timeout");
    }
    if liquid_script.locktime.to_consensus_u32() != liquid_timeout {
        return invalid("Liquid refund script does not match provider timeout");
    }

    let bitcoin_claim_script = expected_claim_script(
        expected_preimage.hash160,
        &response.lockup_details.server_public_key,
    );
    let bitcoin_refund_script = expected_refund_script(&refund_public_key, bitcoin_timeout);
    let liquid_claim_script = expected_claim_script(expected_preimage.hash160, &claim_public_key);
    let liquid_refund_script =
        expected_refund_script(&response.claim_details.server_public_key, liquid_timeout);
    validate_exact_leaf_cross_reference(
        "Bitcoin claim",
        &response.lockup_details.swap_tree.claim_leaf,
        BTC_TAPSCRIPT_LEAF_VERSION,
        &bitcoin_claim_script,
        &creation.btc_claim_script_sha256,
    )?;
    validate_exact_leaf_cross_reference(
        "Bitcoin refund",
        &response.lockup_details.swap_tree.refund_leaf,
        BTC_TAPSCRIPT_LEAF_VERSION,
        &bitcoin_refund_script,
        &creation.btc_refund_script_sha256,
    )?;
    validate_exact_leaf_cross_reference(
        "Liquid claim",
        &response.claim_details.swap_tree.claim_leaf,
        LIQUID_TAPSCRIPT_LEAF_VERSION,
        &liquid_claim_script,
        &creation.liquid_claim_script_sha256,
    )?;
    validate_exact_leaf_cross_reference(
        "Liquid refund",
        &response.claim_details.swap_tree.refund_leaf,
        LIQUID_TAPSCRIPT_LEAF_VERSION,
        &liquid_refund_script,
        &creation.liquid_refund_script_sha256,
    )?;

    response
        .validate(
            &claim_public_key,
            &refund_public_key,
            Chain::Bitcoin(BitcoinChain::Bitcoin),
            Chain::Liquid(LiquidChain::Liquid),
        )
        .map_err(|error| {
            SwapManifestError::InvalidField(format!(
                "provider response fails pinned Boltz validation: {error}"
            ))
        })?;
    Ok(())
}

fn x_only_role_keys_are_distinct(keys: &[&BoltzPublicKey]) -> bool {
    keys.iter().enumerate().all(|(index, key)| {
        let x_only = key.inner.x_only_public_key().0;
        keys[index + 1..]
            .iter()
            .all(|other| other.inner.x_only_public_key().0 != x_only)
    })
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

fn validate_exact_leaf_cross_reference(
    name: &str,
    actual: &Leaf,
    expected_version: u8,
    expected_script: &ScriptBuf,
    stored_sha256: &str,
) -> Result<(), SwapManifestError> {
    if actual.version != expected_version {
        return invalid(format!(
            "{name} leaf version is {}, expected {expected_version}",
            actual.version
        ));
    }
    let actual_script = hex::decode(&actual.output).map_err(|error| {
        SwapManifestError::InvalidField(format!("{name} leaf is not hex: {error}"))
    })?;
    if actual_script != expected_script.as_bytes() {
        return invalid(format!(
            "{name} leaf does not match the exact expected template"
        ));
    }
    if sha256_hex(&actual_script) != stored_sha256 {
        return invalid(format!(
            "{name} leaf digest does not match creation evidence"
        ));
    }
    Ok(())
}

fn require_canonical_liquid_mainnet_address(
    name: &str,
    address: &str,
) -> Result<(), SwapManifestError> {
    let canonical =
        crate::validators::canonical_liquid_mainnet_address(address).map_err(|error| {
            SwapManifestError::InvalidField(format!(
                "{name} is not a confidential Liquid mainnet address: {error}"
            ))
        })?;
    if canonical != address {
        return invalid(format!("{name} is not canonical"));
    }
    Ok(())
}

fn require_canonical_bitcoin_mainnet_address(
    name: &str,
    address: &str,
) -> Result<(), SwapManifestError> {
    let canonical = crate::validators::canonical_btc_mainnet_address(address).map_err(|error| {
        SwapManifestError::InvalidField(format!("{name} is not a Bitcoin mainnet address: {error}"))
    })?;
    if canonical != address {
        return invalid(format!("{name} is not canonical"));
    }
    Ok(())
}

fn validate_network_name(name: &str, value: &str) -> Result<(), SwapManifestError> {
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
    {
        return invalid(format!("{name} is malformed"));
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), SwapManifestError> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return invalid("encryption key id is malformed");
    }
    Ok(())
}

fn require_non_nil(name: &str, id: Uuid) -> Result<(), SwapManifestError> {
    if id.is_nil() {
        return invalid(format!("{name} must not be nil"));
    }
    Ok(())
}

fn require_bounded_no_whitespace(
    name: &str,
    value: &str,
    max_len: usize,
) -> Result<(), SwapManifestError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_whitespace) {
        return invalid(format!("{name} is malformed"));
    }
    Ok(())
}

fn require_lower_hex(name: &str, value: &str, bytes: usize) -> Result<(), SwapManifestError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!("{name} must be {bytes}-byte lowercase hex"));
    }
    Ok(())
}

fn decode_hex(name: &str, value: &str) -> Result<Vec<u8>, SwapManifestError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(format!("{name} is not lowercase hex"));
    }
    hex::decode(value).map_err(|_| SwapManifestError::InvalidField(format!("{name} is invalid")))
}

fn decode_fixed_hex<const N: usize>(name: &str, value: &str) -> Result<[u8; N], SwapManifestError> {
    let decoded = decode_hex(name, value)?;
    decoded
        .try_into()
        .map_err(|_| SwapManifestError::InvalidField(format!("{name} has the wrong length")))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, SwapManifestError> {
    crate::canonical_json::canonical_json_and_sha256(value)
        .map(|(canonical, _)| canonical)
        .map_err(|error| SwapManifestError::Serialization(error.to_string()))
}

fn signing_digest(canonical_manifest: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_DOMAIN);
    hasher.update((canonical_manifest.len() as u64).to_be_bytes());
    hasher.update(canonical_manifest);
    hasher.finalize().into()
}

fn signing_aux(nonce: &[u8; XCHACHA_NONCE_BYTES]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGNING_AUX_DOMAIN);
    hasher.update(nonce);
    hasher.finalize().into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, SwapManifestError> {
    Err(SwapManifestError::InvalidField(reason.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltz_client::swaps::boltz::{ChainSwapDetails, SwapTree, SwapType};
    use boltz_client::{ZKKeyPair, ZKSecp256k1};
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use serde_json::json;

    const ENCRYPTION_KEY: [u8; 32] = [0x42; 32];
    const WRONG_ENCRYPTION_KEY: [u8; 32] = [0x24; 32];
    const NONCE: [u8; XCHACHA_NONCE_BYTES] = [0x17; XCHACHA_NONCE_BYTES];

    fn signing_key() -> Keypair {
        let secret = secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap();
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
    }

    fn other_signing_key() -> Keypair {
        let secret = secp256k1::SecretKey::from_slice(&[0x12; 32]).unwrap();
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
    }

    fn real_shaped_provider_fixture() -> (
        CreateChainResponse,
        Preimage,
        BoltzPublicKey,
        BoltzPublicKey,
    ) {
        const BLINDING_KEY: &str =
            "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";
        let preimage = Preimage::from_str(&"11".repeat(32)).unwrap();
        let claim_public_key = BoltzPublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let refund_public_key = BoltzPublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
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
                id: "ManifestRealShape01".into(),
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

    fn leaf_sha256(leaf: &Leaf) -> String {
        sha256_hex(&hex::decode(&leaf.output).unwrap())
    }

    fn provider_response(manifest: &SwapManifestV1) -> CreateChainResponse {
        serde_json::from_str(&manifest.creation.canonical_provider_response_json).unwrap()
    }

    fn replace_provider_response(manifest: &mut SwapManifestV1, response: &CreateChainResponse) {
        let canonical = canonical_json(response).unwrap();
        manifest.creation.creation_response_sha256 = sha256_hex(canonical.as_bytes());
        manifest.creation.canonical_provider_response_json = canonical;
    }

    fn assert_invalid(manifest: &SwapManifestV1, expected_reason: &str) {
        let error = manifest.validate().unwrap_err();
        assert!(
            error.to_string().contains(expected_reason),
            "expected {expected_reason:?}, got {error}"
        );
    }

    fn replace_liquid_destination(manifest: &mut SwapManifestV1, address: &str) {
        manifest.creation.merchant_liquid_destination = address.to_owned();
        manifest.merchant_policy.merchant_liquid_destination = address.to_owned();
    }

    fn replace_emergency_bitcoin_address(manifest: &mut SwapManifestV1, address: &str) {
        manifest.creation.merchant_emergency_btc_address = Some(address.to_owned());
        manifest.merchant_policy.merchant_emergency_btc_address = Some(address.to_owned());
    }

    fn fixture() -> SwapManifestV1 {
        let (provider_response, preimage, claim_public_key, refund_public_key) =
            real_shaped_provider_fixture();
        let canonical_response = canonical_json(&provider_response).unwrap();
        let lockup_address = provider_response.lockup_details.lockup_address.clone();
        let liquid_destination = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";
        let emergency_address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        SwapManifestV1::new(
            SwapRestoreIdentityV1 {
                manifest_id: Uuid::from_u128(1),
                manifest_sequence: 2,
                previous_manifest_id: Some(Uuid::from_u128(7)),
                chain_swap_id: Uuid::from_u128(2),
                boltz_swap_id: provider_response.id.clone(),
                created_at_unix: 1_784_000_000,
            },
            SwapDerivationLineageV1 {
                root_fingerprint: "0011223344556677".into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                allocation_high_water_child_index: 431,
                claim: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(3),
                    child_index: 430,
                    purpose: ManifestKeyPurposeV1::ChainClaim,
                    public_key_hex: claim_public_key.to_string(),
                    preimage_hash_hex: Some(preimage.sha256.to_string()),
                },
                refund: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(4),
                    child_index: 431,
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
                Uuid::from_u128(5),
                "restore-nym",
                liquid_destination,
                Some((Uuid::from_u128(6), emergency_address)),
            ),
        )
        .unwrap()
    }

    fn signer_public_key(keypair: &Keypair) -> XOnlyPublicKey {
        keypair.x_only_public_key().0
    }

    fn seal_fixture() -> String {
        fixture()
            .seal_with_nonce(
                "manifest-key-2026-01",
                &ENCRYPTION_KEY,
                &signing_key(),
                &NONCE,
            )
            .unwrap()
    }

    #[test]
    fn signed_encrypted_manifest_round_trips() {
        let manifest = fixture();
        let signer = signing_key();
        let encoded = manifest
            .seal_with_nonce("manifest-key-2026-01", &ENCRYPTION_KEY, &signer, &NONCE)
            .unwrap();

        let restored = SwapManifestV1::open(
            &encoded,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signer),
        )
        .unwrap();

        assert_eq!(restored, manifest);
        assert_eq!(restored.format(), SWAP_MANIFEST_FORMAT);
        assert_eq!(restored.version(), SWAP_MANIFEST_VERSION);
    }

    #[test]
    fn real_shaped_provider_response_cross_references_are_accepted() {
        let manifest = fixture();
        let response = provider_response(&manifest);

        manifest.validate().unwrap();
        assert!(response.lockup_details.lockup_address.starts_with("bc1p"));
        assert!(response.claim_details.lockup_address.starts_with("lq1p"));
        assert_eq!(
            response.lockup_details.swap_tree.claim_leaf.version,
            BTC_TAPSCRIPT_LEAF_VERSION
        );
        assert_eq!(
            response.claim_details.swap_tree.claim_leaf.version,
            LIQUID_TAPSCRIPT_LEAF_VERSION
        );
    }

    #[test]
    fn real_mainnet_asset_and_merchant_destinations_are_accepted() {
        let manifest = fixture();

        assert_eq!(
            manifest.creation.liquid_asset_id,
            boltz_client::elements::AssetId::LIQUID_BTC.to_string()
        );
        assert_eq!(
            crate::validators::canonical_liquid_mainnet_address(
                &manifest.creation.merchant_liquid_destination
            )
            .unwrap(),
            manifest.creation.merchant_liquid_destination
        );
        assert_eq!(
            crate::validators::canonical_btc_mainnet_address(
                manifest
                    .creation
                    .merchant_emergency_btc_address
                    .as_deref()
                    .unwrap()
            )
            .unwrap(),
            manifest
                .creation
                .merchant_emergency_btc_address
                .as_deref()
                .unwrap()
        );
        manifest.validate().unwrap();
    }

    #[test]
    fn manifest_v1_rejects_any_asset_other_than_liquid_bitcoin() {
        let mut manifest = fixture();
        manifest.creation.liquid_asset_id = "99".repeat(32);

        assert_invalid(&manifest, "requires the Liquid Bitcoin asset id");
    }

    #[test]
    fn merchant_liquid_destination_rejects_wrong_network_unconfidential_and_malformed() {
        const TESTNET_CONFIDENTIAL: &str = "tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn";
        let mut wrong_network = fixture();
        replace_liquid_destination(&mut wrong_network, TESTNET_CONFIDENTIAL);
        assert_invalid(&wrong_network, "not a confidential Liquid mainnet address");

        let mut parsed = fixture()
            .creation
            .merchant_liquid_destination
            .parse::<lwk_wollet::elements::Address>()
            .unwrap();
        parsed.blinding_pubkey = None;
        let mut unconfidential = fixture();
        replace_liquid_destination(&mut unconfidential, &parsed.to_string());
        assert_invalid(&unconfidential, "not a confidential Liquid mainnet address");

        let mut malformed = fixture();
        replace_liquid_destination(&mut malformed, "not-a-liquid-address");
        assert_invalid(&malformed, "not a confidential Liquid mainnet address");
    }

    #[test]
    fn emergency_bitcoin_destination_rejects_wrong_network_and_malformed() {
        let mut wrong_network = fixture();
        replace_emergency_bitcoin_address(
            &mut wrong_network,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        );
        assert_invalid(&wrong_network, "not a Bitcoin mainnet address");

        let mut malformed = fixture();
        replace_emergency_bitcoin_address(&mut malformed, "not-a-bitcoin-address");
        assert_invalid(&malformed, "not a Bitcoin mainnet address");
    }

    #[test]
    fn emergency_bitcoin_destination_remains_optional_until_issue_84() {
        let mut manifest = fixture();
        manifest.creation.merchant_emergency_btc_address = None;
        manifest.merchant_policy.emergency_bitcoin_commitment_id = None;
        manifest.merchant_policy.merchant_emergency_btc_address = None;

        manifest.validate().unwrap();
    }

    #[test]
    fn merchant_destinations_reject_noncanonical_address_encoding() {
        let mut liquid = fixture();
        let uppercase_liquid = liquid
            .creation
            .merchant_liquid_destination
            .to_ascii_uppercase();
        replace_liquid_destination(&mut liquid, &uppercase_liquid);
        assert_invalid(&liquid, "merchant Liquid destination is not canonical");

        let mut bitcoin = fixture();
        let uppercase_bitcoin = bitcoin
            .creation
            .merchant_emergency_btc_address
            .as_deref()
            .unwrap()
            .to_ascii_uppercase();
        replace_emergency_bitcoin_address(&mut bitcoin, &uppercase_bitcoin);
        assert_invalid(
            &bitcoin,
            "merchant emergency Bitcoin address is not canonical",
        );
    }

    #[test]
    fn genesis_manifest_round_trips_without_a_predecessor() {
        let mut manifest = fixture();
        manifest.restore_identity.manifest_sequence = 1;
        manifest.restore_identity.previous_manifest_id = None;
        let signer = signing_key();
        let encoded = manifest
            .seal_with_nonce("manifest-key-2026-01", &ENCRYPTION_KEY, &signer, &NONCE)
            .unwrap();

        let restored = SwapManifestV1::open(
            &encoded,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signer),
        )
        .unwrap();
        assert_eq!(restored.restore_identity.manifest_sequence, 1);
        assert_eq!(restored.restore_identity.previous_manifest_id, None);
    }

    #[test]
    fn manifest_chain_linkage_is_fail_closed() {
        let mut zero_sequence = fixture();
        zero_sequence.restore_identity.manifest_sequence = 0;
        assert_invalid(&zero_sequence, "manifest sequence must be positive");

        let mut genesis_with_previous = fixture();
        genesis_with_previous.restore_identity.manifest_sequence = 1;
        assert_invalid(
            &genesis_with_previous,
            "genesis manifest must not name a predecessor",
        );

        let mut non_genesis_without_previous = fixture();
        non_genesis_without_previous
            .restore_identity
            .previous_manifest_id = None;
        assert_invalid(
            &non_genesis_without_previous,
            "non-genesis manifest must name its predecessor",
        );

        let mut nil_previous = fixture();
        nil_previous.restore_identity.previous_manifest_id = Some(Uuid::nil());
        assert_invalid(&nil_previous, "previous manifest id must not be nil");

        let mut self_previous = fixture();
        self_previous.restore_identity.previous_manifest_id =
            Some(self_previous.restore_identity.manifest_id);
        assert_invalid(
            &self_previous,
            "manifest must not name itself as its predecessor",
        );
    }

    #[test]
    fn signed_allocation_high_water_covers_both_allocations() {
        let mut trailing = fixture();
        trailing
            .derivation_lineage
            .allocation_high_water_child_index = 430;
        assert_invalid(&trailing, "allocation high-water trails");

        let mut concurrent = fixture();
        concurrent
            .derivation_lineage
            .allocation_high_water_child_index = 450;
        concurrent.validate().unwrap();
    }

    #[test]
    fn maximum_unhardened_derivation_indices_are_accepted() {
        let mut manifest = fixture();
        manifest.derivation_lineage.claim.child_index = MAX_UNHARDENED_SWAP_CHILD_INDEX - 1;
        manifest.derivation_lineage.refund.child_index = MAX_UNHARDENED_SWAP_CHILD_INDEX;
        manifest
            .derivation_lineage
            .allocation_high_water_child_index = MAX_UNHARDENED_SWAP_CHILD_INDEX;

        manifest.validate().unwrap();
    }

    #[test]
    fn hardened_bit_or_larger_derivation_indices_are_rejected() {
        for invalid_index in [MAX_UNHARDENED_SWAP_CHILD_INDEX + 1, i64::MAX] {
            let mut claim = fixture();
            claim.derivation_lineage.claim.child_index = invalid_index;
            assert_invalid(
                &claim,
                "child index is outside the unhardened derivation domain",
            );

            let mut refund = fixture();
            refund.derivation_lineage.refund.child_index = invalid_index;
            assert_invalid(
                &refund,
                "child index is outside the unhardened derivation domain",
            );

            let mut high_water = fixture();
            high_water
                .derivation_lineage
                .allocation_high_water_child_index = invalid_index;
            assert_invalid(
                &high_water,
                "allocation high-water is outside the unhardened derivation domain",
            );
        }
    }

    #[test]
    fn every_stored_leaf_digest_must_match_its_provider_leaf() {
        for (index, name) in [
            "Bitcoin claim",
            "Bitcoin refund",
            "Liquid claim",
            "Liquid refund",
        ]
        .into_iter()
        .enumerate()
        {
            let mut manifest = fixture();
            match index {
                0 => manifest.creation.btc_claim_script_sha256 = "00".repeat(32),
                1 => manifest.creation.btc_refund_script_sha256 = "00".repeat(32),
                2 => manifest.creation.liquid_claim_script_sha256 = "00".repeat(32),
                3 => manifest.creation.liquid_refund_script_sha256 = "00".repeat(32),
                _ => unreachable!(),
            }
            assert_invalid(&manifest, &format!("{name} leaf digest"));
        }
    }

    #[test]
    fn every_provider_leaf_version_is_pinned() {
        for (index, name) in [
            "Bitcoin claim",
            "Bitcoin refund",
            "Liquid claim",
            "Liquid refund",
        ]
        .into_iter()
        .enumerate()
        {
            let mut manifest = fixture();
            let mut response = provider_response(&manifest);
            match index {
                0 => response.lockup_details.swap_tree.claim_leaf.version ^= 1,
                1 => response.lockup_details.swap_tree.refund_leaf.version ^= 1,
                2 => response.claim_details.swap_tree.claim_leaf.version ^= 1,
                3 => response.claim_details.swap_tree.refund_leaf.version ^= 1,
                _ => unreachable!(),
            }
            replace_provider_response(&mut manifest, &response);
            assert_invalid(&manifest, &format!("{name} leaf version"));
        }
    }

    #[test]
    fn stored_timeout_fields_must_match_the_provider_response() {
        let mut bitcoin = fixture();
        bitcoin.creation.btc_timeout_height += 1;
        assert_invalid(&bitcoin, "Bitcoin timeout does not match");

        let mut liquid = fixture();
        liquid.creation.liquid_timeout_height += 1;
        assert_invalid(&liquid, "Liquid timeout does not match");
    }

    #[test]
    fn advertised_timeouts_must_match_both_refund_scripts() {
        let mut bitcoin = fixture();
        let mut bitcoin_response = provider_response(&bitcoin);
        bitcoin_response.lockup_details.timeout_block_height += 1;
        bitcoin.creation.btc_timeout_height += 1;
        replace_provider_response(&mut bitcoin, &bitcoin_response);
        assert_invalid(
            &bitcoin,
            "Bitcoin refund script does not match provider timeout",
        );

        let mut liquid = fixture();
        let mut liquid_response = provider_response(&liquid);
        liquid_response.claim_details.timeout_block_height += 1;
        liquid.creation.liquid_timeout_height += 1;
        replace_provider_response(&mut liquid, &liquid_response);
        assert_invalid(
            &liquid,
            "Liquid refund script does not match provider timeout",
        );
    }

    #[test]
    fn allocation_public_keys_must_match_their_exact_script_roles() {
        let alternate_claim = secp256k1::PublicKey::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[0x13; 32]).unwrap(),
        );
        let alternate_refund = secp256k1::PublicKey::from_secret_key(
            &Secp256k1::new(),
            &secp256k1::SecretKey::from_slice(&[0x14; 32]).unwrap(),
        );

        let mut claim = fixture();
        claim.derivation_lineage.claim.public_key_hex = alternate_claim.to_string();
        assert_invalid(&claim, "Liquid claim leaf does not match");

        let mut refund = fixture();
        refund.derivation_lineage.refund.public_key_hex = alternate_refund.to_string();
        assert_invalid(&refund, "Bitcoin refund leaf does not match");
    }

    #[test]
    fn allocation_purposes_must_match_claim_and_refund_roles() {
        let mut claim = fixture();
        claim.derivation_lineage.claim.purpose = ManifestKeyPurposeV1::ChainRefund;
        assert_invalid(&claim, "derivation allocation purpose is incorrect");

        let mut refund = fixture();
        refund.derivation_lineage.refund.purpose = ManifestKeyPurposeV1::ChainClaim;
        assert_invalid(&refund, "derivation allocation purpose is incorrect");
    }

    #[test]
    fn stored_preimage_sha256_must_derive_both_provider_hashlocks() {
        let mut manifest = fixture();
        manifest.derivation_lineage.claim.preimage_hash_hex = Some("42".repeat(32));
        assert_invalid(
            &manifest,
            "hashlocks do not match the claim preimage SHA-256",
        );
    }

    #[test]
    fn each_provider_leaf_must_match_its_exact_template_even_if_rehashed() {
        for (index, name) in [
            "Bitcoin claim",
            "Bitcoin refund",
            "Liquid claim",
            "Liquid refund",
        ]
        .into_iter()
        .enumerate()
        {
            let mut manifest = fixture();
            let mut response = provider_response(&manifest);
            let digest = match index {
                0 => {
                    response
                        .lockup_details
                        .swap_tree
                        .claim_leaf
                        .output
                        .push_str("61");
                    leaf_sha256(&response.lockup_details.swap_tree.claim_leaf)
                }
                1 => {
                    response
                        .lockup_details
                        .swap_tree
                        .refund_leaf
                        .output
                        .push_str("61");
                    leaf_sha256(&response.lockup_details.swap_tree.refund_leaf)
                }
                2 => {
                    response
                        .claim_details
                        .swap_tree
                        .claim_leaf
                        .output
                        .push_str("61");
                    leaf_sha256(&response.claim_details.swap_tree.claim_leaf)
                }
                3 => {
                    response
                        .claim_details
                        .swap_tree
                        .refund_leaf
                        .output
                        .push_str("61");
                    leaf_sha256(&response.claim_details.swap_tree.refund_leaf)
                }
                _ => unreachable!(),
            };
            match index {
                0 => manifest.creation.btc_claim_script_sha256 = digest,
                1 => manifest.creation.btc_refund_script_sha256 = digest,
                2 => manifest.creation.liquid_claim_script_sha256 = digest,
                3 => manifest.creation.liquid_refund_script_sha256 = digest,
                _ => unreachable!(),
            }
            replace_provider_response(&mut manifest, &response);
            assert_invalid(
                &manifest,
                &format!("{name} leaf does not match the exact expected template"),
            );
        }
    }

    #[test]
    fn each_provider_chain_hashlock_must_match_the_stored_preimage_sha256() {
        for liquid in [false, true] {
            let mut manifest = fixture();
            let expected = Preimage::from_sha256_str(
                manifest
                    .derivation_lineage
                    .claim
                    .preimage_hash_hex
                    .as_deref()
                    .unwrap(),
            )
            .unwrap()
            .hash160
            .to_string();
            let mut response = provider_response(&manifest);
            let leaf = if liquid {
                &mut response.claim_details.swap_tree.claim_leaf
            } else {
                &mut response.lockup_details.swap_tree.claim_leaf
            };
            leaf.output = leaf.output.replacen(&expected, &"00".repeat(20), 1);
            replace_provider_response(&mut manifest, &response);

            assert_invalid(
                &manifest,
                "hashlocks do not match the claim preimage SHA-256",
            );
        }
    }

    #[test]
    fn unexpected_covenant_leaf_is_not_a_fifth_manifest_script() {
        let mut manifest = fixture();
        let mut response = provider_response(&manifest);
        response.claim_details.swap_tree.covenant_claim_leaf =
            Some(response.claim_details.swap_tree.claim_leaf.clone());
        replace_provider_response(&mut manifest, &response);

        assert_invalid(&manifest, "unexpected covenant leaf");
    }

    #[test]
    fn fixed_inputs_have_deterministic_canonical_encoding() {
        let first = seal_fixture();
        let second = seal_fixture();

        assert_eq!(first, second);
        assert!(!first.contains(char::is_whitespace));
        assert_eq!(
            sha256_hex(first.as_bytes()),
            "4c5b7a934a6fa3196d612158f5aa61a3f861222385e302d1c20a0b25e4db787b"
        );
    }

    #[test]
    fn production_sealing_uses_fresh_nonces() {
        let manifest = fixture();
        let signer = signing_key();
        let first = manifest
            .seal("manifest-key-2026-01", &ENCRYPTION_KEY, &signer)
            .unwrap();
        let second = manifest
            .seal("manifest-key-2026-01", &ENCRYPTION_KEY, &signer)
            .unwrap();
        let first_envelope: EncryptedEnvelopeV1 = serde_json::from_str(&first).unwrap();
        let second_envelope: EncryptedEnvelopeV1 = serde_json::from_str(&second).unwrap();

        assert_ne!(
            first_envelope.header.nonce_hex,
            second_envelope.header.nonce_hex
        );
        assert_ne!(first, second);
        assert_eq!(
            SwapManifestV1::open(
                &first,
                "manifest-key-2026-01",
                &ENCRYPTION_KEY,
                &signer_public_key(&signer),
            )
            .unwrap(),
            manifest
        );
    }

    #[test]
    fn ciphertext_tamper_is_rejected() {
        let encoded = seal_fixture();
        let mut envelope: EncryptedEnvelopeV1 = serde_json::from_str(&encoded).unwrap();
        let replacement = if envelope.ciphertext_hex.starts_with('0') {
            '1'
        } else {
            '0'
        };
        envelope
            .ciphertext_hex
            .replace_range(..1, &replacement.to_string());
        let tampered = canonical_json(&envelope).unwrap();

        let error = SwapManifestV1::open(
            &tampered,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::AuthenticationFailed);
    }

    #[test]
    fn wrong_encryption_key_is_rejected() {
        let error = SwapManifestV1::open(
            &seal_fixture(),
            "manifest-key-2026-01",
            &WRONG_ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::AuthenticationFailed);
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let encoded = seal_fixture();
        let mut envelope: EncryptedEnvelopeV1 = serde_json::from_str(&encoded).unwrap();
        envelope
            .ciphertext_hex
            .truncate(envelope.ciphertext_hex.len() - 2);
        let truncated = canonical_json(&envelope).unwrap();

        let error = SwapManifestV1::open(
            &truncated,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::AuthenticationFailed);
    }

    #[test]
    fn expected_signer_is_required() {
        let error = SwapManifestV1::open(
            &seal_fixture(),
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&other_signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::UnexpectedSigner);
    }

    #[test]
    fn unsupported_envelope_version_is_rejected_explicitly() {
        let encoded = seal_fixture();
        let mut envelope: EncryptedEnvelopeV1 = serde_json::from_str(&encoded).unwrap();
        envelope.header.version = 2;
        let future = canonical_json(&envelope).unwrap();

        let error = SwapManifestV1::open(
            &future,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::UnsupportedVersion(2));
    }

    #[test]
    fn unknown_envelope_fields_are_rejected() {
        let mut value = serde_json::from_str::<Value>(&seal_fixture()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unversioned_extension".into(), json!(true));
        let unknown = canonical_json(&value).unwrap();

        let error = SwapManifestV1::open(
            &unknown,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::MalformedEnvelope);
    }

    #[test]
    fn encryption_key_holder_cannot_forge_signed_payload() {
        let encoded = seal_fixture();
        let envelope: EncryptedEnvelopeV1 = serde_json::from_str(&encoded).unwrap();
        let nonce =
            decode_fixed_hex::<XCHACHA_NONCE_BYTES>("envelope nonce", &envelope.header.nonce_hex)
                .unwrap();
        let associated_data = canonical_json(&envelope.header).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&ENCRYPTION_KEY).unwrap();
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &hex::decode(&envelope.ciphertext_hex).unwrap(),
                    aad: associated_data.as_bytes(),
                },
            )
            .unwrap();
        let mut signed: SignedManifestV1 = serde_json::from_slice(&plaintext).unwrap();
        signed.manifest.restore_identity.created_at_unix += 1;
        signed.manifest_sha256 = sha256_hex(canonical_json(&signed.manifest).unwrap().as_bytes());
        let forged_plaintext = canonical_json(&signed).unwrap();
        let forged_ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: forged_plaintext.as_bytes(),
                    aad: associated_data.as_bytes(),
                },
            )
            .unwrap();
        let forged = canonical_json(&EncryptedEnvelopeV1 {
            header: envelope.header,
            ciphertext_hex: hex::encode(forged_ciphertext),
        })
        .unwrap();

        let error = SwapManifestV1::open(
            &forged,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::SignatureVerificationFailed);
    }

    #[test]
    fn manifest_rejects_policy_reference_mismatch() {
        let mut manifest = fixture();
        manifest.merchant_policy.merchant_liquid_destination =
            "lq1qqdifferentdestination0000000000000000000000000000000000000".into();

        let error = manifest
            .seal_with_nonce(
                "manifest-key-2026-01",
                &ENCRYPTION_KEY,
                &signing_key(),
                &NONCE,
            )
            .unwrap_err();
        assert!(matches!(error, SwapManifestError::InvalidField(_)));
    }

    #[test]
    fn manifest_rejects_provider_identity_mismatch() {
        let mut manifest = fixture();
        manifest.restore_identity.boltz_swap_id = "DifferentProviderId".into();

        let error = manifest
            .seal_with_nonce(
                "manifest-key-2026-01",
                &ENCRYPTION_KEY,
                &signing_key(),
                &NONCE,
            )
            .unwrap_err();
        assert!(matches!(error, SwapManifestError::InvalidField(_)));
        assert!(error.to_string().contains("provider response id"));
    }

    #[test]
    fn manifest_rejects_opposite_parity_for_one_taproot_role_key() {
        let mut manifest = fixture();
        manifest.derivation_lineage.refund.public_key_hex =
            "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into();

        let error = manifest
            .seal_with_nonce(
                "manifest-key-2026-01",
                &ENCRYPTION_KEY,
                &signing_key(),
                &NONCE,
            )
            .unwrap_err();
        assert!(matches!(error, SwapManifestError::InvalidField(_)));
        assert!(error.to_string().contains("derivation identities"));
    }

    #[test]
    fn noncanonical_envelope_is_rejected_before_decryption() {
        let encoded = seal_fixture();
        let spaced =
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(&encoded).unwrap())
                .unwrap();

        let error = SwapManifestV1::open(
            &spaced,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::NonCanonicalEncoding);
    }

    #[test]
    fn oversized_input_is_rejected_before_json_parsing() {
        let oversized = "x".repeat(MAX_ENCODED_MANIFEST_BYTES + 1);
        let error = SwapManifestV1::open(
            &oversized,
            "manifest-key-2026-01",
            &ENCRYPTION_KEY,
            &signer_public_key(&signing_key()),
        )
        .unwrap_err();
        assert_eq!(error, SwapManifestError::TooLarge);
    }

    #[test]
    fn closed_schema_has_no_secret_derivation_fields() {
        let value = serde_json::to_value(fixture()).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.keys().cloned().collect::<Vec<_>>(),
            vec![
                "creation",
                "derivation_lineage",
                "format",
                "merchant_policy",
                "restore_identity",
                "version",
            ]
        );
        assert_eq!(
            object["restore_identity"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "boltz_swap_id",
                "chain_swap_id",
                "created_at_unix",
                "manifest_id",
                "manifest_sequence",
                "previous_manifest_id",
            ]
        );
        assert_eq!(
            object["derivation_lineage"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "allocation_high_water_child_index",
                "claim",
                "derivation_scheme_version",
                "key_epoch",
                "refund",
                "root_fingerprint",
            ]
        );
        let encoded = value.to_string();
        for forbidden in [
            "preimage_hex",
            "claim_key_hex",
            "refund_key_hex",
            "secret_key",
            "private_key",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert!(encoded.contains("preimage_hash_hex"));
    }

    #[test]
    fn canonical_json_rejects_unknown_payload_fields() {
        let mut value = serde_json::to_value(fixture()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("secret_extension".into(), json!("not allowed"));
        let error = serde_json::from_value::<SwapManifestV1>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
