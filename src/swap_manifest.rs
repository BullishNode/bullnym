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

/// Stable identities used to correlate an external record with a restored
/// database and the provider's xpub restore output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapRestoreIdentityV1 {
    pub manifest_id: Uuid,
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
        validate_allocation(&lineage.claim, ManifestKeyPurposeV1::ChainClaim)?;
        validate_allocation(&lineage.refund, ManifestKeyPurposeV1::ChainRefund)?;
        if lineage.claim.allocation_id == lineage.refund.allocation_id
            || lineage.claim.child_index == lineage.refund.child_index
            || lineage.claim.public_key_hex == lineage.refund.public_key_hex
        {
            return invalid("claim and refund derivation identities must be distinct");
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
        validate_provider_creation_cross_references(self, &provider_response, &pair_quote)?;
        if creation.btc_timeout_height <= 0 || creation.liquid_timeout_height <= 0 {
            return invalid("swap timeout heights must be positive");
        }
        validate_network_name("Bitcoin network", &creation.btc_network)?;
        validate_network_name("Liquid network", &creation.liquid_network)?;
        if creation.btc_network != "bitcoin" || creation.liquid_network != "liquid" {
            return invalid("manifest-v1 requires the Bitcoin and Liquid mainnet networks");
        }
        require_lower_hex("Liquid asset id", &creation.liquid_asset_id, 32)?;
        require_bounded_no_whitespace(
            "merchant Liquid destination",
            &creation.merchant_liquid_destination,
            512,
        )?;
        if let Some(address) = creation.merchant_emergency_btc_address.as_deref() {
            require_bounded_no_whitespace("merchant emergency Bitcoin address", address, 128)?;
        }

        let policy = &self.merchant_policy;
        require_non_nil("invoice id", policy.invoice_id)?;
        require_bounded_no_whitespace("merchant nym", &policy.merchant_nym, 128)?;
        require_bounded_no_whitespace(
            "policy Liquid destination",
            &policy.merchant_liquid_destination,
            512,
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
) -> Result<(), SwapManifestError> {
    require_non_nil("allocation id", allocation.allocation_id)?;
    if allocation.child_index < 0 {
        return invalid("derivation child index must be non-negative");
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
    secp256k1::PublicKey::from_str(&allocation.public_key_hex)
        .map_err(|_| SwapManifestError::InvalidField("derivation public key is invalid".into()))?;
    match (allocation.purpose, allocation.preimage_hash_hex.as_deref()) {
        (ManifestKeyPurposeV1::ChainClaim, Some(hash)) => {
            require_lower_hex("claim preimage hash", hash, 32)?;
        }
        (ManifestKeyPurposeV1::ChainRefund, None) => {}
        _ => return invalid("preimage hash does not match derivation purpose"),
    }
    Ok(())
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
    response: &Value,
    pair_quote: &Value,
) -> Result<(), SwapManifestError> {
    let creation = &manifest.creation;
    if response.get("id").and_then(Value::as_str)
        != Some(manifest.restore_identity.boltz_swap_id.as_str())
    {
        return invalid("provider response id does not match restore identity");
    }
    let lockup = response.get("lockupDetails");
    if lockup
        .and_then(|details| details.get("lockupAddress"))
        .and_then(Value::as_str)
        != Some(creation.lockup_address.as_str())
    {
        return invalid("provider lockup address does not match creation evidence");
    }
    if lockup
        .and_then(|details| details.get("amount"))
        .and_then(Value::as_i64)
        != Some(creation.user_lock_amount_sat)
    {
        return invalid("provider user-lock amount does not match creation evidence");
    }
    if response
        .get("claimDetails")
        .and_then(|details| details.get("amount"))
        .and_then(Value::as_i64)
        != Some(creation.server_lock_amount_sat)
    {
        return invalid("provider server-lock amount does not match creation evidence");
    }
    if pair_quote.get("hash").and_then(Value::as_str) != Some(creation.pinned_pair_hash.as_str()) {
        return invalid("pair quote hash does not match the pinned pair hash");
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

    fn fixture() -> SwapManifestV1 {
        let canonical_response = r#"{"claimDetails":{"amount":10000},"id":"BoltzRestore01","lockupDetails":{"amount":12000,"lockupAddress":"bc1qmanifestlockup000000000000000000000000000"}}"#;
        let liquid_destination = "lq1qqmanifestdestination000000000000000000000000000000000000000";
        let emergency_address = "bc1qmanifestrecovery0000000000000000000000000";
        SwapManifestV1::new(
            SwapRestoreIdentityV1 {
                manifest_id: Uuid::from_u128(1),
                chain_swap_id: Uuid::from_u128(2),
                boltz_swap_id: "BoltzRestore01".into(),
                created_at_unix: 1_784_000_000,
            },
            SwapDerivationLineageV1 {
                root_fingerprint: "0011223344556677".into(),
                key_epoch: 1,
                derivation_scheme_version: 1,
                claim: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(3),
                    child_index: 430,
                    purpose: ManifestKeyPurposeV1::ChainClaim,
                    public_key_hex:
                        "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
                            .into(),
                    preimage_hash_hex: Some("44".repeat(32)),
                },
                refund: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(4),
                    child_index: 431,
                    purpose: ManifestKeyPurposeV1::ChainRefund,
                    public_key_hex:
                        "02466d7fcae563e5cb09a0d1870bb5803448046179f4104a57d43f1c86f8d1f35a"
                            .into(),
                    preimage_hash_hex: None,
                },
            },
            ImmutableChainSwapCreationV1 {
                lockup_address: "bc1qmanifestlockup000000000000000000000000000".into(),
                lockup_bip21: concat!(
                    "bitcoin:bc1qmanifestlockup000000000000000000000000000?",
                    "amount=0.00012000&label=Send%20to%20L-BTC%20address"
                )
                .into(),
                user_lock_amount_sat: 12_000,
                server_lock_amount_sat: 10_000,
                canonical_provider_response_json: canonical_response.into(),
                pinned_pair_hash: "22".repeat(32),
                canonical_pair_quote_json: r#"{"hash":"2222222222222222222222222222222222222222222222222222222222222222","rate":1}"#.into(),
                creation_response_sha256: sha256_hex(canonical_response.as_bytes()),
                btc_claim_script_sha256: "55".repeat(32),
                btc_refund_script_sha256: "66".repeat(32),
                liquid_claim_script_sha256: "77".repeat(32),
                liquid_refund_script_sha256: "88".repeat(32),
                btc_timeout_height: 900_000,
                liquid_timeout_height: 3_500_000,
                btc_network: "bitcoin".into(),
                liquid_network: "liquid".into(),
                liquid_asset_id: "99".repeat(32),
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
    fn fixed_inputs_have_deterministic_canonical_encoding() {
        let first = seal_fixture();
        let second = seal_fixture();

        assert_eq!(first, second);
        assert!(!first.contains(char::is_whitespace));
        assert_eq!(
            sha256_hex(first.as_bytes()),
            "419c6e87251a6b0924cdbf8175efa5097ea5daf4ce61874ba1cb020395490513"
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
