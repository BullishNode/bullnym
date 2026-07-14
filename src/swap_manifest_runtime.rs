//! Protected-environment configuration for one recovery-manifest witness.
//!
//! This module owns the runtime-only S3 credentials and manifest cryptographic
//! material. It intentionally does not add fields to checked-in configuration,
//! wire application state, change admission, or deliver manifests. Values are
//! read either from an injected key/value lookup or directly from the process
//! environment. Nothing is trimmed, defaulted, or inferred.

use std::env::VarError;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::key::rand::{rngs::OsRng, RngCore};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::swap_manifest::{SwapManifestError, SwapManifestV1};
use crate::swap_manifest_staging::ManifestStagingCrypto;
use crate::swap_manifest_store::{
    RecoveryManifestStore, S3ManifestCredentials, S3ManifestStoreConfig,
};
use crate::swap_manifest_witness::{RecoveryWitnessLoadError, RecoveryWitnessOpenSecretsV1};

pub const S3_ENDPOINT_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_ENDPOINT";
pub const S3_REGION_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_REGION";
pub const S3_BUCKET_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_BUCKET";
pub const S3_PREFIX_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_PREFIX";
pub const S3_PATH_STYLE_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_PATH_STYLE";
pub const S3_ALLOW_HTTP_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_ALLOW_HTTP";
pub const S3_ACCESS_KEY_ID_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_ACCESS_KEY_ID";
pub const S3_SECRET_ACCESS_KEY_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_SECRET_ACCESS_KEY";
pub const S3_SESSION_TOKEN_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_S3_SESSION_TOKEN";
pub const ENCRYPTION_KEY_ID_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_ENCRYPTION_KEY_ID";
pub const ENCRYPTION_KEY_HEX_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_ENCRYPTION_KEY_HEX";
pub const SIGNING_SECRET_KEY_HEX_ENV: &str = "BULLNYM_RECOVERY_MANIFEST_SIGNING_SECRET_KEY_HEX";
pub const EXPECTED_SIGNER_XONLY_HEX_ENV: &str =
    "BULLNYM_RECOVERY_MANIFEST_EXPECTED_SIGNER_XONLY_HEX";

#[cfg(test)]
const REQUIRED_ENV_KEYS: [&str; 12] = [
    S3_ENDPOINT_ENV,
    S3_REGION_ENV,
    S3_BUCKET_ENV,
    S3_PREFIX_ENV,
    S3_PATH_STYLE_ENV,
    S3_ALLOW_HTTP_ENV,
    S3_ACCESS_KEY_ID_ENV,
    S3_SECRET_ACCESS_KEY_ENV,
    ENCRYPTION_KEY_ID_ENV,
    ENCRYPTION_KEY_HEX_ENV,
    SIGNING_SECRET_KEY_HEX_ENV,
    EXPECTED_SIGNER_XONLY_HEX_ENV,
];

/// Fixed failure classes for protected runtime configuration.
///
/// Variants retain no environment name, value, store error, parser error, or
/// cryptographic source. `Debug`, `Display`, and `source()` are therefore
/// bounded and safe for operational reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryManifestRuntimeConfigError {
    MissingRequiredValue,
    InvalidValue,
    StoreConfigurationRejected,
    SigningKeyDoesNotMatchPinnedSigner,
}

/// Bounded failures from the opaque cooperative-signing nonce capability.
///
/// The variants retain no key material, nonce plaintext, ciphertext, AAD, or
/// cryptographic source. Callers may therefore report the class without
/// expanding protected runtime material into logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CooperativeSigningNonceError {
    InvalidContext,
    SealFailed,
    OpenFailed,
}

impl fmt::Display for CooperativeSigningNonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidContext => "cooperative signing nonce context is invalid",
            Self::SealFailed => "cooperative signing nonce seal failed",
            Self::OpenFailed => "cooperative signing nonce open failed",
        })
    }
}

impl std::error::Error for CooperativeSigningNonceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Persistable output of the protected cooperative nonce capability.
///
/// This deliberately has no `Debug` implementation. It contains no plaintext
/// key material, but keeping the envelope non-formattable prevents future
/// field additions from silently broadening operational logs.
pub(crate) struct CooperativeSigningNonceEnvelopeV1 {
    pub format: &'static str,
    pub algorithm: &'static str,
    pub key_id: String,
    pub encryption_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub plaintext_sha256: String,
}

impl CooperativeSigningNonceEnvelopeV1 {
    /// Reconstitute only the encrypted fields admitted by migration 057. The
    /// protected runtime still authenticates every value, including the
    /// derived key identity, before returning plaintext.
    pub(crate) fn from_persisted(
        key_id: impl Into<String>,
        encryption_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        plaintext_sha256: impl Into<String>,
    ) -> Result<Self, CooperativeSigningNonceError> {
        let envelope = Self {
            format: COOPERATIVE_SIGNING_NONCE_FORMAT,
            algorithm: COOPERATIVE_SIGNING_NONCE_ALGORITHM,
            key_id: key_id.into(),
            encryption_nonce,
            ciphertext,
            plaintext_sha256: plaintext_sha256.into(),
        };
        if envelope.key_id.is_empty()
            || envelope.key_id.len() > 64
            || !envelope
                .key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
            || envelope.encryption_nonce.len() != 24
            || envelope.ciphertext.len() != COOPERATIVE_SIGNING_NONCE_CIPHERTEXT_LEN
            || parse_canonical_sha256(&envelope.plaintext_sha256).is_err()
        {
            return Err(CooperativeSigningNonceError::InvalidContext);
        }
        Ok(envelope)
    }
}

/// Opened key-grade material. The bytes are overwritten on drop and cannot be
/// cloned or formatted.
pub(crate) struct ProtectedCooperativeSigningNonce(Zeroizing<Vec<u8>>);

impl ProtectedCooperativeSigningNonce {
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

const COOPERATIVE_SIGNING_NONCE_FORMAT: &str = "secp256k1-musig-secnonce-132-v1";
const COOPERATIVE_SIGNING_NONCE_ALGORITHM: &str = "xchacha20poly1305-v1";
const COOPERATIVE_SIGNING_NONCE_LEN: usize = 132;
const COOPERATIVE_SIGNING_NONCE_CIPHERTEXT_LEN: usize = COOPERATIVE_SIGNING_NONCE_LEN + 16;
const COOPERATIVE_SIGNING_NONCE_DOMAIN: &[u8] =
    b"bullnym/recovery-manifest-runtime/cooperative-signing-secnonce/v1\0";

impl fmt::Display for RecoveryManifestRuntimeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingRequiredValue => "recovery-manifest protected configuration is incomplete",
            Self::InvalidValue => "recovery-manifest protected configuration is invalid",
            Self::StoreConfigurationRejected => {
                "recovery-manifest storage configuration was rejected"
            }
            Self::SigningKeyDoesNotMatchPinnedSigner => {
                "recovery-manifest signing key does not match the pinned signer"
            }
        })
    }
}

impl std::error::Error for RecoveryManifestRuntimeConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Ready, unwired runtime material for one S3-compatible manifest witness.
///
/// All fields are private. The raw encryption and signing keys never leave the
/// type: sealing is performed through [`Self::seal_manifest_v1`], and restore
/// code receives the existing fully redacted [`RecoveryWitnessOpenSecretsV1`].
/// `Debug` reveals no endpoint, bucket, prefix, credential, key identifier,
/// key, or signer.
pub struct RecoveryManifestRuntimeV1 {
    store: RecoveryManifestStore,
    encryption_key_id: String,
    encryption_key: [u8; 32],
    signing_keypair: Keypair,
    expected_signer: XOnlyPublicKey,
}

impl RecoveryManifestRuntimeV1 {
    /// Load exact values from an injected lookup.
    ///
    /// The optional session token is the only value that may be absent. A
    /// present empty token is invalid. Required values are never trimmed or
    /// defaulted, and both booleans must be exactly `true` or `false`.
    pub fn from_lookup<F>(mut lookup: F) -> Result<Self, RecoveryManifestRuntimeConfigError>
    where
        F: FnMut(&str) -> Option<String>,
    {
        Self::from_fallible_lookup(|name| Ok(lookup(name)))
    }

    /// Load the same contract directly from the process environment.
    ///
    /// A non-Unicode value fails as invalid instead of being treated as absent.
    pub fn from_process_env() -> Result<Self, RecoveryManifestRuntimeConfigError> {
        Self::from_fallible_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(VarError::NotPresent) => Ok(None),
            Err(VarError::NotUnicode(_)) => Err(RecoveryManifestRuntimeConfigError::InvalidValue),
        })
    }

    /// Build the protected runtime once for retention in application state.
    ///
    /// Missing, partial, or invalid protected configuration leaves this
    /// capability unavailable instead of stopping existing-obligation HTTP and
    /// recovery paths. The future creation coordinator must treat `None` as a
    /// refusal before any provider mutation. The warning contains only the
    /// bounded source-free error class.
    pub fn for_process_startup() -> Option<Arc<Self>> {
        Self::finish_startup(Self::from_process_env())
    }

    pub fn store(&self) -> &RecoveryManifestStore {
        &self.store
    }

    /// Construct a protected runtime around an injected integration backend.
    ///
    /// The fixed values are test protocol material, not production secrets.
    /// Keeping them inside this redacted capability lets database/object-store
    /// integration tests exercise the production repair path without adding a
    /// public key-extraction API or depending on a networked S3 service.
    #[doc(hidden)]
    pub fn from_store_for_integration_tests(store: RecoveryManifestStore) -> Self {
        let signing_secret =
            SecretKey::from_slice(&[0x43; 32]).expect("fixed integration signing key is valid");
        let signing_keypair = Keypair::from_secret_key(&Secp256k1::new(), &signing_secret);
        let expected_signer = signing_keypair.x_only_public_key().0;
        Self {
            store,
            encryption_key_id: "manifest-key-runtime-integration".to_owned(),
            encryption_key: [0x42; 32],
            signing_keypair,
            expected_signer,
        }
    }

    /// Borrow the opaque sealing inputs required by atomic manifest staging.
    ///
    /// This crate-private adapter returns only the existing non-`Clone`,
    /// non-`Debug` capability. It neither copies nor exposes the encryption or
    /// signing keys, and it does not grant witness-opening access.
    pub(crate) fn borrow_manifest_staging_crypto_v1(&self) -> ManifestStagingCrypto<'_> {
        ManifestStagingCrypto::new(
            &self.encryption_key_id,
            &self.encryption_key,
            &self.signing_keypair,
            &self.expected_signer,
        )
    }

    /// Seal one already validated manifest without exposing key material.
    pub fn seal_manifest_v1(&self, manifest: &SwapManifestV1) -> Result<String, SwapManifestError> {
        manifest.seal(
            &self.encryption_key_id,
            &self.encryption_key,
            &self.signing_keypair,
        )
    }

    /// Copy the opening material into the existing redacted witness type.
    pub fn witness_open_secrets_v1(
        &self,
    ) -> Result<RecoveryWitnessOpenSecretsV1, RecoveryManifestRuntimeConfigError> {
        RecoveryWitnessOpenSecretsV1::new(
            self.encryption_key_id.clone(),
            self.encryption_key,
            self.expected_signer,
        )
        .map_err(|_| RecoveryManifestRuntimeConfigError::InvalidValue)
    }

    /// Seal one MuSig secret nonce through the protected runtime key.
    ///
    /// The derived subkey is domain-separated from manifest encryption and is
    /// bound to both the immutable swap identity and the exact persisted
    /// signing-session digest. The configured key and derived subkey never
    /// leave this capability.
    pub(crate) fn seal_cooperative_signing_nonce_v1(
        &self,
        chain_swap_id: uuid::Uuid,
        session_sha256: &str,
        secret_nonce: &[u8],
    ) -> Result<CooperativeSigningNonceEnvelopeV1, CooperativeSigningNonceError> {
        if secret_nonce.len() != COOPERATIVE_SIGNING_NONCE_LEN {
            return Err(CooperativeSigningNonceError::InvalidContext);
        }
        let session_digest = parse_canonical_sha256(session_sha256)?;
        let (subkey, key_id) =
            self.cooperative_signing_nonce_subkey(chain_swap_id, &session_digest)?;
        let cipher = XChaCha20Poly1305::new_from_slice(subkey.as_ref())
            .map_err(|_| CooperativeSigningNonceError::SealFailed)?;
        let mut encryption_nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut encryption_nonce);
        let aad = cooperative_signing_nonce_aad(chain_swap_id, &session_digest, &key_id);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&encryption_nonce),
                Payload {
                    msg: secret_nonce,
                    aad: &aad,
                },
            )
            .map_err(|_| CooperativeSigningNonceError::SealFailed)?;
        if ciphertext.len() != COOPERATIVE_SIGNING_NONCE_CIPHERTEXT_LEN {
            return Err(CooperativeSigningNonceError::SealFailed);
        }

        Ok(CooperativeSigningNonceEnvelopeV1 {
            format: COOPERATIVE_SIGNING_NONCE_FORMAT,
            algorithm: COOPERATIVE_SIGNING_NONCE_ALGORITHM,
            key_id,
            encryption_nonce: encryption_nonce.to_vec(),
            ciphertext,
            plaintext_sha256: hex::encode(Sha256::digest(secret_nonce)),
        })
    }

    /// Open a persisted MuSig secret nonce without exposing the runtime key.
    ///
    /// Every envelope field is checked exactly before decryption. A swap,
    /// session, key identity, nonce, ciphertext, or plaintext commitment
    /// mismatch collapses to one source-free failure class.
    pub(crate) fn open_cooperative_signing_nonce_v1(
        &self,
        chain_swap_id: uuid::Uuid,
        session_sha256: &str,
        envelope: &CooperativeSigningNonceEnvelopeV1,
    ) -> Result<ProtectedCooperativeSigningNonce, CooperativeSigningNonceError> {
        if envelope.format != COOPERATIVE_SIGNING_NONCE_FORMAT
            || envelope.algorithm != COOPERATIVE_SIGNING_NONCE_ALGORITHM
            || envelope.encryption_nonce.len() != 24
            || envelope.ciphertext.len() != COOPERATIVE_SIGNING_NONCE_CIPHERTEXT_LEN
        {
            return Err(CooperativeSigningNonceError::OpenFailed);
        }
        let session_digest = parse_canonical_sha256(session_sha256)
            .map_err(|_| CooperativeSigningNonceError::OpenFailed)?;
        let expected_plaintext_digest = parse_canonical_sha256(&envelope.plaintext_sha256)
            .map_err(|_| CooperativeSigningNonceError::OpenFailed)?;
        let (subkey, expected_key_id) = self
            .cooperative_signing_nonce_subkey(chain_swap_id, &session_digest)
            .map_err(|_| CooperativeSigningNonceError::OpenFailed)?;
        if envelope.key_id != expected_key_id {
            return Err(CooperativeSigningNonceError::OpenFailed);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(subkey.as_ref())
            .map_err(|_| CooperativeSigningNonceError::OpenFailed)?;
        let aad = cooperative_signing_nonce_aad(chain_swap_id, &session_digest, &expected_key_id);
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&envelope.encryption_nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CooperativeSigningNonceError::OpenFailed)?;
        if plaintext.len() != COOPERATIVE_SIGNING_NONCE_LEN {
            return Err(CooperativeSigningNonceError::OpenFailed);
        }
        let actual_plaintext_digest: [u8; 32] = Sha256::digest(&plaintext).into();
        if !bool::from(actual_plaintext_digest.ct_eq(&expected_plaintext_digest)) {
            return Err(CooperativeSigningNonceError::OpenFailed);
        }
        Ok(ProtectedCooperativeSigningNonce(Zeroizing::new(plaintext)))
    }

    fn cooperative_signing_nonce_subkey(
        &self,
        chain_swap_id: uuid::Uuid,
        session_digest: &[u8; 32],
    ) -> Result<(Zeroizing<[u8; 32]>, String), CooperativeSigningNonceError> {
        let mut derivation = <Hmac<Sha256> as Mac>::new_from_slice(&self.encryption_key)
            .map_err(|_| CooperativeSigningNonceError::InvalidContext)?;
        derivation.update(COOPERATIVE_SIGNING_NONCE_DOMAIN);
        derivation.update(chain_swap_id.as_bytes());
        derivation.update(session_digest);
        derivation.update(
            &u32::try_from(self.encryption_key_id.len())
                .map_err(|_| CooperativeSigningNonceError::InvalidContext)?
                .to_be_bytes(),
        );
        derivation.update(self.encryption_key_id.as_bytes());
        let subkey: [u8; 32] = derivation.finalize().into_bytes().into();

        let mut key_identity = <Hmac<Sha256> as Mac>::new_from_slice(&self.encryption_key)
            .map_err(|_| CooperativeSigningNonceError::InvalidContext)?;
        key_identity.update(b"bullnym/recovery-manifest-runtime/cooperative-signing-key-id/v1\0");
        key_identity.update(self.encryption_key_id.as_bytes());
        let key_identity = key_identity.finalize().into_bytes();
        Ok((
            Zeroizing::new(subkey),
            format!("recovery-cap-v1:{}", hex::encode(&key_identity[..16])),
        ))
    }

    fn from_fallible_lookup<F>(mut lookup: F) -> Result<Self, RecoveryManifestRuntimeConfigError>
    where
        F: FnMut(&str) -> Result<Option<String>, RecoveryManifestRuntimeConfigError>,
    {
        let raw = RawProtectedValues {
            endpoint: required_value(&mut lookup, S3_ENDPOINT_ENV)?,
            region: required_value(&mut lookup, S3_REGION_ENV)?,
            bucket: required_value(&mut lookup, S3_BUCKET_ENV)?,
            prefix: required_value(&mut lookup, S3_PREFIX_ENV)?,
            path_style: required_value(&mut lookup, S3_PATH_STYLE_ENV)?,
            allow_http: required_value(&mut lookup, S3_ALLOW_HTTP_ENV)?,
            access_key_id: required_value(&mut lookup, S3_ACCESS_KEY_ID_ENV)?,
            secret_access_key: required_value(&mut lookup, S3_SECRET_ACCESS_KEY_ENV)?,
            session_token: optional_value(&mut lookup, S3_SESSION_TOKEN_ENV)?,
            encryption_key_id: required_value(&mut lookup, ENCRYPTION_KEY_ID_ENV)?,
            encryption_key_hex: required_value(&mut lookup, ENCRYPTION_KEY_HEX_ENV)?,
            signing_secret_key_hex: required_value(&mut lookup, SIGNING_SECRET_KEY_HEX_ENV)?,
            expected_signer_xonly_hex: required_value(&mut lookup, EXPECTED_SIGNER_XONLY_HEX_ENV)?,
        };

        validate_canonical_endpoint(&raw.endpoint)?;
        let path_style = parse_canonical_bool(&raw.path_style)?;
        let allow_http = parse_canonical_bool(&raw.allow_http)?;
        let encryption_key = decode_canonical_secret_hex(&raw.encryption_key_hex)?;
        let signing_secret = decode_canonical_secret_hex(&raw.signing_secret_key_hex)?;
        let signing_secret = SecretKey::from_slice(&signing_secret)
            .map_err(|_| RecoveryManifestRuntimeConfigError::InvalidValue)?;
        let signing_keypair = Keypair::from_secret_key(&Secp256k1::new(), &signing_secret);
        let expected_signer = parse_canonical_xonly(&raw.expected_signer_xonly_hex)?;
        if signing_keypair.x_only_public_key().0 != expected_signer {
            return Err(RecoveryManifestRuntimeConfigError::SigningKeyDoesNotMatchPinnedSigner);
        }

        RecoveryWitnessOpenSecretsV1::new(
            raw.encryption_key_id.clone(),
            encryption_key,
            expected_signer,
        )
        .map_err(collapse_opening_configuration_error)?;

        let credentials =
            S3ManifestCredentials::new(raw.access_key_id, raw.secret_access_key, raw.session_token);
        let store_config = S3ManifestStoreConfig::new(
            raw.endpoint,
            raw.region,
            raw.bucket,
            raw.prefix,
            path_style,
            allow_http,
            credentials,
        );
        let store = RecoveryManifestStore::from_s3(store_config)
            .map_err(|_| RecoveryManifestRuntimeConfigError::StoreConfigurationRejected)?;

        Ok(Self {
            store,
            encryption_key_id: raw.encryption_key_id,
            encryption_key,
            signing_keypair,
            expected_signer,
        })
    }

    fn finish_startup(
        result: Result<Self, RecoveryManifestRuntimeConfigError>,
    ) -> Option<Arc<Self>> {
        match result {
            Ok(runtime) => {
                tracing::info!(
                    event = "recovery_manifest_runtime_configured",
                    "recovery-manifest protected runtime configured"
                );
                Some(Arc::new(runtime))
            }
            Err(error) => {
                tracing::warn!(
                    event = "recovery_manifest_runtime_unavailable",
                    error = %error,
                    "recovery-manifest protected runtime unavailable; new chain-swap creation must remain closed"
                );
                None
            }
        }
    }
}

fn parse_canonical_sha256(value: &str) -> Result<[u8; 32], CooperativeSigningNonceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CooperativeSigningNonceError::InvalidContext);
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(value, &mut digest)
        .map_err(|_| CooperativeSigningNonceError::InvalidContext)?;
    Ok(digest)
}

fn cooperative_signing_nonce_aad(
    chain_swap_id: uuid::Uuid,
    session_digest: &[u8; 32],
    key_id: &str,
) -> Vec<u8> {
    let mut aad =
        Vec::with_capacity(COOPERATIVE_SIGNING_NONCE_DOMAIN.len() + 16 + 32 + 4 + key_id.len());
    aad.extend_from_slice(COOPERATIVE_SIGNING_NONCE_DOMAIN);
    aad.extend_from_slice(chain_swap_id.as_bytes());
    aad.extend_from_slice(session_digest);
    aad.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

impl fmt::Debug for RecoveryManifestRuntimeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryManifestRuntimeV1")
            .field("store", &"<redacted>")
            .field("manifest_crypto", &"<redacted>")
            .finish()
    }
}

struct RawProtectedValues {
    endpoint: String,
    region: String,
    bucket: String,
    prefix: String,
    path_style: String,
    allow_http: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    encryption_key_id: String,
    encryption_key_hex: String,
    signing_secret_key_hex: String,
    expected_signer_xonly_hex: String,
}

fn required_value<F>(
    lookup: &mut F,
    name: &str,
) -> Result<String, RecoveryManifestRuntimeConfigError>
where
    F: FnMut(&str) -> Result<Option<String>, RecoveryManifestRuntimeConfigError>,
{
    let value = lookup(name)?.ok_or(RecoveryManifestRuntimeConfigError::MissingRequiredValue)?;
    validate_injected_text(&value)?;
    Ok(value)
}

fn optional_value<F>(
    lookup: &mut F,
    name: &str,
) -> Result<Option<String>, RecoveryManifestRuntimeConfigError>
where
    F: FnMut(&str) -> Result<Option<String>, RecoveryManifestRuntimeConfigError>,
{
    lookup(name)?
        .map(|value| {
            validate_injected_text(&value)?;
            Ok(value)
        })
        .transpose()
}

fn validate_injected_text(value: &str) -> Result<(), RecoveryManifestRuntimeConfigError> {
    if value.is_empty() || !value.is_ascii() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(RecoveryManifestRuntimeConfigError::InvalidValue);
    }
    Ok(())
}

fn validate_canonical_endpoint(value: &str) -> Result<(), RecoveryManifestRuntimeConfigError> {
    let endpoint =
        reqwest::Url::parse(value).map_err(|_| RecoveryManifestRuntimeConfigError::InvalidValue)?;
    if endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        return Err(RecoveryManifestRuntimeConfigError::InvalidValue);
    }
    let canonical = endpoint
        .as_str()
        .strip_suffix('/')
        .unwrap_or(endpoint.as_str());
    if canonical != value {
        return Err(RecoveryManifestRuntimeConfigError::InvalidValue);
    }
    Ok(())
}

fn parse_canonical_bool(value: &str) -> Result<bool, RecoveryManifestRuntimeConfigError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(RecoveryManifestRuntimeConfigError::InvalidValue),
    }
}

fn decode_canonical_secret_hex(
    value: &str,
) -> Result<[u8; 32], RecoveryManifestRuntimeConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RecoveryManifestRuntimeConfigError::InvalidValue);
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| RecoveryManifestRuntimeConfigError::InvalidValue)?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(RecoveryManifestRuntimeConfigError::InvalidValue);
    }
    Ok(decoded)
}

fn parse_canonical_xonly(
    value: &str,
) -> Result<XOnlyPublicKey, RecoveryManifestRuntimeConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(RecoveryManifestRuntimeConfigError::InvalidValue);
    }
    let signer = XOnlyPublicKey::from_str(value)
        .map_err(|_| RecoveryManifestRuntimeConfigError::InvalidValue)?;
    if signer.to_string() != value {
        return Err(RecoveryManifestRuntimeConfigError::InvalidValue);
    }
    Ok(signer)
}

fn collapse_opening_configuration_error(
    _: RecoveryWitnessLoadError,
) -> RecoveryManifestRuntimeConfigError {
    RecoveryManifestRuntimeConfigError::InvalidValue
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error as _;

    use uuid::Uuid;

    use super::*;
    use crate::swap_manifest_store::ManifestObjectId;

    fn signing_pair(byte: u8) -> (String, String) {
        let bytes = [byte; 32];
        let secret = SecretKey::from_slice(&bytes).expect("fixed valid secret");
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        (
            hex::encode(bytes),
            keypair.x_only_public_key().0.to_string(),
        )
    }

    fn valid_values() -> BTreeMap<String, String> {
        let (signing_secret, expected_signer) = signing_pair(0x21);
        BTreeMap::from([
            (
                S3_ENDPOINT_ENV.to_owned(),
                "https://witness.example".to_owned(),
            ),
            (S3_REGION_ENV.to_owned(), "us-east-1".to_owned()),
            (S3_BUCKET_ENV.to_owned(), "bullnym-recovery".to_owned()),
            (S3_PREFIX_ENV.to_owned(), "bullnym/recovery".to_owned()),
            (S3_PATH_STYLE_ENV.to_owned(), "true".to_owned()),
            (S3_ALLOW_HTTP_ENV.to_owned(), "false".to_owned()),
            (
                S3_ACCESS_KEY_ID_ENV.to_owned(),
                "ACCESSKEYRUNTIMEFIXTURE".to_owned(),
            ),
            (
                S3_SECRET_ACCESS_KEY_ENV.to_owned(),
                "secret-runtime-fixture-value".to_owned(),
            ),
            (
                S3_SESSION_TOKEN_ENV.to_owned(),
                "session-runtime-fixture-value".to_owned(),
            ),
            (
                ENCRYPTION_KEY_ID_ENV.to_owned(),
                "manifest-key-runtime-v1".to_owned(),
            ),
            (ENCRYPTION_KEY_HEX_ENV.to_owned(), hex::encode([0x42; 32])),
            (SIGNING_SECRET_KEY_HEX_ENV.to_owned(), signing_secret),
            (EXPECTED_SIGNER_XONLY_HEX_ENV.to_owned(), expected_signer),
        ])
    }

    fn load(
        values: &BTreeMap<String, String>,
    ) -> Result<RecoveryManifestRuntimeV1, RecoveryManifestRuntimeConfigError> {
        RecoveryManifestRuntimeV1::from_lookup(|name| values.get(name).cloned())
    }

    fn rejected(values: &BTreeMap<String, String>) -> RecoveryManifestRuntimeConfigError {
        match load(values) {
            Ok(_) => panic!("protected configuration unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn complete_configuration_builds_store_and_opening_material() {
        let values = valid_values();
        let runtime = load(&values).expect("valid protected configuration");
        let id = ManifestObjectId::new(Uuid::from_u128(1), Uuid::from_u128(2)).unwrap();
        assert_eq!(
            runtime.store().object_key_v1(id),
            "bullnym/recovery/v1/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002.json"
        );
        let opening = runtime
            .witness_open_secrets_v1()
            .expect("validated opening material");
        let opening_debug = format!("{opening:?}");
        assert!(opening_debug.contains("<redacted>"));
        for value in values.values() {
            assert!(!opening_debug.contains(value));
        }
    }

    #[test]
    fn cooperative_nonce_capability_is_external_bound_and_tamper_evident() {
        let values = valid_values();
        let runtime = load(&values).expect("valid protected configuration");
        let swap_id = Uuid::from_u128(0x85);
        let session_sha256 = "11".repeat(32);
        let secret_nonce = Zeroizing::new(vec![0x37_u8; COOPERATIVE_SIGNING_NONCE_LEN]);

        let mut envelope = runtime
            .seal_cooperative_signing_nonce_v1(swap_id, &session_sha256, &secret_nonce)
            .expect("protected nonce seal");
        assert_eq!(envelope.format, COOPERATIVE_SIGNING_NONCE_FORMAT);
        assert_eq!(envelope.algorithm, COOPERATIVE_SIGNING_NONCE_ALGORITHM);
        assert_eq!(envelope.encryption_nonce.len(), 24);
        assert_eq!(
            envelope.ciphertext.len(),
            COOPERATIVE_SIGNING_NONCE_CIPHERTEXT_LEN
        );
        assert_ne!(envelope.ciphertext, secret_nonce.as_slice());
        assert!(envelope.key_id.starts_with("recovery-cap-v1:"));
        assert!(!envelope.key_id.contains(&values[ENCRYPTION_KEY_ID_ENV]));

        let opened = runtime
            .open_cooperative_signing_nonce_v1(swap_id, &session_sha256, &envelope)
            .expect("protected nonce open");
        assert_eq!(opened.expose(), secret_nonce.as_slice());
        assert!(runtime
            .open_cooperative_signing_nonce_v1(Uuid::from_u128(0x86), &session_sha256, &envelope,)
            .is_err());
        assert!(runtime
            .open_cooperative_signing_nonce_v1(swap_id, &"12".repeat(32), &envelope)
            .is_err());

        envelope.ciphertext[0] ^= 1;
        assert!(runtime
            .open_cooperative_signing_nonce_v1(swap_id, &session_sha256, &envelope)
            .is_err());
    }

    #[test]
    fn optional_session_token_may_be_absent_but_not_empty() {
        let mut without_token = valid_values();
        without_token.remove(S3_SESSION_TOKEN_ENV);
        assert!(load(&without_token).is_ok());

        let mut empty_token = valid_values();
        empty_token.insert(S3_SESSION_TOKEN_ENV.to_owned(), String::new());
        assert_eq!(
            rejected(&empty_token),
            RecoveryManifestRuntimeConfigError::InvalidValue
        );
    }

    #[test]
    fn every_required_value_is_mandatory_and_empty_is_not_missing() {
        for name in REQUIRED_ENV_KEYS {
            let mut missing = valid_values();
            missing.remove(name);
            assert_eq!(
                rejected(&missing),
                RecoveryManifestRuntimeConfigError::MissingRequiredValue,
                "missing key {name}"
            );

            let mut empty = valid_values();
            empty.insert(name.to_owned(), String::new());
            assert_eq!(
                rejected(&empty),
                RecoveryManifestRuntimeConfigError::InvalidValue,
                "empty key {name}"
            );
        }
    }

    #[test]
    fn injected_values_are_exact_and_never_trimmed() {
        for name in REQUIRED_ENV_KEYS.into_iter().chain([S3_SESSION_TOKEN_ENV]) {
            let mut values = valid_values();
            let original = values.get(name).unwrap();
            values.insert(name.to_owned(), format!(" {original}"));
            assert_eq!(
                rejected(&values),
                RecoveryManifestRuntimeConfigError::InvalidValue,
                "noncanonical key {name}"
            );
        }
    }

    #[test]
    fn booleans_require_exact_lowercase_words() {
        for name in [S3_PATH_STYLE_ENV, S3_ALLOW_HTTP_ENV] {
            for invalid in ["True", "FALSE", "1", "0", "yes", "on"] {
                let mut values = valid_values();
                values.insert(name.to_owned(), invalid.to_owned());
                assert_eq!(
                    rejected(&values),
                    RecoveryManifestRuntimeConfigError::InvalidValue
                );
            }
        }
    }

    #[test]
    fn endpoint_must_be_a_canonical_origin_and_http_is_explicit() {
        for invalid in [
            "https://witness.example/",
            "HTTPS://witness.example",
            "https://WITNESS.example",
            "https://witness.example:443",
            "https://witness.example/base",
            "https://user@witness.example",
            "https://witness.example?query=1",
            "https://witness.example#fragment",
        ] {
            let mut values = valid_values();
            values.insert(S3_ENDPOINT_ENV.to_owned(), invalid.to_owned());
            assert_eq!(
                rejected(&values),
                RecoveryManifestRuntimeConfigError::InvalidValue
            );
        }

        let mut blocked_http = valid_values();
        blocked_http.insert(
            S3_ENDPOINT_ENV.to_owned(),
            "http://127.0.0.1:9000".to_owned(),
        );
        assert_eq!(
            rejected(&blocked_http),
            RecoveryManifestRuntimeConfigError::StoreConfigurationRejected
        );
        blocked_http.insert(S3_ALLOW_HTTP_ENV.to_owned(), "true".to_owned());
        assert!(load(&blocked_http).is_ok());
    }

    #[test]
    fn existing_s3_validation_is_reused_and_collapsed() {
        for (name, invalid) in [
            (S3_REGION_ENV, "us/east"),
            (S3_BUCKET_ENV, "bad/bucket"),
            (S3_PREFIX_ENV, "Bullnym/recovery"),
            (S3_PREFIX_ENV, "bullnym//recovery"),
            (S3_PREFIX_ENV, "/bullnym/recovery"),
        ] {
            let mut values = valid_values();
            values.insert(name.to_owned(), invalid.to_owned());
            assert_eq!(
                rejected(&values),
                RecoveryManifestRuntimeConfigError::StoreConfigurationRejected
            );
        }
    }

    #[test]
    fn encryption_and_signing_secrets_require_exact_nonzero_32_byte_hex() {
        for name in [ENCRYPTION_KEY_HEX_ENV, SIGNING_SECRET_KEY_HEX_ENV] {
            for invalid in [
                "11".repeat(31),
                "11".repeat(33),
                "AA".repeat(32),
                "gg".repeat(32),
                "00".repeat(32),
            ] {
                let mut values = valid_values();
                values.insert(name.to_owned(), invalid);
                assert_eq!(
                    rejected(&values),
                    RecoveryManifestRuntimeConfigError::InvalidValue
                );
            }
        }

        let mut out_of_range_signing_key = valid_values();
        out_of_range_signing_key.insert(SIGNING_SECRET_KEY_HEX_ENV.to_owned(), "ff".repeat(32));
        assert_eq!(
            rejected(&out_of_range_signing_key),
            RecoveryManifestRuntimeConfigError::InvalidValue
        );
    }

    #[test]
    fn key_identifier_and_pinned_signer_are_canonical() {
        for invalid in [
            "bad/key".to_owned(),
            "key id".to_owned(),
            "x".repeat(65),
            "clé".to_owned(),
        ] {
            let mut values = valid_values();
            values.insert(ENCRYPTION_KEY_ID_ENV.to_owned(), invalid);
            assert_eq!(
                rejected(&values),
                RecoveryManifestRuntimeConfigError::InvalidValue
            );
        }

        let canonical_signer = valid_values()
            .remove(EXPECTED_SIGNER_XONLY_HEX_ENV)
            .unwrap();
        for invalid in [
            canonical_signer.to_ascii_uppercase(),
            canonical_signer[..62].to_owned(),
            "gg".repeat(32),
            "ff".repeat(32),
        ] {
            let mut values = valid_values();
            values.insert(EXPECTED_SIGNER_XONLY_HEX_ENV.to_owned(), invalid);
            assert_eq!(
                rejected(&values),
                RecoveryManifestRuntimeConfigError::InvalidValue
            );
        }
    }

    #[test]
    fn signing_secret_must_match_the_separately_pinned_signer() {
        let (_, different_signer) = signing_pair(0x22);
        let mut values = valid_values();
        values.insert(EXPECTED_SIGNER_XONLY_HEX_ENV.to_owned(), different_signer);
        assert_eq!(
            rejected(&values),
            RecoveryManifestRuntimeConfigError::SigningKeyDoesNotMatchPinnedSigner
        );
    }

    #[test]
    fn runtime_and_errors_are_source_free_bounded_and_redacted() {
        let values = valid_values();
        let runtime = load(&values).unwrap();
        let runtime_debug = format!("{runtime:?}");
        assert_eq!(
            runtime_debug,
            "RecoveryManifestRuntimeV1 { store: \"<redacted>\", manifest_crypto: \"<redacted>\" }"
        );
        for value in values.values() {
            assert!(!runtime_debug.contains(value));
        }

        for error in [
            RecoveryManifestRuntimeConfigError::MissingRequiredValue,
            RecoveryManifestRuntimeConfigError::InvalidValue,
            RecoveryManifestRuntimeConfigError::StoreConfigurationRejected,
            RecoveryManifestRuntimeConfigError::SigningKeyDoesNotMatchPinnedSigner,
        ] {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(display.len() <= 80);
            assert!(debug.len() <= 48);
            assert!(error.source().is_none());
            for value in values.values() {
                assert!(!display.contains(value));
                assert!(!debug.contains(value));
            }
        }
    }

    fn consume_staging_crypto(_: ManifestStagingCrypto<'_>) {}

    #[test]
    fn staging_crypto_capability_borrows_without_exposing_runtime_material() {
        let runtime = load(&valid_values()).expect("valid protected configuration");

        consume_staging_crypto(runtime.borrow_manifest_staging_crypto_v1());

        let id = ManifestObjectId::new(Uuid::from_u128(5), Uuid::from_u128(6)).unwrap();
        assert_eq!(
            runtime.store().object_key_v1(id),
            "bullnym/recovery/v1/00000000-0000-0000-0000-000000000005/00000000-0000-0000-0000-000000000006.json"
        );
    }

    #[test]
    fn staging_crypto_borrow_preserves_runtime_and_witness_redaction() {
        let values = valid_values();
        let runtime = load(&values).expect("valid protected configuration");
        let runtime_debug_before = format!("{runtime:?}");

        consume_staging_crypto(runtime.borrow_manifest_staging_crypto_v1());

        assert_eq!(format!("{runtime:?}"), runtime_debug_before);
        let opening_debug = format!(
            "{:?}",
            runtime
                .witness_open_secrets_v1()
                .expect("validated opening material")
        );
        for value in values.values() {
            assert!(!runtime_debug_before.contains(value));
            assert!(!opening_debug.contains(value));
        }
    }

    #[test]
    fn fallible_lookup_failure_is_collapsed_without_a_source() {
        let error = RecoveryManifestRuntimeV1::from_fallible_lookup(|_| {
            Err(RecoveryManifestRuntimeConfigError::InvalidValue)
        })
        .unwrap_err();
        assert_eq!(error, RecoveryManifestRuntimeConfigError::InvalidValue);
        assert!(error.source().is_none());
    }

    #[test]
    fn startup_state_retains_a_complete_configured_runtime() {
        let runtime = RecoveryManifestRuntimeV1::finish_startup(load(&valid_values()))
            .expect("complete protected configuration must be retained");
        let id = ManifestObjectId::new(Uuid::from_u128(3), Uuid::from_u128(4)).unwrap();
        assert_eq!(
            runtime.store().object_key_v1(id),
            "bullnym/recovery/v1/00000000-0000-0000-0000-000000000003/00000000-0000-0000-0000-000000000004.json"
        );
    }

    #[test]
    fn startup_state_is_unavailable_when_protected_config_is_missing() {
        let missing = BTreeMap::new();
        assert!(RecoveryManifestRuntimeV1::finish_startup(load(&missing)).is_none());
    }

    #[test]
    fn startup_state_is_unavailable_when_protected_config_is_invalid() {
        let mut invalid = valid_values();
        invalid.insert(S3_PATH_STYLE_ENV.to_owned(), "True".to_owned());
        assert!(RecoveryManifestRuntimeV1::finish_startup(load(&invalid)).is_none());
    }
}
