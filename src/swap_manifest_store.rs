//! Create-only off-host storage for encrypted chain-swap recovery manifests.
//!
//! This package deliberately stops at the passive storage boundary. It does
//! not wire manifest delivery into swap creation, decide admission policy, or
//! reconstruct database rows. The public runtime API has no overwrite or
//! delete operation.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use futures_util::TryStreamExt;
use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
use object_store::path::Path;
use object_store::{Attribute, Attributes, ObjectStore, ObjectStoreExt, PutMode, PutOptions};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The format package has the same one-MiB encoded-envelope ceiling.
pub const MAX_MANIFEST_OBJECT_BYTES: usize = 1_048_576;
/// A caller must explicitly page or narrow a later restore scan above this cap.
pub const MAX_MANIFEST_LIST_RESULTS: usize = 1_000;

const OBJECT_FORMAT_VERSION: &str = "1";
const OBJECT_DIGEST_ATTRIBUTE: &str = "bullnym-sha256";
const OBJECT_FORMAT_ATTRIBUTE: &str = "bullnym-manifest-format-version";
const OBJECT_CONTENT_TYPE: &str = "application/vnd.bullnym.chain-swap-manifest.v1+json";

/// Static S3-compatible credentials supplied by the future runtime wiring.
///
/// Fields are private and every `Debug` representation is redacted. The
/// integration package should source these from a protected environment file,
/// never from checked-in TOML.
pub struct S3ManifestCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl S3ManifestCredentials {
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            session_token,
        }
    }

    fn validate(&self) -> Result<(), ManifestStoreError> {
        validate_secret("access_key_id", &self.access_key_id, 1_024)?;
        validate_secret("secret_access_key", &self.secret_access_key, 4_096)?;
        if let Some(token) = self.session_token.as_deref() {
            validate_secret("session_token", token, 16_384)?;
        }
        Ok(())
    }
}

impl fmt::Debug for S3ManifestCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3ManifestCredentials")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Explicit configuration for one S3-compatible passive witness.
///
/// `path_style=true` produces `endpoint/bucket/key`; `false` uses virtual-host
/// style. Plain HTTP must be opted into explicitly and is intended only for
/// isolated development endpoints.
pub struct S3ManifestStoreConfig {
    endpoint: String,
    region: String,
    bucket: String,
    prefix: String,
    path_style: bool,
    allow_http: bool,
    credentials: S3ManifestCredentials,
}

impl S3ManifestStoreConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        path_style: bool,
        allow_http: bool,
        credentials: S3ManifestCredentials,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            region: region.into(),
            bucket: bucket.into(),
            prefix: prefix.into(),
            path_style,
            allow_http,
            credentials,
        }
    }

    pub fn validate(&self) -> Result<(), ManifestStoreError> {
        let endpoint = reqwest::Url::parse(&self.endpoint).map_err(|_| {
            ManifestStoreError::configuration("endpoint", "must be an absolute HTTP(S) URL")
        })?;
        match endpoint.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            "http" => {
                return Err(ManifestStoreError::configuration(
                    "endpoint",
                    "plain HTTP requires allow_http=true",
                ));
            }
            _ => {
                return Err(ManifestStoreError::configuration(
                    "endpoint",
                    "scheme must be HTTPS or explicitly allowed HTTP",
                ));
            }
        }
        if endpoint.host_str().is_none() {
            return Err(ManifestStoreError::configuration(
                "endpoint",
                "must include a host",
            ));
        }
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ManifestStoreError::configuration(
                "endpoint",
                "must not embed credentials, a query, or a fragment",
            ));
        }
        validate_plain_field("region", &self.region, 128, false)?;
        validate_plain_field("bucket", &self.bucket, 255, false)?;
        validate_prefix(&self.prefix)?;
        self.credentials.validate()
    }
}

impl fmt::Debug for S3ManifestStoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3ManifestStoreConfig")
            .field("endpoint", &"<redacted>")
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("allow_http", &self.allow_http)
            .field("credentials", &self.credentials)
            .finish()
    }
}

/// Stable, injection-proof identity for one version-1 external record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestObjectId {
    chain_swap_id: Uuid,
    manifest_id: Uuid,
}

impl ManifestObjectId {
    pub fn new(chain_swap_id: Uuid, manifest_id: Uuid) -> Result<Self, ManifestStoreError> {
        if chain_swap_id.is_nil() {
            return Err(ManifestStoreError::configuration(
                "chain_swap_id",
                "must not be nil",
            ));
        }
        if manifest_id.is_nil() {
            return Err(ManifestStoreError::configuration(
                "manifest_id",
                "must not be nil",
            ));
        }
        Ok(Self {
            chain_swap_id,
            manifest_id,
        })
    }

    pub fn chain_swap_id(self) -> Uuid {
        self.chain_swap_id
    }

    pub fn manifest_id(self) -> Uuid {
        self.manifest_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestWriteOutcome {
    Created,
    AlreadyPresent,
}

/// A verified encrypted manifest returned by the passive store.
pub struct StoredRecoveryManifest {
    encoded: String,
    sha256_hex: String,
}

impl StoredRecoveryManifest {
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }

    pub fn into_encoded(self) -> String {
        self.encoded
    }
}

impl fmt::Debug for StoredRecoveryManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredRecoveryManifest")
            .field("encoded_bytes", &self.encoded.len())
            .field("sha256_hex", &self.sha256_hex)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestObjectSummary {
    pub id: ManifestObjectId,
    pub encoded_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestListPage {
    pub objects: Vec<ManifestObjectSummary>,
    pub truncated: bool,
    /// Exclusive key cursor for the next bounded S3 listing request.
    pub next_after: Option<ManifestObjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorruptReadKind {
    EmptyObject,
    OversizedObject { actual: u64 },
    LengthMismatch { declared: u64, actual: usize },
    MissingDigest,
    MalformedDigest,
    DigestMismatch,
    WrongFormatVersion,
    InvalidUtf8,
    UnexpectedObjectKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestStoreError {
    Configuration {
        field: &'static str,
        problem: &'static str,
    },
    EncodedSize {
        actual: usize,
        max: usize,
    },
    InvalidListLimit {
        requested: usize,
        max: usize,
    },
    NotFound {
        id: ManifestObjectId,
    },
    Authentication {
        operation: &'static str,
    },
    Unavailable {
        operation: &'static str,
    },
    Conflict {
        id: ManifestObjectId,
        requested_sha256: String,
        stored_sha256: String,
    },
    CorruptRead {
        id: Option<ManifestObjectId>,
        kind: CorruptReadKind,
    },
}

impl ManifestStoreError {
    fn configuration(field: &'static str, problem: &'static str) -> Self {
        Self::Configuration { field, problem }
    }

    fn corrupt(id: ManifestObjectId, kind: CorruptReadKind) -> Self {
        Self::CorruptRead { id: Some(id), kind }
    }
}

impl fmt::Display for ManifestStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration { field, problem } => {
                write!(f, "invalid recovery-manifest storage {field}: {problem}")
            }
            Self::EncodedSize { actual, max } => {
                write!(
                    f,
                    "encoded recovery manifest has {actual} bytes; allowed range is 1..={max}"
                )
            }
            Self::InvalidListLimit { requested, max } => {
                write!(
                    f,
                    "recovery-manifest list limit {requested} is outside 1..={max}"
                )
            }
            Self::NotFound { .. } => f.write_str("recovery manifest was not found"),
            Self::Authentication { operation } => {
                write!(
                    f,
                    "recovery-manifest storage authentication failed during {operation}"
                )
            }
            Self::Unavailable { operation } => {
                write!(
                    f,
                    "recovery-manifest storage is unavailable during {operation}"
                )
            }
            Self::Conflict { .. } => {
                f.write_str("recovery-manifest identity already contains different bytes")
            }
            Self::CorruptRead { kind, .. } => {
                write!(
                    f,
                    "recovery-manifest storage returned corrupt data: {kind:?}"
                )
            }
        }
    }
}

impl std::error::Error for ManifestStoreError {}

/// Create-only runtime handle over one S3-compatible object store.
#[derive(Clone)]
pub struct RecoveryManifestStore {
    backend: Arc<dyn ObjectStore>,
    prefix: Path,
}

impl fmt::Debug for RecoveryManifestStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryManifestStore")
            .field("backend", &"<redacted>")
            .field("prefix", &self.prefix.as_ref())
            .finish()
    }
}

impl RecoveryManifestStore {
    /// Construct the production-capable S3 adapter using Apache `object_store`.
    /// The builder owns SigV4 and conditional-request behavior.
    pub fn from_s3(config: S3ManifestStoreConfig) -> Result<Self, ManifestStoreError> {
        config.validate()?;
        let S3ManifestStoreConfig {
            endpoint,
            region,
            bucket,
            prefix,
            path_style,
            allow_http,
            credentials,
        } = config;
        let S3ManifestCredentials {
            access_key_id,
            secret_access_key,
            session_token,
        } = credentials;

        let mut builder = AmazonS3Builder::new()
            .with_endpoint(endpoint)
            .with_region(region)
            .with_bucket_name(bucket)
            .with_virtual_hosted_style_request(!path_style)
            .with_conditional_put(S3ConditionalPut::ETagMatch)
            .with_allow_http(allow_http)
            .with_access_key_id(access_key_id)
            .with_secret_access_key(secret_access_key);
        if let Some(token) = session_token {
            builder = builder.with_token(token);
        }
        let backend = builder.build().map_err(|_| {
            ManifestStoreError::configuration("s3", "object-store builder rejected configuration")
        })?;
        Ok(Self::with_backend(Arc::new(backend), prefix))
    }

    /// Deterministic key containing only canonical UUID segments.
    pub fn object_key_v1(&self, id: ManifestObjectId) -> String {
        format!(
            "{}/v1/{}/{}.json",
            self.prefix, id.chain_swap_id, id.manifest_id
        )
    }

    /// Atomically create one immutable object and synchronously verify it.
    ///
    /// Retrying identical bytes is idempotent. Reusing an identity for any
    /// other bytes is an integrity conflict and never overwrites the object.
    pub async fn put_v1(
        &self,
        id: ManifestObjectId,
        encoded: &str,
    ) -> Result<ManifestWriteOutcome, ManifestStoreError> {
        validate_encoded_size(encoded.len())?;
        let requested_sha256 = sha256_hex(encoded.as_bytes());
        let location = Path::from(self.object_key_v1(id));
        let options = PutOptions {
            mode: PutMode::Create,
            attributes: object_attributes(&requested_sha256),
            ..Default::default()
        };

        match self
            .backend
            .put_opts(&location, encoded.as_bytes().to_vec().into(), options)
            .await
        {
            Ok(_) => {
                let stored = self.get_v1(id).await?;
                if stored.encoded.as_bytes() != encoded.as_bytes()
                    || stored.sha256_hex != requested_sha256
                {
                    return Err(ManifestStoreError::corrupt(
                        id,
                        CorruptReadKind::DigestMismatch,
                    ));
                }
                Ok(ManifestWriteOutcome::Created)
            }
            Err(error) if object_store_conflict(&error) => {
                let stored = self.get_v1(id).await?;
                if stored.encoded.as_bytes() == encoded.as_bytes()
                    && stored.sha256_hex == requested_sha256
                {
                    Ok(ManifestWriteOutcome::AlreadyPresent)
                } else {
                    Err(ManifestStoreError::Conflict {
                        id,
                        requested_sha256,
                        stored_sha256: stored.sha256_hex,
                    })
                }
            }
            Err(error) => Err(map_object_store_error(error, "create", Some(id))),
        }
    }

    /// Get one exact object with size, metadata-digest, and UTF-8 validation.
    pub async fn get_v1(
        &self,
        id: ManifestObjectId,
    ) -> Result<StoredRecoveryManifest, ManifestStoreError> {
        let location = Path::from(self.object_key_v1(id));
        let result = self
            .backend
            .get(&location)
            .await
            .map_err(|error| map_object_store_error(error, "get", Some(id)))?;
        let declared_size = result.meta.size;
        if declared_size == 0 {
            return Err(ManifestStoreError::corrupt(
                id,
                CorruptReadKind::EmptyObject,
            ));
        }
        if declared_size > MAX_MANIFEST_OBJECT_BYTES as u64 {
            return Err(ManifestStoreError::corrupt(
                id,
                CorruptReadKind::OversizedObject {
                    actual: declared_size,
                },
            ));
        }
        let attributes = result.attributes.clone();
        let mut stream = result.into_stream();
        let mut encoded = Vec::with_capacity(declared_size as usize);
        while let Some(chunk) = stream
            .try_next()
            .await
            .map_err(|error| map_object_store_error(error, "read", Some(id)))?
        {
            if encoded.len().saturating_add(chunk.len()) > MAX_MANIFEST_OBJECT_BYTES {
                return Err(ManifestStoreError::corrupt(
                    id,
                    CorruptReadKind::OversizedObject {
                        actual: encoded.len().saturating_add(chunk.len()) as u64,
                    },
                ));
            }
            encoded.extend_from_slice(&chunk);
        }
        if encoded.len() != declared_size as usize {
            return Err(ManifestStoreError::corrupt(
                id,
                CorruptReadKind::LengthMismatch {
                    declared: declared_size,
                    actual: encoded.len(),
                },
            ));
        }

        let format = metadata_value(&attributes, OBJECT_FORMAT_ATTRIBUTE)
            .ok_or_else(|| ManifestStoreError::corrupt(id, CorruptReadKind::WrongFormatVersion))?;
        if format != OBJECT_FORMAT_VERSION {
            return Err(ManifestStoreError::corrupt(
                id,
                CorruptReadKind::WrongFormatVersion,
            ));
        }
        let stored_sha256 = metadata_value(&attributes, OBJECT_DIGEST_ATTRIBUTE)
            .ok_or_else(|| ManifestStoreError::corrupt(id, CorruptReadKind::MissingDigest))?;
        if stored_sha256.len() != 64
            || !stored_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || stored_sha256 != stored_sha256.to_ascii_lowercase()
        {
            return Err(ManifestStoreError::corrupt(
                id,
                CorruptReadKind::MalformedDigest,
            ));
        }
        let actual_sha256 = sha256_hex(&encoded);
        if actual_sha256 != stored_sha256 {
            return Err(ManifestStoreError::corrupt(
                id,
                CorruptReadKind::DigestMismatch,
            ));
        }
        let encoded = String::from_utf8(encoded)
            .map_err(|_| ManifestStoreError::corrupt(id, CorruptReadKind::InvalidUtf8))?;
        Ok(StoredRecoveryManifest {
            encoded,
            sha256_hex: actual_sha256,
        })
    }

    /// Return a bounded diagnostic/restore page under the dedicated v1 prefix.
    pub async fn list_v1(&self, limit: usize) -> Result<ManifestListPage, ManifestStoreError> {
        self.list_v1_after(None, limit).await
    }

    /// Continue a bounded S3 listing after the prior page's exclusive cursor.
    pub async fn list_v1_after(
        &self,
        after: Option<ManifestObjectId>,
        limit: usize,
    ) -> Result<ManifestListPage, ManifestStoreError> {
        if !(1..=MAX_MANIFEST_LIST_RESULTS).contains(&limit) {
            return Err(ManifestStoreError::InvalidListLimit {
                requested: limit,
                max: MAX_MANIFEST_LIST_RESULTS,
            });
        }
        let list_prefix = Path::from(format!("{}/v1", self.prefix));
        let mut stream = match after {
            Some(after) => {
                let offset = Path::from(self.object_key_v1(after));
                self.backend.list_with_offset(Some(&list_prefix), &offset)
            }
            None => self.backend.list(Some(&list_prefix)),
        };
        let mut objects = Vec::with_capacity(limit.saturating_add(1));
        while objects.len() <= limit {
            let Some(meta) = stream
                .try_next()
                .await
                .map_err(|error| map_object_store_error(error, "list", None))?
            else {
                break;
            };
            let id = self.parse_object_key_v1(&meta.location).ok_or(
                ManifestStoreError::CorruptRead {
                    id: None,
                    kind: CorruptReadKind::UnexpectedObjectKey,
                },
            )?;
            if meta.size == 0 {
                return Err(ManifestStoreError::corrupt(
                    id,
                    CorruptReadKind::EmptyObject,
                ));
            }
            if meta.size > MAX_MANIFEST_OBJECT_BYTES as u64 {
                return Err(ManifestStoreError::corrupt(
                    id,
                    CorruptReadKind::OversizedObject { actual: meta.size },
                ));
            }
            objects.push(ManifestObjectSummary {
                id,
                encoded_bytes: meta.size,
            });
        }
        let truncated = objects.len() > limit;
        objects.truncate(limit);
        objects.sort_by_key(|object| object.id);
        let next_after = truncated.then(|| objects.last().expect("positive list limit").id);
        Ok(ManifestListPage {
            objects,
            truncated,
            next_after,
        })
    }

    fn with_backend(backend: Arc<dyn ObjectStore>, prefix: String) -> Self {
        Self {
            backend,
            prefix: Path::from(prefix),
        }
    }

    fn parse_object_key_v1(&self, location: &Path) -> Option<ManifestObjectId> {
        let expected_prefix = format!("{}/v1/", self.prefix);
        let suffix = location.as_ref().strip_prefix(&expected_prefix)?;
        let (chain_swap_id, manifest_file) = suffix.split_once('/')?;
        if manifest_file.contains('/') {
            return None;
        }
        let manifest_id = manifest_file.strip_suffix(".json")?;
        let chain_swap_id = parse_canonical_uuid(chain_swap_id)?;
        let manifest_id = parse_canonical_uuid(manifest_id)?;
        ManifestObjectId::new(chain_swap_id, manifest_id).ok()
    }
}

fn object_attributes(sha256: &str) -> Attributes {
    let mut attributes = Attributes::new();
    attributes.insert(Attribute::ContentType, OBJECT_CONTENT_TYPE.into());
    attributes.insert(
        Attribute::Metadata(Cow::Borrowed(OBJECT_FORMAT_ATTRIBUTE)),
        OBJECT_FORMAT_VERSION.into(),
    );
    attributes.insert(
        Attribute::Metadata(Cow::Borrowed(OBJECT_DIGEST_ATTRIBUTE)),
        sha256.to_owned().into(),
    );
    attributes
}

fn metadata_value<'a>(attributes: &'a Attributes, name: &'static str) -> Option<&'a str> {
    attributes
        .get(&Attribute::Metadata(Cow::Borrowed(name)))
        .map(AsRef::as_ref)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_encoded_size(actual: usize) -> Result<(), ManifestStoreError> {
    if actual == 0 || actual > MAX_MANIFEST_OBJECT_BYTES {
        return Err(ManifestStoreError::EncodedSize {
            actual,
            max: MAX_MANIFEST_OBJECT_BYTES,
        });
    }
    Ok(())
}

fn validate_secret(field: &'static str, value: &str, max: usize) -> Result<(), ManifestStoreError> {
    if value.is_empty() {
        return Err(ManifestStoreError::configuration(
            field,
            "must not be empty",
        ));
    }
    if value.len() > max {
        return Err(ManifestStoreError::configuration(field, "is too long"));
    }
    if value.contains('\0') {
        return Err(ManifestStoreError::configuration(
            field,
            "must not contain NUL",
        ));
    }
    Ok(())
}

fn validate_plain_field(
    field: &'static str,
    value: &str,
    max: usize,
    allow_slash: bool,
) -> Result<(), ManifestStoreError> {
    if value.is_empty() {
        return Err(ManifestStoreError::configuration(
            field,
            "must not be empty",
        ));
    }
    if value.len() > max {
        return Err(ManifestStoreError::configuration(field, "is too long"));
    }
    if value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || (!allow_slash && value.contains('/'))
    {
        return Err(ManifestStoreError::configuration(
            field,
            "contains unsafe characters",
        ));
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<(), ManifestStoreError> {
    validate_plain_field("prefix", prefix, 256, true)?;
    if prefix.starts_with('/') || prefix.ends_with('/') {
        return Err(ManifestStoreError::configuration(
            "prefix",
            "must not start or end with a slash",
        ));
    }
    for segment in prefix.split('/') {
        if segment.is_empty()
            || matches!(segment, "." | "..")
            || segment.len() > 63
            || !segment.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(ManifestStoreError::configuration(
                "prefix",
                "must use safe lowercase path segments",
            ));
        }
    }
    Ok(())
}

fn parse_canonical_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn object_store_conflict(error: &object_store::Error) -> bool {
    matches!(
        error,
        object_store::Error::AlreadyExists { .. }
            | object_store::Error::Precondition { .. }
            | object_store::Error::NotModified { .. }
    )
}

fn map_object_store_error(
    error: object_store::Error,
    operation: &'static str,
    id: Option<ManifestObjectId>,
) -> ManifestStoreError {
    match error {
        object_store::Error::NotFound { .. } => id
            .map_or(ManifestStoreError::Unavailable { operation }, |id| {
                ManifestStoreError::NotFound { id }
            }),
        object_store::Error::PermissionDenied { .. }
        | object_store::Error::Unauthenticated { .. } => {
            ManifestStoreError::Authentication { operation }
        }
        _ => ManifestStoreError::Unavailable { operation },
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use object_store::memory::InMemory;

    fn id(number: u128) -> ManifestObjectId {
        ManifestObjectId::new(Uuid::from_u128(number), Uuid::from_u128(number + 10_000)).unwrap()
    }

    fn memory_store() -> (Arc<InMemory>, RecoveryManifestStore) {
        let backend = Arc::new(InMemory::new());
        let store = RecoveryManifestStore::with_backend(backend.clone(), "bullnym/recovery".into());
        (backend, store)
    }

    fn source() -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(io::Error::other(
            "classified without surfacing provider details",
        ))
    }

    #[test]
    fn credentials_and_runtime_debug_are_redacted() {
        let access_key = "ACCESS-KEY-MUST-NOT-LEAK";
        let secret_key = "SECRET-KEY-MUST-NOT-LEAK";
        let session_token = "SESSION-TOKEN-MUST-NOT-LEAK";
        let endpoint = "https://private-storage.example.invalid";
        let config = S3ManifestStoreConfig::new(
            endpoint,
            "region-1",
            "bullnym-manifests",
            "bullnym/recovery",
            true,
            false,
            S3ManifestCredentials::new(access_key, secret_key, Some(session_token.to_owned())),
        );
        let debug = format!("{config:?}");
        for forbidden in [access_key, secret_key, session_token, endpoint] {
            assert!(!debug.contains(forbidden));
        }
        assert!(debug.contains("<redacted>"));

        let store = RecoveryManifestStore::from_s3(config).unwrap();
        let debug = format!("{store:?}");
        assert!(debug.contains("backend: \"<redacted>\""));
        for forbidden in [access_key, secret_key, session_token, endpoint] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[test]
    fn config_requires_safe_explicit_endpoint_and_prefix() {
        let credentials = || S3ManifestCredentials::new("access", "secret", None);
        let valid = S3ManifestStoreConfig::new(
            "https://objects.example.com",
            "region-1",
            "bucket",
            "bullnym/recovery",
            true,
            false,
            credentials(),
        );
        assert_eq!(valid.validate(), Ok(()));

        let embedded_secret = S3ManifestStoreConfig::new(
            "https://user:password@objects.example.com?token=secret",
            "region-1",
            "bucket",
            "bullnym/recovery",
            true,
            false,
            credentials(),
        );
        assert!(matches!(
            embedded_secret.validate(),
            Err(ManifestStoreError::Configuration {
                field: "endpoint",
                ..
            })
        ));

        let insecure = S3ManifestStoreConfig::new(
            "http://objects.example.com",
            "region-1",
            "bucket",
            "bullnym/recovery",
            true,
            false,
            credentials(),
        );
        assert!(insecure.validate().is_err());

        let unsafe_prefix = S3ManifestStoreConfig::new(
            "https://objects.example.com",
            "region-1",
            "bucket",
            "bullnym/../recovery",
            true,
            false,
            credentials(),
        );
        assert!(unsafe_prefix.validate().is_err());
    }

    #[tokio::test]
    async fn identical_concurrent_creates_are_idempotent() {
        let (_, store) = memory_store();
        let object_id = id(1);
        let first = store.clone();
        let second = store.clone();
        let (first, second) = tokio::join!(
            first.put_v1(object_id, "{\"ciphertext\":\"aa\"}"),
            second.put_v1(object_id, "{\"ciphertext\":\"aa\"}"),
        );
        let mut outcomes = [first.unwrap(), second.unwrap()];
        outcomes.sort_by_key(|outcome| match outcome {
            ManifestWriteOutcome::Created => 0,
            ManifestWriteOutcome::AlreadyPresent => 1,
        });
        assert_eq!(
            outcomes,
            [
                ManifestWriteOutcome::Created,
                ManifestWriteOutcome::AlreadyPresent
            ]
        );
    }

    #[tokio::test]
    async fn concurrent_different_bytes_never_overwrite() {
        let (_, store) = memory_store();
        let object_id = id(2);
        let first = store.clone();
        let second = store.clone();
        let (first, second) = tokio::join!(
            first.put_v1(object_id, "{\"ciphertext\":\"aa\"}"),
            second.put_v1(object_id, "{\"ciphertext\":\"bb\"}"),
        );
        let results = [first, second];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ManifestStoreError::Conflict { .. })))
                .count(),
            1
        );
        let stored = store.get_v1(object_id).await.unwrap();
        assert!(matches!(
            stored.encoded(),
            "{\"ciphertext\":\"aa\"}" | "{\"ciphertext\":\"bb\"}"
        ));
    }

    #[tokio::test]
    async fn retry_with_different_bytes_is_an_integrity_conflict() {
        let (_, store) = memory_store();
        let object_id = id(3);
        assert_eq!(
            store.put_v1(object_id, "first").await.unwrap(),
            ManifestWriteOutcome::Created
        );
        assert!(matches!(
            store.put_v1(object_id, "second").await,
            Err(ManifestStoreError::Conflict { id, .. }) if id == object_id
        ));
        assert_eq!(store.get_v1(object_id).await.unwrap().encoded(), "first");
    }

    #[tokio::test]
    async fn read_detects_corrupt_bytes_against_stored_digest() {
        let (backend, store) = memory_store();
        let object_id = id(4);
        let original = "{\"ciphertext\":\"original\"}";
        store.put_v1(object_id, original).await.unwrap();

        let location = Path::from(store.object_key_v1(object_id));
        let options = PutOptions {
            mode: PutMode::Overwrite,
            attributes: object_attributes(&sha256_hex(original.as_bytes())),
            ..Default::default()
        };
        backend
            .put_opts(&location, b"tampered".to_vec().into(), options)
            .await
            .unwrap();

        assert!(matches!(
            store.get_v1(object_id).await,
            Err(ManifestStoreError::CorruptRead {
                kind: CorruptReadKind::DigestMismatch,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn listing_is_bounded_and_keys_are_deterministic() {
        let (_, store) = memory_store();
        for number in 10..13 {
            store
                .put_v1(id(number), &format!("manifest-{number}"))
                .await
                .unwrap();
        }
        assert_eq!(
            store.object_key_v1(id(10)),
            "bullnym/recovery/v1/00000000-0000-0000-0000-00000000000a/00000000-0000-0000-0000-00000000271a.json"
        );

        let bounded = store.list_v1(2).await.unwrap();
        assert_eq!(bounded.objects.len(), 2);
        assert!(bounded.truncated);
        let next_after = bounded.next_after.expect("truncated page has a cursor");
        let final_page = store.list_v1_after(Some(next_after), 2).await.unwrap();
        assert_eq!(final_page.objects.len(), 1);
        assert!(!final_page.truncated);
        assert_eq!(final_page.next_after, None);

        let complete = store.list_v1(10).await.unwrap();
        assert_eq!(complete.objects.len(), 3);
        assert!(!complete.truncated);
        assert_eq!(complete.next_after, None);
        assert!(matches!(
            store.list_v1(0).await,
            Err(ManifestStoreError::InvalidListLimit { .. })
        ));
    }

    #[tokio::test]
    async fn unexpected_key_under_reserved_prefix_fails_closed() {
        let (backend, store) = memory_store();
        backend
            .put(
                &Path::from("bullnym/recovery/v1/not-a-uuid/object.json"),
                b"bad".to_vec().into(),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.list_v1(10).await,
            Err(ManifestStoreError::CorruptRead {
                kind: CorruptReadKind::UnexpectedObjectKey,
                ..
            })
        ));
    }

    #[test]
    fn provider_errors_are_classified_without_source_leakage() {
        let object_id = id(20);
        let auth = object_store::Error::Unauthenticated {
            path: "redacted".into(),
            source: source(),
        };
        assert_eq!(
            map_object_store_error(auth, "get", Some(object_id)),
            ManifestStoreError::Authentication { operation: "get" }
        );

        let unavailable = object_store::Error::Generic {
            store: "test",
            source: source(),
        };
        let classified = map_object_store_error(unavailable, "list", None);
        assert_eq!(
            classified,
            ManifestStoreError::Unavailable { operation: "list" }
        );
        assert!(!classified.to_string().contains("provider details"));
    }

    #[tokio::test]
    async fn encoded_size_and_missing_object_are_distinct() {
        let (_, store) = memory_store();
        let object_id = id(30);
        assert!(matches!(
            store.put_v1(object_id, "").await,
            Err(ManifestStoreError::EncodedSize { actual: 0, .. })
        ));
        let oversized = "x".repeat(MAX_MANIFEST_OBJECT_BYTES + 1);
        assert!(matches!(
            store.put_v1(object_id, &oversized).await,
            Err(ManifestStoreError::EncodedSize { actual, max })
                if actual == MAX_MANIFEST_OBJECT_BYTES + 1
                    && max == MAX_MANIFEST_OBJECT_BYTES
        ));
        assert!(matches!(
            store.get_v1(object_id).await,
            Err(ManifestStoreError::NotFound { id }) if id == object_id
        ));
    }
}
