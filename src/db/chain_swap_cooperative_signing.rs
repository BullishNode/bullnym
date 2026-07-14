use std::{fmt, str::FromStr};

use bitcoin::{consensus::deserialize, Transaction};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, QueryBuilder, Transaction as SqlxTransaction};
use uuid::Uuid;

use crate::{
    fee_decision_record::{FeeConstructionPurpose, FeeDecisionRecord, FEE_POLICY_VERSION},
    fee_policy::{FeeObservationSource, FeeProvenance, FeeRail, SatPerVbyte},
};

const SHA256_HEX_LENGTH: usize = 64;
const PUBLIC_NONCE_HEX_LENGTH: usize = 132;
const PARTIAL_SIGNATURE_HEX_LENGTH: usize = 64;
const SECRET_NONCE_ENCRYPTION_NONCE_LENGTH: usize = 24;
const SECRET_NONCE_CIPHERTEXT_LENGTH: usize = 148;
const SECRET_NONCE_FORMAT: &str = "secp256k1-musig-secnonce-132-v1";
const SECRET_NONCE_ENCRYPTION_ALGORITHM: &str = "xchacha20poly1305-v1";
const SUPERSEDED_REASON: &str = "unilateral_timeout_reached";
const MAX_TRANSACTION_HEX_LENGTH: usize = 200_000;
const MAX_SCRIPT_HEX_LENGTH: usize = 20_000;
const PROVIDER_RESPONSE_DIGEST_DOMAIN: &[u8] = b"bullnym:cooperative-signing-provider-response:v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooperativeSigningState {
    Prepared,
    Requested,
    Ambiguous,
    ResponseReceived,
    Completed,
    IntegrityHold,
    Superseded,
}

impl CooperativeSigningState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Requested => "requested",
            Self::Ambiguous => "ambiguous",
            Self::ResponseReceived => "response_received",
            Self::Completed => "completed",
            Self::IntegrityHold => "integrity_hold",
            Self::Superseded => "superseded",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::IntegrityHold | Self::Superseded
        )
    }
}

impl FromStr for CooperativeSigningState {
    type Err = CooperativeSigningDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "requested" => Ok(Self::Requested),
            "ambiguous" => Ok(Self::Ambiguous),
            "response_received" => Ok(Self::ResponseReceived),
            "completed" => Ok(Self::Completed),
            "integrity_hold" => Ok(Self::IntegrityHold),
            "superseded" => Ok(Self::Superseded),
            _ => Err(CooperativeSigningDomainError::InvalidStoredState),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooperativeSigningErrorClass {
    Timeout,
    Transport,
    ProviderServerError,
    MalformedResponse,
    LocalCommitUncertainty,
    UnknownProviderOutcome,
}

impl CooperativeSigningErrorClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::ProviderServerError => "provider_server_error",
            Self::MalformedResponse => "malformed_response",
            Self::LocalCommitUncertainty => "local_commit_uncertainty",
            Self::UnknownProviderOutcome => "unknown_provider_outcome",
        }
    }
}

impl FromStr for CooperativeSigningErrorClass {
    type Err = CooperativeSigningDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "timeout" => Ok(Self::Timeout),
            "transport" => Ok(Self::Transport),
            "provider_server_error" => Ok(Self::ProviderServerError),
            "malformed_response" => Ok(Self::MalformedResponse),
            "local_commit_uncertainty" => Ok(Self::LocalCommitUncertainty),
            "unknown_provider_outcome" => Ok(Self::UnknownProviderOutcome),
            _ => Err(CooperativeSigningDomainError::InvalidStoredErrorClass),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooperativeSigningDomainError {
    InvalidField { field: &'static str },
    DigestMismatch { field: &'static str },
    InvalidStoredState,
    InvalidStoredErrorClass,
    InvalidStoredLifecycle,
    InvalidTransactionTemplate,
    InvalidFinalTransaction,
    FeeAmountMismatch,
}

impl fmt::Display for CooperativeSigningDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => {
                write!(
                    formatter,
                    "cooperative signing operation has invalid {field}"
                )
            }
            Self::DigestMismatch { field } => {
                write!(
                    formatter,
                    "cooperative signing operation has mismatched {field}"
                )
            }
            Self::InvalidStoredState => {
                formatter.write_str("cooperative signing operation has an unknown state")
            }
            Self::InvalidStoredErrorClass => formatter
                .write_str("cooperative signing operation has an unknown error classification"),
            Self::InvalidStoredLifecycle => {
                formatter.write_str("cooperative signing operation has an invalid lifecycle")
            }
            Self::InvalidTransactionTemplate => {
                formatter.write_str("cooperative signing transaction template is invalid")
            }
            Self::InvalidFinalTransaction => {
                formatter.write_str("cooperative signing final transaction is invalid")
            }
            Self::FeeAmountMismatch => {
                formatter.write_str("cooperative signing fee does not match exact fee authority")
            }
        }
    }
}

impl std::error::Error for CooperativeSigningDomainError {}

/// Already-encrypted MuSig secret nonce material. The plaintext never crosses
/// this persistence API, and neither encrypted bytes nor their commitment are
/// emitted through `Debug` or store-error diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedCooperativeSecretNonce {
    key_id: String,
    encryption_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    plaintext_sha256: String,
}

impl EncryptedCooperativeSecretNonce {
    pub fn new(
        key_id: impl Into<String>,
        encryption_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        plaintext_sha256: impl Into<String>,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let value = Self {
            key_id: key_id.into(),
            encryption_nonce,
            ciphertext,
            plaintext_sha256: plaintext_sha256.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), CooperativeSigningDomainError> {
        if self.key_id.is_empty()
            || self.key_id.len() > 64
            || !self
                .key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "secret_nonce_key_id",
            });
        }
        if self.encryption_nonce.len() != SECRET_NONCE_ENCRYPTION_NONCE_LENGTH {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "secret_nonce_encryption_nonce",
            });
        }
        if self.ciphertext.len() != SECRET_NONCE_CIPHERTEXT_LENGTH {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "secret_nonce_ciphertext",
            });
        }
        validate_sha256(&self.plaintext_sha256, "secret_nonce_plaintext_sha256")
    }

    pub const fn format(&self) -> &'static str {
        SECRET_NONCE_FORMAT
    }

    pub const fn encryption_algorithm(&self) -> &'static str {
        SECRET_NONCE_ENCRYPTION_ALGORITHM
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Explicit runtime decryption boundary. Do not copy these bytes into
    /// diagnostics or arbitrary API responses.
    pub fn encryption_nonce_for_decryption(&self) -> &[u8] {
        &self.encryption_nonce
    }

    /// Explicit runtime decryption boundary. The returned bytes remain
    /// encrypted and must only be opened for the persisted session/sighash.
    pub fn ciphertext_for_decryption(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }
}

impl fmt::Debug for EncryptedCooperativeSecretNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedCooperativeSecretNonce")
            .field("format", &SECRET_NONCE_FORMAT)
            .field("encryption_algorithm", &SECRET_NONCE_ENCRYPTION_ALGORITHM)
            .field("key_id", &"<redacted>")
            .field("encryption_nonce", &"<redacted>")
            .field("ciphertext", &"<redacted>")
            .field("plaintext_sha256", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct CooperativeSigningFeeAuthority {
    source: FeeObservationSource,
    rate: SatPerVbyte,
    quoted_at_unix: u64,
    evaluated_at_unix: u64,
    freshness_age_secs: u64,
    freshness_max_age_secs: u64,
    provenance: FeeProvenance,
    policy_floor: SatPerVbyte,
    policy_cap: SatPerVbyte,
}

impl CooperativeSigningFeeAuthority {
    pub fn from_decision(
        decision: &FeeDecisionRecord,
    ) -> Result<Self, CooperativeSigningDomainError> {
        if decision.purpose() != FeeConstructionPurpose::BitcoinRecovery
            || decision.rail() != FeeRail::Bitcoin
            || decision.target().as_str() != "fastestFee"
            || !matches!(
                decision.source(),
                FeeObservationSource::LiveBitcoin | FeeObservationSource::BitcoinLastKnownGood
            )
            || decision.policy_version() != FEE_POLICY_VERSION
        {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "fee_authority",
            });
        }
        Self::from_persisted(
            decision.source().as_str().to_owned(),
            decision.rate().as_f64(),
            checked_u64_to_i64(decision.quoted_at_unix(), "fee_decision_quoted_at_unix")?,
            checked_u64_to_i64(
                decision.evaluated_at_unix(),
                "fee_decision_evaluated_at_unix",
            )?,
            checked_u64_to_i64(
                decision.freshness_age_secs(),
                "fee_decision_freshness_age_secs",
            )?,
            checked_u64_to_i64(
                decision.freshness_max_age_secs(),
                "fee_decision_freshness_max_age_secs",
            )?,
            decision.provenance_for_persistence().to_owned(),
            decision.policy_floor().as_f64(),
            decision.policy_cap().as_f64(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_persisted(
        source: String,
        rate: f64,
        quoted_at_unix: i64,
        evaluated_at_unix: i64,
        freshness_age_secs: i64,
        freshness_max_age_secs: i64,
        provenance: String,
        policy_floor: f64,
        policy_cap: f64,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let source = match source.as_str() {
            "bitcoin_live" => FeeObservationSource::LiveBitcoin,
            "bitcoin_last_known_good" => FeeObservationSource::BitcoinLastKnownGood,
            _ => {
                return Err(CooperativeSigningDomainError::InvalidField {
                    field: "fee_decision_source",
                })
            }
        };
        let rate = SatPerVbyte::try_from(rate).map_err(|_| {
            CooperativeSigningDomainError::InvalidField {
                field: "fee_decision_rate_sat_vb",
            }
        })?;
        let policy_floor = SatPerVbyte::try_from(policy_floor).map_err(|_| {
            CooperativeSigningDomainError::InvalidField {
                field: "fee_decision_policy_floor_sat_vb",
            }
        })?;
        let policy_cap = SatPerVbyte::try_from(policy_cap).map_err(|_| {
            CooperativeSigningDomainError::InvalidField {
                field: "fee_decision_policy_cap_sat_vb",
            }
        })?;
        let quoted_at_unix =
            checked_nonnegative_u64(quoted_at_unix, "fee_decision_quoted_at_unix")?;
        let evaluated_at_unix =
            checked_nonnegative_u64(evaluated_at_unix, "fee_decision_evaluated_at_unix")?;
        let freshness_age_secs =
            checked_nonnegative_u64(freshness_age_secs, "fee_decision_freshness_age_secs")?;
        let freshness_max_age_secs = checked_positive_u64(
            freshness_max_age_secs,
            "fee_decision_freshness_max_age_secs",
        )?;
        if evaluated_at_unix.checked_sub(quoted_at_unix) != Some(freshness_age_secs)
            || freshness_age_secs > freshness_max_age_secs
            || policy_cap < policy_floor
            || rate < policy_floor
            || rate > policy_cap
        {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "fee_decision_freshness_or_bounds",
            });
        }
        let provenance = FeeProvenance::new(provenance).map_err(|_| {
            CooperativeSigningDomainError::InvalidField {
                field: "fee_decision_provenance",
            }
        })?;
        Ok(Self {
            source,
            rate,
            quoted_at_unix,
            evaluated_at_unix,
            freshness_age_secs,
            freshness_max_age_secs,
            provenance,
            policy_floor,
            policy_cap,
        })
    }

    pub const fn source(&self) -> FeeObservationSource {
        self.source
    }

    pub const fn rate(&self) -> SatPerVbyte {
        self.rate
    }

    pub const fn quoted_at_unix(&self) -> u64 {
        self.quoted_at_unix
    }

    pub const fn evaluated_at_unix(&self) -> u64 {
        self.evaluated_at_unix
    }

    pub const fn freshness_age_secs(&self) -> u64 {
        self.freshness_age_secs
    }

    pub const fn freshness_max_age_secs(&self) -> u64 {
        self.freshness_max_age_secs
    }

    pub fn provenance_for_persistence(&self) -> &str {
        self.provenance.expose_for_persistence()
    }

    pub const fn policy_floor(&self) -> SatPerVbyte {
        self.policy_floor
    }

    pub const fn policy_cap(&self) -> SatPerVbyte {
        self.policy_cap
    }

    pub const fn policy_version(&self) -> &'static str {
        FEE_POLICY_VERSION
    }

    /// Reconstruct fee metadata only for inserting/verifying the already
    /// committed final bytes in `chain_swap_tx_attempts`. The returned record
    /// cannot authorize fresh construction.
    #[allow(dead_code)] // Consumed when this slice is composed with the executor.
    pub(crate) fn to_fee_decision_record_for_committed_bytes(
        &self,
    ) -> Result<FeeDecisionRecord, CooperativeSigningDomainError> {
        FeeDecisionRecord::from_persisted_bitcoin_authority(
            self.source,
            self.rate,
            self.quoted_at_unix,
            self.evaluated_at_unix,
            self.freshness_age_secs,
            self.freshness_max_age_secs,
            self.provenance.clone(),
            self.policy_floor,
            self.policy_cap,
        )
        .map_err(|_| CooperativeSigningDomainError::InvalidField {
            field: "fee_authority",
        })
    }

    fn exact_fee_sat(&self, vbytes: u64) -> Result<u64, CooperativeSigningDomainError> {
        self.rate
            .checked_fee_for_vbytes(vbytes)
            .map_err(|_| CooperativeSigningDomainError::FeeAmountMismatch)
    }
}

impl fmt::Debug for CooperativeSigningFeeAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeSigningFeeAuthority")
            .field("source", &self.source)
            .field("rate", &self.rate)
            .field("quoted_at_unix", &self.quoted_at_unix)
            .field("evaluated_at_unix", &self.evaluated_at_unix)
            .field("freshness_age_secs", &self.freshness_age_secs)
            .field("freshness_max_age_secs", &self.freshness_max_age_secs)
            .field("provenance", &"<redacted>")
            .field("policy_floor", &self.policy_floor)
            .field("policy_cap", &self.policy_cap)
            .field("policy_version", &FEE_POLICY_VERSION)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CooperativeSigningSource {
    txid: String,
    vout: u32,
    amount_sat: u64,
    script_pubkey_hex: String,
}

impl fmt::Debug for CooperativeSigningSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeSigningSource")
            .field("txid", &"<redacted>")
            .field("vout", &"<redacted>")
            .field("amount_sat", &"<redacted>")
            .field("script_pubkey_hex", &"<redacted>")
            .finish()
    }
}

impl CooperativeSigningSource {
    pub fn new(
        txid: impl Into<String>,
        vout: u32,
        amount_sat: u64,
        script_pubkey_hex: impl Into<String>,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let value = Self {
            txid: txid.into(),
            vout,
            amount_sat,
            script_pubkey_hex: script_pubkey_hex.into(),
        };
        validate_sha256(&value.txid, "source_txid")?;
        if value.amount_sat == 0 || value.amount_sat > i64::MAX as u64 {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "source_amount_sat",
            });
        }
        validate_hex(
            &value.script_pubkey_hex,
            2,
            MAX_SCRIPT_HEX_LENGTH,
            "source_script_pubkey_hex",
        )?;
        Ok(value)
    }

    pub fn txid(&self) -> &str {
        &self.txid
    }

    pub const fn vout(&self) -> u32 {
        self.vout
    }

    pub const fn amount_sat(&self) -> u64 {
        self.amount_sat
    }

    pub fn script_pubkey_hex(&self) -> &str {
        &self.script_pubkey_hex
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CooperativeSigningDestination {
    address: String,
    script_pubkey_hex: String,
    amount_sat: u64,
}

impl CooperativeSigningDestination {
    pub fn new(
        address: impl Into<String>,
        script_pubkey_hex: impl Into<String>,
        amount_sat: u64,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let value = Self {
            address: address.into(),
            script_pubkey_hex: script_pubkey_hex.into(),
            amount_sat,
        };
        if value.address.is_empty()
            || value.address.len() > 200
            || value.address.trim() != value.address
            || value.address.chars().any(char::is_whitespace)
        {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "destination_address",
            });
        }
        if value.amount_sat == 0 || value.amount_sat > i64::MAX as u64 {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "destination_amount_sat",
            });
        }
        validate_hex(
            &value.script_pubkey_hex,
            2,
            MAX_SCRIPT_HEX_LENGTH,
            "destination_script_pubkey_hex",
        )?;
        Ok(value)
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn script_pubkey_hex(&self) -> &str {
        &self.script_pubkey_hex
    }

    pub const fn amount_sat(&self) -> u64 {
        self.amount_sat
    }
}

impl fmt::Debug for CooperativeSigningDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeSigningDestination")
            .field("address", &"<redacted>")
            .field("script_pubkey_hex", &"<redacted>")
            .field("amount_sat", &self.amount_sat)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CooperativeSigningRequest {
    transaction_hex: String,
    transaction_sha256: String,
    transaction_txid: String,
    sighash_hex: String,
    aggregate_key_xonly_hex: String,
    client_public_nonce_hex: String,
    provider_request_sha256: String,
    session_sha256: String,
    secret_nonce: EncryptedCooperativeSecretNonce,
}

impl CooperativeSigningRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_hex: impl Into<String>,
        transaction_txid: impl Into<String>,
        sighash_hex: impl Into<String>,
        aggregate_key_xonly_hex: impl Into<String>,
        client_public_nonce_hex: impl Into<String>,
        provider_request_sha256: impl Into<String>,
        session_sha256: impl Into<String>,
        secret_nonce: EncryptedCooperativeSecretNonce,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let transaction_hex = transaction_hex.into();
        validate_hex(
            &transaction_hex,
            2,
            MAX_TRANSACTION_HEX_LENGTH,
            "request_transaction_hex",
        )?;
        let transaction_bytes = hex::decode(&transaction_hex).map_err(|_| {
            CooperativeSigningDomainError::InvalidField {
                field: "request_transaction_hex",
            }
        })?;
        let value = Self {
            transaction_sha256: sha256_hex(&transaction_bytes),
            transaction_hex,
            transaction_txid: transaction_txid.into(),
            sighash_hex: sighash_hex.into(),
            aggregate_key_xonly_hex: aggregate_key_xonly_hex.into(),
            client_public_nonce_hex: client_public_nonce_hex.into(),
            provider_request_sha256: provider_request_sha256.into(),
            session_sha256: session_sha256.into(),
            secret_nonce,
        };
        validate_sha256(&value.transaction_txid, "request_transaction_txid")?;
        validate_sha256(&value.sighash_hex, "sighash_hex")?;
        validate_sha256(&value.aggregate_key_xonly_hex, "aggregate_key_xonly_hex")?;
        validate_exact_hex_length(
            &value.client_public_nonce_hex,
            PUBLIC_NONCE_HEX_LENGTH,
            "client_public_nonce_hex",
        )?;
        validate_sha256(&value.provider_request_sha256, "provider_request_sha256")?;
        validate_sha256(&value.session_sha256, "session_sha256")?;
        value.secret_nonce.validate()?;
        Ok(value)
    }

    pub fn transaction_hex(&self) -> &str {
        &self.transaction_hex
    }

    pub fn transaction_sha256(&self) -> &str {
        &self.transaction_sha256
    }

    pub fn transaction_txid(&self) -> &str {
        &self.transaction_txid
    }

    pub fn sighash_hex(&self) -> &str {
        &self.sighash_hex
    }

    pub fn aggregate_key_xonly_hex(&self) -> &str {
        &self.aggregate_key_xonly_hex
    }

    pub fn client_public_nonce_hex(&self) -> &str {
        &self.client_public_nonce_hex
    }

    pub fn provider_request_sha256(&self) -> &str {
        &self.provider_request_sha256
    }

    pub fn session_sha256(&self) -> &str {
        &self.session_sha256
    }

    pub fn secret_nonce(&self) -> &EncryptedCooperativeSecretNonce {
        &self.secret_nonce
    }
}

impl fmt::Debug for CooperativeSigningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeSigningRequest")
            .field("transaction_hex", &"<redacted>")
            .field("transaction_sha256", &self.transaction_sha256)
            .field("transaction_txid", &self.transaction_txid)
            .field("sighash_hex", &self.sighash_hex)
            .field("aggregate_key_xonly_hex", &self.aggregate_key_xonly_hex)
            .field("client_public_nonce_hex", &"<redacted>")
            .field("provider_request_sha256", &self.provider_request_sha256)
            .field("session_sha256", &self.session_sha256)
            .field("secret_nonce", &self.secret_nonce)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct ChainSwapCooperativeSigningIdentity {
    chain_swap_id: Uuid,
    boltz_swap_id: String,
    source: CooperativeSigningSource,
    destination: CooperativeSigningDestination,
    fee_amount_sat: u64,
    fee_vbytes: u64,
    fee_authority: CooperativeSigningFeeAuthority,
    request: CooperativeSigningRequest,
}

impl ChainSwapCooperativeSigningIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_swap_id: Uuid,
        boltz_swap_id: impl Into<String>,
        source: CooperativeSigningSource,
        destination: CooperativeSigningDestination,
        fee_amount_sat: u64,
        fee_vbytes: u64,
        fee_authority: CooperativeSigningFeeAuthority,
        request: CooperativeSigningRequest,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let value = Self {
            chain_swap_id,
            boltz_swap_id: boltz_swap_id.into(),
            source,
            destination,
            fee_amount_sat,
            fee_vbytes,
            fee_authority,
            request,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), CooperativeSigningDomainError> {
        if self.chain_swap_id.is_nil() {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "chain_swap_id",
            });
        }
        if self.boltz_swap_id.is_empty()
            || self.boltz_swap_id.len() > 200
            || self.boltz_swap_id.trim() != self.boltz_swap_id
            || self.boltz_swap_id.chars().any(char::is_whitespace)
        {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "boltz_swap_id",
            });
        }
        if self.fee_amount_sat == 0
            || self.fee_amount_sat > i64::MAX as u64
            || self.fee_vbytes == 0
            || self.fee_vbytes > i64::MAX as u64
            || self.destination.amount_sat.checked_add(self.fee_amount_sat)
                != Some(self.source.amount_sat)
        {
            return Err(CooperativeSigningDomainError::FeeAmountMismatch);
        }
        if self.fee_authority.exact_fee_sat(self.fee_vbytes)? != self.fee_amount_sat {
            return Err(CooperativeSigningDomainError::FeeAmountMismatch);
        }
        validate_transaction_against_identity(
            &self.request.transaction_hex,
            &self.request.transaction_txid,
            &self.source,
            &self.destination,
            false,
        )?;
        Ok(())
    }

    pub const fn chain_swap_id(&self) -> Uuid {
        self.chain_swap_id
    }

    pub fn boltz_swap_id(&self) -> &str {
        &self.boltz_swap_id
    }

    pub fn source(&self) -> &CooperativeSigningSource {
        &self.source
    }

    pub fn destination(&self) -> &CooperativeSigningDestination {
        &self.destination
    }

    pub const fn fee_amount_sat(&self) -> u64 {
        self.fee_amount_sat
    }

    pub const fn fee_vbytes(&self) -> u64 {
        self.fee_vbytes
    }

    pub fn fee_authority(&self) -> &CooperativeSigningFeeAuthority {
        &self.fee_authority
    }

    pub fn request(&self) -> &CooperativeSigningRequest {
        &self.request
    }
}

impl fmt::Debug for ChainSwapCooperativeSigningIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainSwapCooperativeSigningIdentity")
            .field("chain_swap_id", &self.chain_swap_id)
            .field("boltz_swap_id", &"<redacted>")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("fee_amount_sat", &self.fee_amount_sat)
            .field("fee_vbytes", &self.fee_vbytes)
            .field("fee_authority", &self.fee_authority)
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CooperativeSigningProviderResponse {
    public_nonce_hex: String,
    partial_signature_hex: String,
    response_sha256: String,
}

impl CooperativeSigningProviderResponse {
    pub fn new(
        public_nonce_hex: impl Into<String>,
        partial_signature_hex: impl Into<String>,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let public_nonce_hex = public_nonce_hex.into();
        let partial_signature_hex = partial_signature_hex.into();
        validate_exact_hex_length(
            &public_nonce_hex,
            PUBLIC_NONCE_HEX_LENGTH,
            "provider_public_nonce_hex",
        )?;
        validate_exact_hex_length(
            &partial_signature_hex,
            PARTIAL_SIGNATURE_HEX_LENGTH,
            "provider_partial_signature_hex",
        )?;
        let response_sha256 = provider_response_sha256(&public_nonce_hex, &partial_signature_hex)?;
        Ok(Self {
            public_nonce_hex,
            partial_signature_hex,
            response_sha256,
        })
    }

    pub fn public_nonce_hex(&self) -> &str {
        &self.public_nonce_hex
    }

    pub fn partial_signature_hex(&self) -> &str {
        &self.partial_signature_hex
    }

    pub fn response_sha256(&self) -> &str {
        &self.response_sha256
    }
}

impl fmt::Debug for CooperativeSigningProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeSigningProviderResponse")
            .field("public_nonce_hex", &"<redacted>")
            .field("partial_signature_hex", &"<redacted>")
            .field("response_sha256", &self.response_sha256)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CooperativeSigningCompletion {
    final_transaction_hex: String,
    final_transaction_sha256: String,
    final_txid: String,
    local_partial_signature_sha256: String,
}

impl CooperativeSigningCompletion {
    pub fn new(
        final_transaction_hex: impl Into<String>,
        local_partial_signature_sha256: impl Into<String>,
    ) -> Result<Self, CooperativeSigningDomainError> {
        let final_transaction_hex = final_transaction_hex.into();
        validate_hex(
            &final_transaction_hex,
            2,
            MAX_TRANSACTION_HEX_LENGTH,
            "final_transaction_hex",
        )?;
        let raw = hex::decode(&final_transaction_hex).map_err(|_| {
            CooperativeSigningDomainError::InvalidField {
                field: "final_transaction_hex",
            }
        })?;
        let transaction: Transaction = deserialize(&raw)
            .map_err(|_| CooperativeSigningDomainError::InvalidFinalTransaction)?;
        let value = Self {
            final_transaction_hex,
            final_transaction_sha256: sha256_hex(&raw),
            final_txid: transaction.compute_txid().to_string(),
            local_partial_signature_sha256: local_partial_signature_sha256.into(),
        };
        validate_sha256(
            &value.local_partial_signature_sha256,
            "local_partial_signature_sha256",
        )?;
        Ok(value)
    }

    fn validate_against(
        &self,
        identity: &ChainSwapCooperativeSigningIdentity,
    ) -> Result<(), CooperativeSigningDomainError> {
        validate_transaction_against_identity(
            &self.final_transaction_hex,
            &self.final_txid,
            &identity.source,
            &identity.destination,
            true,
        )?;
        if self.final_txid != identity.request.transaction_txid {
            return Err(CooperativeSigningDomainError::InvalidFinalTransaction);
        }
        let raw = hex::decode(&self.final_transaction_hex)
            .map_err(|_| CooperativeSigningDomainError::InvalidFinalTransaction)?;
        let transaction: Transaction = deserialize(&raw)
            .map_err(|_| CooperativeSigningDomainError::InvalidFinalTransaction)?;
        if u64::try_from(transaction.vsize()).ok() != Some(identity.fee_vbytes) {
            return Err(CooperativeSigningDomainError::FeeAmountMismatch);
        }
        Ok(())
    }

    pub fn final_transaction_hex(&self) -> &str {
        &self.final_transaction_hex
    }

    pub fn final_transaction_sha256(&self) -> &str {
        &self.final_transaction_sha256
    }

    pub fn final_txid(&self) -> &str {
        &self.final_txid
    }

    pub fn local_partial_signature_sha256(&self) -> &str {
        &self.local_partial_signature_sha256
    }
}

impl fmt::Debug for CooperativeSigningCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CooperativeSigningCompletion")
            .field("final_transaction_hex", &"<redacted>")
            .field("final_transaction_sha256", &self.final_transaction_sha256)
            .field("final_txid", &self.final_txid)
            .field("local_partial_signature_sha256", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct ChainSwapCooperativeSigningOperation {
    identity: ChainSwapCooperativeSigningIdentity,
    state: CooperativeSigningState,
    request_attempt_count: u32,
    version: u64,
    requested_at_unix: Option<i64>,
    ambiguous_at_unix: Option<i64>,
    last_error_class: Option<CooperativeSigningErrorClass>,
    provider_response: Option<CooperativeSigningProviderResponse>,
    response_received_at_unix: Option<i64>,
    completion: Option<CooperativeSigningCompletion>,
    completed_at_unix: Option<i64>,
    integrity_reason_sha256: Option<String>,
    integrity_hold_at_unix: Option<i64>,
    superseded_reason: Option<String>,
    superseded_at_unix: Option<i64>,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl ChainSwapCooperativeSigningOperation {
    pub fn identity(&self) -> &ChainSwapCooperativeSigningIdentity {
        &self.identity
    }

    pub const fn state(&self) -> CooperativeSigningState {
        self.state
    }

    pub const fn request_attempt_count(&self) -> u32 {
        self.request_attempt_count
    }

    pub const fn version(&self) -> u64 {
        self.version
    }

    pub const fn requested_at_unix(&self) -> Option<i64> {
        self.requested_at_unix
    }

    pub const fn ambiguous_at_unix(&self) -> Option<i64> {
        self.ambiguous_at_unix
    }

    pub const fn last_error_class(&self) -> Option<CooperativeSigningErrorClass> {
        self.last_error_class
    }

    pub fn provider_response(&self) -> Option<&CooperativeSigningProviderResponse> {
        self.provider_response.as_ref()
    }

    pub const fn response_received_at_unix(&self) -> Option<i64> {
        self.response_received_at_unix
    }

    pub fn completion(&self) -> Option<&CooperativeSigningCompletion> {
        self.completion.as_ref()
    }

    pub const fn completed_at_unix(&self) -> Option<i64> {
        self.completed_at_unix
    }

    pub fn integrity_reason_sha256(&self) -> Option<&str> {
        self.integrity_reason_sha256.as_deref()
    }

    pub const fn integrity_hold_at_unix(&self) -> Option<i64> {
        self.integrity_hold_at_unix
    }

    pub const fn was_superseded_at_unilateral_timeout(&self) -> bool {
        matches!(self.state, CooperativeSigningState::Superseded)
    }

    pub const fn superseded_at_unix(&self) -> Option<i64> {
        self.superseded_at_unix
    }

    pub const fn created_at_unix(&self) -> i64 {
        self.created_at_unix
    }

    pub const fn updated_at_unix(&self) -> i64 {
        self.updated_at_unix
    }
}

impl fmt::Debug for ChainSwapCooperativeSigningOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainSwapCooperativeSigningOperation")
            .field("identity", &self.identity)
            .field("state", &self.state)
            .field("request_attempt_count", &self.request_attempt_count)
            .field("version", &self.version)
            .field("requested_at_unix", &self.requested_at_unix)
            .field("ambiguous_at_unix", &self.ambiguous_at_unix)
            .field("last_error_class", &self.last_error_class)
            .field("provider_response", &self.provider_response)
            .field("response_received_at_unix", &self.response_received_at_unix)
            .field("completion", &self.completion)
            .field("completed_at_unix", &self.completed_at_unix)
            .field("integrity_reason_sha256", &self.integrity_reason_sha256)
            .field("integrity_hold_at_unix", &self.integrity_hold_at_unix)
            .field("superseded_reason", &self.superseded_reason)
            .field("superseded_at_unix", &self.superseded_at_unix)
            .field("created_at_unix", &self.created_at_unix)
            .field("updated_at_unix", &self.updated_at_unix)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooperativeSigningCasDisposition {
    Applied,
    ExactRetry,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CooperativeSigningTransitionOutcome {
    pub operation: ChainSwapCooperativeSigningOperation,
    pub disposition: CooperativeSigningCasDisposition,
}

pub enum ChainSwapCooperativeSigningStoreError {
    Database(sqlx::Error),
    Domain(CooperativeSigningDomainError),
    NotFound {
        chain_swap_id: Uuid,
    },
    IdentityConflict {
        chain_swap_id: Uuid,
    },
    CasMiss {
        chain_swap_id: Uuid,
    },
    InvalidTransition {
        chain_swap_id: Uuid,
        state: CooperativeSigningState,
    },
}

impl fmt::Debug for ChainSwapCooperativeSigningStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("Database(<redacted>)"),
            Self::Domain(error) => formatter.debug_tuple("Domain").field(error).finish(),
            Self::NotFound { chain_swap_id } => formatter
                .debug_struct("NotFound")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::IdentityConflict { chain_swap_id } => formatter
                .debug_struct("IdentityConflict")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::CasMiss { chain_swap_id } => formatter
                .debug_struct("CasMiss")
                .field("chain_swap_id", chain_swap_id)
                .finish(),
            Self::InvalidTransition {
                chain_swap_id,
                state,
            } => formatter
                .debug_struct("InvalidTransition")
                .field("chain_swap_id", chain_swap_id)
                .field("state", state)
                .finish(),
        }
    }
}

impl fmt::Display for ChainSwapCooperativeSigningStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => formatter.write_str("cooperative signing database request failed"),
            Self::Domain(error) => error.fmt(formatter),
            Self::NotFound { .. } => {
                formatter.write_str("cooperative signing operation was not found")
            }
            Self::IdentityConflict { .. } => formatter
                .write_str("chain swap already has a different cooperative signing identity"),
            Self::CasMiss { .. } => {
                formatter.write_str("cooperative signing operation changed during compare-and-swap")
            }
            Self::InvalidTransition { .. } => {
                formatter.write_str("cooperative signing transition is not permitted")
            }
        }
    }
}

impl std::error::Error for ChainSwapCooperativeSigningStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Domain(error) => Some(error),
            // Database diagnostics can echo bound evidence; keep them out of
            // generic reporter chains.
            Self::Database(_)
            | Self::NotFound { .. }
            | Self::IdentityConflict { .. }
            | Self::CasMiss { .. }
            | Self::InvalidTransition { .. } => None,
        }
    }
}

impl From<sqlx::Error> for ChainSwapCooperativeSigningStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<CooperativeSigningDomainError> for ChainSwapCooperativeSigningStoreError {
    fn from(error: CooperativeSigningDomainError) -> Self {
        Self::Domain(error)
    }
}

const OPERATION_COLUMNS: &str = "chain_swap_id, state, boltz_swap_id, \
    source_txid, source_vout, source_amount_sat, source_script_pubkey_hex, \
    destination_address, destination_script_pubkey_hex, destination_amount_sat, \
    fee_amount_sat, fee_vbytes, fee_decision_purpose, fee_decision_rail, \
    fee_decision_target, fee_decision_source, fee_decision_rate_sat_vb, \
    fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
    fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
    fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
    fee_decision_policy_cap_sat_vb, fee_decision_policy_version, \
    request_transaction_hex, request_transaction_sha256, request_transaction_txid, \
    request_input_index, sighash_hex, aggregate_key_xonly_hex, \
    client_public_nonce_hex, provider_request_sha256, session_sha256, \
    secret_nonce_format, secret_nonce_encryption_algorithm, secret_nonce_key_id, \
    secret_nonce_encryption_nonce, secret_nonce_ciphertext, \
    secret_nonce_plaintext_sha256, request_attempt_count, version, \
    EXTRACT(EPOCH FROM requested_at)::BIGINT AS requested_at_unix, \
    EXTRACT(EPOCH FROM ambiguous_at)::BIGINT AS ambiguous_at_unix, last_error_class, \
    provider_public_nonce_hex, provider_partial_signature_hex, \
    provider_response_sha256, \
    EXTRACT(EPOCH FROM response_received_at)::BIGINT AS response_received_at_unix, \
    final_transaction_hex, final_transaction_sha256, final_txid, \
    local_partial_signature_sha256, \
    EXTRACT(EPOCH FROM completed_at)::BIGINT AS completed_at_unix, \
    integrity_reason_sha256, \
    EXTRACT(EPOCH FROM integrity_hold_at)::BIGINT AS integrity_hold_at_unix, \
    superseded_reason, \
    EXTRACT(EPOCH FROM superseded_at)::BIGINT AS superseded_at_unix, \
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix, \
    EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at_unix";

#[derive(sqlx::FromRow)]
struct CooperativeSigningOperationDbRow {
    chain_swap_id: Uuid,
    state: String,
    boltz_swap_id: String,
    source_txid: String,
    source_vout: i64,
    source_amount_sat: i64,
    source_script_pubkey_hex: String,
    destination_address: String,
    destination_script_pubkey_hex: String,
    destination_amount_sat: i64,
    fee_amount_sat: i64,
    fee_vbytes: i64,
    fee_decision_purpose: String,
    fee_decision_rail: String,
    fee_decision_target: String,
    fee_decision_source: String,
    fee_decision_rate_sat_vb: f64,
    fee_decision_quoted_at_unix: i64,
    fee_decision_evaluated_at_unix: i64,
    fee_decision_freshness_age_secs: i64,
    fee_decision_freshness_max_age_secs: i64,
    fee_decision_provenance: String,
    fee_decision_policy_floor_sat_vb: f64,
    fee_decision_policy_cap_sat_vb: f64,
    fee_decision_policy_version: String,
    request_transaction_hex: String,
    request_transaction_sha256: String,
    request_transaction_txid: String,
    request_input_index: i32,
    sighash_hex: String,
    aggregate_key_xonly_hex: String,
    client_public_nonce_hex: String,
    provider_request_sha256: String,
    session_sha256: String,
    secret_nonce_format: String,
    secret_nonce_encryption_algorithm: String,
    secret_nonce_key_id: String,
    secret_nonce_encryption_nonce: Vec<u8>,
    secret_nonce_ciphertext: Vec<u8>,
    secret_nonce_plaintext_sha256: String,
    request_attempt_count: i32,
    version: i64,
    requested_at_unix: Option<i64>,
    ambiguous_at_unix: Option<i64>,
    last_error_class: Option<String>,
    provider_public_nonce_hex: Option<String>,
    provider_partial_signature_hex: Option<String>,
    provider_response_sha256: Option<String>,
    response_received_at_unix: Option<i64>,
    final_transaction_hex: Option<String>,
    final_transaction_sha256: Option<String>,
    final_txid: Option<String>,
    local_partial_signature_sha256: Option<String>,
    completed_at_unix: Option<i64>,
    integrity_reason_sha256: Option<String>,
    integrity_hold_at_unix: Option<i64>,
    superseded_reason: Option<String>,
    superseded_at_unix: Option<i64>,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl TryFrom<CooperativeSigningOperationDbRow> for ChainSwapCooperativeSigningOperation {
    type Error = CooperativeSigningDomainError;

    fn try_from(row: CooperativeSigningOperationDbRow) -> Result<Self, Self::Error> {
        expect_text(
            &row.fee_decision_purpose,
            "bitcoin_recovery",
            "fee_decision_purpose",
        )?;
        expect_text(&row.fee_decision_rail, "bitcoin", "fee_decision_rail")?;
        expect_text(
            &row.fee_decision_target,
            "fastestFee",
            "fee_decision_target",
        )?;
        expect_text(
            &row.fee_decision_policy_version,
            FEE_POLICY_VERSION,
            "fee_decision_policy_version",
        )?;
        expect_text(
            &row.secret_nonce_format,
            SECRET_NONCE_FORMAT,
            "secret_nonce_format",
        )?;
        expect_text(
            &row.secret_nonce_encryption_algorithm,
            SECRET_NONCE_ENCRYPTION_ALGORITHM,
            "secret_nonce_encryption_algorithm",
        )?;
        if row.request_input_index != 0 {
            return Err(CooperativeSigningDomainError::InvalidField {
                field: "request_input_index",
            });
        }

        let source = CooperativeSigningSource::new(
            row.source_txid,
            u32::try_from(row.source_vout).map_err(|_| {
                CooperativeSigningDomainError::InvalidField {
                    field: "source_vout",
                }
            })?,
            checked_nonnegative_u64(row.source_amount_sat, "source_amount_sat")?,
            row.source_script_pubkey_hex,
        )?;
        let destination = CooperativeSigningDestination::new(
            row.destination_address,
            row.destination_script_pubkey_hex,
            checked_nonnegative_u64(row.destination_amount_sat, "destination_amount_sat")?,
        )?;
        let fee_authority = CooperativeSigningFeeAuthority::from_persisted(
            row.fee_decision_source,
            row.fee_decision_rate_sat_vb,
            row.fee_decision_quoted_at_unix,
            row.fee_decision_evaluated_at_unix,
            row.fee_decision_freshness_age_secs,
            row.fee_decision_freshness_max_age_secs,
            row.fee_decision_provenance,
            row.fee_decision_policy_floor_sat_vb,
            row.fee_decision_policy_cap_sat_vb,
        )?;
        let secret_nonce = EncryptedCooperativeSecretNonce::new(
            row.secret_nonce_key_id,
            row.secret_nonce_encryption_nonce,
            row.secret_nonce_ciphertext,
            row.secret_nonce_plaintext_sha256,
        )?;
        let request = CooperativeSigningRequest::new(
            row.request_transaction_hex,
            row.request_transaction_txid,
            row.sighash_hex,
            row.aggregate_key_xonly_hex,
            row.client_public_nonce_hex,
            row.provider_request_sha256,
            row.session_sha256,
            secret_nonce,
        )?;
        if request.transaction_sha256 != row.request_transaction_sha256 {
            return Err(CooperativeSigningDomainError::DigestMismatch {
                field: "request_transaction_sha256",
            });
        }
        let identity = ChainSwapCooperativeSigningIdentity::new(
            row.chain_swap_id,
            row.boltz_swap_id,
            source,
            destination,
            checked_positive_u64(row.fee_amount_sat, "fee_amount_sat")?,
            checked_positive_u64(row.fee_vbytes, "fee_vbytes")?,
            fee_authority,
            request,
        )?;

        let provider_response = match (
            row.provider_public_nonce_hex,
            row.provider_partial_signature_hex,
            row.provider_response_sha256,
        ) {
            (None, None, None) => None,
            (Some(public_nonce), Some(partial_signature), Some(response_sha256)) => {
                let response =
                    CooperativeSigningProviderResponse::new(public_nonce, partial_signature)?;
                if response.response_sha256 != response_sha256 {
                    return Err(CooperativeSigningDomainError::DigestMismatch {
                        field: "provider_response_sha256",
                    });
                }
                Some(response)
            }
            _ => return Err(CooperativeSigningDomainError::InvalidStoredLifecycle),
        };
        let completion = match (
            row.final_transaction_hex,
            row.final_transaction_sha256,
            row.final_txid,
            row.local_partial_signature_sha256,
        ) {
            (None, None, None, None) => None,
            (Some(transaction_hex), Some(transaction_sha256), Some(txid), Some(local_sha256)) => {
                let completion = CooperativeSigningCompletion::new(transaction_hex, local_sha256)?;
                if completion.final_transaction_sha256 != transaction_sha256
                    || completion.final_txid != txid
                {
                    return Err(CooperativeSigningDomainError::DigestMismatch {
                        field: "final_transaction_identity",
                    });
                }
                completion.validate_against(&identity)?;
                Some(completion)
            }
            _ => return Err(CooperativeSigningDomainError::InvalidStoredLifecycle),
        };
        let state = CooperativeSigningState::from_str(&row.state)?;
        let request_attempt_count = u32::try_from(row.request_attempt_count)
            .map_err(|_| CooperativeSigningDomainError::InvalidStoredLifecycle)?;
        let version = u64::try_from(row.version)
            .map_err(|_| CooperativeSigningDomainError::InvalidStoredLifecycle)?;
        let last_error_class = row
            .last_error_class
            .as_deref()
            .map(CooperativeSigningErrorClass::from_str)
            .transpose()?;
        if let Some(reason) = row.integrity_reason_sha256.as_deref() {
            validate_sha256(reason, "integrity_reason_sha256")?;
        }
        if row
            .superseded_reason
            .as_deref()
            .is_some_and(|reason| reason != SUPERSEDED_REASON)
        {
            return Err(CooperativeSigningDomainError::InvalidStoredLifecycle);
        }
        let operation = Self {
            identity,
            state,
            request_attempt_count,
            version,
            requested_at_unix: row.requested_at_unix,
            ambiguous_at_unix: row.ambiguous_at_unix,
            last_error_class,
            provider_response,
            response_received_at_unix: row.response_received_at_unix,
            completion,
            completed_at_unix: row.completed_at_unix,
            integrity_reason_sha256: row.integrity_reason_sha256,
            integrity_hold_at_unix: row.integrity_hold_at_unix,
            superseded_reason: row.superseded_reason,
            superseded_at_unix: row.superseded_at_unix,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        };
        operation.validate_lifecycle()?;
        Ok(operation)
    }
}

impl ChainSwapCooperativeSigningOperation {
    fn validate_lifecycle(&self) -> Result<(), CooperativeSigningDomainError> {
        if self.version == 0
            || self.created_at_unix < 0
            || self.updated_at_unix < self.created_at_unix
            || !timestamp_in_range(
                self.requested_at_unix,
                self.created_at_unix,
                self.updated_at_unix,
            )
            || !timestamp_in_range(
                self.ambiguous_at_unix,
                self.requested_at_unix.unwrap_or(self.created_at_unix),
                self.updated_at_unix,
            )
            || !timestamp_in_range(
                self.response_received_at_unix,
                self.requested_at_unix.unwrap_or(self.created_at_unix),
                self.updated_at_unix,
            )
            || !timestamp_in_range(
                self.completed_at_unix,
                self.response_received_at_unix
                    .unwrap_or(self.created_at_unix),
                self.updated_at_unix,
            )
            || !timestamp_in_range(
                self.integrity_hold_at_unix,
                self.created_at_unix,
                self.updated_at_unix,
            )
            || !timestamp_in_range(
                self.superseded_at_unix,
                self.created_at_unix,
                self.updated_at_unix,
            )
            || self.provider_response.is_some() != self.response_received_at_unix.is_some()
            || self.completion.is_some() != self.completed_at_unix.is_some()
            || self.integrity_reason_sha256.is_some() != self.integrity_hold_at_unix.is_some()
            || self.superseded_reason.is_some() != self.superseded_at_unix.is_some()
        {
            return Err(CooperativeSigningDomainError::InvalidStoredLifecycle);
        }

        let ambiguity_shape = (self.ambiguous_at_unix.is_none() && self.last_error_class.is_none())
            || (self.ambiguous_at_unix.is_some() && self.last_error_class.is_some());
        let valid = match self.state {
            CooperativeSigningState::Prepared => {
                self.request_attempt_count == 0
                    && self.requested_at_unix.is_none()
                    && self.ambiguous_at_unix.is_none()
                    && self.last_error_class.is_none()
                    && self.provider_response.is_none()
                    && self.completion.is_none()
                    && self.integrity_reason_sha256.is_none()
                    && self.superseded_reason.is_none()
            }
            CooperativeSigningState::Requested => {
                self.request_attempt_count == 1
                    && self.requested_at_unix.is_some()
                    && self.ambiguous_at_unix.is_none()
                    && self.last_error_class.is_none()
                    && self.provider_response.is_none()
                    && self.completion.is_none()
                    && self.integrity_reason_sha256.is_none()
                    && self.superseded_reason.is_none()
            }
            CooperativeSigningState::Ambiguous => {
                self.request_attempt_count == 1
                    && self.requested_at_unix.is_some()
                    && self.ambiguous_at_unix.is_some()
                    && self.last_error_class.is_some()
                    && self.provider_response.is_none()
                    && self.completion.is_none()
                    && self.integrity_reason_sha256.is_none()
                    && self.superseded_reason.is_none()
            }
            CooperativeSigningState::ResponseReceived => {
                self.request_attempt_count == 1
                    && self.requested_at_unix.is_some()
                    && ambiguity_shape
                    && self.provider_response.is_some()
                    && self.completion.is_none()
                    && self.integrity_reason_sha256.is_none()
                    && self.superseded_reason.is_none()
            }
            CooperativeSigningState::Completed => {
                self.request_attempt_count == 1
                    && self.requested_at_unix.is_some()
                    && ambiguity_shape
                    && self.provider_response.is_some()
                    && self.completion.is_some()
                    && self.integrity_reason_sha256.is_none()
                    && self.superseded_reason.is_none()
            }
            CooperativeSigningState::IntegrityHold => {
                self.completion.is_none()
                    && self.integrity_reason_sha256.is_some()
                    && self.superseded_reason.is_none()
                    && ((self.request_attempt_count == 0 && self.requested_at_unix.is_none())
                        || (self.request_attempt_count == 1 && self.requested_at_unix.is_some()))
                    && ambiguity_shape
            }
            CooperativeSigningState::Superseded => {
                self.provider_response.is_none()
                    && self.completion.is_none()
                    && self.integrity_reason_sha256.is_none()
                    && self.superseded_reason.as_deref() == Some(SUPERSEDED_REASON)
                    && ((self.request_attempt_count == 0 && self.requested_at_unix.is_none())
                        || (self.request_attempt_count == 1 && self.requested_at_unix.is_some()))
                    && ambiguity_shape
            }
        };
        if valid {
            Ok(())
        } else {
            Err(CooperativeSigningDomainError::InvalidStoredLifecycle)
        }
    }
}

/// Persist one immutable signing intent before any provider mutation. Exact
/// retries return the existing operation; any byte, fee, source, session, or
/// encrypted-nonce difference fails closed.
pub async fn persist_prepared_chain_swap_cooperative_signing(
    pool: &PgPool,
    identity: &ChainSwapCooperativeSigningIdentity,
) -> Result<ChainSwapCooperativeSigningOperation, ChainSwapCooperativeSigningStoreError> {
    let mut tx = pool.begin().await?;
    let operation =
        persist_prepared_chain_swap_cooperative_signing_in_transaction(&mut tx, identity).await?;
    tx.commit().await?;
    Ok(operation)
}

/// Executor-facing persistence boundary. The caller's transaction retains the
/// shared `chain-claim:<id>` advisory lock and parent `FOR UPDATE` lock across
/// fee/source validation, immutable preparation, and the requested-intent CAS.
/// Production callers must use this variant (normally followed by
/// `mark_chain_swap_cooperative_signing_requested_in_transaction`) and may POST
/// only after the outer transaction commits.
pub async fn persist_prepared_chain_swap_cooperative_signing_in_transaction(
    conn: &mut PgConnection,
    identity: &ChainSwapCooperativeSigningIdentity,
) -> Result<ChainSwapCooperativeSigningOperation, ChainSwapCooperativeSigningStoreError> {
    identity.validate()?;
    acquire_chain_claim_boundary(
        conn,
        identity.chain_swap_id,
        Some(identity.boltz_swap_id.as_str()),
    )
    .await?;
    insert_prepared_operation(conn, identity).await?;
    let operation = load_operation_for_update(conn, identity.chain_swap_id)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::NotFound {
            chain_swap_id: identity.chain_swap_id,
        })?;
    if operation.identity != *identity {
        return Err(ChainSwapCooperativeSigningStoreError::IdentityConflict {
            chain_swap_id: identity.chain_swap_id,
        });
    }
    Ok(operation)
}

async fn insert_prepared_operation(
    conn: &mut PgConnection,
    identity: &ChainSwapCooperativeSigningIdentity,
) -> Result<(), ChainSwapCooperativeSigningStoreError> {
    let source = &identity.source;
    let destination = &identity.destination;
    let fee = &identity.fee_authority;
    let request = &identity.request;
    let secret = &request.secret_nonce;
    let mut query = QueryBuilder::<Postgres>::new(
        "INSERT INTO chain_swap_cooperative_signing_operations (\
            chain_swap_id, state, boltz_swap_id, source_txid, source_vout, \
            source_amount_sat, source_script_pubkey_hex, destination_address, \
            destination_script_pubkey_hex, destination_amount_sat, fee_amount_sat, \
            fee_vbytes, fee_decision_purpose, fee_decision_rail, fee_decision_target, \
            fee_decision_source, fee_decision_rate_sat_vb, \
            fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
            fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
            fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
            fee_decision_policy_cap_sat_vb, fee_decision_policy_version, \
            request_transaction_hex, request_transaction_sha256, \
            request_transaction_txid, request_input_index, sighash_hex, \
            aggregate_key_xonly_hex, client_public_nonce_hex, provider_request_sha256, \
            session_sha256, secret_nonce_format, secret_nonce_encryption_algorithm, \
            secret_nonce_key_id, secret_nonce_encryption_nonce, secret_nonce_ciphertext, \
            secret_nonce_plaintext_sha256, request_attempt_count, version) VALUES (",
    );
    {
        let mut values = query.separated(", ");
        values.push_bind(identity.chain_swap_id);
        values.push_bind(CooperativeSigningState::Prepared.as_str());
        values.push_bind(&identity.boltz_swap_id);
        values.push_bind(&source.txid);
        values.push_bind(i64::from(source.vout));
        values.push_bind(checked_u64_to_i64(source.amount_sat, "source_amount_sat")?);
        values.push_bind(&source.script_pubkey_hex);
        values.push_bind(&destination.address);
        values.push_bind(&destination.script_pubkey_hex);
        values.push_bind(checked_u64_to_i64(
            destination.amount_sat,
            "destination_amount_sat",
        )?);
        values.push_bind(checked_u64_to_i64(
            identity.fee_amount_sat,
            "fee_amount_sat",
        )?);
        values.push_bind(checked_u64_to_i64(identity.fee_vbytes, "fee_vbytes")?);
        values.push_bind(FeeConstructionPurpose::BitcoinRecovery.as_str());
        values.push_bind(FeeRail::Bitcoin.as_str());
        values.push_bind("fastestFee");
        values.push_bind(fee.source.as_str());
        values.push_bind(fee.rate.as_f64());
        values.push_bind(checked_u64_to_i64(
            fee.quoted_at_unix,
            "fee_decision_quoted_at_unix",
        )?);
        values.push_bind(checked_u64_to_i64(
            fee.evaluated_at_unix,
            "fee_decision_evaluated_at_unix",
        )?);
        values.push_bind(checked_u64_to_i64(
            fee.freshness_age_secs,
            "fee_decision_freshness_age_secs",
        )?);
        values.push_bind(checked_u64_to_i64(
            fee.freshness_max_age_secs,
            "fee_decision_freshness_max_age_secs",
        )?);
        values.push_bind(fee.provenance.expose_for_persistence());
        values.push_bind(fee.policy_floor.as_f64());
        values.push_bind(fee.policy_cap.as_f64());
        values.push_bind(FEE_POLICY_VERSION);
        values.push_bind(&request.transaction_hex);
        values.push_bind(&request.transaction_sha256);
        values.push_bind(&request.transaction_txid);
        values.push_bind(0_i32);
        values.push_bind(&request.sighash_hex);
        values.push_bind(&request.aggregate_key_xonly_hex);
        values.push_bind(&request.client_public_nonce_hex);
        values.push_bind(&request.provider_request_sha256);
        values.push_bind(&request.session_sha256);
        values.push_bind(SECRET_NONCE_FORMAT);
        values.push_bind(SECRET_NONCE_ENCRYPTION_ALGORITHM);
        values.push_bind(&secret.key_id);
        values.push_bind(&secret.encryption_nonce);
        values.push_bind(&secret.ciphertext);
        values.push_bind(&secret.plaintext_sha256);
        values.push_bind(0_i32);
        values.push_bind(1_i64);
    }
    query.push(") ON CONFLICT (chain_swap_id) DO NOTHING");
    query.build().execute(&mut *conn).await?;
    Ok(())
}

pub async fn get_chain_swap_cooperative_signing(
    pool: &PgPool,
    chain_swap_id: Uuid,
) -> Result<Option<ChainSwapCooperativeSigningOperation>, ChainSwapCooperativeSigningStoreError> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} \
           FROM chain_swap_cooperative_signing_operations \
          WHERE chain_swap_id = $1"
    );
    decode_optional(
        sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
            .bind(chain_swap_id)
            .fetch_optional(pool)
            .await?,
    )
}

/// Runtime-only locking read. Secret nonce fields are intentionally absent
/// from every diagnostic/readiness query; this method exists solely for the
/// signing executor's persisted-session recovery path.
pub async fn get_chain_swap_cooperative_signing_for_update(
    conn: &mut PgConnection,
    chain_swap_id: Uuid,
) -> Result<Option<ChainSwapCooperativeSigningOperation>, ChainSwapCooperativeSigningStoreError> {
    load_operation_for_update(conn, chain_swap_id).await
}

/// Commit this CAS before issuing the single permitted provider POST. Only an
/// `Applied` disposition authorizes that call; `ExactRetry` proves it was
/// already authorized and therefore must never cause a second POST.
pub async fn mark_chain_swap_cooperative_signing_requested(
    pool: &PgPool,
    chain_swap_id: Uuid,
    expected_version: u64,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    let mut tx = pool.begin().await?;
    let outcome = mark_chain_swap_cooperative_signing_requested_in_transaction(
        &mut tx,
        chain_swap_id,
        expected_version,
    )
    .await?;
    tx.commit().await?;
    Ok(outcome)
}

pub async fn mark_chain_swap_cooperative_signing_requested_in_transaction(
    conn: &mut PgConnection,
    chain_swap_id: Uuid,
    expected_version: u64,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    acquire_chain_claim_boundary(conn, chain_swap_id, None).await?;
    let current = load_operation_for_update(conn, chain_swap_id)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::NotFound { chain_swap_id })?;
    if state_exact_retry(
        &current,
        expected_version,
        CooperativeSigningState::Requested,
    ) {
        return Ok(exact_retry(current));
    }
    require_version(&current, expected_version)?;
    require_state(&current, CooperativeSigningState::Prepared)?;
    let sql = format!(
        "UPDATE chain_swap_cooperative_signing_operations \
            SET state = 'requested', request_attempt_count = 1, \
                requested_at = clock_timestamp(), version = version + 1 \
          WHERE chain_swap_id = $1 AND state = 'prepared' AND version = $2 \
          RETURNING {OPERATION_COLUMNS}"
    );
    let updated = sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .bind(checked_version(expected_version)?)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::CasMiss { chain_swap_id })?;
    let operation = decode_row(updated)?;
    Ok(applied(operation))
}

/// One-call production boundary for initial intent. The exact identity is
/// inserted (or verified) and `prepared -> requested` is advanced inside the
/// caller's existing transaction and shared chain lock.
pub async fn prepare_and_mark_chain_swap_cooperative_signing_requested_in_transaction(
    conn: &mut PgConnection,
    identity: &ChainSwapCooperativeSigningIdentity,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    let prepared =
        persist_prepared_chain_swap_cooperative_signing_in_transaction(conn, identity).await?;
    match prepared.state {
        CooperativeSigningState::Prepared => {
            mark_chain_swap_cooperative_signing_requested_in_transaction(
                conn,
                identity.chain_swap_id,
                prepared.version,
            )
            .await
        }
        CooperativeSigningState::Requested => Ok(exact_retry(prepared)),
        state => Err(ChainSwapCooperativeSigningStoreError::InvalidTransition {
            chain_swap_id: identity.chain_swap_id,
            state,
        }),
    }
}

pub async fn mark_chain_swap_cooperative_signing_ambiguous(
    pool: &PgPool,
    chain_swap_id: Uuid,
    expected_version: u64,
    error_class: CooperativeSigningErrorClass,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    let mut tx = pool.begin().await?;
    let current = load_required_for_update(&mut tx, chain_swap_id).await?;
    if current.state == CooperativeSigningState::Ambiguous
        && current.last_error_class == Some(error_class)
        && version_is_exact_retry(current.version, expected_version)
    {
        tx.commit().await?;
        return Ok(exact_retry(current));
    }
    require_version(&current, expected_version)?;
    require_state(&current, CooperativeSigningState::Requested)?;
    let sql = format!(
        "UPDATE chain_swap_cooperative_signing_operations \
            SET state = 'ambiguous', ambiguous_at = clock_timestamp(), \
                last_error_class = $3, version = version + 1 \
          WHERE chain_swap_id = $1 AND state = 'requested' AND version = $2 \
          RETURNING {OPERATION_COLUMNS}"
    );
    let updated = sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .bind(checked_version(expected_version)?)
        .bind(error_class.as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::CasMiss { chain_swap_id })?;
    let operation = decode_row(updated)?;
    tx.commit().await?;
    Ok(applied(operation))
}

/// Persist the exact response to either a requested or an ambiguous POST.
/// A byte-identical late response is idempotent. A different response after
/// one response is already durable preserves the first evidence and moves the
/// operation to integrity hold; it never overwrites provider evidence.
pub async fn record_chain_swap_cooperative_signing_response(
    pool: &PgPool,
    chain_swap_id: Uuid,
    expected_version: u64,
    response: &CooperativeSigningProviderResponse,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    let mut tx = pool.begin().await?;
    let current = load_required_for_update(&mut tx, chain_swap_id).await?;

    if current.state == CooperativeSigningState::ResponseReceived {
        let existing = current
            .provider_response
            .as_ref()
            .ok_or(CooperativeSigningDomainError::InvalidStoredLifecycle)?;
        if existing == response
            && (current.version == expected_version
                || version_is_exact_retry(current.version, expected_version))
        {
            tx.commit().await?;
            return Ok(exact_retry(current));
        }
        if current.version == expected_version
            || version_is_exact_retry(current.version, expected_version)
        {
            let reason_sha256 = provider_response_conflict_sha256(existing, response);
            let operation = transition_to_integrity_hold(
                &mut tx,
                chain_swap_id,
                current.version,
                &reason_sha256,
            )
            .await?;
            tx.commit().await?;
            return Ok(applied(operation));
        }
    }
    if current.state == CooperativeSigningState::IntegrityHold {
        if let Some(existing) = current.provider_response.as_ref() {
            let reason_sha256 = provider_response_conflict_sha256(existing, response);
            if current.integrity_reason_sha256.as_deref() == Some(reason_sha256.as_str())
                && (current.version == expected_version
                    || current.version.checked_sub(1) == Some(expected_version)
                    || current.version.checked_sub(2) == Some(expected_version))
            {
                tx.commit().await?;
                return Ok(exact_retry(current));
            }
        }
    }

    require_version(&current, expected_version)?;
    if !matches!(
        current.state,
        CooperativeSigningState::Requested | CooperativeSigningState::Ambiguous
    ) {
        return Err(ChainSwapCooperativeSigningStoreError::InvalidTransition {
            chain_swap_id,
            state: current.state,
        });
    }
    let sql = format!(
        "UPDATE chain_swap_cooperative_signing_operations \
            SET state = 'response_received', provider_public_nonce_hex = $3, \
                provider_partial_signature_hex = $4, provider_response_sha256 = $5, \
                response_received_at = clock_timestamp(), version = version + 1 \
          WHERE chain_swap_id = $1 AND state = $6 AND version = $2 \
          RETURNING {OPERATION_COLUMNS}"
    );
    let updated = sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .bind(checked_version(expected_version)?)
        .bind(&response.public_nonce_hex)
        .bind(&response.partial_signature_hex)
        .bind(&response.response_sha256)
        .bind(current.state.as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::CasMiss { chain_swap_id })?;
    let operation = decode_row(updated)?;
    tx.commit().await?;
    Ok(applied(operation))
}

/// Complete the signing journal through an existing database transaction.
/// The caller must first insert the exact `btc_recovery` transaction attempt
/// in this same transaction. Migration 057 independently enforces that exact
/// raw bytes, txid, source, destination, fee, and authority all match before
/// this CAS can advance; broadcasting is permitted only after the outer commit.
pub async fn complete_chain_swap_cooperative_signing_in_transaction(
    conn: &mut PgConnection,
    chain_swap_id: Uuid,
    expected_version: u64,
    completion: &CooperativeSigningCompletion,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    acquire_chain_claim_boundary(conn, chain_swap_id, None).await?;
    let current = load_operation_for_update(conn, chain_swap_id)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::NotFound { chain_swap_id })?;
    completion.validate_against(&current.identity)?;
    if current.state == CooperativeSigningState::Completed
        && current.completion.as_ref() == Some(completion)
        && (current.version == expected_version
            || version_is_exact_retry(current.version, expected_version))
    {
        return Ok(exact_retry(current));
    }
    require_version(&current, expected_version)?;
    require_state(&current, CooperativeSigningState::ResponseReceived)?;
    let sql = format!(
        "UPDATE chain_swap_cooperative_signing_operations \
            SET state = 'completed', final_transaction_hex = $3, \
                final_transaction_sha256 = $4, final_txid = $5, \
                local_partial_signature_sha256 = $6, \
                completed_at = clock_timestamp(), version = version + 1 \
          WHERE chain_swap_id = $1 AND state = 'response_received' AND version = $2 \
          RETURNING {OPERATION_COLUMNS}"
    );
    let updated = sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .bind(checked_version(expected_version)?)
        .bind(&completion.final_transaction_hex)
        .bind(&completion.final_transaction_sha256)
        .bind(&completion.final_txid)
        .bind(&completion.local_partial_signature_sha256)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::CasMiss { chain_swap_id })?;
    Ok(applied(decode_row(updated)?))
}

pub async fn mark_chain_swap_cooperative_signing_integrity_hold(
    pool: &PgPool,
    chain_swap_id: Uuid,
    expected_version: u64,
    integrity_reason_sha256: &str,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    validate_sha256(integrity_reason_sha256, "integrity_reason_sha256")?;
    let mut tx = pool.begin().await?;
    let current = load_required_for_update(&mut tx, chain_swap_id).await?;
    if current.state == CooperativeSigningState::IntegrityHold
        && current.integrity_reason_sha256.as_deref() == Some(integrity_reason_sha256)
        && (current.version == expected_version
            || version_is_exact_retry(current.version, expected_version))
    {
        tx.commit().await?;
        return Ok(exact_retry(current));
    }
    require_version(&current, expected_version)?;
    if current.state.is_terminal() {
        return Err(ChainSwapCooperativeSigningStoreError::InvalidTransition {
            chain_swap_id,
            state: current.state,
        });
    }
    let operation = transition_to_integrity_hold(
        &mut tx,
        chain_swap_id,
        expected_version,
        integrity_reason_sha256,
    )
    .await?;
    tx.commit().await?;
    Ok(applied(operation))
}

pub async fn supersede_chain_swap_cooperative_signing_at_unilateral_timeout(
    pool: &PgPool,
    chain_swap_id: Uuid,
    expected_version: u64,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    let mut tx = pool.begin().await?;
    let outcome = supersede_chain_swap_cooperative_signing_at_unilateral_timeout_in_transaction(
        &mut tx,
        chain_swap_id,
        expected_version,
    )
    .await?;
    tx.commit().await?;
    Ok(outcome)
}

pub async fn supersede_chain_swap_cooperative_signing_at_unilateral_timeout_in_transaction(
    conn: &mut PgConnection,
    chain_swap_id: Uuid,
    expected_version: u64,
) -> Result<CooperativeSigningTransitionOutcome, ChainSwapCooperativeSigningStoreError> {
    acquire_chain_claim_boundary(conn, chain_swap_id, None).await?;
    let current = load_operation_for_update(conn, chain_swap_id)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::NotFound { chain_swap_id })?;
    if state_exact_retry(
        &current,
        expected_version,
        CooperativeSigningState::Superseded,
    ) {
        return Ok(exact_retry(current));
    }
    require_version(&current, expected_version)?;
    if !matches!(
        current.state,
        CooperativeSigningState::Prepared
            | CooperativeSigningState::Requested
            | CooperativeSigningState::Ambiguous
    ) {
        return Err(ChainSwapCooperativeSigningStoreError::InvalidTransition {
            chain_swap_id,
            state: current.state,
        });
    }
    let sql = format!(
        "UPDATE chain_swap_cooperative_signing_operations \
            SET state = 'superseded', superseded_reason = $3, \
                superseded_at = clock_timestamp(), version = version + 1 \
          WHERE chain_swap_id = $1 AND state = $4 AND version = $2 \
          RETURNING {OPERATION_COLUMNS}"
    );
    let updated = sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .bind(checked_version(expected_version)?)
        .bind(SUPERSEDED_REASON)
        .bind(current.state.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::CasMiss { chain_swap_id })?;
    let operation = decode_row(updated)?;
    Ok(applied(operation))
}

async fn transition_to_integrity_hold(
    tx: &mut SqlxTransaction<'_, Postgres>,
    chain_swap_id: Uuid,
    expected_version: u64,
    integrity_reason_sha256: &str,
) -> Result<ChainSwapCooperativeSigningOperation, ChainSwapCooperativeSigningStoreError> {
    let sql = format!(
        "UPDATE chain_swap_cooperative_signing_operations \
            SET state = 'integrity_hold', integrity_reason_sha256 = $3, \
                integrity_hold_at = clock_timestamp(), version = version + 1 \
          WHERE chain_swap_id = $1 \
            AND state IN ('prepared', 'requested', 'ambiguous', 'response_received') \
            AND version = $2 \
          RETURNING {OPERATION_COLUMNS}"
    );
    let row = sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
        .bind(chain_swap_id)
        .bind(checked_version(expected_version)?)
        .bind(integrity_reason_sha256)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::CasMiss { chain_swap_id })?;
    decode_row(row)
}

async fn acquire_chain_claim_boundary(
    conn: &mut PgConnection,
    chain_swap_id: Uuid,
    expected_boltz_swap_id: Option<&str>,
) -> Result<(), ChainSwapCooperativeSigningStoreError> {
    let lock_key = format!("chain-claim:{chain_swap_id}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(lock_key)
        .execute(&mut *conn)
        .await?;
    let parent_boltz_swap_id: Option<String> =
        sqlx::query_scalar("SELECT boltz_swap_id FROM chain_swap_records WHERE id = $1 FOR UPDATE")
            .bind(chain_swap_id)
            .fetch_optional(&mut *conn)
            .await?;
    let parent_boltz_swap_id = parent_boltz_swap_id
        .ok_or(ChainSwapCooperativeSigningStoreError::NotFound { chain_swap_id })?;
    if expected_boltz_swap_id.is_some_and(|expected| expected != parent_boltz_swap_id) {
        return Err(ChainSwapCooperativeSigningStoreError::IdentityConflict { chain_swap_id });
    }
    Ok(())
}

async fn load_required_for_update(
    tx: &mut SqlxTransaction<'_, Postgres>,
    chain_swap_id: Uuid,
) -> Result<ChainSwapCooperativeSigningOperation, ChainSwapCooperativeSigningStoreError> {
    load_operation_for_update(tx, chain_swap_id)
        .await?
        .ok_or(ChainSwapCooperativeSigningStoreError::NotFound { chain_swap_id })
}

async fn load_operation_for_update(
    conn: &mut PgConnection,
    chain_swap_id: Uuid,
) -> Result<Option<ChainSwapCooperativeSigningOperation>, ChainSwapCooperativeSigningStoreError> {
    let sql = format!(
        "SELECT {OPERATION_COLUMNS} \
           FROM chain_swap_cooperative_signing_operations \
          WHERE chain_swap_id = $1 FOR UPDATE"
    );
    decode_optional(
        sqlx::query_as::<_, CooperativeSigningOperationDbRow>(&sql)
            .bind(chain_swap_id)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

fn decode_optional(
    row: Option<CooperativeSigningOperationDbRow>,
) -> Result<Option<ChainSwapCooperativeSigningOperation>, ChainSwapCooperativeSigningStoreError> {
    row.map(decode_row).transpose()
}

fn decode_row(
    row: CooperativeSigningOperationDbRow,
) -> Result<ChainSwapCooperativeSigningOperation, ChainSwapCooperativeSigningStoreError> {
    row.try_into().map_err(Into::into)
}

fn require_version(
    operation: &ChainSwapCooperativeSigningOperation,
    expected_version: u64,
) -> Result<(), ChainSwapCooperativeSigningStoreError> {
    if operation.version == expected_version {
        Ok(())
    } else {
        Err(ChainSwapCooperativeSigningStoreError::CasMiss {
            chain_swap_id: operation.identity.chain_swap_id,
        })
    }
}

fn require_state(
    operation: &ChainSwapCooperativeSigningOperation,
    expected: CooperativeSigningState,
) -> Result<(), ChainSwapCooperativeSigningStoreError> {
    if operation.state == expected {
        Ok(())
    } else {
        Err(ChainSwapCooperativeSigningStoreError::InvalidTransition {
            chain_swap_id: operation.identity.chain_swap_id,
            state: operation.state,
        })
    }
}

fn state_exact_retry(
    operation: &ChainSwapCooperativeSigningOperation,
    expected_version: u64,
    state: CooperativeSigningState,
) -> bool {
    operation.state == state && version_is_exact_retry(operation.version, expected_version)
}

fn version_is_exact_retry(actual: u64, expected: u64) -> bool {
    expected.checked_add(1) == Some(actual)
}

fn checked_version(version: u64) -> Result<i64, CooperativeSigningDomainError> {
    checked_u64_to_i64(version, "version")
}

fn applied(operation: ChainSwapCooperativeSigningOperation) -> CooperativeSigningTransitionOutcome {
    CooperativeSigningTransitionOutcome {
        operation,
        disposition: CooperativeSigningCasDisposition::Applied,
    }
}

fn exact_retry(
    operation: ChainSwapCooperativeSigningOperation,
) -> CooperativeSigningTransitionOutcome {
    CooperativeSigningTransitionOutcome {
        operation,
        disposition: CooperativeSigningCasDisposition::ExactRetry,
    }
}

fn provider_response_conflict_sha256(
    existing: &CooperativeSigningProviderResponse,
    incoming: &CooperativeSigningProviderResponse,
) -> String {
    sha256_hex(
        format!(
            "bullnym:cooperative-signing-response-conflict:v1:{}:{}",
            existing.response_sha256, incoming.response_sha256
        )
        .as_bytes(),
    )
}

fn provider_response_sha256(
    public_nonce_hex: &str,
    partial_signature_hex: &str,
) -> Result<String, CooperativeSigningDomainError> {
    let public_nonce =
        hex::decode(public_nonce_hex).map_err(|_| CooperativeSigningDomainError::InvalidField {
            field: "provider_public_nonce_hex",
        })?;
    let partial_signature = hex::decode(partial_signature_hex).map_err(|_| {
        CooperativeSigningDomainError::InvalidField {
            field: "provider_partial_signature_hex",
        }
    })?;
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_RESPONSE_DIGEST_DOMAIN);
    hasher.update(public_nonce);
    hasher.update(partial_signature);
    Ok(hex::encode(hasher.finalize()))
}

fn validate_transaction_against_identity(
    transaction_hex: &str,
    expected_txid: &str,
    source: &CooperativeSigningSource,
    destination: &CooperativeSigningDestination,
    require_final_signature: bool,
) -> Result<(), CooperativeSigningDomainError> {
    let raw = hex::decode(transaction_hex).map_err(|_| {
        if require_final_signature {
            CooperativeSigningDomainError::InvalidFinalTransaction
        } else {
            CooperativeSigningDomainError::InvalidTransactionTemplate
        }
    })?;
    let transaction: Transaction = deserialize(&raw).map_err(|_| {
        if require_final_signature {
            CooperativeSigningDomainError::InvalidFinalTransaction
        } else {
            CooperativeSigningDomainError::InvalidTransactionTemplate
        }
    })?;
    let invalid = transaction.input.len() != 1
        || transaction.output.len() != 1
        || transaction.lock_time != bitcoin::absolute::LockTime::ZERO
        || transaction.input[0].previous_output.txid.to_string() != source.txid
        || transaction.input[0].previous_output.vout != source.vout
        || transaction.input[0].sequence != bitcoin::Sequence::MAX
        || transaction.output[0].value.to_sat() != destination.amount_sat
        || hex::encode(transaction.output[0].script_pubkey.as_bytes())
            != destination.script_pubkey_hex
        || transaction.compute_txid().to_string() != expected_txid;
    let witness_invalid = if require_final_signature {
        let witness = &transaction.input[0].witness;
        witness.len() != 1
            || !witness
                .iter()
                .next()
                .is_some_and(|signature| signature.len() == 64 && signature.iter().any(|b| *b != 0))
    } else {
        let witness = &transaction.input[0].witness;
        witness.len() != 1
            || !witness
                .iter()
                .next()
                .is_some_and(|stub| stub.len() == 64 && stub.iter().all(|byte| *byte == 0))
    };
    if invalid || witness_invalid {
        Err(if require_final_signature {
            CooperativeSigningDomainError::InvalidFinalTransaction
        } else {
            CooperativeSigningDomainError::InvalidTransactionTemplate
        })
    } else {
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), CooperativeSigningDomainError> {
    validate_exact_hex_length(value, SHA256_HEX_LENGTH, field)
}

fn validate_exact_hex_length(
    value: &str,
    length: usize,
    field: &'static str,
) -> Result<(), CooperativeSigningDomainError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Err(CooperativeSigningDomainError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn validate_hex(
    value: &str,
    minimum_length: usize,
    maximum_length: usize,
    field: &'static str,
) -> Result<(), CooperativeSigningDomainError> {
    if value.len() < minimum_length
        || value.len() > maximum_length
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Err(CooperativeSigningDomainError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn expect_text(
    value: &str,
    expected: &str,
    field: &'static str,
) -> Result<(), CooperativeSigningDomainError> {
    if value == expected {
        Ok(())
    } else {
        Err(CooperativeSigningDomainError::InvalidField { field })
    }
}

fn checked_nonnegative_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, CooperativeSigningDomainError> {
    u64::try_from(value).map_err(|_| CooperativeSigningDomainError::InvalidField { field })
}

fn checked_positive_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, CooperativeSigningDomainError> {
    if value <= 0 {
        Err(CooperativeSigningDomainError::InvalidField { field })
    } else {
        Ok(value as u64)
    }
}

fn checked_u64_to_i64(
    value: u64,
    field: &'static str,
) -> Result<i64, CooperativeSigningDomainError> {
    i64::try_from(value).map_err(|_| CooperativeSigningDomainError::InvalidField { field })
}

fn timestamp_in_range(value: Option<i64>, minimum: i64, maximum: i64) -> bool {
    value.is_none_or(|value| value >= minimum && value <= maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_nonce_debug_is_fully_redacted() {
        let nonce = EncryptedCooperativeSecretNonce::new(
            "manifest-key:swap-1",
            vec![0x11; SECRET_NONCE_ENCRYPTION_NONCE_LENGTH],
            vec![0x22; SECRET_NONCE_CIPHERTEXT_LENGTH],
            "33".repeat(32),
        )
        .unwrap();
        let diagnostic = format!("{nonce:?}");
        assert!(diagnostic.contains("<redacted>"));
        assert!(!diagnostic.contains("manifest-key"));
        assert!(!diagnostic.contains(&"11".repeat(24)));
        assert!(!diagnostic.contains(&"22".repeat(32)));
        assert!(!diagnostic.contains(&"33".repeat(32)));
    }

    #[test]
    fn cooperative_source_debug_redacts_exact_prevout_and_value() {
        let source = CooperativeSigningSource::new(
            "11".repeat(32),
            7,
            123_456,
            format!("5120{}", "22".repeat(32)),
        )
        .unwrap();
        let diagnostic = format!("{source:?}");
        assert!(diagnostic.contains("<redacted>"));
        assert!(!diagnostic.contains(&"11".repeat(32)));
        assert!(!diagnostic.contains("123456"));
        assert!(!diagnostic.contains(&"22".repeat(32)));
    }

    #[test]
    fn provider_response_conflict_digest_is_ordered_and_redacted() {
        let first =
            CooperativeSigningProviderResponse::new("11".repeat(66), "22".repeat(32)).unwrap();
        let duplicate = first.clone();
        let conflicting =
            CooperativeSigningProviderResponse::new("44".repeat(66), "55".repeat(32)).unwrap();
        assert_eq!(first, duplicate);
        assert_ne!(first, conflicting);
        assert_eq!(
            provider_response_conflict_sha256(&first, &conflicting).len(),
            SHA256_HEX_LENGTH
        );
        assert_ne!(
            provider_response_conflict_sha256(&first, &conflicting),
            provider_response_conflict_sha256(&conflicting, &first)
        );
        let diagnostic = format!("{conflicting:?}");
        assert!(!diagnostic.contains(&"44".repeat(66)));
        assert!(!diagnostic.contains(&"55".repeat(32)));
    }

    #[test]
    fn envelope_rejects_wrong_nonce_or_ciphertext_size() {
        assert!(EncryptedCooperativeSecretNonce::new(
            "key-1",
            vec![0; SECRET_NONCE_ENCRYPTION_NONCE_LENGTH - 1],
            vec![0; SECRET_NONCE_CIPHERTEXT_LENGTH],
            "11".repeat(32),
        )
        .is_err());
        assert!(EncryptedCooperativeSecretNonce::new(
            "key-1",
            vec![0; SECRET_NONCE_ENCRYPTION_NONCE_LENGTH],
            vec![0; SECRET_NONCE_CIPHERTEXT_LENGTH + 1],
            "11".repeat(32),
        )
        .is_err());
    }
}
