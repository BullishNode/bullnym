use std::fmt;
use std::str::FromStr;

use uuid::Uuid;

const SHA256_HEX_LENGTH: usize = 64;
const MAX_POLICY_VERSION_BYTES: usize = 128;

/// Durable lifecycle for one wrong-amount Boltz quote.
///
/// `Ambiguous -> AcceptRequested` is the only retry edge. It records a new
/// durable accept attempt before the caller may repeat the remote mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenegotiationState {
    Quoted,
    AcceptRequested,
    Ambiguous,
    Accepted,
    Declined,
}

impl RenegotiationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::AcceptRequested => "accept_requested",
            Self::Ambiguous => "ambiguous",
            Self::Accepted => "accepted",
            Self::Declined => "declined",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Accepted | Self::Declined)
    }
}

impl fmt::Display for RenegotiationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RenegotiationState {
    type Err = RenegotiationDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "quoted" => Ok(Self::Quoted),
            "accept_requested" => Ok(Self::AcceptRequested),
            "ambiguous" => Ok(Self::Ambiguous),
            "accepted" => Ok(Self::Accepted),
            "declined" => Ok(Self::Declined),
            _ => Err(RenegotiationDomainError::InvalidStoredState),
        }
    }
}

/// Sanitized persisted classification with no response body, URL, or arbitrary
/// error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenegotiationErrorClass {
    Timeout,
    Transport,
    ProviderServerError,
    MalformedResponse,
    BackendDisagreement,
    UnknownProviderOutcome,
}

impl RenegotiationErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::ProviderServerError => "provider_server_error",
            Self::MalformedResponse => "malformed_response",
            Self::BackendDisagreement => "backend_disagreement",
            Self::UnknownProviderOutcome => "unknown_provider_outcome",
        }
    }
}

impl FromStr for RenegotiationErrorClass {
    type Err = RenegotiationDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "timeout" => Ok(Self::Timeout),
            "transport" => Ok(Self::Transport),
            "provider_server_error" => Ok(Self::ProviderServerError),
            "malformed_response" => Ok(Self::MalformedResponse),
            "backend_disagreement" => Ok(Self::BackendDisagreement),
            "unknown_provider_outcome" => Ok(Self::UnknownProviderOutcome),
            _ => Err(RenegotiationDomainError::InvalidStoredErrorClass),
        }
    }
}

/// Immutable identity of the exact provider quote and policy evaluation.
///
/// Digests are canonical lowercase SHA-256 hex. The policy digest commits to
/// all inputs and bounds used by the caller, so this journal need not duplicate
/// mutable policy fields or infer their meaning later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenegotiationIdentity {
    pub chain_swap_id: Uuid,
    pub quoted_actual_amount_sat: u64,
    quote_response_digest: String,
    pub quote_observed_at_unix: i64,
    policy_version: String,
    policy_evidence_digest: String,
    pub policy_validated_at_unix: i64,
}

impl RenegotiationIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_swap_id: Uuid,
        quoted_actual_amount_sat: u64,
        quote_response_digest: impl Into<String>,
        quote_observed_at_unix: i64,
        policy_version: impl Into<String>,
        policy_evidence_digest: impl Into<String>,
        policy_validated_at_unix: i64,
    ) -> Result<Self, RenegotiationDomainError> {
        let identity = Self {
            chain_swap_id,
            quoted_actual_amount_sat,
            quote_response_digest: quote_response_digest.into(),
            quote_observed_at_unix,
            policy_version: policy_version.into(),
            policy_evidence_digest: policy_evidence_digest.into(),
            policy_validated_at_unix,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn quote_response_digest(&self) -> &str {
        &self.quote_response_digest
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    pub fn policy_evidence_digest(&self) -> &str {
        &self.policy_evidence_digest
    }

    pub(crate) fn validate(&self) -> Result<(), RenegotiationDomainError> {
        if self.chain_swap_id.is_nil() {
            return Err(RenegotiationDomainError::InvalidIdentity {
                field: "chain_swap_id",
            });
        }
        if self.quoted_actual_amount_sat == 0 || self.quoted_actual_amount_sat > i64::MAX as u64 {
            return Err(RenegotiationDomainError::InvalidIdentity {
                field: "quoted_actual_amount_sat",
            });
        }
        validate_digest(&self.quote_response_digest, "quote_response_digest")?;
        if self.quote_observed_at_unix <= 0 {
            return Err(RenegotiationDomainError::InvalidIdentity {
                field: "quote_observed_at_unix",
            });
        }
        if self.policy_version.is_empty()
            || self.policy_version.len() > MAX_POLICY_VERSION_BYTES
            || self.policy_version.chars().any(char::is_whitespace)
        {
            return Err(RenegotiationDomainError::InvalidIdentity {
                field: "policy_version",
            });
        }
        validate_digest(&self.policy_evidence_digest, "policy_evidence_digest")?;
        if self.policy_validated_at_unix < self.quote_observed_at_unix {
            return Err(RenegotiationDomainError::InvalidIdentity {
                field: "policy_validated_at_unix",
            });
        }
        Ok(())
    }
}

/// Persisted per-swap operation. Quote and policy evidence remain immutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSwapRenegotiationOperation {
    pub identity: RenegotiationIdentity,
    pub state: RenegotiationState,
    pub accept_attempt_count: u32,
    pub last_error_class: Option<RenegotiationErrorClass>,
    pub version: u64,
    pub accept_requested_at_unix: Option<i64>,
    pub ambiguous_at_unix: Option<i64>,
    terminal_response_digest: Option<String>,
    pub terminal_observed_at_unix: Option<i64>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl ChainSwapRenegotiationOperation {
    pub fn terminal_response_digest(&self) -> Option<&str> {
        self.terminal_response_digest.as_deref()
    }

    pub fn plan_transition(
        &self,
        transition: &RenegotiationTransition,
    ) -> Result<TransitionDisposition, RenegotiationDomainError> {
        transition.validate()?;
        if self.identity != transition.identity {
            return Err(RenegotiationDomainError::IdentityMismatch);
        }

        if transition.expected_version.checked_add(1) == Some(self.version)
            && transition.effect_matches(self)
        {
            return Ok(TransitionDisposition::ExactRetry);
        }
        if transition.expected_version != self.version {
            return Err(RenegotiationDomainError::StaleVersion {
                expected: transition.expected_version,
                actual: self.version,
            });
        }
        if self.version == i64::MAX as u64 {
            return Err(RenegotiationDomainError::VersionExhausted);
        }
        if matches!(transition.kind, RenegotiationTransitionKind::RequestAccept)
            && self.accept_attempt_count == i32::MAX as u32
        {
            return Err(RenegotiationDomainError::AttemptCountExhausted);
        }

        let legal = match (&transition.kind, self.state) {
            (
                RenegotiationTransitionKind::RequestAccept,
                RenegotiationState::Quoted | RenegotiationState::Ambiguous,
            ) => true,
            (
                RenegotiationTransitionKind::MarkAmbiguous { .. },
                RenegotiationState::AcceptRequested,
            ) => true,
            (
                RenegotiationTransitionKind::MarkAccepted { .. },
                RenegotiationState::AcceptRequested | RenegotiationState::Ambiguous,
            ) => true,
            (
                RenegotiationTransitionKind::MarkDeclined { .. },
                RenegotiationState::Quoted | RenegotiationState::AcceptRequested,
            ) => true,
            _ => false,
        };
        if !legal {
            return Err(RenegotiationDomainError::IllegalTransition {
                from: self.state,
                to: transition.kind.target_state(),
            });
        }

        Ok(TransitionDisposition::Apply)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_persisted_parts(
        identity: RenegotiationIdentity,
        state: RenegotiationState,
        accept_attempt_count: u32,
        last_error_class: Option<RenegotiationErrorClass>,
        version: u64,
        accept_requested_at_unix: Option<i64>,
        ambiguous_at_unix: Option<i64>,
        terminal_response_digest: Option<String>,
        terminal_observed_at_unix: Option<i64>,
        created_at_unix: i64,
        updated_at_unix: i64,
    ) -> Result<Self, RenegotiationDomainError> {
        identity.validate()?;
        if version == 0 || version > i64::MAX as u64 {
            return Err(RenegotiationDomainError::InvalidStoredVersion);
        }
        if accept_attempt_count > i32::MAX as u32 {
            return Err(RenegotiationDomainError::InvalidStoredAttemptCount);
        }
        if created_at_unix <= 0 || updated_at_unix < created_at_unix {
            return Err(RenegotiationDomainError::InvalidStoredTimestamp);
        }
        for timestamp in [
            accept_requested_at_unix,
            ambiguous_at_unix,
            terminal_observed_at_unix,
        ]
        .into_iter()
        .flatten()
        {
            if timestamp < created_at_unix || timestamp > updated_at_unix {
                return Err(RenegotiationDomainError::InvalidStoredTimestamp);
            }
        }
        if let Some(digest) = terminal_response_digest.as_deref() {
            validate_digest(digest, "terminal_response_digest")?;
        }

        let request_follows_policy = accept_requested_at_unix
            .is_some_and(|requested_at| requested_at >= identity.policy_validated_at_unix);
        let terminal_follows_policy = terminal_observed_at_unix
            .is_some_and(|terminal_at| terminal_at >= identity.policy_validated_at_unix);
        let ambiguity_history_is_paired = ambiguous_at_unix.is_some() == last_error_class.is_some();

        let shape_is_valid = match state {
            RenegotiationState::Quoted => {
                version == 1
                    && accept_attempt_count == 0
                    && last_error_class.is_none()
                    && accept_requested_at_unix.is_none()
                    && ambiguous_at_unix.is_none()
                    && terminal_response_digest.is_none()
                    && terminal_observed_at_unix.is_none()
            }
            RenegotiationState::AcceptRequested => {
                accept_attempt_count > 0
                    && request_follows_policy
                    && ambiguity_history_is_paired
                    && ambiguous_at_unix
                        .zip(accept_requested_at_unix)
                        .is_none_or(|(ambiguous_at, requested_at)| ambiguous_at <= requested_at)
                    && terminal_response_digest.is_none()
                    && terminal_observed_at_unix.is_none()
            }
            RenegotiationState::Ambiguous => {
                accept_attempt_count > 0
                    && last_error_class.is_some()
                    && request_follows_policy
                    && ambiguous_at_unix
                        .zip(accept_requested_at_unix)
                        .is_some_and(|(ambiguous_at, requested_at)| ambiguous_at >= requested_at)
                    && terminal_response_digest.is_none()
                    && terminal_observed_at_unix.is_none()
            }
            RenegotiationState::Accepted => {
                accept_attempt_count > 0
                    && request_follows_policy
                    && ambiguity_history_is_paired
                    && terminal_response_digest.is_some()
                    && terminal_observed_at_unix
                        .zip(accept_requested_at_unix)
                        .is_some_and(|(terminal_at, requested_at)| terminal_at >= requested_at)
                    && ambiguous_at_unix
                        .zip(terminal_observed_at_unix)
                        .is_none_or(|(ambiguous_at, terminal_at)| terminal_at >= ambiguous_at)
            }
            RenegotiationState::Declined => {
                ((accept_attempt_count == 0
                    && accept_requested_at_unix.is_none()
                    && ambiguous_at_unix.is_none()
                    && last_error_class.is_none()
                    && terminal_follows_policy)
                    || (accept_attempt_count > 0
                        && request_follows_policy
                        && ambiguity_history_is_paired
                        && terminal_observed_at_unix
                            .zip(accept_requested_at_unix)
                            .is_some_and(|(terminal_at, requested_at)| {
                                terminal_at >= requested_at
                            })
                        && ambiguous_at_unix.zip(accept_requested_at_unix).is_none_or(
                            |(ambiguous_at, requested_at)| ambiguous_at <= requested_at,
                        )))
                    && terminal_response_digest.is_some()
                    && terminal_observed_at_unix.is_some()
            }
        };
        if !shape_is_valid {
            return Err(RenegotiationDomainError::InvalidStoredShape);
        }

        Ok(Self {
            identity,
            state,
            accept_attempt_count,
            last_error_class,
            version,
            accept_requested_at_unix,
            ambiguous_at_unix,
            terminal_response_digest,
            terminal_observed_at_unix,
            created_at_unix,
            updated_at_unix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenegotiationTransition {
    pub identity: RenegotiationIdentity,
    pub expected_version: u64,
    pub kind: RenegotiationTransitionKind,
}

impl RenegotiationTransition {
    pub fn new(
        identity: RenegotiationIdentity,
        expected_version: u64,
        kind: RenegotiationTransitionKind,
    ) -> Result<Self, RenegotiationDomainError> {
        let transition = Self {
            identity,
            expected_version,
            kind,
        };
        transition.validate()?;
        Ok(transition)
    }

    fn validate(&self) -> Result<(), RenegotiationDomainError> {
        self.identity.validate()?;
        if self.expected_version == 0 || self.expected_version > i64::MAX as u64 {
            return Err(RenegotiationDomainError::InvalidExpectedVersion);
        }
        if let RenegotiationTransitionKind::MarkAccepted {
            terminal_response_digest,
        }
        | RenegotiationTransitionKind::MarkDeclined {
            terminal_response_digest,
        } = &self.kind
        {
            validate_digest(terminal_response_digest, "terminal_response_digest")?;
        }
        Ok(())
    }

    fn effect_matches(&self, operation: &ChainSwapRenegotiationOperation) -> bool {
        match &self.kind {
            RenegotiationTransitionKind::RequestAccept => {
                operation.state == RenegotiationState::AcceptRequested
            }
            RenegotiationTransitionKind::MarkAmbiguous { error_class } => {
                operation.state == RenegotiationState::Ambiguous
                    && operation.last_error_class == Some(*error_class)
            }
            RenegotiationTransitionKind::MarkAccepted {
                terminal_response_digest,
            } => {
                operation.state == RenegotiationState::Accepted
                    && operation.terminal_response_digest()
                        == Some(terminal_response_digest.as_str())
            }
            RenegotiationTransitionKind::MarkDeclined {
                terminal_response_digest,
            } => {
                operation.state == RenegotiationState::Declined
                    && operation.terminal_response_digest()
                        == Some(terminal_response_digest.as_str())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenegotiationTransitionKind {
    RequestAccept,
    MarkAmbiguous {
        error_class: RenegotiationErrorClass,
    },
    MarkAccepted {
        terminal_response_digest: String,
    },
    MarkDeclined {
        terminal_response_digest: String,
    },
}

impl RenegotiationTransitionKind {
    pub fn target_state(&self) -> RenegotiationState {
        match self {
            Self::RequestAccept => RenegotiationState::AcceptRequested,
            Self::MarkAmbiguous { .. } => RenegotiationState::Ambiguous,
            Self::MarkAccepted { .. } => RenegotiationState::Accepted,
            Self::MarkDeclined { .. } => RenegotiationState::Declined,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionDisposition {
    Apply,
    ExactRetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenegotiationDomainError {
    InvalidIdentity {
        field: &'static str,
    },
    InvalidExpectedVersion,
    InvalidStoredState,
    InvalidStoredErrorClass,
    InvalidStoredVersion,
    InvalidStoredAttemptCount,
    InvalidStoredTimestamp,
    InvalidStoredShape,
    IdentityMismatch,
    StaleVersion {
        expected: u64,
        actual: u64,
    },
    IllegalTransition {
        from: RenegotiationState,
        to: RenegotiationState,
    },
    VersionExhausted,
    AttemptCountExhausted,
}

impl fmt::Display for RenegotiationDomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity { field } => {
                write!(f, "renegotiation operation has invalid {field}")
            }
            Self::InvalidExpectedVersion => {
                f.write_str("renegotiation transition has invalid expected version")
            }
            Self::InvalidStoredState => {
                f.write_str("renegotiation operation has an unknown stored state")
            }
            Self::InvalidStoredErrorClass => {
                f.write_str("renegotiation operation has an unknown stored error class")
            }
            Self::InvalidStoredVersion => {
                f.write_str("renegotiation operation has an invalid stored version")
            }
            Self::InvalidStoredAttemptCount => {
                f.write_str("renegotiation operation has an invalid stored attempt count")
            }
            Self::InvalidStoredTimestamp => {
                f.write_str("renegotiation operation has an invalid stored timestamp")
            }
            Self::InvalidStoredShape => {
                f.write_str("renegotiation operation has an invalid persisted state shape")
            }
            Self::IdentityMismatch => {
                f.write_str("renegotiation transition does not match the persisted quote policy")
            }
            Self::StaleVersion { expected, actual } => write!(
                f,
                "renegotiation transition expected version {expected}, current version is {actual}"
            ),
            Self::IllegalTransition { from, to } => {
                write!(f, "illegal renegotiation transition {from} -> {to}")
            }
            Self::VersionExhausted => {
                f.write_str("renegotiation operation version exhausted PostgreSQL BIGINT")
            }
            Self::AttemptCountExhausted => {
                f.write_str("renegotiation accept attempts exhausted PostgreSQL INTEGER")
            }
        }
    }
}

impl std::error::Error for RenegotiationDomainError {}

fn validate_digest(value: &str, field: &'static str) -> Result<(), RenegotiationDomainError> {
    if value.len() != SHA256_HEX_LENGTH
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(RenegotiationDomainError::InvalidIdentity { field });
    }
    Ok(())
}
