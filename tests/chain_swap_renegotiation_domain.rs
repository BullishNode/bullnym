use std::str::FromStr;

use pay_service::chain_swap_renegotiation::{
    RenegotiationDomainError, RenegotiationErrorClass, RenegotiationIdentity, RenegotiationState,
    RenegotiationTransition, RenegotiationTransitionKind,
};
use uuid::Uuid;

fn exact_identity() -> RenegotiationIdentity {
    RenegotiationIdentity::new(
        Uuid::from_u128(0x38000000000000000000000000000001),
        24_750,
        "aa".repeat(32),
        1_721_000_000,
        "issue38-v1",
        "bb".repeat(32),
        1_721_000_001,
    )
    .unwrap()
}

#[test]
fn quote_policy_identity_rejects_noncanonical_or_time_travelling_evidence() {
    let invalid_digest = RenegotiationIdentity::new(
        Uuid::new_v4(),
        24_750,
        "AA".repeat(32),
        1_721_000_000,
        "issue38-v1",
        "bb".repeat(32),
        1_721_000_001,
    )
    .unwrap_err();
    assert_eq!(
        invalid_digest,
        RenegotiationDomainError::InvalidIdentity {
            field: "quote_response_digest"
        }
    );

    let invalid_policy_time = RenegotiationIdentity::new(
        Uuid::new_v4(),
        24_750,
        "aa".repeat(32),
        1_721_000_001,
        "issue38-v1",
        "bb".repeat(32),
        1_721_000_000,
    )
    .unwrap_err();
    assert_eq!(
        invalid_policy_time,
        RenegotiationDomainError::InvalidIdentity {
            field: "policy_validated_at_unix"
        }
    );
}

#[test]
fn typed_transitions_refuse_unversioned_or_uncommitted_terminal_evidence() {
    let unversioned = RenegotiationTransition::new(
        exact_identity(),
        0,
        RenegotiationTransitionKind::RequestAccept,
    )
    .unwrap_err();
    assert_eq!(
        unversioned,
        RenegotiationDomainError::InvalidExpectedVersion
    );

    let invalid_terminal = RenegotiationTransition::new(
        exact_identity(),
        1,
        RenegotiationTransitionKind::MarkAccepted {
            terminal_response_digest: "provider-body-is-not-evidence".to_owned(),
        },
    )
    .unwrap_err();
    assert_eq!(
        invalid_terminal,
        RenegotiationDomainError::InvalidIdentity {
            field: "terminal_response_digest"
        }
    );
}

#[test]
fn persisted_state_and_sanitized_error_vocabulary_is_exact() {
    for (stored, state) in [
        ("quoted", RenegotiationState::Quoted),
        ("accept_requested", RenegotiationState::AcceptRequested),
        ("ambiguous", RenegotiationState::Ambiguous),
        ("accepted", RenegotiationState::Accepted),
        ("declined", RenegotiationState::Declined),
    ] {
        assert_eq!(RenegotiationState::from_str(stored).unwrap(), state);
        assert_eq!(state.as_str(), stored);
    }

    for (stored, error_class) in [
        ("timeout", RenegotiationErrorClass::Timeout),
        ("transport", RenegotiationErrorClass::Transport),
        (
            "provider_server_error",
            RenegotiationErrorClass::ProviderServerError,
        ),
        (
            "malformed_response",
            RenegotiationErrorClass::MalformedResponse,
        ),
        (
            "backend_disagreement",
            RenegotiationErrorClass::BackendDisagreement,
        ),
        (
            "unknown_provider_outcome",
            RenegotiationErrorClass::UnknownProviderOutcome,
        ),
    ] {
        assert_eq!(
            RenegotiationErrorClass::from_str(stored).unwrap(),
            error_class
        );
        assert_eq!(error_class.as_str(), stored);
    }

    assert_eq!(
        RenegotiationState::from_str("refund_due").unwrap_err(),
        RenegotiationDomainError::InvalidStoredState
    );
    assert_eq!(
        RenegotiationErrorClass::from_str("provider response body").unwrap_err(),
        RenegotiationDomainError::InvalidStoredErrorClass
    );
}
