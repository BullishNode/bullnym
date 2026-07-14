use std::str::FromStr;

use pay_service::chain_swap_renegotiation::{
    ChainSwapRenegotiationOperation, ChangedQuoteRedrive, RenegotiationBlockReason,
    RenegotiationDomainError, RenegotiationErrorClass, RenegotiationFallbackGate,
    RenegotiationIdentity, RenegotiationReconciliationDecision,
    RenegotiationReconciliationObservation, RenegotiationRestartAction, RenegotiationState,
    RenegotiationTransition, RenegotiationTransitionKind, TransitionDisposition,
    VerifiedRenegotiationAcceptance,
};
use pay_service::db::ChainSwapRenegotiationStoreError;
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

const CREATED_AT: i64 = 1_721_000_002;
const ACCEPT_REQUESTED_AT: i64 = 1_721_000_003;
const AMBIGUOUS_AT: i64 = 1_721_000_004;
const TERMINAL_AT: i64 = 1_721_000_005;

fn operation(
    identity: RenegotiationIdentity,
    state: RenegotiationState,
    accept_attempt_count: u32,
    last_error_class: Option<RenegotiationErrorClass>,
    version: u64,
    accept_requested_at_unix: Option<i64>,
    ambiguous_at_unix: Option<i64>,
    terminal_response_digest: Option<String>,
    terminal_observed_at_unix: Option<i64>,
    updated_at_unix: i64,
) -> ChainSwapRenegotiationOperation {
    ChainSwapRenegotiationOperation::from_persisted_parts(
        identity,
        state,
        accept_attempt_count,
        last_error_class,
        version,
        accept_requested_at_unix,
        ambiguous_at_unix,
        terminal_response_digest,
        terminal_observed_at_unix,
        CREATED_AT,
        updated_at_unix,
    )
    .unwrap()
}

fn quoted_operation() -> ChainSwapRenegotiationOperation {
    operation(
        exact_identity(),
        RenegotiationState::Quoted,
        0,
        None,
        1,
        None,
        None,
        None,
        None,
        CREATED_AT,
    )
}

fn accept_requested_operation() -> ChainSwapRenegotiationOperation {
    operation(
        exact_identity(),
        RenegotiationState::AcceptRequested,
        1,
        None,
        2,
        Some(ACCEPT_REQUESTED_AT),
        None,
        None,
        None,
        ACCEPT_REQUESTED_AT,
    )
}

fn ambiguous_operation() -> ChainSwapRenegotiationOperation {
    operation(
        exact_identity(),
        RenegotiationState::Ambiguous,
        1,
        Some(RenegotiationErrorClass::Timeout),
        3,
        Some(ACCEPT_REQUESTED_AT),
        Some(AMBIGUOUS_AT),
        None,
        None,
        AMBIGUOUS_AT,
    )
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
            "local_commit_uncertainty",
            RenegotiationErrorClass::LocalCommitUncertainty,
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

#[test]
fn database_error_debug_never_exposes_quote_evidence() {
    let secret = "secret quote evidence";
    let error = ChainSwapRenegotiationStoreError::Database(sqlx::Error::Protocol(secret.into()));
    let debug = format!("{error:?}");

    assert_eq!(debug, "Database(<redacted>)");
    assert!(!debug.contains(secret));
    assert_eq!(
        error.to_string(),
        "renegotiation operation database request failed"
    );
}

#[test]
fn renegotiation_durable_fallback_gate_only_opens_after_explicit_decline() {
    let accepted = operation(
        exact_identity(),
        RenegotiationState::Accepted,
        1,
        None,
        3,
        Some(ACCEPT_REQUESTED_AT),
        None,
        Some("cc".repeat(32)),
        Some(TERMINAL_AT),
        TERMINAL_AT,
    );
    let declined = operation(
        exact_identity(),
        RenegotiationState::Declined,
        0,
        None,
        2,
        None,
        None,
        Some("dd".repeat(32)),
        Some(TERMINAL_AT),
        TERMINAL_AT,
    );

    for (operation, reason) in [
        (quoted_operation(), RenegotiationBlockReason::QuotePending),
        (
            accept_requested_operation(),
            RenegotiationBlockReason::AcceptRequested,
        ),
        (ambiguous_operation(), RenegotiationBlockReason::Ambiguous),
        (accepted, RenegotiationBlockReason::AcceptedAwaitingLiquid),
    ] {
        assert_eq!(
            operation.fallback_gate(),
            RenegotiationFallbackGate::Blocked(reason)
        );
        assert!(operation.fallback_gate().blocks_bitcoin_fallback());
    }
    assert_eq!(
        declined.fallback_gate(),
        RenegotiationFallbackGate::ExplicitlyDeclined
    );
    assert!(!declined.fallback_gate().blocks_bitcoin_fallback());
}

#[test]
fn renegotiation_restart_never_blindly_retries_an_unresolved_accept() {
    assert_eq!(
        accept_requested_operation().restart_action(),
        RenegotiationRestartAction::ObserveUntilReconciled
    );
    assert_eq!(
        ambiguous_operation().restart_action(),
        RenegotiationRestartAction::ReobserveAndRevalidateQuote
    );
}

#[test]
fn renegotiation_old_or_repeated_ambiguity_never_becomes_decline_without_new_evidence() {
    let exhausted_looking = operation(
        exact_identity(),
        RenegotiationState::Ambiguous,
        i32::MAX as u32,
        Some(RenegotiationErrorClass::UnknownProviderOutcome),
        1_000_000,
        Some(ACCEPT_REQUESTED_AT),
        Some(AMBIGUOUS_AT),
        None,
        None,
        AMBIGUOUS_AT,
    );

    assert_eq!(
        exhausted_looking.fallback_gate(),
        RenegotiationFallbackGate::Blocked(RenegotiationBlockReason::Ambiguous)
    );
    assert_eq!(
        exhausted_looking
            .reconcile(RenegotiationReconciliationObservation::NoNewEvidence)
            .unwrap(),
        RenegotiationReconciliationDecision::Observe
    );
    assert_eq!(
        exhausted_looking
            .reconcile(
                RenegotiationReconciliationObservation::DefinitelyUnavailable {
                    terminal_response_digest: "ee".repeat(32),
                }
            )
            .unwrap(),
        RenegotiationReconciliationDecision::Observe
    );
}

#[test]
fn renegotiation_uncertain_local_commit_is_a_durable_blocking_ambiguity() {
    let requested = accept_requested_operation();
    let transition = RenegotiationTransition::new(
        requested.identity.clone(),
        requested.version,
        RenegotiationTransitionKind::MarkAmbiguous {
            error_class: RenegotiationErrorClass::LocalCommitUncertainty,
        },
    )
    .unwrap();
    assert_eq!(
        requested.plan_transition(&transition).unwrap(),
        TransitionDisposition::Apply
    );

    let uncertain = operation(
        exact_identity(),
        RenegotiationState::Ambiguous,
        1,
        Some(RenegotiationErrorClass::LocalCommitUncertainty),
        3,
        Some(ACCEPT_REQUESTED_AT),
        Some(AMBIGUOUS_AT),
        None,
        None,
        AMBIGUOUS_AT,
    );
    assert_eq!(
        uncertain.fallback_gate(),
        RenegotiationFallbackGate::Blocked(RenegotiationBlockReason::Ambiguous)
    );
    assert_eq!(
        uncertain.restart_action(),
        RenegotiationRestartAction::ReobserveAndRevalidateQuote
    );
}

#[test]
fn renegotiation_verified_acceptance_must_match_the_current_exact_identity() {
    let current = accept_requested_operation();
    let different_identity = RenegotiationIdentity::new(
        current.identity.chain_swap_id,
        current.identity.quoted_actual_amount_sat,
        "cc".repeat(32),
        current.identity.quote_observed_at_unix + 1,
        "issue38-v2",
        "dd".repeat(32),
        current.identity.policy_validated_at_unix + 1,
    )
    .unwrap();
    let evidence = VerifiedRenegotiationAcceptance::new(
        different_identity.clone(),
        different_identity.quoted_actual_amount_sat,
        different_identity.quote_response_digest(),
        "ee".repeat(32),
    )
    .unwrap();

    assert_eq!(
        current
            .reconcile(RenegotiationReconciliationObservation::AcceptanceConfirmed { evidence })
            .unwrap_err(),
        RenegotiationDomainError::AcceptanceEvidenceMismatch
    );
    assert_eq!(
        VerifiedRenegotiationAcceptance::new(
            exact_identity(),
            exact_identity().quoted_actual_amount_sat + 1,
            exact_identity().quote_response_digest(),
            "ff".repeat(32),
        )
        .unwrap_err(),
        RenegotiationDomainError::AcceptanceEvidenceMismatch
    );
}

#[test]
fn renegotiation_changed_quote_redrive_has_exact_cas_and_retry_semantics() {
    let current = ambiguous_operation();
    let replacement = RenegotiationIdentity::new(
        current.identity.chain_swap_id,
        current.identity.quoted_actual_amount_sat + 500,
        "cc".repeat(32),
        1_721_000_010,
        "issue38-v2",
        "dd".repeat(32),
        1_721_000_011,
    )
    .unwrap();
    let redrive = ChangedQuoteRedrive::new(
        current.identity.clone(),
        replacement.clone(),
        current.version,
    )
    .unwrap();
    assert_eq!(
        redrive.plan(&current).unwrap(),
        TransitionDisposition::Apply
    );

    let accepted_request = operation(
        replacement,
        RenegotiationState::AcceptRequested,
        current.accept_attempt_count + 1,
        current.last_error_class,
        current.version + 1,
        Some(1_721_000_012),
        current.ambiguous_at_unix,
        None,
        None,
        1_721_000_012,
    );
    assert_eq!(
        redrive.plan(&accepted_request).unwrap(),
        TransitionDisposition::ExactRetry
    );

    let stale = ChangedQuoteRedrive::new(
        current.identity.clone(),
        redrive.replacement_identity.clone(),
        current.version - 1,
    )
    .unwrap();
    assert_eq!(
        stale.plan(&current).unwrap_err(),
        RenegotiationDomainError::StaleVersion {
            expected: current.version - 1,
            actual: current.version,
        }
    );
}
