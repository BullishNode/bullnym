use super::*;

use crate::chain_lockup_witness_audit::{
    ChainLockupConflictFieldV1, ChainLockupFindingClassificationV1, ChainLockupInclusionV1,
    ChainLockupManifestClassificationV1, ChainLockupManifestWitnessAuditV1, ChainLockupSpendV1,
    ChainLockupWitnessFindingV1,
};
use crate::chain_swap_primary_source::{
    project_primary_bitcoin_source_v1, PrimaryBitcoinSourceAuthorityV1,
};
use crate::chain_swap_renegotiation::{
    ChainSwapRenegotiationOperation, ChangedQuoteRedrive, RenegotiationBlockReason,
    RenegotiationErrorClass, RenegotiationFallbackGate, RenegotiationIdentity,
    RenegotiationReconciliationDecision, RenegotiationReconciliationObservation,
    RenegotiationRestartAction, RenegotiationState, RenegotiationTransition,
    RenegotiationTransitionKind, TransitionDisposition, VerifiedRenegotiationAcceptance,
};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;

const QUOTE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CHANGED_QUOTE_DIGEST: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const POLICY_DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const TERMINAL_DIGEST: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn quote(amount_sat: u64, response_sha256: &str) -> ChainSwapQuote {
    ChainSwapQuote {
        amount_sat,
        response_sha256: response_sha256.to_string(),
    }
}

fn quote_error(
    kind: ChainSwapQuoteProviderErrorKind,
    terminal_evidence_sha256: Option<&str>,
) -> ChainSwapQuoteProviderError {
    ChainSwapQuoteProviderError {
        kind,
        terminal_evidence_sha256: terminal_evidence_sha256.map(str::to_string),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderCall {
    GetQuote(String),
    AcceptQuote { swap_id: String, amount_sat: u64 },
}

struct FakeProvider {
    get_results: Mutex<VecDeque<Result<ChainSwapQuote, ChainSwapQuoteProviderError>>>,
    accept_results: Mutex<VecDeque<Result<String, ChainSwapQuoteProviderError>>>,
    calls: Mutex<Vec<ProviderCall>>,
    accept_barrier: Option<Arc<tokio::sync::Barrier>>,
    accept_started_barrier: Option<Arc<tokio::sync::Barrier>>,
    accept_release_barrier: Option<Arc<tokio::sync::Barrier>>,
}

impl FakeProvider {
    fn new(
        get_results: impl IntoIterator<Item = Result<ChainSwapQuote, ChainSwapQuoteProviderError>>,
        accept_results: impl IntoIterator<Item = Result<String, ChainSwapQuoteProviderError>>,
    ) -> Self {
        Self {
            get_results: Mutex::new(get_results.into_iter().collect()),
            accept_results: Mutex::new(accept_results.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
            accept_barrier: None,
            accept_started_barrier: None,
            accept_release_barrier: None,
        }
    }

    fn with_accept_barrier(mut self, barrier: Arc<tokio::sync::Barrier>) -> Self {
        self.accept_barrier = Some(barrier);
        self
    }

    fn with_accept_gates(
        mut self,
        started: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    ) -> Self {
        self.accept_started_barrier = Some(started);
        self.accept_release_barrier = Some(release);
        self
    }

    fn calls(&self) -> Vec<ProviderCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl ChainSwapRenegotiationProvider for FakeProvider {
    async fn get_quote(
        &self,
        swap_id: &str,
    ) -> Result<ChainSwapQuote, ChainSwapQuoteProviderError> {
        self.calls
            .lock()
            .unwrap()
            .push(ProviderCall::GetQuote(swap_id.to_string()));
        self.get_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected get_quote call")
    }

    async fn accept_quote(
        &self,
        swap_id: &str,
        amount_sat: u64,
    ) -> Result<String, ChainSwapQuoteProviderError> {
        self.calls.lock().unwrap().push(ProviderCall::AcceptQuote {
            swap_id: swap_id.to_string(),
            amount_sat,
        });
        let result = self
            .accept_results
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected accept_quote call");
        if let Some(barrier) = self.accept_barrier.as_ref() {
            barrier.wait().await;
        }
        if let Some(barrier) = self.accept_started_barrier.as_ref() {
            barrier.wait().await;
        }
        if let Some(barrier) = self.accept_release_barrier.as_ref() {
            barrier.wait().await;
        }
        result
    }
}

struct FaultObserver {
    fail_at: Option<RenegotiationCheckpoint>,
    reached: Mutex<Vec<RenegotiationCheckpoint>>,
}

impl FaultObserver {
    fn never_fail() -> Self {
        Self {
            fail_at: None,
            reached: Mutex::new(Vec::new()),
        }
    }

    fn fail_at(checkpoint: RenegotiationCheckpoint) -> Self {
        Self {
            fail_at: Some(checkpoint),
            reached: Mutex::new(Vec::new()),
        }
    }

    fn reached(&self) -> Vec<RenegotiationCheckpoint> {
        self.reached.lock().unwrap().clone()
    }
}

impl RenegotiationCheckpointObserver for FaultObserver {
    fn reached(&self, checkpoint: RenegotiationCheckpoint) -> Result<(), AppError> {
        self.reached.lock().unwrap().push(checkpoint);
        if self.fail_at == Some(checkpoint) {
            return Err(AppError::ClaimError(format!(
                "simulated crash at {checkpoint:?}"
            )));
        }
        Ok(())
    }
}

#[derive(Default)]
struct MemoryStoreState {
    operation: Option<ChainSwapRenegotiationOperation>,
    accepted_parent_amount_sat: Option<u64>,
    events: Vec<RenegotiationState>,
    fail_record_once: bool,
}

#[derive(Default)]
struct MemoryStore {
    state: Mutex<MemoryStoreState>,
}

impl MemoryStore {
    fn operation(&self) -> Option<ChainSwapRenegotiationOperation> {
        self.state.lock().unwrap().operation.clone()
    }

    fn accepted_parent_amount_sat(&self) -> Option<u64> {
        self.state.lock().unwrap().accepted_parent_amount_sat
    }

    fn operation_and_parent(&self) -> (Option<ChainSwapRenegotiationOperation>, Option<u64>) {
        let state = self.state.lock().unwrap();
        (state.operation.clone(), state.accepted_parent_amount_sat)
    }

    fn events(&self) -> Vec<RenegotiationState> {
        self.state.lock().unwrap().events.clone()
    }

    fn make_accept_request_stale(&self) {
        let mut state = self.state.lock().unwrap();
        let operation = state.operation.as_mut().unwrap();
        assert_eq!(operation.state, RenegotiationState::AcceptRequested);
        let requested_at = operation.accept_requested_at_unix.unwrap();
        let stale_requested_at =
            current_unix_time().unwrap() - RENEGOTIATION_ACCEPT_REQUEST_STALE_AFTER_SECS - 1;
        let delta = requested_at.checked_sub(stale_requested_at).unwrap();
        assert!(delta > 0);
        operation.identity.quote_observed_at_unix = operation
            .identity
            .quote_observed_at_unix
            .checked_sub(delta)
            .unwrap();
        operation.identity.policy_validated_at_unix = operation
            .identity
            .policy_validated_at_unix
            .checked_sub(delta)
            .unwrap();
        operation.created_at_unix = operation.created_at_unix.checked_sub(delta).unwrap();
        operation.updated_at_unix = operation.updated_at_unix.checked_sub(delta).unwrap();
        operation.accept_requested_at_unix = Some(stale_requested_at);
    }

    fn fail_next_acceptance_commit(&self) {
        self.state.lock().unwrap().fail_record_once = true;
    }

    fn operation_after(
        current: &ChainSwapRenegotiationOperation,
        state: RenegotiationState,
        error: Option<RenegotiationErrorClass>,
        terminal_response_digest: Option<String>,
    ) -> ChainSwapRenegotiationOperation {
        let next_version = current.version + 1;
        let now = current_unix_time().unwrap().max(current.updated_at_unix);
        let is_request = state == RenegotiationState::AcceptRequested;
        let is_ambiguous = state == RenegotiationState::Ambiguous;
        let is_terminal = state.is_terminal();
        ChainSwapRenegotiationOperation::from_persisted_parts(
            current.identity.clone(),
            state,
            current.accept_attempt_count + u32::from(is_request),
            if is_ambiguous {
                error
            } else {
                current.last_error_class
            },
            next_version,
            if is_request {
                Some(now)
            } else {
                current.accept_requested_at_unix
            },
            if is_ambiguous {
                Some(now)
            } else {
                current.ambiguous_at_unix
            },
            terminal_response_digest,
            is_terminal.then_some(now),
            current.created_at_unix,
            now,
        )
        .unwrap()
    }

    fn apply_transition(
        state: &mut MemoryStoreState,
        transition: RenegotiationTransition,
    ) -> Result<(ChainSwapRenegotiationOperation, TransitionDisposition), AppError> {
        let current = state
            .operation
            .clone()
            .ok_or_else(|| AppError::DbError("fake operation missing".into()))?;
        let disposition = current
            .plan_transition(&transition)
            .map_err(|error| AppError::DbError(error.to_string()))?;
        if disposition == TransitionDisposition::ExactRetry {
            return Ok((current, disposition));
        }
        let (target, error, terminal) = match transition.kind {
            RenegotiationTransitionKind::RequestAccept => {
                (RenegotiationState::AcceptRequested, None, None)
            }
            RenegotiationTransitionKind::MarkAmbiguous { error_class } => {
                (RenegotiationState::Ambiguous, Some(error_class), None)
            }
            RenegotiationTransitionKind::MarkAccepted {
                terminal_response_digest,
            } => (
                RenegotiationState::Accepted,
                None,
                Some(terminal_response_digest),
            ),
            RenegotiationTransitionKind::MarkDeclined {
                terminal_response_digest,
            } => (
                RenegotiationState::Declined,
                None,
                Some(terminal_response_digest),
            ),
        };
        let next = Self::operation_after(&current, target, error, terminal);
        state.events.push(next.state);
        state.operation = Some(next.clone());
        Ok((next, disposition))
    }

    fn store_transition(
        operation: ChainSwapRenegotiationOperation,
        disposition: TransitionDisposition,
    ) -> RenegotiationStoreTransition {
        match disposition {
            TransitionDisposition::Apply => RenegotiationStoreTransition::Applied(operation),
            TransitionDisposition::ExactRetry => {
                RenegotiationStoreTransition::ExactRetry(operation)
            }
        }
    }
}

#[async_trait]
impl ChainSwapRenegotiationStore for MemoryStore {
    async fn get(
        &self,
        chain_swap_id: Uuid,
    ) -> Result<Option<ChainSwapRenegotiationOperation>, AppError> {
        Ok(self
            .operation()
            .filter(|operation| operation.identity.chain_swap_id == chain_swap_id))
    }

    async fn persist_quoted(
        &self,
        identity: &RenegotiationIdentity,
    ) -> Result<ChainSwapRenegotiationOperation, AppError> {
        let mut state = self.state.lock().unwrap();
        if let Some(current) = state.operation.as_ref() {
            if current.identity != *identity {
                return Err(AppError::DbError("fake quote identity conflict".into()));
            }
            return Ok(current.clone());
        }
        let created_at = identity.policy_validated_at_unix.max(1);
        let operation = ChainSwapRenegotiationOperation::from_persisted_parts(
            identity.clone(),
            RenegotiationState::Quoted,
            0,
            None,
            1,
            None,
            None,
            None,
            None,
            created_at,
            created_at,
        )
        .unwrap();
        state.events.push(RenegotiationState::Quoted);
        state.operation = Some(operation.clone());
        Ok(operation)
    }

    async fn record_initial_decline(
        &self,
        identity: &RenegotiationIdentity,
        terminal_response_digest: &str,
    ) -> Result<DefiniteDeclineFinalization, AppError> {
        let mut state = self.state.lock().unwrap();
        if state.accepted_parent_amount_sat.is_some() {
            return Ok(DefiniteDeclineFinalization::LiquidPathActive);
        }
        if let Some(current) = state.operation.as_ref() {
            if current.identity == *identity
                && current.state == RenegotiationState::Declined
                && current.terminal_response_digest() == Some(terminal_response_digest)
            {
                return Ok(DefiniteDeclineFinalization::Declined(Box::new(
                    current.clone(),
                )));
            }
            return Err(AppError::DbError(
                "fake initial decline identity conflict".into(),
            ));
        }

        let created_at = identity.policy_validated_at_unix.max(1);
        let quoted = ChainSwapRenegotiationOperation::from_persisted_parts(
            identity.clone(),
            RenegotiationState::Quoted,
            0,
            None,
            1,
            None,
            None,
            None,
            None,
            created_at,
            created_at,
        )
        .unwrap();
        let declined = Self::operation_after(
            &quoted,
            RenegotiationState::Declined,
            None,
            Some(terminal_response_digest.to_owned()),
        );
        state.events.push(RenegotiationState::Declined);
        state.operation = Some(declined.clone());
        Ok(DefiniteDeclineFinalization::Declined(Box::new(declined)))
    }

    async fn request_accept(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
    ) -> Result<RenegotiationStoreTransition, AppError> {
        let transition = RenegotiationTransition::new(
            identity.clone(),
            expected_version,
            RenegotiationTransitionKind::RequestAccept,
        )
        .map_err(|error| AppError::DbError(error.to_string()))?;
        Self::apply_transition(&mut self.state.lock().unwrap(), transition)
            .map(|(operation, disposition)| Self::store_transition(operation, disposition))
    }

    async fn request_changed_accept(
        &self,
        current: &ChainSwapRenegotiationOperation,
        replacement: &RenegotiationIdentity,
    ) -> Result<RenegotiationStoreTransition, AppError> {
        let redrive = ChangedQuoteRedrive::new(
            current.identity.clone(),
            replacement.clone(),
            current.version,
        )
        .map_err(|error| AppError::DbError(error.to_string()))?;
        let mut state = self.state.lock().unwrap();
        let persisted = state
            .operation
            .clone()
            .ok_or_else(|| AppError::DbError("fake operation missing".into()))?;
        let disposition = redrive
            .plan(&persisted)
            .map_err(|error| AppError::DbError(error.to_string()))?;
        if disposition == TransitionDisposition::ExactRetry {
            return Ok(RenegotiationStoreTransition::ExactRetry(persisted));
        }
        let now = current_unix_time().unwrap().max(persisted.updated_at_unix);
        let next = ChainSwapRenegotiationOperation::from_persisted_parts(
            replacement.clone(),
            RenegotiationState::AcceptRequested,
            persisted.accept_attempt_count + 1,
            persisted.last_error_class,
            persisted.version + 1,
            Some(now),
            persisted.ambiguous_at_unix,
            None,
            None,
            persisted.created_at_unix,
            now,
        )
        .unwrap();
        state.events.push(next.state);
        state.operation = Some(next.clone());
        Ok(RenegotiationStoreTransition::Applied(next))
    }

    async fn mark_ambiguous(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
        error_class: RenegotiationErrorClass,
    ) -> Result<RenegotiationStoreTransition, AppError> {
        let transition = RenegotiationTransition::new(
            identity.clone(),
            expected_version,
            RenegotiationTransitionKind::MarkAmbiguous { error_class },
        )
        .map_err(|error| AppError::DbError(error.to_string()))?;
        Self::apply_transition(&mut self.state.lock().unwrap(), transition)
            .map(|(operation, disposition)| Self::store_transition(operation, disposition))
    }

    async fn mark_declined(
        &self,
        identity: &RenegotiationIdentity,
        expected_version: u64,
        terminal_response_digest: &str,
    ) -> Result<DefiniteDeclineFinalization, AppError> {
        let transition = RenegotiationTransition::new(
            identity.clone(),
            expected_version,
            RenegotiationTransitionKind::MarkDeclined {
                terminal_response_digest: terminal_response_digest.to_string(),
            },
        )
        .map_err(|error| AppError::DbError(error.to_string()))?;
        Self::apply_transition(&mut self.state.lock().unwrap(), transition)
            .map(|(operation, _)| DefiniteDeclineFinalization::Declined(Box::new(operation)))
    }

    async fn record_accepted(
        &self,
        evidence: &VerifiedRenegotiationAcceptance,
        expected_version: u64,
    ) -> Result<AcceptedRenegotiationFinalization, AppError> {
        let mut state = self.state.lock().unwrap();
        if state.fail_record_once {
            state.fail_record_once = false;
            return Err(AppError::DbError(
                "simulated acceptance commit uncertainty".into(),
            ));
        }
        let transition = RenegotiationTransition::new(
            evidence.identity().clone(),
            expected_version,
            RenegotiationTransitionKind::MarkAccepted {
                terminal_response_digest: evidence.terminal_response_digest().to_string(),
            },
        )
        .map_err(|error| AppError::DbError(error.to_string()))?;
        let (operation, _) = Self::apply_transition(&mut state, transition)?;
        state.accepted_parent_amount_sat = Some(evidence.accepted_actual_amount_sat());
        Ok(AcceptedRenegotiationFinalization::Committed(Box::new(
            operation,
        )))
    }
}

fn identity(amount_sat: u64) -> RenegotiationIdentity {
    identity_at(amount_sat, QUOTE_DIGEST, 100)
}

fn primary_mismatch(
    observed_amount_sat: u64,
    expected_amount_sat: u64,
) -> VerifiedPrimaryFundingAmountMismatch {
    VerifiedPrimaryFundingAmountMismatch::new_complete_and_agreed(
        Uuid::from_u128(0x83),
        observed_amount_sat,
        expected_amount_sat,
        100,
        current_unix_time().unwrap(),
        format!("primary:{observed_amount_sat}"),
        POLICY_DIGEST,
    )
    .unwrap()
}

fn chain_swap(expected_amount_sat: i64) -> db::ChainSwapRecord {
    chain_swap_with_pair_limits(expected_amount_sat, 1, 25_000_000)
}

fn chain_swap_with_pair_limits(
    expected_amount_sat: i64,
    minimal: u64,
    maximal: u64,
) -> db::ChainSwapRecord {
    let pair: ChainPair = serde_json::from_value(serde_json::json!({
        "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "rate": 1.0,
        "limits": {
            "maximal": maximal,
            "minimal": minimal,
            "maximalZeroConf": 0
        },
        "fees": {
            "percentage": 0.1,
            "minerFees": {
                "server": 405,
                "user": {"claim": 20, "lockup": 385}
            }
        }
    }))
    .unwrap();
    let (canonical_pair_quote_json, _) =
        crate::canonical_json::canonical_json_and_sha256(&pair).unwrap();
    db::ChainSwapRecord {
        id: Uuid::from_u128(0x83),
        invoice_id: Uuid::from_u128(0x84),
        nym: Some("renegotiation-tests".into()),
        boltz_swap_id: "issue38-swap".into(),
        from_chain: "BTC".into(),
        to_chain: "L-BTC".into(),
        lockup_address: "bc1qrenegotiationtest".into(),
        lockup_bip21: None,
        user_lock_amount_sat: expected_amount_sat,
        server_lock_amount_sat: expected_amount_sat - 10,
        preimage_hex: "11".repeat(32),
        claim_key_hex: "22".repeat(32),
        refund_key_hex: "33".repeat(32),
        boltz_response_json: "{}".into(),
        status: "user_lock_confirmed".into(),
        claim_txid: None,
        claim_tx_hex: None,
        claim_fee_authority: db::LiquidClaimFeeAuthority::Legacy,
        claim_attempts: 0,
        last_claim_error: None,
        cooperative_refused: true,
        creation_terms: Some(db::ChainSwapCreationTerms {
            pinned_pair_hash: pair.hash,
            canonical_pair_quote_json,
            creation_response_sha256: "55".repeat(32),
            btc_claim_script_sha256: "66".repeat(32),
            btc_refund_script_sha256: "77".repeat(32),
            liquid_claim_script_sha256: "88".repeat(32),
            liquid_refund_script_sha256: "99".repeat(32),
            btc_timeout_height: 200,
            liquid_timeout_height: 300,
            btc_network: "bitcoin".into(),
            liquid_network: "liquid".into(),
            liquid_asset_id: "aa".repeat(32),
            merchant_liquid_destination: "lq1qrenegotiationtest".into(),
            merchant_emergency_btc_address: None,
            recovery_address_commitment_id: None,
        }),
        renegotiated_server_lock_amount_sat: None,
        refund_address: Some("bc1qrefundtest".into()),
        refund_txid: None,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn collected_primary_mismatch(
    swap: &db::ChainSwapRecord,
    inclusion: ChainLockupInclusionV1,
) -> CollectedPendingExpiryEvidence {
    let txid = "ab".repeat(32);
    let projection = project_primary_bitcoin_source_v1(
        &ChainLockupManifestWitnessAuditV1 {
            manifest_sequence: 1,
            manifest_id: Uuid::from_u128(0x82),
            chain_swap_id: swap.id,
            expected_amount_sat: u64::try_from(swap.user_lock_amount_sat).unwrap(),
            classification: ChainLockupManifestClassificationV1::Conflicting,
            findings: vec![ChainLockupWitnessFindingV1 {
                txid: txid.clone(),
                vout: 0,
                observed_amount_sat: 900,
                inclusion,
                spend: ChainLockupSpendV1::Unspent,
                classification: ChainLockupFindingClassificationV1::Conflicting {
                    fields: vec![ChainLockupConflictFieldV1::ExpectedAmount],
                },
            }],
        },
        Some(&txid),
        PrimaryBitcoinSourceAuthorityV1::SelfHostedNode,
    )
    .unwrap();
    let mut evidence = ChainSwapProviderEvidence::incomplete().evidence;
    evidence.quality = EvidenceQuality::CompleteAndAgreed;
    evidence.liquid_lock = LiquidLockEvidence::NotObserved;
    CollectedPendingExpiryEvidence {
        provider_status: Some("transaction.lockupFailed".into()),
        evidence,
        primary_bitcoin: Some(projection),
        primary_chain_swap_id: Some(swap.id),
        primary_tip_height: Some(900_000),
        primary_evidence_sha256: Some(POLICY_DIGEST.into()),
    }
}

fn identity_at(amount_sat: u64, quote_digest: &str, observed_at: i64) -> RenegotiationIdentity {
    RenegotiationIdentity::new(
        Uuid::from_u128(0x83),
        amount_sat,
        quote_digest,
        observed_at,
        RENEGOTIATION_POLICY_VERSION,
        POLICY_DIGEST,
        observed_at + 1,
    )
    .unwrap()
}

fn operation(state: RenegotiationState) -> ChainSwapRenegotiationOperation {
    let identity = identity(900);
    let (accept_attempt_count, error, version, requested_at, ambiguous_at, terminal, terminal_at) =
        match state {
            RenegotiationState::Quoted => (0, None, 1, None, None, None, None),
            RenegotiationState::AcceptRequested => (1, None, 2, Some(102), None, None, None),
            RenegotiationState::Ambiguous => (
                1,
                Some(RenegotiationErrorClass::Timeout),
                3,
                Some(102),
                Some(103),
                None,
                None,
            ),
            RenegotiationState::Accepted => (
                1,
                Some(RenegotiationErrorClass::Timeout),
                4,
                Some(102),
                Some(103),
                Some(TERMINAL_DIGEST.to_string()),
                Some(104),
            ),
            RenegotiationState::Declined => (
                0,
                None,
                2,
                None,
                None,
                Some(TERMINAL_DIGEST.to_string()),
                Some(102),
            ),
        };
    ChainSwapRenegotiationOperation::from_persisted_parts(
        identity,
        state,
        accept_attempt_count,
        error,
        version,
        requested_at,
        ambiguous_at,
        terminal,
        terminal_at,
        100,
        terminal_at.or(ambiguous_at).or(requested_at).unwrap_or(101),
    )
    .unwrap()
}

#[tokio::test]
async fn exact_primary_amount_is_ineligible_while_under_and_over_are_verified_mismatches() {
    let swap = chain_swap(1_000);
    let store = MemoryStore::default();
    let provider = FakeProvider::new(Vec::new(), Vec::new());
    let correct_observation = VerifiedPrimaryFundingObservation::new_complete_and_agreed(
        Uuid::from_u128(0x83),
        1_000,
        1_000,
        100,
        current_unix_time().unwrap(),
        "primary:correct",
        POLICY_DIGEST,
    )
    .unwrap();
    assert!(correct_observation.mismatch().is_none());
    assert_eq!(
        adopt_verified_primary_funding_for_renegotiation_using(
            &store,
            &provider,
            &FaultObserver::never_fail(),
            &swap,
            "transaction.lockupFailed",
            &correct_observation,
        )
        .await
        .unwrap(),
        RenegotiationAdoptionOutcome::NotApplicable
    );
    assert!(provider.calls().is_empty());
    assert!(store.operation().is_none());

    let wrong_status_observation = VerifiedPrimaryFundingObservation::new_complete_and_agreed(
        Uuid::from_u128(0x83),
        900,
        1_000,
        100,
        current_unix_time().unwrap(),
        "primary:wrong-status",
        POLICY_DIGEST,
    )
    .unwrap();
    assert_eq!(
        adopt_verified_primary_funding_for_renegotiation_using(
            &store,
            &provider,
            &FaultObserver::never_fail(),
            &swap,
            "transaction.failed",
            &wrong_status_observation,
        )
        .await
        .unwrap(),
        RenegotiationAdoptionOutcome::NotApplicable
    );
    assert!(provider.calls().is_empty());
    assert!(store.operation().is_none());

    let correct = VerifiedPrimaryFundingAmountMismatch::new_complete_and_agreed(
        Uuid::from_u128(0x83),
        1_000,
        1_000,
        100,
        current_unix_time().unwrap(),
        "primary:correct",
        POLICY_DIGEST,
    );
    assert!(correct.is_err());

    for observed_amount_sat in [900, 1_100] {
        let mismatch = VerifiedPrimaryFundingAmountMismatch::new_complete_and_agreed(
            Uuid::from_u128(0x83),
            observed_amount_sat,
            1_000,
            100,
            current_unix_time().unwrap(),
            format!("primary:{observed_amount_sat}"),
            POLICY_DIGEST,
        )
        .unwrap();
        assert_eq!(mismatch.observed_amount_sat, observed_amount_sat);
        assert_eq!(mismatch.expected_amount_sat, 1_000);
    }
}

#[test]
fn chain_claim_construction_uses_the_durable_renegotiated_amount() {
    let mut swap = chain_swap(1_000);
    assert_eq!(swap.server_lock_amount_sat, 990);
    assert_eq!(effective_chain_claim_amount_sat(&swap).unwrap(), 990);

    swap.renegotiated_server_lock_amount_sat = Some(890);
    assert_eq!(effective_chain_claim_amount_sat(&swap).unwrap(), 890);

    swap.renegotiated_server_lock_amount_sat = Some(0);
    assert!(effective_chain_claim_amount_sat(&swap).is_err());
}

#[test]
fn runtime_projection_constructs_renegotiation_capability_only_after_confirmed_exact_identity() {
    let swap = chain_swap(1_000);
    let confirmed = collected_primary_mismatch(
        &swap,
        ChainLockupInclusionV1::Confirmed {
            confirmations: 1,
            block_height: 899_999,
            block_hash: "cd".repeat(32),
        },
    );
    let observation = verified_primary_funding_observation_from_locked_evidence(&swap, &confirmed)
        .unwrap()
        .expect("complete confirmed mismatch must reach the guarded journal executor");
    let mismatch = observation.mismatch().unwrap();
    assert_eq!(mismatch.chain_swap_id, swap.id);
    assert_eq!(mismatch.observed_amount_sat, 900);
    assert_eq!(mismatch.expected_amount_sat, 1_000);
    assert_eq!(mismatch.authoritative_bitcoin_tip, 900_000);

    let mempool = collected_primary_mismatch(&swap, ChainLockupInclusionV1::Mempool);
    assert!(
        verified_primary_funding_observation_from_locked_evidence(&swap, &mempool)
            .unwrap()
            .is_none()
    );

    let mut crossed_identity = collected_primary_mismatch(
        &swap,
        ChainLockupInclusionV1::Confirmed {
            confirmations: 1,
            block_height: 899_999,
            block_hash: "ef".repeat(32),
        },
    );
    crossed_identity.primary_chain_swap_id = Some(Uuid::from_u128(0xdead));
    assert!(
        verified_primary_funding_observation_from_locked_evidence(&swap, &crossed_identity)
            .unwrap()
            .is_none()
    );

    let mut stale_provider = collected_primary_mismatch(
        &swap,
        ChainLockupInclusionV1::Confirmed {
            confirmations: 1,
            block_height: 899_999,
            block_hash: "12".repeat(32),
        },
    );
    stale_provider.provider_status = Some("transaction.confirmed".into());
    assert!(
        verified_primary_funding_observation_from_locked_evidence(&swap, &stale_provider)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn under_and_over_funding_commit_intent_before_provider_acceptance() {
    for (observed_amount_sat, accepted_amount_sat) in [(900, 890), (1_100, 1_090)] {
        let swap = chain_swap(1_000);
        let evidence = primary_mismatch(observed_amount_sat, 1_000);
        let store = MemoryStore::default();
        let provider = FakeProvider::new(
            [Ok(quote(accepted_amount_sat, QUOTE_DIGEST))],
            [Ok(TERMINAL_DIGEST.to_string())],
        );
        let observer = FaultObserver::never_fail();

        let handled = try_renegotiate_chain_swap_with_verified_mismatch_using(
            &store,
            &provider,
            &observer,
            &swap,
            "transaction.lockupFailed",
            &evidence,
        )
        .await
        .unwrap();

        assert!(handled);
        assert_eq!(
            provider.calls(),
            vec![
                ProviderCall::GetQuote(swap.boltz_swap_id.clone()),
                ProviderCall::AcceptQuote {
                    swap_id: swap.boltz_swap_id.clone(),
                    amount_sat: accepted_amount_sat,
                },
            ]
        );
        assert_eq!(
            store.events(),
            vec![
                RenegotiationState::Quoted,
                RenegotiationState::AcceptRequested,
                RenegotiationState::Accepted,
            ]
        );
        assert_eq!(
            store.accepted_parent_amount_sat(),
            Some(accepted_amount_sat)
        );
        assert_eq!(
            observer.reached(),
            vec![
                RenegotiationCheckpoint::QuoteObservedBeforePersistence,
                RenegotiationCheckpoint::QuotePersisted,
                RenegotiationCheckpoint::AcceptRequested,
                RenegotiationCheckpoint::ProviderAcceptedResponse,
                RenegotiationCheckpoint::BeforeAcceptanceCommit,
                RenegotiationCheckpoint::AcceptanceCommitted,
            ]
        );
    }
}

#[tokio::test]
async fn creation_pair_bounds_never_preempt_the_live_quote_protocol() {
    let swap = chain_swap_with_pair_limits(1_000, 950, 1_050);

    let below_minimum = primary_mismatch(900, 1_000);
    let store = MemoryStore::default();
    let provider = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST))],
        [Ok(TERMINAL_DIGEST.to_string())],
    );
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &below_minimum,
    )
    .await
    .unwrap());
    assert_eq!(
        provider.calls(),
        vec![
            ProviderCall::GetQuote(swap.boltz_swap_id.clone()),
            ProviderCall::AcceptQuote {
                swap_id: swap.boltz_swap_id.clone(),
                amount_sat: 890,
            },
        ]
    );

    for (observed_amount_sat, kind) in [
        (900, ChainSwapQuoteProviderErrorKind::BelowMinimum),
        (1_100, ChainSwapQuoteProviderErrorKind::AboveMaximum),
    ] {
        let store = MemoryStore::default();
        let provider =
            FakeProvider::new([Err(quote_error(kind, Some(TERMINAL_DIGEST)))], Vec::new());
        let evidence = primary_mismatch(observed_amount_sat, 1_000);
        let observer = FaultObserver::never_fail();
        assert!(!try_renegotiate_chain_swap_with_verified_mismatch_using(
            &store,
            &provider,
            &observer,
            &swap,
            "transaction.lockupFailed",
            &evidence,
        )
        .await
        .unwrap());
        assert_eq!(
            provider.calls(),
            vec![ProviderCall::GetQuote(swap.boltz_swap_id.clone())]
        );
        let operation = store.operation().unwrap();
        assert_eq!(operation.state, RenegotiationState::Declined);
        assert_eq!(operation.version, 2);
        assert_eq!(operation.accept_attempt_count, 0);
        assert_eq!(operation.terminal_response_digest(), Some(TERMINAL_DIGEST));
        assert_eq!(store.events(), vec![RenegotiationState::Declined]);
        assert_eq!(
            observer.reached(),
            vec![
                RenegotiationCheckpoint::ExplicitDeclineObservedBeforePersistence,
                RenegotiationCheckpoint::ExplicitDeclinePersisted,
            ]
        );

        // Restarting the same webhook consumes only the durable terminal row;
        // it cannot call either provider endpoint again.
        assert!(!try_renegotiate_chain_swap_with_verified_mismatch_using(
            &store,
            &provider,
            &FaultObserver::never_fail(),
            &swap,
            "transaction.lockupFailed",
            &evidence,
        )
        .await
        .unwrap());
        assert_eq!(store.events(), vec![RenegotiationState::Declined]);
        assert_eq!(
            provider.calls(),
            vec![ProviderCall::GetQuote(swap.boltz_swap_id.clone())]
        );
    }
}

#[tokio::test]
async fn initial_explicit_refusal_crash_boundaries_never_expose_an_acceptable_quote() {
    let swap = chain_swap(1_000);
    let evidence = primary_mismatch(900, 1_000);

    let before_store = MemoryStore::default();
    let before_provider = FakeProvider::new(
        [
            Err(quote_error(
                ChainSwapQuoteProviderErrorKind::BelowMinimum,
                Some(TERMINAL_DIGEST),
            )),
            Err(quote_error(
                ChainSwapQuoteProviderErrorKind::BelowMinimum,
                Some(TERMINAL_DIGEST),
            )),
        ],
        Vec::new(),
    );
    let before_persistence =
        FaultObserver::fail_at(RenegotiationCheckpoint::ExplicitDeclineObservedBeforePersistence);
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &before_store,
        &before_provider,
        &before_persistence,
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .is_err());
    assert!(before_store.operation().is_none());
    assert!(before_store.events().is_empty());

    assert!(!try_renegotiate_chain_swap_with_verified_mismatch_using(
        &before_store,
        &before_provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .unwrap());
    assert_eq!(before_store.events(), vec![RenegotiationState::Declined]);
    assert!(before_provider
        .calls()
        .iter()
        .all(|call| matches!(call, ProviderCall::GetQuote(_))));

    let after_store = MemoryStore::default();
    let after_provider = FakeProvider::new(
        [Err(quote_error(
            ChainSwapQuoteProviderErrorKind::BelowMinimum,
            Some(TERMINAL_DIGEST),
        ))],
        Vec::new(),
    );
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &after_store,
        &after_provider,
        &FaultObserver::fail_at(RenegotiationCheckpoint::ExplicitDeclinePersisted),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .is_err());
    let durable = after_store.operation().unwrap();
    assert_eq!(durable.state, RenegotiationState::Declined);
    assert_eq!(durable.accept_attempt_count, 0);
    assert_eq!(after_store.events(), vec![RenegotiationState::Declined]);

    assert!(!try_renegotiate_chain_swap_with_verified_mismatch_using(
        &after_store,
        &after_provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .unwrap());
    assert_eq!(
        after_provider.calls(),
        vec![ProviderCall::GetQuote(swap.boltz_swap_id.clone())]
    );
}

#[tokio::test]
async fn explicit_decline_falls_through_but_timeout_5xx_and_malformed_stay_blocked() {
    let swap = chain_swap(1_000);
    let evidence = primary_mismatch(900, 1_000);
    let store = MemoryStore::default();
    let provider = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST))],
        [Err(quote_error(
            ChainSwapQuoteProviderErrorKind::RefundAlreadySigned,
            Some(TERMINAL_DIGEST),
        ))],
    );
    let declined = try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .unwrap();
    assert!(!declined);
    let operation = store.operation().unwrap();
    assert_eq!(operation.state, RenegotiationState::Declined);
    assert_eq!(
        operation.fallback_gate(),
        RenegotiationFallbackGate::ExplicitlyDeclined
    );
    assert_eq!(store.accepted_parent_amount_sat(), None);

    for (kind, error_class) in [
        (
            ChainSwapQuoteProviderErrorKind::Timeout,
            RenegotiationErrorClass::Timeout,
        ),
        (
            ChainSwapQuoteProviderErrorKind::ProviderServerError,
            RenegotiationErrorClass::ProviderServerError,
        ),
        (
            ChainSwapQuoteProviderErrorKind::MalformedResponse,
            RenegotiationErrorClass::MalformedResponse,
        ),
    ] {
        let store = MemoryStore::default();
        let provider = FakeProvider::new(
            [Ok(quote(890, QUOTE_DIGEST))],
            [Err(quote_error(kind, None))],
        );
        let result = try_renegotiate_chain_swap_with_verified_mismatch_using(
            &store,
            &provider,
            &FaultObserver::never_fail(),
            &swap,
            "transaction.lockupFailed",
            &evidence,
        )
        .await;
        assert!(result.is_err());
        let operation = store.operation().unwrap();
        assert_eq!(operation.state, RenegotiationState::Ambiguous);
        assert_eq!(operation.last_error_class, Some(error_class));
        assert!(operation.fallback_gate().blocks_bitcoin_fallback());
        assert_eq!(store.accepted_parent_amount_sat(), None);
    }
}

#[tokio::test]
async fn definite_provider_response_with_uncertain_local_commit_becomes_durable_ambiguous() {
    let swap = chain_swap(1_000);
    let evidence = primary_mismatch(900, 1_000);
    let store = MemoryStore::default();
    store.fail_next_acceptance_commit();
    let provider = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST))],
        [Ok(TERMINAL_DIGEST.to_string())],
    );

    let result = try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await;
    assert!(result.is_err());
    let operation = store.operation().unwrap();
    assert_eq!(operation.state, RenegotiationState::Ambiguous);
    assert_eq!(
        operation.last_error_class,
        Some(RenegotiationErrorClass::LocalCommitUncertainty)
    );
    assert!(operation.fallback_gate().blocks_bitcoin_fallback());
    assert_eq!(store.accepted_parent_amount_sat(), None);
    assert_eq!(
        provider
            .calls()
            .iter()
            .filter(|call| matches!(call, ProviderCall::AcceptQuote { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn every_crash_boundary_restarts_without_losing_or_inventing_authority() {
    let cases = [
        (
            RenegotiationCheckpoint::QuoteObservedBeforePersistence,
            None,
            2,
            1,
        ),
        (
            RenegotiationCheckpoint::QuotePersisted,
            Some(RenegotiationState::Quoted),
            1,
            1,
        ),
        (
            RenegotiationCheckpoint::AcceptRequested,
            Some(RenegotiationState::AcceptRequested),
            2,
            1,
        ),
        (
            RenegotiationCheckpoint::ProviderAcceptedResponse,
            Some(RenegotiationState::AcceptRequested),
            2,
            2,
        ),
        (
            RenegotiationCheckpoint::BeforeAcceptanceCommit,
            Some(RenegotiationState::AcceptRequested),
            2,
            2,
        ),
        (
            RenegotiationCheckpoint::AcceptanceCommitted,
            Some(RenegotiationState::Accepted),
            1,
            1,
        ),
    ];

    for (checkpoint, state_after_crash, expected_gets, expected_accepts) in cases {
        let swap = chain_swap(1_000);
        let evidence = primary_mismatch(900, 1_000);
        let store = MemoryStore::default();
        let provider = FakeProvider::new(
            [Ok(quote(890, QUOTE_DIGEST)), Ok(quote(890, QUOTE_DIGEST))],
            [
                Ok(TERMINAL_DIGEST.to_string()),
                Ok(TERMINAL_DIGEST.to_string()),
            ],
        );
        let crash = FaultObserver::fail_at(checkpoint);
        let first = try_renegotiate_chain_swap_with_verified_mismatch_using(
            &store,
            &provider,
            &crash,
            &swap,
            "transaction.lockupFailed",
            &evidence,
        )
        .await;
        assert!(first.is_err(), "{checkpoint:?}");
        assert_eq!(crash.reached().last(), Some(&checkpoint));
        assert_eq!(
            store.operation().as_ref().map(|operation| operation.state),
            state_after_crash,
            "{checkpoint:?}"
        );
        if checkpoint != RenegotiationCheckpoint::AcceptanceCommitted {
            assert_eq!(store.accepted_parent_amount_sat(), None, "{checkpoint:?}");
        }
        if state_after_crash == Some(RenegotiationState::AcceptRequested) {
            store.make_accept_request_stale();
        }

        let restarted = try_renegotiate_chain_swap_with_verified_mismatch_using(
            &store,
            &provider,
            &FaultObserver::never_fail(),
            &swap,
            "transaction.lockupFailed",
            &evidence,
        )
        .await
        .unwrap();
        assert!(restarted, "{checkpoint:?}");
        assert_eq!(
            store.operation().unwrap().state,
            RenegotiationState::Accepted,
            "{checkpoint:?}"
        );
        assert_eq!(store.accepted_parent_amount_sat(), Some(890));
        if state_after_crash == Some(RenegotiationState::AcceptRequested) {
            assert_eq!(
                store.events(),
                vec![
                    RenegotiationState::Quoted,
                    RenegotiationState::AcceptRequested,
                    RenegotiationState::Ambiguous,
                    RenegotiationState::AcceptRequested,
                    RenegotiationState::Accepted,
                ],
                "{checkpoint:?}"
            );
        }
        assert_eq!(
            provider
                .calls()
                .iter()
                .filter(|call| matches!(call, ProviderCall::GetQuote(_)))
                .count(),
            expected_gets,
            "{checkpoint:?}"
        );
        assert_eq!(
            provider
                .calls()
                .iter()
                .filter(|call| matches!(call, ProviderCall::AcceptQuote { .. }))
                .count(),
            expected_accepts,
            "{checkpoint:?}"
        );
    }
}

#[tokio::test]
async fn ambiguous_restart_reuses_exact_amount_and_changed_quote_gets_one_bounded_redrive() {
    let swap = chain_swap(1_000);
    let evidence = primary_mismatch(900, 1_000);
    let store = MemoryStore::default();
    let provider = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST)), Ok(quote(890, QUOTE_DIGEST))],
        [
            Err(quote_error(ChainSwapQuoteProviderErrorKind::Timeout, None)),
            Ok(TERMINAL_DIGEST.to_string()),
        ],
    );
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .is_err());
    assert_eq!(
        store.operation().unwrap().state,
        RenegotiationState::Ambiguous
    );
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .unwrap());
    let accepted_amounts: Vec<_> = provider
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            ProviderCall::AcceptQuote { amount_sat, .. } => Some(amount_sat),
            ProviderCall::GetQuote(_) => None,
        })
        .collect();
    assert_eq!(accepted_amounts, vec![890, 890]);

    let changed_store = MemoryStore::default();
    let changed_provider = FakeProvider::new(
        [
            Ok(quote(890, QUOTE_DIGEST)),
            Ok(quote(889, CHANGED_QUOTE_DIGEST)),
        ],
        [
            Err(quote_error(
                ChainSwapQuoteProviderErrorKind::InvalidOrStaleQuote,
                None,
            )),
            Ok(TERMINAL_DIGEST.to_string()),
        ],
    );
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &changed_store,
        &changed_provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .unwrap());
    assert_eq!(
        changed_store.events(),
        vec![
            RenegotiationState::Quoted,
            RenegotiationState::AcceptRequested,
            RenegotiationState::Ambiguous,
            RenegotiationState::AcceptRequested,
            RenegotiationState::Accepted,
        ]
    );
    assert_eq!(changed_store.accepted_parent_amount_sat(), Some(889));
    let changed_operation = changed_store.operation().unwrap();
    assert_eq!(changed_operation.state, RenegotiationState::Accepted);
    assert_eq!(changed_operation.identity.quoted_actual_amount_sat, 889);
    assert_eq!(
        changed_operation.identity.quote_response_digest(),
        CHANGED_QUOTE_DIGEST
    );
    assert_eq!(changed_operation.accept_attempt_count, 2);
    assert_eq!(changed_operation.version, 5);
}

#[tokio::test]
async fn verified_server_lock_wins_ambiguous_accept_without_another_provider_call() {
    let swap = chain_swap(1_000);
    let evidence = primary_mismatch(900, 1_000);
    let store = MemoryStore::default();
    let provider = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST))],
        [Err(quote_error(
            ChainSwapQuoteProviderErrorKind::Timeout,
            None,
        ))],
    );
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .is_err());
    assert_eq!(
        store.operation().unwrap().state,
        RenegotiationState::Ambiguous
    );
    let calls_before_reconciliation = provider.calls();
    let stale_local_amount = VerifiedLiquidServerLockProgression::new(
        swap.id,
        889,
        "liquid:server-lock:stale",
        CHANGED_QUOTE_DIGEST,
        current_unix_time().unwrap(),
    )
    .unwrap();
    assert!(reconcile_renegotiation_from_verified_server_lock_using(
        &store,
        &swap,
        &stale_local_amount,
    )
    .await
    .is_err());
    assert_eq!(
        store.operation().unwrap().state,
        RenegotiationState::Ambiguous
    );
    assert_eq!(store.accepted_parent_amount_sat(), None);
    assert_eq!(provider.calls(), calls_before_reconciliation);

    let server_lock = VerifiedLiquidServerLockProgression::new(
        swap.id,
        890,
        "liquid:server-lock:0",
        CHANGED_QUOTE_DIGEST,
        current_unix_time().unwrap(),
    )
    .unwrap();
    assert_eq!(
        reconcile_renegotiation_from_verified_server_lock_using(&store, &swap, &server_lock)
            .await
            .unwrap(),
        ServerLockRenegotiationOutcome::LiquidPathWon
    );
    assert_eq!(provider.calls(), calls_before_reconciliation);
    assert_eq!(
        store.operation().unwrap().state,
        RenegotiationState::Accepted
    );
    assert_eq!(store.accepted_parent_amount_sat(), Some(890));
}

#[tokio::test]
async fn duplicate_workers_converge_and_accepted_replay_makes_no_provider_call() {
    let swap = chain_swap(1_000);
    let evidence = primary_mismatch(900, 1_000);
    let store = MemoryStore::default();
    let accept_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let provider = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST))],
        [Ok(TERMINAL_DIGEST.to_string())],
    )
    .with_accept_barrier(accept_barrier.clone());
    let crash = FaultObserver::fail_at(RenegotiationCheckpoint::QuotePersisted);
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &crash,
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .is_err());

    let first_observer = FaultObserver::never_fail();
    let second_observer = FaultObserver::never_fail();
    let first = try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &first_observer,
        &swap,
        "transaction.lockupFailed",
        &evidence,
    );
    let second = try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &second_observer,
        &swap,
        "transaction.lockupFailed",
        &evidence,
    );
    let (first, second, _) = tokio::join!(first, second, accept_barrier.wait());
    assert!(first.unwrap());
    assert!(second.unwrap());
    assert_eq!(
        store.events(),
        vec![
            RenegotiationState::Quoted,
            RenegotiationState::AcceptRequested,
            RenegotiationState::Accepted,
        ]
    );
    let calls_after_race = provider.calls();
    assert_eq!(
        calls_after_race
            .iter()
            .filter(|call| matches!(call, ProviderCall::AcceptQuote { .. }))
            .count(),
        1
    );

    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &store,
        &provider,
        &FaultObserver::never_fail(),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .unwrap());
    assert_eq!(provider.calls(), calls_after_race);
}

#[tokio::test]
async fn duplicate_runtime_and_server_lock_race_converge_with_at_most_one_provider_mutation() {
    let swap = chain_swap(1_000);
    let evidence = primary_mismatch(900, 1_000);
    let server_lock = VerifiedLiquidServerLockProgression::new(
        swap.id,
        890,
        "liquid:server-lock:race",
        CHANGED_QUOTE_DIGEST,
        current_unix_time().unwrap(),
    )
    .unwrap();

    // Provider-first ordering: one worker owns the durable intent and blocks
    // inside its one POST. A duplicate worker observes the fresh intent and
    // does not mutate the provider; verified Liquid progression atomically
    // wins before the first response is released.
    let provider_first_store = MemoryStore::default();
    let accept_started = Arc::new(tokio::sync::Barrier::new(2));
    let accept_release = Arc::new(tokio::sync::Barrier::new(2));
    let provider_first = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST))],
        [Ok(TERMINAL_DIGEST.to_string())],
    )
    .with_accept_gates(accept_started.clone(), accept_release.clone());
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &provider_first_store,
        &provider_first,
        &FaultObserver::fail_at(RenegotiationCheckpoint::QuotePersisted),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .is_err());
    assert!(provider_first_store
        .operation()
        .unwrap()
        .fallback_gate()
        .blocks_bitcoin_fallback());

    let owning_worker_observer = FaultObserver::never_fail();
    let owning_worker = try_renegotiate_chain_swap_with_verified_mismatch_using(
        &provider_first_store,
        &provider_first,
        &owning_worker_observer,
        &swap,
        "transaction.lockupFailed",
        &evidence,
    );
    let reordered_work_and_reconciliation = async {
        accept_started.wait().await;
        let requested = provider_first_store.operation().unwrap();
        assert_eq!(requested.state, RenegotiationState::AcceptRequested);
        assert!(requested.fallback_gate().blocks_bitcoin_fallback());
        let duplicate = try_renegotiate_chain_swap_with_verified_mismatch_using(
            &provider_first_store,
            &provider_first,
            &FaultObserver::never_fail(),
            &swap,
            "transaction.lockupFailed",
            &evidence,
        )
        .await;
        let reconciled = reconcile_renegotiation_from_verified_server_lock_using(
            &provider_first_store,
            &swap,
            &server_lock,
        )
        .await;
        accept_release.wait().await;
        (duplicate, reconciled)
    };
    let (owning_worker, (duplicate, reconciled)) =
        tokio::join!(owning_worker, reordered_work_and_reconciliation);
    assert!(owning_worker.unwrap());
    assert!(duplicate.unwrap());
    assert_eq!(
        reconciled.unwrap(),
        ServerLockRenegotiationOutcome::LiquidPathWon
    );
    assert_eq!(
        provider_first
            .calls()
            .iter()
            .filter(|call| matches!(call, ProviderCall::AcceptQuote { .. }))
            .count(),
        1
    );
    let (operation, parent_amount) = provider_first_store.operation_and_parent();
    let operation = operation.unwrap();
    assert_eq!(operation.state, RenegotiationState::Accepted);
    assert_eq!(operation.version, 3);
    assert_eq!(operation.accept_attempt_count, 1);
    assert_eq!(parent_amount, Some(890));
    assert!(operation.fallback_gate().blocks_bitcoin_fallback());
    assert_eq!(
        provider_first_store.events(),
        vec![
            RenegotiationState::Quoted,
            RenegotiationState::AcceptRequested,
            RenegotiationState::Accepted,
        ]
    );

    // Server-first ordering: crash after the durable request but before POST,
    // adopt verified Liquid progression, then replay duplicate runtime work.
    // Both workers converge without any provider mutation.
    let server_first_store = MemoryStore::default();
    let server_first = FakeProvider::new(
        [Ok(quote(890, QUOTE_DIGEST))],
        Vec::<Result<String, ChainSwapQuoteProviderError>>::new(),
    );
    assert!(try_renegotiate_chain_swap_with_verified_mismatch_using(
        &server_first_store,
        &server_first,
        &FaultObserver::fail_at(RenegotiationCheckpoint::AcceptRequested),
        &swap,
        "transaction.lockupFailed",
        &evidence,
    )
    .await
    .is_err());
    let requested = server_first_store.operation().unwrap();
    assert_eq!(requested.state, RenegotiationState::AcceptRequested);
    assert!(requested.fallback_gate().blocks_bitcoin_fallback());
    assert_eq!(
        reconcile_renegotiation_from_verified_server_lock_using(
            &server_first_store,
            &swap,
            &server_lock,
        )
        .await
        .unwrap(),
        ServerLockRenegotiationOutcome::LiquidPathWon
    );
    let first_replay_observer = FaultObserver::never_fail();
    let first_replay = try_renegotiate_chain_swap_with_verified_mismatch_using(
        &server_first_store,
        &server_first,
        &first_replay_observer,
        &swap,
        "transaction.lockupFailed",
        &evidence,
    );
    let second_replay_observer = FaultObserver::never_fail();
    let second_replay = try_renegotiate_chain_swap_with_verified_mismatch_using(
        &server_first_store,
        &server_first,
        &second_replay_observer,
        &swap,
        "transaction.lockupFailed",
        &evidence,
    );
    let (first_replay, second_replay) = tokio::join!(first_replay, second_replay);
    assert!(first_replay.unwrap());
    assert!(second_replay.unwrap());
    assert_eq!(
        server_first
            .calls()
            .iter()
            .filter(|call| matches!(call, ProviderCall::AcceptQuote { .. }))
            .count(),
        0
    );
    let (operation, parent_amount) = server_first_store.operation_and_parent();
    let operation = operation.unwrap();
    assert_eq!(operation.state, RenegotiationState::Accepted);
    assert_eq!(operation.version, 3);
    assert_eq!(operation.accept_attempt_count, 1);
    assert_eq!(parent_amount, Some(890));
    assert!(operation.fallback_gate().blocks_bitcoin_fallback());
    assert_eq!(
        server_first_store.events(),
        vec![
            RenegotiationState::Quoted,
            RenegotiationState::AcceptRequested,
            RenegotiationState::Accepted,
        ]
    );
}

#[test]
fn every_unresolved_or_accepted_state_blocks_fallback_and_has_one_restart_action() {
    let cases = [
        (
            RenegotiationState::Quoted,
            RenegotiationBlockReason::QuotePending,
            RenegotiationRestartAction::RequestAccept,
        ),
        (
            RenegotiationState::AcceptRequested,
            RenegotiationBlockReason::AcceptRequested,
            RenegotiationRestartAction::ObserveUntilReconciled,
        ),
        (
            RenegotiationState::Ambiguous,
            RenegotiationBlockReason::Ambiguous,
            RenegotiationRestartAction::ReobserveAndRevalidateQuote,
        ),
        (
            RenegotiationState::Accepted,
            RenegotiationBlockReason::AcceptedAwaitingLiquid,
            RenegotiationRestartAction::RepairParentOrReturn,
        ),
    ];

    for (state, reason, restart) in cases {
        let operation = operation(state);
        assert_eq!(
            operation.fallback_gate(),
            RenegotiationFallbackGate::Blocked(reason)
        );
        assert!(operation.fallback_gate().blocks_bitcoin_fallback());
        assert_eq!(operation.restart_action(), restart);
    }

    let declined = operation(RenegotiationState::Declined);
    assert_eq!(
        declined.fallback_gate(),
        RenegotiationFallbackGate::ExplicitlyDeclined
    );
    assert!(!declined.fallback_gate().blocks_bitcoin_fallback());
    assert_eq!(
        declined.restart_action(),
        RenegotiationRestartAction::FallThrough
    );
}

#[test]
fn ambiguous_acceptance_reconciliation_is_exact_and_accepted_replay_is_a_noop() {
    let ambiguous = operation(RenegotiationState::Ambiguous);
    let evidence = VerifiedRenegotiationAcceptance::new(
        ambiguous.identity.clone(),
        ambiguous.identity.quoted_actual_amount_sat,
        ambiguous.identity.quote_response_digest(),
        TERMINAL_DIGEST,
    )
    .unwrap();
    let decision = ambiguous
        .reconcile(
            RenegotiationReconciliationObservation::AcceptanceConfirmed {
                evidence: evidence.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        decision,
        RenegotiationReconciliationDecision::RecordAccepted { evidence }
    );

    let accepted = operation(RenegotiationState::Accepted);
    let accepted_evidence = VerifiedRenegotiationAcceptance::new(
        accepted.identity.clone(),
        accepted.identity.quoted_actual_amount_sat,
        accepted.identity.quote_response_digest(),
        TERMINAL_DIGEST,
    )
    .unwrap();
    assert_eq!(
        accepted
            .reconcile(
                RenegotiationReconciliationObservation::AcceptanceConfirmed {
                    evidence: accepted_evidence,
                }
            )
            .unwrap(),
        RenegotiationReconciliationDecision::AlreadyAccepted
    );
}

#[test]
fn changed_quote_redrive_requires_newer_same_swap_identity() {
    let ambiguous = operation(RenegotiationState::Ambiguous);
    let replacement = identity_at(901, CHANGED_QUOTE_DIGEST, 104);
    assert_eq!(
        ambiguous
            .reconcile(RenegotiationReconciliationObservation::ChangedQuoteValid {
                replacement_identity: replacement.clone(),
            })
            .unwrap(),
        RenegotiationReconciliationDecision::RequestChangedQuoteAccept {
            replacement_identity: replacement,
        }
    );

    let regressed = identity_at(901, CHANGED_QUOTE_DIGEST, 99);
    assert!(ambiguous
        .reconcile(RenegotiationReconciliationObservation::ChangedQuoteValid {
            replacement_identity: regressed,
        })
        .is_err());
}

#[test]
fn local_quote_amount_cannot_manufacture_acceptance_authority() {
    let identity = identity(900);
    assert!(VerifiedRenegotiationAcceptance::new(
        identity.clone(),
        901,
        identity.quote_response_digest(),
        TERMINAL_DIGEST,
    )
    .is_err());
    assert!(VerifiedRenegotiationAcceptance::new(
        identity,
        900,
        CHANGED_QUOTE_DIGEST,
        TERMINAL_DIGEST,
    )
    .is_err());
}

#[test]
fn explicit_provider_declines_are_distinct_from_ambiguous_failures() {
    for kind in [
        ChainSwapQuoteProviderErrorKind::RefundAlreadySigned,
        ChainSwapQuoteProviderErrorKind::FundingNotAmountRejected,
        ChainSwapQuoteProviderErrorKind::ExpiryMarginTooShort,
        ChainSwapQuoteProviderErrorKind::AboveMaximum,
        ChainSwapQuoteProviderErrorKind::BelowMinimum,
    ] {
        assert!(kind.is_explicit_non_eligibility());
    }

    for (kind, expected) in [
        (
            ChainSwapQuoteProviderErrorKind::Timeout,
            RenegotiationErrorClass::Timeout,
        ),
        (
            ChainSwapQuoteProviderErrorKind::ProviderServerError,
            RenegotiationErrorClass::ProviderServerError,
        ),
        (
            ChainSwapQuoteProviderErrorKind::MalformedResponse,
            RenegotiationErrorClass::MalformedResponse,
        ),
    ] {
        assert!(!kind.is_explicit_non_eligibility());
        assert_eq!(renegotiation_error_class(kind), expected);
    }
}
