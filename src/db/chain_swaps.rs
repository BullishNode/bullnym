use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::ClaimFailureOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapStatus {
    Pending,
    UserLockMempool,
    UserLockConfirmed,
    ServerLockMempool,
    ServerLockConfirmed,
    Claiming,
    Claimed,
    ClaimFailed,
    ClaimStuck,
    Expired,
    LockupFailed,
    Refunded,
    /// Funded lockup on a failed/expired swap whose BTC is still recoverable.
    /// NON-TERMINAL and the join point of the refund waterfall: set on funded
    /// failure, later drained by renegotiation (→ settle/`Claimed`) or customer
    /// self-claim (→ `Refunded`). Must never be terminalized to a dead state.
    RefundDue,
    /// Customer self-claim refund in flight (Phase 4). Set atomically from
    /// `RefundDue` in the same transaction that commits the exact BTC recovery
    /// attempt, and EXCLUDED from every claim path — this is the double-payout
    /// guard (G12): the L-BTC claim and the BTC recovery spend different UTXOs
    /// on different chains and could otherwise both confirm. NON-TERMINAL: an
    /// ambiguous broadcast remains `Refunding` and replays the committed bytes;
    /// known broadcast advances to `Refunded`.
    Refunding,
}

impl ChainSwapStatus {
    pub fn is_terminal(self) -> bool {
        // `RefundDue` and `Refunding` are deliberately NOT terminal — the
        // reconciler must keep revisiting them so the waterfall can drain them
        // (and a failed refund broadcast can revert `Refunding` → `RefundDue`).
        matches!(
            self,
            Self::Claimed | Self::ClaimStuck | Self::Expired | Self::LockupFailed | Self::Refunded
        )
    }
}

/// One provider-status observation delivered by either the Boltz webhook or
/// the reconciler. This is deliberately limited to status persistence: the
/// later chain-evidence action reducer owns claim/recovery decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapProviderStatusInput {
    /// Re-read and lock the current row without changing provider-derived
    /// state. Used for status hints such as `transaction.claimed` whose truth
    /// must be independently established by the local claim path.
    Observe,
    UserLockMempool,
    UserLockConfirmed,
    ServerLockMempool,
    ServerLockConfirmed,
    /// Boltz's wall-clock expiry hint. A funded user lock becomes recoverable;
    /// a still-viable Liquid path only switches permanently to script claim.
    SwapExpired,
    /// Provider evidence that the normal server-lock creation failed. Combined
    /// with a locally observed user lock this can make the row recoverable, but
    /// it must never overwrite a server lock or in-flight/finished settlement.
    FundingFailed,
}

/// Result of applying one provider observation under the chain-swap row lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSwapProviderTransition {
    pub previous_status: ChainSwapStatus,
    pub current_status: ChainSwapStatus,
    pub cooperative_refused: bool,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChainSwapProviderDecision {
    status: ChainSwapStatus,
    cooperative_refused: bool,
}

fn provider_progress_status(input: ChainSwapProviderStatusInput) -> Option<ChainSwapStatus> {
    match input {
        ChainSwapProviderStatusInput::UserLockMempool => Some(ChainSwapStatus::UserLockMempool),
        ChainSwapProviderStatusInput::UserLockConfirmed => Some(ChainSwapStatus::UserLockConfirmed),
        ChainSwapProviderStatusInput::ServerLockMempool => Some(ChainSwapStatus::ServerLockMempool),
        ChainSwapProviderStatusInput::ServerLockConfirmed => {
            Some(ChainSwapStatus::ServerLockConfirmed)
        }
        ChainSwapProviderStatusInput::Observe
        | ChainSwapProviderStatusInput::SwapExpired
        | ChainSwapProviderStatusInput::FundingFailed => None,
    }
}

fn provider_progress_rank(status: ChainSwapStatus) -> Option<u8> {
    match status {
        ChainSwapStatus::Pending => Some(0),
        ChainSwapStatus::UserLockMempool => Some(1),
        ChainSwapStatus::UserLockConfirmed => Some(2),
        ChainSwapStatus::ServerLockMempool => Some(3),
        ChainSwapStatus::ServerLockConfirmed => Some(4),
        // Claim, recovery, and legacy terminal states are separate branches.
        // Provider lifecycle hints may redrive their executor, but may not
        // rewrite the persisted branch back to an earlier observation.
        ChainSwapStatus::Claiming
        | ChainSwapStatus::Claimed
        | ChainSwapStatus::ClaimFailed
        | ChainSwapStatus::ClaimStuck
        | ChainSwapStatus::Expired
        | ChainSwapStatus::LockupFailed
        | ChainSwapStatus::Refunded
        | ChainSwapStatus::RefundDue
        | ChainSwapStatus::Refunding => None,
    }
}

fn reduce_chain_swap_provider_status(
    current: ChainSwapStatus,
    cooperative_refused: bool,
    input: ChainSwapProviderStatusInput,
) -> ChainSwapProviderDecision {
    if let Some(observed) = provider_progress_status(input) {
        if cooperative_refused
            && matches!(
                current,
                ChainSwapStatus::Pending
                    | ChainSwapStatus::UserLockMempool
                    | ChainSwapStatus::UserLockConfirmed
            )
            && matches!(
                observed,
                ChainSwapStatus::UserLockMempool | ChainSwapStatus::UserLockConfirmed
            )
        {
            // Expiry/failure can arrive before local payer-lock evidence. The
            // one-way refusal fact is not recovery authority by itself, but it
            // combines with a later user lock exactly as the opposite delivery
            // order does.
            return ChainSwapProviderDecision {
                status: ChainSwapStatus::RefundDue,
                cooperative_refused,
            };
        }
        let status = match (
            provider_progress_rank(current),
            provider_progress_rank(observed),
        ) {
            (Some(current_rank), Some(observed_rank)) if observed_rank > current_rank => observed,
            // `refund_due` is only a provisional recovery-eligibility branch.
            // A late valid server lock restores the normal Liquid path until a
            // recovery executor has atomically claimed ownership by moving the
            // row to `refunding`.
            (None, Some(observed_rank))
                if current == ChainSwapStatus::RefundDue
                    && observed_rank
                        >= provider_progress_rank(ChainSwapStatus::ServerLockMempool)
                            .expect("server-lock progress rank") =>
            {
                observed
            }
            _ => current,
        };
        return ChainSwapProviderDecision {
            status,
            cooperative_refused,
        };
    }

    match input {
        ChainSwapProviderStatusInput::SwapExpired => match current {
            ChainSwapStatus::UserLockMempool | ChainSwapStatus::UserLockConfirmed => {
                ChainSwapProviderDecision {
                    status: ChainSwapStatus::RefundDue,
                    // Preserve the expiry fact even if a late server lock
                    // subsequently revokes recovery eligibility.
                    cooperative_refused: true,
                }
            }
            ChainSwapStatus::Pending
            | ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::Claiming
            | ChainSwapStatus::ClaimFailed => ChainSwapProviderDecision {
                status: current,
                cooperative_refused: true,
            },
            ChainSwapStatus::Claimed
            | ChainSwapStatus::ClaimStuck
            | ChainSwapStatus::Expired
            | ChainSwapStatus::LockupFailed
            | ChainSwapStatus::Refunded
            | ChainSwapStatus::RefundDue
            | ChainSwapStatus::Refunding => ChainSwapProviderDecision {
                status: current,
                cooperative_refused,
            },
        },
        ChainSwapProviderStatusInput::FundingFailed => match current {
            ChainSwapStatus::UserLockMempool | ChainSwapStatus::UserLockConfirmed => {
                ChainSwapProviderDecision {
                    status: ChainSwapStatus::RefundDue,
                    cooperative_refused: true,
                }
            }
            // Provider failure alone is not proof that the payer funded the
            // Bitcoin lock. Pending remains pending, while the one-way fact is
            // retained so later local user-lock evidence can combine with it.
            ChainSwapStatus::Pending => ChainSwapProviderDecision {
                status: current,
                cooperative_refused: true,
            },
            ChainSwapStatus::ServerLockMempool
            | ChainSwapStatus::ServerLockConfirmed
            | ChainSwapStatus::Claiming
            | ChainSwapStatus::Claimed
            | ChainSwapStatus::ClaimFailed
            | ChainSwapStatus::ClaimStuck
            | ChainSwapStatus::Expired
            | ChainSwapStatus::LockupFailed
            | ChainSwapStatus::Refunded
            | ChainSwapStatus::RefundDue
            | ChainSwapStatus::Refunding => ChainSwapProviderDecision {
                status: current,
                cooperative_refused,
            },
        },
        ChainSwapProviderStatusInput::Observe => ChainSwapProviderDecision {
            status: current,
            cooperative_refused,
        },
        ChainSwapProviderStatusInput::UserLockMempool
        | ChainSwapProviderStatusInput::UserLockConfirmed
        | ChainSwapProviderStatusInput::ServerLockMempool
        | ChainSwapProviderStatusInput::ServerLockConfirmed => {
            unreachable!("provider progress inputs return above")
        }
    }
}

#[cfg(test)]
mod provider_transition_tests {
    use super::*;

    const ALL_STATUSES: &[ChainSwapStatus] = &[
        ChainSwapStatus::Pending,
        ChainSwapStatus::UserLockMempool,
        ChainSwapStatus::UserLockConfirmed,
        ChainSwapStatus::ServerLockMempool,
        ChainSwapStatus::ServerLockConfirmed,
        ChainSwapStatus::Claiming,
        ChainSwapStatus::Claimed,
        ChainSwapStatus::ClaimFailed,
        ChainSwapStatus::ClaimStuck,
        ChainSwapStatus::Expired,
        ChainSwapStatus::LockupFailed,
        ChainSwapStatus::Refunded,
        ChainSwapStatus::RefundDue,
        ChainSwapStatus::Refunding,
    ];

    const PROGRESS_INPUTS: &[ChainSwapProviderStatusInput] = &[
        ChainSwapProviderStatusInput::UserLockMempool,
        ChainSwapProviderStatusInput::UserLockConfirmed,
        ChainSwapProviderStatusInput::ServerLockMempool,
        ChainSwapProviderStatusInput::ServerLockConfirmed,
    ];

    #[test]
    fn provider_progress_is_monotonic_and_branch_sticky() {
        for &current in ALL_STATUSES {
            for &input in PROGRESS_INPUTS {
                let observed = provider_progress_status(input).unwrap();
                let decision = reduce_chain_swap_provider_status(current, false, input);
                let expected = match (
                    provider_progress_rank(current),
                    provider_progress_rank(observed),
                ) {
                    (Some(current_rank), Some(observed_rank)) if observed_rank > current_rank => {
                        observed
                    }
                    (None, Some(observed_rank))
                        if current == ChainSwapStatus::RefundDue
                            && observed_rank
                                >= provider_progress_rank(ChainSwapStatus::ServerLockMempool)
                                    .unwrap() =>
                    {
                        observed
                    }
                    _ => current,
                };
                assert_eq!(
                    decision.status, expected,
                    "current={current:?}, input={input:?}"
                );
                assert!(!decision.cooperative_refused);
            }
        }
    }

    #[test]
    fn duplicate_and_reordered_progress_are_noops() {
        let cases = [
            (
                ChainSwapStatus::UserLockConfirmed,
                ChainSwapProviderStatusInput::UserLockMempool,
            ),
            (
                ChainSwapStatus::UserLockConfirmed,
                ChainSwapProviderStatusInput::UserLockConfirmed,
            ),
            (
                ChainSwapStatus::ServerLockConfirmed,
                ChainSwapProviderStatusInput::ServerLockMempool,
            ),
            (
                ChainSwapStatus::ServerLockConfirmed,
                ChainSwapProviderStatusInput::UserLockMempool,
            ),
            (
                ChainSwapStatus::ClaimFailed,
                ChainSwapProviderStatusInput::ServerLockConfirmed,
            ),
        ];
        for (current, input) in cases {
            let decision = reduce_chain_swap_provider_status(current, false, input);
            assert_eq!(decision.status, current);
            assert!(!decision.cooperative_refused);
        }
    }

    #[test]
    fn expiry_preserves_liquid_progress_and_only_recovers_user_lock_states() {
        for &current in ALL_STATUSES {
            let decision = reduce_chain_swap_provider_status(
                current,
                false,
                ChainSwapProviderStatusInput::SwapExpired,
            );
            let (expected_status, expected_refused) = match current {
                ChainSwapStatus::UserLockMempool | ChainSwapStatus::UserLockConfirmed => {
                    (ChainSwapStatus::RefundDue, true)
                }
                ChainSwapStatus::Pending
                | ChainSwapStatus::ServerLockMempool
                | ChainSwapStatus::ServerLockConfirmed
                | ChainSwapStatus::Claiming
                | ChainSwapStatus::ClaimFailed => (current, true),
                ChainSwapStatus::Claimed
                | ChainSwapStatus::ClaimStuck
                | ChainSwapStatus::Expired
                | ChainSwapStatus::LockupFailed
                | ChainSwapStatus::Refunded
                | ChainSwapStatus::RefundDue
                | ChainSwapStatus::Refunding => (current, false),
            };
            assert_eq!(
                (decision.status, decision.cooperative_refused),
                (expected_status, expected_refused),
                "current={current:?}"
            );
        }
    }

    #[test]
    fn failure_evidence_cannot_overwrite_server_or_resolution_branches() {
        for &current in ALL_STATUSES {
            let decision = reduce_chain_swap_provider_status(
                current,
                false,
                ChainSwapProviderStatusInput::FundingFailed,
            );
            let (expected_status, expected_refused) = match current {
                ChainSwapStatus::UserLockMempool | ChainSwapStatus::UserLockConfirmed => {
                    (ChainSwapStatus::RefundDue, true)
                }
                ChainSwapStatus::Pending => (current, true),
                _ => (current, false),
            };
            assert_eq!(
                (decision.status, decision.cooperative_refused),
                (expected_status, expected_refused),
                "current={current:?}"
            );
        }
    }

    #[test]
    fn late_server_lock_revokes_unstarted_recovery_and_reenters_claim_path() {
        let failed = reduce_chain_swap_provider_status(
            ChainSwapStatus::UserLockConfirmed,
            false,
            ChainSwapProviderStatusInput::FundingFailed,
        );
        assert_eq!(failed.status, ChainSwapStatus::RefundDue);

        let late_server_lock = reduce_chain_swap_provider_status(
            failed.status,
            failed.cooperative_refused,
            ChainSwapProviderStatusInput::ServerLockConfirmed,
        );
        assert_eq!(
            late_server_lock.status,
            ChainSwapStatus::ServerLockConfirmed
        );

        let recovery_already_owned = reduce_chain_swap_provider_status(
            ChainSwapStatus::Refunding,
            false,
            ChainSwapProviderStatusInput::ServerLockConfirmed,
        );
        assert_eq!(
            recovery_already_owned.status,
            ChainSwapStatus::Refunding,
            "provider hints may not cross an already-owned recovery execution"
        );
    }

    #[test]
    fn early_failure_or_expiry_combines_with_later_user_lock_in_either_order() {
        for failure in [
            ChainSwapProviderStatusInput::FundingFailed,
            ChainSwapProviderStatusInput::SwapExpired,
        ] {
            let failure_first =
                reduce_chain_swap_provider_status(ChainSwapStatus::Pending, false, failure);
            assert_eq!(failure_first.status, ChainSwapStatus::Pending);
            assert!(failure_first.cooperative_refused);
            assert_eq!(
                reduce_chain_swap_provider_status(
                    failure_first.status,
                    failure_first.cooperative_refused,
                    failure,
                ),
                failure_first,
                "duplicate failure evidence must be a no-op"
            );
            let user_after = reduce_chain_swap_provider_status(
                failure_first.status,
                failure_first.cooperative_refused,
                ChainSwapProviderStatusInput::UserLockConfirmed,
            );

            let user_first = reduce_chain_swap_provider_status(
                ChainSwapStatus::Pending,
                false,
                ChainSwapProviderStatusInput::UserLockConfirmed,
            );
            let failure_after = reduce_chain_swap_provider_status(
                user_first.status,
                user_first.cooperative_refused,
                failure,
            );

            assert_eq!(user_after, failure_after, "failure={failure:?}");
            assert_eq!(user_after.status, ChainSwapStatus::RefundDue);
            assert!(user_after.cooperative_refused);
        }
    }
}

impl fmt::Display for ChainSwapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::UserLockMempool => "user_lock_mempool",
            Self::UserLockConfirmed => "user_lock_confirmed",
            Self::ServerLockMempool => "server_lock_mempool",
            Self::ServerLockConfirmed => "server_lock_confirmed",
            Self::Claiming => "claiming",
            Self::Claimed => "claimed",
            Self::ClaimFailed => "claim_failed",
            Self::ClaimStuck => "claim_stuck",
            Self::Expired => "expired",
            Self::LockupFailed => "lockup_failed",
            Self::Refunded => "refunded",
            Self::RefundDue => "refund_due",
            Self::Refunding => "refunding",
        })
    }
}

impl FromStr for ChainSwapStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "user_lock_mempool" => Ok(Self::UserLockMempool),
            "user_lock_confirmed" => Ok(Self::UserLockConfirmed),
            "server_lock_mempool" => Ok(Self::ServerLockMempool),
            "server_lock_confirmed" => Ok(Self::ServerLockConfirmed),
            "claiming" => Ok(Self::Claiming),
            "claimed" => Ok(Self::Claimed),
            "claim_failed" => Ok(Self::ClaimFailed),
            "claim_stuck" => Ok(Self::ClaimStuck),
            "expired" => Ok(Self::Expired),
            "lockup_failed" => Ok(Self::LockupFailed),
            "refunded" => Ok(Self::Refunded),
            "refund_due" => Ok(Self::RefundDue),
            "refunding" => Ok(Self::Refunding),
            other => Err(format!("unknown chain swap status: {other}")),
        }
    }
}

pub struct NewChainSwapRecord<'a> {
    pub invoice_id: Uuid,
    pub nym: Option<&'a str>,
    pub boltz_swap_id: &'a str,
    pub lockup_address: &'a str,
    pub lockup_bip21: Option<&'a str>,
    pub user_lock_amount_sat: i64,
    pub server_lock_amount_sat: i64,
    pub preimage_hex: &'a str,
    pub claim_key_hex: &'a str,
    pub refund_key_hex: &'a str,
    pub boltz_response_json: &'a str,
    /// Derivation indices of the claim/refund keys from `swap_key_seq`, and the
    /// seed fingerprint they are relative to, recorded so a rewound sequence
    /// after a DB restore is detectable. See migration 044.
    pub claim_key_index: Option<i64>,
    pub refund_key_index: Option<i64>,
    pub root_fingerprint: Option<&'a str>,
}

/// Complete non-secret evidence approved before a chain-swap payer instruction
/// is exposed. Migration 051 requires this packet on every new row and makes
/// it immutable. Historical rows decode as `None` because these facts cannot
/// be reconstructed safely after creation.
#[derive(Debug, Clone, Copy)]
pub struct NewChainSwapCreationTerms<'a> {
    pub pinned_pair_hash: &'a str,
    pub canonical_pair_quote_json: &'a str,
    pub creation_response_sha256: &'a str,
    pub btc_claim_script_sha256: &'a str,
    pub btc_refund_script_sha256: &'a str,
    pub liquid_claim_script_sha256: &'a str,
    pub liquid_refund_script_sha256: &'a str,
    pub btc_timeout_height: i64,
    pub liquid_timeout_height: i64,
    pub btc_network: &'a str,
    pub liquid_network: &'a str,
    pub liquid_asset_id: &'a str,
    pub merchant_liquid_destination: &'a str,
    pub merchant_emergency_btc_address: Option<&'a str>,
}

/// Complete creation evidence accepted by the post-053 insert path.
///
/// The optional identity keeps legacy/rolling callers source-compatible, but
/// migration 053 rejects every new row unless both this ID and the address in
/// [`NewChainSwapCreationTerms`] are present and match one immutable registry
/// row. New creation code should use this wrapper rather than the legacy
/// creation-terms insertion function.
#[derive(Debug, Clone, Copy)]
pub struct NewChainSwapCreationEvidence<'a> {
    pub creation_terms: NewChainSwapCreationTerms<'a>,
    pub recovery_address_commitment_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSwapCreationTerms {
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
    pub recovery_address_commitment_id: Option<Uuid>,
}

impl From<&NewChainSwapCreationTerms<'_>> for ChainSwapCreationTerms {
    fn from(terms: &NewChainSwapCreationTerms<'_>) -> Self {
        Self {
            pinned_pair_hash: terms.pinned_pair_hash.to_owned(),
            canonical_pair_quote_json: terms.canonical_pair_quote_json.to_owned(),
            creation_response_sha256: terms.creation_response_sha256.to_owned(),
            btc_claim_script_sha256: terms.btc_claim_script_sha256.to_owned(),
            btc_refund_script_sha256: terms.btc_refund_script_sha256.to_owned(),
            liquid_claim_script_sha256: terms.liquid_claim_script_sha256.to_owned(),
            liquid_refund_script_sha256: terms.liquid_refund_script_sha256.to_owned(),
            btc_timeout_height: terms.btc_timeout_height,
            liquid_timeout_height: terms.liquid_timeout_height,
            btc_network: terms.btc_network.to_owned(),
            liquid_network: terms.liquid_network.to_owned(),
            liquid_asset_id: terms.liquid_asset_id.to_owned(),
            merchant_liquid_destination: terms.merchant_liquid_destination.to_owned(),
            merchant_emergency_btc_address: terms.merchant_emergency_btc_address.map(str::to_owned),
            recovery_address_commitment_id: None,
        }
    }
}

impl From<&NewChainSwapCreationEvidence<'_>> for ChainSwapCreationTerms {
    fn from(evidence: &NewChainSwapCreationEvidence<'_>) -> Self {
        let mut terms = Self::from(&evidence.creation_terms);
        terms.recovery_address_commitment_id = evidence.recovery_address_commitment_id;
        terms
    }
}

pub struct ChainSwapLineage<'a> {
    pub claim_allocation_id: Uuid,
    pub refund_allocation_id: Uuid,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub claim_public_key_hex: &'a str,
    pub refund_public_key_hex: &'a str,
    pub preimage_hash_hex: &'a str,
}

#[derive(Debug, sqlx::FromRow)]
pub struct ChainSwapRecord {
    pub id: Uuid,
    pub invoice_id: Uuid,
    pub nym: Option<String>,
    pub boltz_swap_id: String,
    pub from_chain: String,
    pub to_chain: String,
    pub lockup_address: String,
    pub lockup_bip21: Option<String>,
    pub user_lock_amount_sat: i64,
    pub server_lock_amount_sat: i64,
    pub preimage_hex: String,
    pub claim_key_hex: String,
    pub refund_key_hex: String,
    pub boltz_response_json: String,
    pub status: String,
    pub claim_txid: Option<String>,
    pub claim_tx_hex: Option<String>,
    pub claim_attempts: i32,
    pub last_claim_error: Option<String>,
    pub cooperative_refused: bool,
    /// Immutable creation evidence, absent only for rows created before
    /// migration 051.
    #[sqlx(json(nullable))]
    pub creation_terms: Option<ChainSwapCreationTerms>,
    /// Server-lockup amount Boltz accepted after a Phase 3 quote renegotiation
    /// (get_quote/accept_quote), or NULL when the swap was never renegotiated.
    pub renegotiated_server_lock_amount_sat: Option<i64>,
    /// Customer-supplied BTC refund address (Phase 4), first-write-wins and
    /// immutable once set. NULL until the customer submits one.
    pub refund_address: Option<String>,
    /// Broadcast customer-refund transaction id (Phase 4), NULL until refunded.
    pub refund_txid: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl ChainSwapRecord {
    pub fn parsed_status(&self) -> Result<ChainSwapStatus, String> {
        self.status.parse()
    }

    /// Amount to credit the merchant for this swap: the renegotiated
    /// server-lockup amount if the swap was renegotiated (Phase 3), otherwise
    /// the original server-lockup amount (= invoice under gross-up pricing).
    /// After a renegotiation the on-chain L-BTC actually claimed to the
    /// merchant is the renegotiated amount, so crediting the stale original
    /// would over- or under-credit the invoice.
    pub fn effective_server_lock_amount_sat(&self) -> i64 {
        self.renegotiated_server_lock_amount_sat
            .unwrap_or(self.server_lock_amount_sat)
    }

    /// New swaps persist the exact canonical provider response alongside an
    /// immutable digest. Verify that evidence before any signing path parses
    /// or acts on it. Historical rows have no creation packet and retain their
    /// explicit legacy behavior.
    pub fn verify_creation_response_integrity(&self) -> Result<(), String> {
        let Some(terms) = self.creation_terms.as_ref() else {
            return Ok(());
        };
        let actual = creation_response_sha256(&self.boltz_response_json);
        if actual != terms.creation_response_sha256 {
            return Err(format!(
                "chain swap {} canonical creation response digest mismatch",
                self.id
            ));
        }
        Ok(())
    }
}

fn creation_response_sha256(canonical_response_json: &str) -> String {
    hex::encode(Sha256::digest(canonical_response_json.as_bytes()))
}

#[cfg(test)]
mod creation_integrity_tests {
    use super::creation_response_sha256;

    #[test]
    fn response_digest_commits_exact_canonical_bytes() {
        let canonical = r#"{"a":1,"b":2}"#;
        assert_eq!(
            creation_response_sha256(canonical),
            "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
        assert_ne!(
            creation_response_sha256(canonical),
            creation_response_sha256(r#"{"a":1, "b":2}"#)
        );
    }
}

const CHAIN_SWAP_RECORD_COLUMNS: &str =
    "id, invoice_id, nym, boltz_swap_id, from_chain, to_chain, \
     lockup_address, lockup_bip21, user_lock_amount_sat, server_lock_amount_sat, \
     preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json, status, claim_txid, \
     claim_tx_hex, claim_attempts, last_claim_error, cooperative_refused, \
     CASE WHEN pinned_pair_hash IS NULL THEN NULL ELSE jsonb_build_object( \
         'pinned_pair_hash', pinned_pair_hash, \
         'canonical_pair_quote_json', canonical_pair_quote_json, \
         'creation_response_sha256', creation_response_sha256, \
         'btc_claim_script_sha256', btc_claim_script_sha256, \
         'btc_refund_script_sha256', btc_refund_script_sha256, \
         'liquid_claim_script_sha256', liquid_claim_script_sha256, \
         'liquid_refund_script_sha256', liquid_refund_script_sha256, \
         'btc_timeout_height', btc_timeout_height, \
         'liquid_timeout_height', liquid_timeout_height, \
         'btc_network', btc_network, \
         'liquid_network', liquid_network, \
         'liquid_asset_id', liquid_asset_id, \
         'merchant_liquid_destination', merchant_liquid_destination, \
         'merchant_emergency_btc_address', merchant_emergency_btc_address, \
         'recovery_address_commitment_id', recovery_address_commitment_id \
     ) END AS creation_terms, \
     renegotiated_server_lock_amount_sat, refund_address, refund_txid, \
     EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix, \
     EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at_unix";

/// Highest claim- or refund-key index persisted for `fingerprint` across chain
/// swaps. `None` when no derivation metadata has been recorded yet. Paired with
/// [`super::max_persisted_reverse_key_index`] to bound the rollback check across
/// both swap tables. See migration 044.
pub async fn max_persisted_chain_key_index(
    pool: &PgPool,
    fingerprint: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT MAX(idx) FROM ( \
             SELECT claim_key_index AS idx FROM chain_swap_records \
                 WHERE root_fingerprint = $1 AND claim_key_index IS NOT NULL \
             UNION ALL \
             SELECT refund_key_index AS idx FROM chain_swap_records \
                 WHERE root_fingerprint = $1 AND refund_key_index IS NOT NULL \
         ) AS indices",
    )
    .bind(fingerprint)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn record_chain_swap(
    pool: &PgPool,
    swap: &NewChainSwapRecord<'_>,
) -> Result<ChainSwapRecord, sqlx::Error> {
    insert_chain_swap(pool, swap, None, None).await
}

pub async fn record_chain_swap_with_lineage(
    pool: &PgPool,
    swap: &NewChainSwapRecord<'_>,
    lineage: &ChainSwapLineage<'_>,
) -> Result<ChainSwapRecord, sqlx::Error> {
    insert_chain_swap(pool, swap, Some(lineage), None).await
}

/// Legacy migration-051 insertion API. It carries complete provider creation
/// terms but no recovery commitment identity, so migration 053 rejects its new
/// rows. It remains only for source compatibility while callers compose onto
/// [`record_chain_swap_with_lineage_and_creation_evidence`].
pub async fn record_chain_swap_with_lineage_and_creation_terms(
    pool: &PgPool,
    swap: &NewChainSwapRecord<'_>,
    lineage: &ChainSwapLineage<'_>,
    creation_terms: &NewChainSwapCreationTerms<'_>,
) -> Result<ChainSwapRecord, sqlx::Error> {
    let evidence = NewChainSwapCreationEvidence {
        creation_terms: *creation_terms,
        recovery_address_commitment_id: None,
    };
    insert_chain_swap(pool, swap, Some(lineage), Some(&evidence)).await
}

/// Persist a fully validated post-053 chain swap and its exact recovery-policy
/// identity. The database remains authoritative: `None`, a missing address,
/// or an ID/address mismatch is rejected before the row becomes durable.
pub async fn record_chain_swap_with_lineage_and_creation_evidence(
    pool: &PgPool,
    swap: &NewChainSwapRecord<'_>,
    lineage: &ChainSwapLineage<'_>,
    creation_evidence: &NewChainSwapCreationEvidence<'_>,
) -> Result<ChainSwapRecord, sqlx::Error> {
    insert_chain_swap(pool, swap, Some(lineage), Some(creation_evidence)).await
}

pub async fn record_chain_swap_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    swap: &NewChainSwapRecord<'_>,
) -> Result<ChainSwapRecord, sqlx::Error> {
    insert_chain_swap(&mut **tx, swap, None, None).await
}

async fn insert_chain_swap<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    swap: &NewChainSwapRecord<'_>,
    lineage: Option<&ChainSwapLineage<'_>>,
    creation_evidence: Option<&NewChainSwapCreationEvidence<'_>>,
) -> Result<ChainSwapRecord, sqlx::Error> {
    let creation_terms = creation_evidence.map(|evidence| &evidence.creation_terms);
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "INSERT INTO chain_swap_records \
             (invoice_id, nym, boltz_swap_id, from_chain, to_chain, lockup_address, lockup_bip21, \
              user_lock_amount_sat, server_lock_amount_sat, preimage_hex, claim_key_hex, \
              refund_key_hex, boltz_response_json, claim_key_index, refund_key_index, \
              root_fingerprint, claim_key_allocation_id, refund_key_allocation_id, \
              key_epoch, derivation_scheme_version, claim_public_key_hex, \
              refund_public_key_hex, preimage_hash_hex, pinned_pair_hash, \
              canonical_pair_quote_json, creation_response_sha256, \
              btc_claim_script_sha256, btc_refund_script_sha256, \
              liquid_claim_script_sha256, liquid_refund_script_sha256, \
              btc_timeout_height, liquid_timeout_height, btc_network, liquid_network, \
              liquid_asset_id, merchant_liquid_destination, \
              merchant_emergency_btc_address, recovery_address_commitment_id) \
         VALUES ($1, $2, $3, 'BTC', 'L-BTC', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                 $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, \
                 $30, $31, $32, $33, $34, $35, $36) \
         RETURNING {CHAIN_SWAP_RECORD_COLUMNS}"
    ))
    .bind(swap.invoice_id)
    .bind(swap.nym)
    .bind(swap.boltz_swap_id)
    .bind(swap.lockup_address)
    .bind(swap.lockup_bip21)
    .bind(swap.user_lock_amount_sat)
    .bind(swap.server_lock_amount_sat)
    .bind(swap.preimage_hex)
    .bind(swap.claim_key_hex)
    .bind(swap.refund_key_hex)
    .bind(swap.boltz_response_json)
    .bind(swap.claim_key_index)
    .bind(swap.refund_key_index)
    .bind(swap.root_fingerprint)
    .bind(lineage.map(|lineage| lineage.claim_allocation_id))
    .bind(lineage.map(|lineage| lineage.refund_allocation_id))
    .bind(lineage.map(|lineage| lineage.key_epoch))
    .bind(lineage.map(|lineage| lineage.derivation_scheme_version))
    .bind(lineage.map(|lineage| lineage.claim_public_key_hex))
    .bind(lineage.map(|lineage| lineage.refund_public_key_hex))
    .bind(lineage.map(|lineage| lineage.preimage_hash_hex))
    .bind(creation_terms.map(|terms| terms.pinned_pair_hash))
    .bind(creation_terms.map(|terms| terms.canonical_pair_quote_json))
    .bind(creation_terms.map(|terms| terms.creation_response_sha256))
    .bind(creation_terms.map(|terms| terms.btc_claim_script_sha256))
    .bind(creation_terms.map(|terms| terms.btc_refund_script_sha256))
    .bind(creation_terms.map(|terms| terms.liquid_claim_script_sha256))
    .bind(creation_terms.map(|terms| terms.liquid_refund_script_sha256))
    .bind(creation_terms.map(|terms| terms.btc_timeout_height))
    .bind(creation_terms.map(|terms| terms.liquid_timeout_height))
    .bind(creation_terms.map(|terms| terms.btc_network))
    .bind(creation_terms.map(|terms| terms.liquid_network))
    .bind(creation_terms.map(|terms| terms.liquid_asset_id))
    .bind(creation_terms.map(|terms| terms.merchant_liquid_destination))
    .bind(creation_terms.and_then(|terms| terms.merchant_emergency_btc_address))
    .bind(creation_evidence.and_then(|evidence| evidence.recovery_address_commitment_id))
    .fetch_one(executor)
    .await
}

pub async fn get_chain_swap_by_boltz_id(
    pool: &PgPool,
    boltz_swap_id: &str,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records WHERE boltz_swap_id = $1"
    ))
    .bind(boltz_swap_id)
    .fetch_optional(pool)
    .await
}

pub async fn get_chain_swap_by_id<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
}

/// Same as [`get_chain_swap_by_id`] but takes a `FOR UPDATE` row lock, so a
/// read-modify-write inside a transaction serializes against concurrent
/// `update_chain_swap_status` writers (which run lock-free on the pool). Used by
/// the Phase 3 renegotiation path to re-read the row under the advisory lock
/// before persisting the renegotiated amount.
pub async fn get_chain_swap_by_id_for_update<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
}

pub async fn latest_payable_chain_swap_for_invoice<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    invoice_id: Uuid,
    amount_sat: i64,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        // Match on server_lock_amount_sat (the L-BTC settled to the merchant,
        // = the invoice/remaining amount) NOT user_lock_amount_sat: under
        // payer-pays gross-up pricing the user lockup is grossed up above the
        // invoice, so matching user_lock would never find the swap and the BTC
        // rail would silently vanish from the payment page + status API.
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} FROM chain_swap_records \
         WHERE invoice_id = $1 \
           AND status = 'pending' \
           AND server_lock_amount_sat = $2 \
         ORDER BY created_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .bind(amount_sat)
    .fetch_optional(executor)
    .await
}

/// Atomically fold one webhook/reconciliation provider status into the
/// persisted chain-swap lifecycle.
///
/// The row lock makes concurrent webhook and polling inputs serialize on the
/// latest committed state. The reducer is monotonic for provider progress,
/// keeps owned recovery/claim branches sticky, lets a late server lock revoke
/// only an unstarted `refund_due`, and treats duplicates as true no-ops
/// (including preserving `updated_at`). No delivery-dedup row participates in
/// this correctness decision, so an aborted caller can safely retry the same
/// evidence later.
pub async fn apply_chain_swap_provider_status(
    pool: &PgPool,
    id: Uuid,
    input: ChainSwapProviderStatusInput,
) -> Result<Option<ChainSwapProviderTransition>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let Some(current) = get_chain_swap_by_id_for_update(&mut *tx, id).await? else {
        tx.commit().await?;
        return Ok(None);
    };
    let previous_status = current.parsed_status().map_err(|error| {
        sqlx::Error::Protocol(format!(
            "invalid persisted chain swap status for {}: {error}",
            current.id
        ))
    })?;
    let decision =
        reduce_chain_swap_provider_status(previous_status, current.cooperative_refused, input);
    let changed = decision.status != previous_status
        || decision.cooperative_refused != current.cooperative_refused;

    if changed {
        let updated = sqlx::query(
            "UPDATE chain_swap_records \
             SET status = $2, cooperative_refused = $3, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .bind(decision.status.to_string())
        .bind(decision.cooperative_refused)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(sqlx::Error::Protocol(format!(
                "locked chain swap disappeared during provider transition: {id}"
            )));
        }
    }

    tx.commit().await?;
    Ok(Some(ChainSwapProviderTransition {
        previous_status,
        current_status: decision.status,
        cooperative_refused: decision.cooperative_refused,
        changed,
    }))
}

pub async fn update_chain_swap_status(
    pool: &PgPool,
    id: Uuid,
    status: ChainSwapStatus,
    claim_txid: Option<&str>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = $2, claim_txid = COALESCE($3, claim_txid), updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refunding')",
    )
    .bind(id)
    .bind(status.to_string())
    .bind(claim_txid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn get_ready_to_claim_chain_swaps(
    pool: &PgPool,
) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE status IN ('server_lock_mempool', 'server_lock_confirmed', 'claiming', 'claim_failed') \
           AND (next_claim_attempt_at IS NULL OR next_claim_attempt_at <= NOW()) \
         ORDER BY next_claim_attempt_at NULLS FIRST"
    ))
    .fetch_all(pool)
    .await
}

/// Flip `cooperative_refused` to TRUE (one-way). Set when Boltz reports
/// `swap.expired` for a chain swap, or when a cooperative claim is refused at
/// runtime, so the next claim attempt takes the script path. Never writes
/// through a terminal row. Mirrors `swaps::mark_cooperative_refused`.
pub async fn mark_chain_swap_cooperative_refused<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET cooperative_refused = TRUE, updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refunding')",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Mark a funded-but-failed/expired chain swap `refund_due` (non-terminal) so
/// its BTC is recoverable rather than silently terminalized. Guarded against
/// terminal rows; NOT guarded against `refund_due` itself so this is
/// idempotent. `refund_due` is not in the terminal NOT-IN set, so a later
/// `update_chain_swap_status` can still advance it to `claimed` (renegotiation)
/// or `refunded` (self-claim) — that is the join point of the refund waterfall.
pub async fn mark_chain_swap_refund_due(pool: &PgPool, id: Uuid) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'refund_due', updated_at = NOW() \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refunding')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Records a successful Phase 3 quote renegotiation: persists the server-lockup
/// amount Boltz accepted and returns the swap to a live lifecycle state
/// (`user_lock_confirmed`) so the normal claim path drives it to settlement as
/// Boltz creates its (renegotiated) server lockup. Guarded to be idempotent —
/// only the first renegotiation on a still-live, not-yet-renegotiated row takes
/// effect (a re-delivered `lockupFailed` webhook is a no-op), and it never
/// resurrects a terminal swap. Returns rows affected (1 = applied, 0 = a
/// concurrent/duplicate call already handled it or the row is terminal).
pub async fn mark_chain_swap_renegotiated<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
    renegotiated_server_lock_amount_sat: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        // Persist the renegotiated amount UNCONDITIONALLY as long as the swap is
        // still live and not already renegotiated — crediting reads this, so it
        // must be recorded even if a concurrent `transaction.server.mempool`
        // webhook has already advanced the status past the funded lockup states.
        // The status nudge back to `user_lock_confirmed` is therefore CASE-gated:
        // only applied when still in a pre-server-lock funded state, so we never
        // REGRESS a more-advanced lifecycle state (the race SHOULD-FIX 3 flags).
        // `refund_due` is excluded from the guard so a late/duplicate
        // `lockupFailed` cannot resurrect an operator-visible refund case.
        "UPDATE chain_swap_records \
         SET renegotiated_server_lock_amount_sat = $2, \
             renegotiated_at = NOW(), \
             status = CASE \
                 WHEN status IN ('user_lock_mempool', 'user_lock_confirmed') \
                 THEN 'user_lock_confirmed' ELSE status END, \
             updated_at = NOW() \
         WHERE id = $1 \
           AND renegotiated_server_lock_amount_sat IS NULL \
           AND status NOT IN \
               ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck', 'refund_due', 'refunding')",
    )
    .bind(id)
    .bind(renegotiated_server_lock_amount_sat)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Chain swaps currently in `refund_due`, oldest first. Backs the operator
/// surface listing stranded-but-recoverable lockups.
/// Chain swaps that reached terminal `claimed` (merchant funds are on chain)
/// with a persisted claim txid, but whose `bitcoin_boltz_chain` invoice payment
/// event is missing — the crash-consistency gap in issue #61. The mirror of
/// `list_claimed_swaps_missing_lightning_event` for the chain rail: a crash or
/// error between marking `claimed` and recording the payment event leaves the
/// merchant paid while the invoice looks unpaid, and `claimed` is terminal so
/// normal reconciliation no longer selects the row.
///
/// Requires a persisted `claim_txid` — a terminal status alone is NOT treated
/// as proof of payment (a row without claim evidence is surfaced as an
/// integrity incident by the caller, never fabricated into a payment).
/// Bounded + oldest-first so repair cannot monopolize the reconciler.
pub(crate) const CHAIN_SETTLEMENT_REPAIR_ELIGIBILITY_SQL: &str = "WHERE c.status = 'claimed' \
       AND c.claim_txid IS NOT NULL \
       AND c.updated_at <= scan.epoch \
       AND c.updated_at > scan.epoch - ($1 || ' seconds')::interval \
       AND ($3::uuid IS NULL OR c.id > $3) \
       AND NOT EXISTS ( \
             SELECT 1 FROM invoice_payment_events e \
              WHERE e.invoice_id = c.invoice_id \
                AND e.event_key = 'bitcoin_boltz_chain:' || c.boltz_swap_id \
         )";

pub async fn list_claimed_chain_swaps_missing_payment_event(
    pool: &PgPool,
    max_age_secs: u64,
    epoch_micros: i64,
    after_id: Option<Uuid>,
    limit: u32,
) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "WITH scan AS ( \
             SELECT to_timestamp($2::double precision / 1000000.0) AS epoch \
         ) \
         SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records c, scan \
         {CHAIN_SETTLEMENT_REPAIR_ELIGIBILITY_SQL} \
         ORDER BY c.id ASC \
         LIMIT $4"
    ))
    .bind(max_age_secs as i64)
    .bind(epoch_micros)
    .bind(after_id)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
}

pub async fn list_refund_due_chain_swaps(
    pool: &PgPool,
) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE status = 'refund_due' \
         ORDER BY created_at ASC"
    ))
    .fetch_all(pool)
    .await
}

/// The `refund_due` chain swap for an invoice, if any (Phase 4). Used by the
/// customer self-claim endpoint to locate the swap whose BTC is refundable.
/// There is at most one refundable chain swap per invoice in practice; newest
/// first for determinism.
pub async fn find_refund_due_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE invoice_id = $1 AND status = 'refund_due' \
         ORDER BY created_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(pool)
    .await
}

/// The already-`refunded` chain swap for an invoice, if any (Phase 4). Lets the
/// self-claim endpoint short-circuit a retried request idempotently — returning
/// the recorded `refund_txid` instead of erroring because the swap is no longer
/// `refund_due`.
pub async fn get_refunded_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE invoice_id = $1 AND status = 'refunded' \
         ORDER BY updated_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(pool)
    .await
}

/// The in-flight (`refunding`) chain swap for an invoice, if any (Phase 4).
/// Lets the recovery endpoint return a distinct "recovery in progress" signal
/// (rather than "not available") when a merchant retries during the broadcast
/// window or while a stuck row awaits the reconciler backstop.
pub async fn get_refunding_chain_swap_for_invoice(
    pool: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records \
         WHERE invoice_id = $1 AND status = 'refunding' \
         ORDER BY updated_at DESC \
         LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(pool)
    .await
}

/// Merchant-detection projection: one row per chain swap of this npub in a
/// recovery lifecycle state (`refund_due | refunding | refunded`), joined with
/// minimal invoice context. Excludes ALL key material (`preimage_hex`,
/// `claim_key_hex`, `refund_key_hex`, `boltz_response_json`, `boltz_swap_id`)
/// by construction — those columns are never selected. Backs the signed
/// `GET /api/v1/invoices/recoverable` detection endpoint; see
/// `invoice::list_recoverable_signed`.
#[derive(Debug, sqlx::FromRow)]
pub struct RecoverableChainSwapRow {
    pub invoice_id: Uuid,
    /// Owning nym (SF1 guarantees this is set for any swap that can exist; a
    /// NULL row is legacy/manual data the API path skips). Used to build the
    /// per-nym recover URL client-side.
    pub nym: Option<String>,
    pub status: String,
    pub user_lock_amount_sat: i64,
    /// COALESCE(renegotiated, original) — the renegotiation-aware value.
    pub effective_server_lock_amount_sat: i64,
    pub lockup_address: String,
    /// Committed first-write-wins refund destination, or NULL. Part of the
    /// reinstall reconciliation payload.
    pub refund_address: Option<String>,
    /// Broadcast recovery txid, or NULL until `refunded`.
    pub refund_txid: Option<String>,
    pub swap_created_at_unix: i64,
    pub swap_updated_at_unix: i64,
    pub invoice_status: String,
    pub invoice_amount_sat: i64,
    pub invoice_fiat_amount_minor: Option<i32>,
    pub invoice_fiat_currency: Option<String>,
    pub invoice_public_description: Option<String>,
    pub invoice_number: Option<String>,
    pub invoice_created_at_unix: i64,
}

/// All chain swaps owned by `npub_owner` currently in a recovery lifecycle
/// state, oldest-first within status (`refund_due` before `refunding` before
/// `refunded`). Scoped by `invoices.npub_owner`, so it answers "does this
/// merchant have stranded funds?" in one query with no pagination — the
/// populated size is stuck-swap incidents (expected 0). `limit` is applied as a
/// hard cap (handler passes `RECOVERABLE_LIST_LIMIT + 1` to detect overflow).
/// Driven by `chain_swap_records_status_idx` (migration 025) over a globally
/// rare status set. Selects no key material.
pub async fn list_recoverable_chain_swaps_for_npub(
    pool: &PgPool,
    npub_owner: &str,
    limit: i64,
) -> Result<Vec<RecoverableChainSwapRow>, sqlx::Error> {
    sqlx::query_as::<_, RecoverableChainSwapRow>(
        "SELECT cs.invoice_id, \
                cs.nym, \
                cs.status, \
                cs.user_lock_amount_sat, \
                COALESCE(cs.renegotiated_server_lock_amount_sat, \
                         cs.server_lock_amount_sat) AS effective_server_lock_amount_sat, \
                cs.lockup_address, \
                cs.refund_address, \
                cs.refund_txid, \
                EXTRACT(EPOCH FROM cs.created_at)::BIGINT AS swap_created_at_unix, \
                EXTRACT(EPOCH FROM cs.updated_at)::BIGINT AS swap_updated_at_unix, \
                i.status AS invoice_status, \
                i.amount_sat AS invoice_amount_sat, \
                i.fiat_amount_minor AS invoice_fiat_amount_minor, \
                i.fiat_currency AS invoice_fiat_currency, \
                i.public_description AS invoice_public_description, \
                i.invoice_number, \
                EXTRACT(EPOCH FROM i.created_at)::BIGINT AS invoice_created_at_unix \
         FROM chain_swap_records cs \
         JOIN invoices i ON i.id = cs.invoice_id \
         WHERE i.npub_owner = $1 \
           AND cs.status IN ('refund_due', 'refunding', 'refunded') \
         ORDER BY CASE cs.status \
                      WHEN 'refund_due' THEN 0 \
                      WHEN 'refunding'  THEN 1 \
                      ELSE 2 \
                  END, \
                  cs.created_at ASC \
         LIMIT $2",
    )
    .bind(npub_owner)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Records the customer's BTC refund address, FIRST-WRITE-WINS and immutable
/// (G13/G14): the UPDATE only fires when `refund_address IS NULL` and the swap
/// is still `refund_due`, so a bystander who knows the public invoice URL cannot
/// overwrite an address already committed. Returns rows affected (1 = this call
/// set it; 0 = already set, or the swap is no longer `refund_due`). The caller
/// distinguishes "already set to the same address" (idempotent success) from
/// "set to a different address" (reject) by reading the row.
pub async fn set_chain_swap_refund_address(
    pool: &PgPool,
    id: Uuid,
    refund_address: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET refund_address = $2, updated_at = NOW() \
         WHERE id = $1 AND refund_address IS NULL AND status = 'refund_due'",
    )
    .bind(id)
    .bind(refund_address)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Atomically transitions `refund_due` -> `refunding` (Phase 4 G12 double-payout
/// guard). Only fires from `refund_due` with a refund address already committed;
/// `refunding` is excluded from every claim path, so once this succeeds no claim
/// can start. Runs inside the caller's advisory-locked transaction. Returns rows
/// affected (1 = we own the refund; 0 = not `refund_due`, or no address).
pub async fn mark_chain_swap_refunding<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        // `claim_txid IS NULL` is the G12 double-payout guard: a swap can reach
        // `refund_due` from `claiming`/`claim_failed` while our L-BTC claim tx is
        // still unconfirmed in the mempool (preimage already public). Refunding
        // the BTC lockup then would pay the customer AND let the merchant's claim
        // confirm — a genuine double payout. If we ever constructed/broadcast a
        // claim, refuse the refund and let the claim path win.
        "UPDATE chain_swap_records \
         SET status = 'refunding', updated_at = NOW() \
         WHERE id = $1 AND status = 'refund_due' \
           AND refund_address IS NOT NULL \
           AND claim_txid IS NULL AND claim_tx_hex IS NULL",
    )
    .bind(id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Terminal success: `refunding` -> `refunded`, recording the broadcast txid.
/// Legacy/test compatibility helper; the journal executor uses the stricter
/// atomic attempt+swap update. Guarded to `refunding` so it cannot terminalize
/// a swap that was never in flight. Returns rows affected.
pub async fn mark_chain_swap_refunded(
    pool: &PgPool,
    id: Uuid,
    refund_txid: &str,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'refunded', refund_txid = $2, updated_at = NOW() \
         WHERE id = $1 AND status = 'refunding'",
    )
    .bind(id)
    .bind(refund_txid)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Stale in-flight Bitcoin recoveries for the reconciler.  They must remain in
/// `refunding`: resetting to `refund_due` used to authorize reconstruction
/// after an ambiguous broadcast.  The journal executor instead reloads and
/// reconciles/rebroadcasts the exact committed attempt.  Legacy rows without
/// an attempt are returned too so the executor can stop them with an explicit
/// integrity alert rather than silently manufacture new bytes.
pub(crate) const STALE_REFUNDING_CHAIN_SCAN_ELIGIBILITY_SQL: &str = "WHERE c.status = 'refunding' \
       AND c.updated_at <= scan.epoch - ($1 || ' seconds')::interval \
       AND ($3::uuid IS NULL OR c.id > $3)";

pub async fn list_stale_refunding_chain_swaps(
    pool: &PgPool,
    min_age_secs: i64,
    epoch_micros: i64,
    after_id: Option<Uuid>,
    limit: u32,
) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "WITH scan AS ( \
             SELECT to_timestamp($2::double precision / 1000000.0) AS epoch \
         ) \
         SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
           FROM chain_swap_records c, scan \
          {STALE_REFUNDING_CHAIN_SCAN_ELIGIBILITY_SQL} \
          ORDER BY c.id ASC \
          LIMIT $4"
    ))
    .bind(min_age_secs)
    .bind(epoch_micros)
    .bind(after_id)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
}

/// Non-terminal chain swaps in the frozen `epoch_micros` snapshot, older than
/// `min_age_secs`, not yet visited in that epoch, and capped at `limit`. Drives
/// the chain-swap reconciler: unlike the claim sweep
/// (`get_ready_to_claim_chain_swaps`, which only covers server-lock/claiming
/// states), this covers EVERY non-terminal state — including `pending` and
/// `user_lock_*` — so a chain swap stranded by a dropped Boltz webhook is
/// re-driven by polling Boltz `get_swap`. Mirrors
/// `swaps::list_non_terminal_swaps_oldest_first`.
pub(crate) const CHAIN_RECONCILER_ELIGIBILITY_SQL: &str =
    "WHERE c.status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck') \
       AND c.status <> 'refunding' \
       AND c.updated_at <= scan.epoch - ($1 || ' seconds')::interval \
       AND ($3::uuid IS NULL OR c.id > $3)";

pub async fn list_non_terminal_chain_swaps_oldest_first(
    pool: &PgPool,
    min_age_secs: u64,
    epoch_micros: i64,
    after_id: Option<Uuid>,
    limit: u32,
) -> Result<Vec<ChainSwapRecord>, sqlx::Error> {
    sqlx::query_as::<_, ChainSwapRecord>(&format!(
        "WITH scan AS ( \
             SELECT to_timestamp($2::double precision / 1000000.0) AS epoch \
         ) \
         SELECT {CHAIN_SWAP_RECORD_COLUMNS} \
         FROM chain_swap_records c, scan \
         {CHAIN_RECONCILER_ELIGIBILITY_SQL} \
         ORDER BY c.id ASC \
         LIMIT $4"
    ))
    .bind(min_age_secs as i64)
    .bind(epoch_micros)
    .bind(after_id)
    .bind(limit as i64)
    .fetch_all(pool)
    .await
}

pub async fn record_chain_swap_claim_failure(
    pool: &PgPool,
    id: Uuid,
    error_msg: &str,
    max_attempts: i32,
) -> Result<ClaimFailureOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let bumped: Option<(i32,)> = sqlx::query_as(
        "UPDATE chain_swap_records \
         SET claim_attempts = claim_attempts + 1, \
             last_claim_error = $2, \
             last_claim_error_at = NOW(), \
             updated_at = NOW(), \
             next_claim_attempt_at = NOW() + ( \
                 CASE \
                     WHEN claim_attempts + 1 <= 1 THEN INTERVAL '10 seconds' \
                     WHEN claim_attempts + 1 = 2 THEN INTERVAL '20 seconds' \
                     WHEN claim_attempts + 1 = 3 THEN INTERVAL '60 seconds' \
                     WHEN claim_attempts + 1 = 4 THEN INTERVAL '300 seconds' \
                     WHEN claim_attempts + 1 = 5 THEN INTERVAL '600 seconds' \
                     WHEN claim_attempts + 1 = 6 THEN INTERVAL '1800 seconds' \
                     ELSE INTERVAL '3600 seconds' \
                 END \
             ) * (0.8 + 0.4 * random()) \
         WHERE id = $1 \
           AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck') \
         RETURNING claim_attempts",
    )
    .bind(id)
    .bind(error_msg)
    .fetch_optional(&mut *tx)
    .await?;

    let outcome = match bumped {
        None => ClaimFailureOutcome::NoOp,
        Some((attempts,)) if attempts >= max_attempts => {
            sqlx::query(
                "UPDATE chain_swap_records \
                 SET status = 'claim_stuck', updated_at = NOW() \
                 WHERE id = $1 \
                   AND status NOT IN ('claimed', 'expired', 'lockup_failed', 'refunded', 'claim_stuck')",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            ClaimFailureOutcome::Stuck
        }
        Some(_) => ClaimFailureOutcome::Scheduled,
    };

    tx.commit().await?;
    Ok(outcome)
}

/// Funded chain swaps stranded in `claim_stuck` whose slow-recovery backoff is
/// due (issue #63). Bounded + oldest-first; returns `(id, boltz_swap_id,
/// slow_attempts)`. Mirror of `swaps::list_claim_stuck_swaps_for_slow_retry`.
pub async fn list_claim_stuck_chain_swaps_for_slow_retry(
    pool: &PgPool,
    limit: u32,
) -> Result<Vec<(Uuid, String, i32)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, String, i32)>(
        "SELECT id, boltz_swap_id, slow_attempts \
         FROM chain_swap_records \
         WHERE status = 'claim_stuck' \
           AND (next_slow_attempt_at IS NULL OR next_slow_attempt_at <= NOW()) \
         ORDER BY next_slow_attempt_at NULLS FIRST \
         LIMIT $1",
    )
    .bind(limit as i64)
    .fetch_all(pool)
    .await
}

/// Revive a `claim_stuck` chain swap into the normal claim sweep for exactly one
/// more attempt (status → `claim_failed`, which `get_ready_to_claim_chain_swaps`
/// selects; `claim_attempts → max-1`; due now) and schedule the next slow
/// revival with capped backoff. Guarded on `status='claim_stuck'`. The retry's
/// own outspend-probe recovery handles an already-spent lockup, so this never
/// blindly rebuilds. Returns rows affected (0 or 1). Mirror of
/// `swaps::revive_claim_stuck_swap_for_slow_retry`.
pub async fn revive_claim_stuck_chain_swap_for_slow_retry(
    pool: &PgPool,
    id: Uuid,
    max_attempts: i32,
    backoff_secs: u64,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE chain_swap_records \
         SET status = 'claim_failed', \
             claim_attempts = GREATEST(0, $2 - 1), \
             next_claim_attempt_at = NOW(), \
             slow_attempts = slow_attempts + 1, \
             next_slow_attempt_at = NOW() + (($3 || ' seconds')::interval) * (0.8 + 0.4 * random()), \
             updated_at = NOW() \
         WHERE id = $1 AND status = 'claim_stuck'",
    )
    .bind(id)
    .bind(max_attempts)
    .bind(backoff_secs as i64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn clear_chain_swap_claim_failure_state(
    pool: &PgPool,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE chain_swap_records \
         SET last_claim_error = NULL, \
             last_claim_error_at = NULL, \
             next_claim_attempt_at = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}
