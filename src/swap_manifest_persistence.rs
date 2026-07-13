//! Unwired durable provider-result persistence and manifest delivery for one
//! chain swap.
//!
//! The fully validated migration-050/051 chain-swap row is committed first so
//! no later recovery-manifest failure can erase the only canonical record of a
//! provider-created swap. That row remains a non-terminal `pending`
//! obligation. A following transaction owns the migration-052 ledger tail,
//! stages from the exact persisted evidence, and inserts the pending delivery
//! row. After commit, the immutable delivery is synchronously
//! create/read-verified off-host and acknowledged before the secret-bearing
//! [`crate::db::ChainSwapRecord`] can be returned.
//!
//! Every failure after canonical row persistence deliberately returns no swap
//! record, withholding the payer instruction. A post-ledger-commit failure
//! also leaves the sole pending delivery available to
//! [`crate::swap_manifest_delivery::resume_pending_manifest_delivery`]. This
//! module does not participate in invoice creation, admission, startup, worker
//! scheduling, or retry policy.

use std::fmt;

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::db::{
    insert_manifest_delivery, load_manifest_staging_evidence, lock_manifest_delivery_tail,
    record_chain_swap_with_lineage_and_creation_terms, ChainSwapLineage, ChainSwapRecord,
    ManifestDeliveryError, NewChainSwapCreationTerms, NewChainSwapRecord,
};
use crate::swap_manifest::MerchantPolicyReferencesV1;
use crate::swap_manifest_delivery::{
    deliver_exact_manifest_delivery, ManifestDeliveryResumeOutcome,
};
use crate::swap_manifest_staging::{
    stage_swap_manifest_v1, ManifestStagingCrypto, ManifestStagingRequest,
};
use crate::swap_manifest_store::RecoveryManifestStore;

/// Complete borrowed input for one atomic persist-and-deliver attempt.
///
/// This type implements neither `Clone` nor `Debug`: it borrows the private
/// swap material and the manifest cryptographic material without creating a
/// format surface for either.
pub struct PersistAndDeliverChainSwapRequest<'a> {
    pub swap: &'a NewChainSwapRecord<'a>,
    pub lineage: &'a ChainSwapLineage<'a>,
    pub creation_terms: &'a NewChainSwapCreationTerms<'a>,
    pub manifest_id: Uuid,
    pub merchant_policy: &'a MerchantPolicyReferencesV1,
    pub crypto: ManifestStagingCrypto<'a>,
}

/// Fixed, source-free failure classes for the atomic persistence boundary.
///
/// No variant retains SQLx/object-store errors, provider responses, endpoints,
/// object identities, envelope bytes, private keys, or other request values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistAndDeliverChainSwapError {
    TransactionBeginFailed,
    PendingManifestDelivery,
    ManifestTailReservationFailed,
    ChainSwapPersistenceFailed,
    ManifestEvidenceReadFailed,
    ManifestEvidenceMissing,
    ManifestStagingFailed,
    ManifestIdentityFailed,
    ManifestLedgerInsertFailed,
    ManifestLedgerInvariantFailed,
    TransactionRollbackFailed,
    TransactionCommitFailed,
    ManifestDeliveryFailed,
    ManifestDeliveryInvariantFailed,
}

impl fmt::Display for PersistAndDeliverChainSwapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TransactionBeginFailed => "chain-swap persistence transaction could not begin",
            Self::PendingManifestDelivery => "a prior recovery-manifest delivery is still pending",
            Self::ManifestTailReservationFailed => {
                "recovery-manifest ledger tail could not be reserved"
            }
            Self::ChainSwapPersistenceFailed => "validated chain swap could not be persisted",
            Self::ManifestEvidenceReadFailed => {
                "persisted recovery-manifest evidence could not be read"
            }
            Self::ManifestEvidenceMissing => {
                "persisted recovery-manifest evidence is unexpectedly absent"
            }
            Self::ManifestStagingFailed => "recovery manifest could not be staged",
            Self::ManifestIdentityFailed => "recovery-manifest identity is invalid",
            Self::ManifestLedgerInsertFailed => {
                "pending recovery-manifest delivery could not be persisted"
            }
            Self::ManifestLedgerInvariantFailed => {
                "pending recovery-manifest delivery did not match staged evidence"
            }
            Self::TransactionRollbackFailed => "chain-swap persistence transaction rollback failed",
            Self::TransactionCommitFailed => "chain-swap persistence transaction commit failed",
            Self::ManifestDeliveryFailed => "recovery-manifest durable delivery failed",
            Self::ManifestDeliveryInvariantFailed => {
                "recovery-manifest durable delivery did not match the committed row"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for PersistAndDeliverChainSwapError {}

/// Persist one canonical provider-created chain swap first, then stage,
/// durably deliver, and acknowledge its exact manifest before returning it to
/// the payer-facing caller.
///
/// Once the first insert succeeds, every later error leaves that row intact in
/// non-terminal `pending` state. Callers must treat every error as a hard
/// refusal to expose the payer address.
pub async fn persist_and_deliver_chain_swap(
    pool: &PgPool,
    store: &RecoveryManifestStore,
    request: PersistAndDeliverChainSwapRequest<'_>,
) -> Result<ChainSwapRecord, PersistAndDeliverChainSwapError> {
    let PersistAndDeliverChainSwapRequest {
        swap,
        lineage,
        creation_terms,
        manifest_id,
        merchant_policy,
        crypto,
    } = request;

    // This is the crash-safety boundary immediately after the mutating
    // provider call. Do not put the only canonical provider response, keys,
    // and lineage inside the manifest transaction: a staging or ledger error
    // would roll all of it back and make the remote swap undiscoverable.
    let chain_swap =
        record_chain_swap_with_lineage_and_creation_terms(pool, swap, lineage, creation_terms)
            .await
            .map_err(|_| PersistAndDeliverChainSwapError::ChainSwapPersistenceFailed)?;

    // Only the manifest-ledger reservation and row are transactional from
    // here. Rolling this transaction back must never erase `chain_swap`.
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| PersistAndDeliverChainSwapError::TransactionBeginFailed)?;

    let reservation = match lock_manifest_delivery_tail(&mut tx).await {
        Ok(reservation) => reservation,
        Err(ManifestDeliveryError::PendingDelivery { .. }) => {
            return Err(rollback_or_replace(
                tx,
                PersistAndDeliverChainSwapError::PendingManifestDelivery,
            )
            .await);
        }
        Err(_) => {
            return Err(rollback_or_replace(
                tx,
                PersistAndDeliverChainSwapError::ManifestTailReservationFailed,
            )
            .await);
        }
    };

    let evidence = match load_manifest_staging_evidence(&mut *tx, chain_swap.id).await {
        Ok(Some(evidence)) => evidence,
        Ok(None) => {
            return Err(rollback_or_replace(
                tx,
                PersistAndDeliverChainSwapError::ManifestEvidenceMissing,
            )
            .await);
        }
        Err(_) => {
            return Err(rollback_or_replace(
                tx,
                PersistAndDeliverChainSwapError::ManifestEvidenceReadFailed,
            )
            .await);
        }
    };

    let staged = match stage_swap_manifest_v1(ManifestStagingRequest {
        chain_swap: &chain_swap,
        persisted_lineage: &evidence.persisted_lineage,
        claim_allocation: &evidence.claim_allocation,
        refund_allocation: &evidence.refund_allocation,
        sequence_reservation: reservation,
        manifest_id,
        allocation_high_water: &evidence.allocation_high_water,
        merchant_policy,
        crypto,
    }) {
        Ok(staged) => staged,
        Err(_) => {
            return Err(rollback_or_replace(
                tx,
                PersistAndDeliverChainSwapError::ManifestStagingFailed,
            )
            .await);
        }
    };

    let identity = match reservation.identity(manifest_id, chain_swap.id) {
        Ok(identity) => identity,
        Err(_) => {
            return Err(rollback_or_replace(
                tx,
                PersistAndDeliverChainSwapError::ManifestIdentityFailed,
            )
            .await);
        }
    };
    let delivery =
        match insert_manifest_delivery(&mut tx, &identity, &staged.encrypted_envelope).await {
            Ok(delivery) => delivery,
            Err(_) => {
                return Err(rollback_or_replace(
                    tx,
                    PersistAndDeliverChainSwapError::ManifestLedgerInsertFailed,
                )
                .await);
            }
        };

    let expected_digest = hex::encode(Sha256::digest(
        staged.encrypted_envelope.encoded().as_bytes(),
    ));
    if delivery.identity() != identity
        || delivery.encrypted_envelope() != &staged.encrypted_envelope
        || delivery.envelope_sha256 != expected_digest
        || delivery.delivery_state != "pending"
        || delivery.delivered_at_unix.is_some()
    {
        return Err(rollback_or_replace(
            tx,
            PersistAndDeliverChainSwapError::ManifestLedgerInvariantFailed,
        )
        .await);
    }

    tx.commit()
        .await
        .map_err(|_| PersistAndDeliverChainSwapError::TransactionCommitFailed)?;

    match deliver_exact_manifest_delivery(pool, store, &delivery).await {
        Ok(ManifestDeliveryResumeOutcome::Delivered {
            identity: delivered_identity,
            ..
        }) if delivered_identity == identity => Ok(chain_swap),
        Ok(_) => Err(PersistAndDeliverChainSwapError::ManifestDeliveryInvariantFailed),
        Err(_) => Err(PersistAndDeliverChainSwapError::ManifestDeliveryFailed),
    }
}

async fn rollback_or_replace(
    tx: Transaction<'_, Postgres>,
    original: PersistAndDeliverChainSwapError,
) -> PersistAndDeliverChainSwapError {
    match tx.rollback().await {
        Ok(()) => original,
        Err(_) => PersistAndDeliverChainSwapError::TransactionRollbackFailed,
    }
}
