//! Unwired, single-pending recovery-manifest delivery coordination.
//!
//! This module joins the append-only local ledger to the create-only manifest
//! store. It deliberately does not start workers, choose retry policy, alter
//! admission, or participate in swap creation.

use std::fmt;

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::{
    list_pending_manifest_deliveries, mark_manifest_delivered, ChainSwapManifestDelivery,
    ManifestDeliveryIdentity,
};
use crate::swap_manifest_store::{
    ManifestObjectId, ManifestStoreError, ManifestWriteOutcome, RecoveryManifestStore,
};

/// Result of one bounded pass over the migration-052 pending set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestDeliveryResumeOutcome {
    NoPending,
    Delivered {
        identity: ManifestDeliveryIdentity,
        storage_outcome: ManifestWriteOutcome,
    },
}

/// Sanitized coordinator failures.
///
/// No variant retains database errors, object-store errors, provider sources,
/// configuration, credentials, endpoints, or envelope bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ManifestDeliveryCoordinatorError {
    PendingReadFailed,
    PendingInvariantViolated {
        observed_at_least: usize,
    },
    EnvelopeDigestMismatch {
        manifest_id: Uuid,
    },
    InvalidObjectIdentity {
        manifest_id: Uuid,
        chain_swap_id: Uuid,
    },
    StorageConflict {
        object_id: ManifestObjectId,
    },
    StorageFailed {
        object_id: ManifestObjectId,
    },
    AcknowledgementFailed {
        manifest_id: Uuid,
    },
    AcknowledgementMismatch {
        manifest_id: Uuid,
    },
}

impl fmt::Debug for ManifestDeliveryCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("ManifestDeliveryCoordinatorError");
        match self {
            Self::PendingReadFailed => {
                debug.field("kind", &"pending_read_failed");
            }
            Self::PendingInvariantViolated { observed_at_least } => {
                debug
                    .field("kind", &"pending_invariant_violated")
                    .field("observed_at_least", observed_at_least);
            }
            Self::EnvelopeDigestMismatch { manifest_id } => {
                debug
                    .field("kind", &"envelope_digest_mismatch")
                    .field("manifest_id", manifest_id);
            }
            Self::InvalidObjectIdentity {
                manifest_id,
                chain_swap_id,
            } => {
                debug
                    .field("kind", &"invalid_object_identity")
                    .field("manifest_id", manifest_id)
                    .field("chain_swap_id", chain_swap_id);
            }
            Self::StorageConflict { object_id } => {
                debug
                    .field("kind", &"storage_conflict")
                    .field("object_id", object_id);
            }
            Self::StorageFailed { object_id } => {
                debug
                    .field("kind", &"storage_failed")
                    .field("object_id", object_id);
            }
            Self::AcknowledgementFailed { manifest_id } => {
                debug
                    .field("kind", &"acknowledgement_failed")
                    .field("manifest_id", manifest_id);
            }
            Self::AcknowledgementMismatch { manifest_id } => {
                debug
                    .field("kind", &"acknowledgement_mismatch")
                    .field("manifest_id", manifest_id);
            }
        }
        debug.finish()
    }
}

impl fmt::Display for ManifestDeliveryCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PendingReadFailed => f.write_str("recovery-manifest pending ledger read failed"),
            Self::PendingInvariantViolated { .. } => {
                f.write_str("recovery-manifest pending ledger invariant is violated")
            }
            Self::EnvelopeDigestMismatch { .. } => {
                f.write_str("recovery-manifest ledger envelope digest is inconsistent")
            }
            Self::InvalidObjectIdentity { .. } => {
                f.write_str("recovery-manifest storage identity is invalid")
            }
            Self::StorageConflict { .. } => {
                f.write_str("recovery-manifest storage identity contains different bytes")
            }
            Self::StorageFailed { .. } => f.write_str("recovery-manifest durable storage failed"),
            Self::AcknowledgementFailed { .. } => {
                f.write_str("recovery-manifest delivery acknowledgement failed")
            }
            Self::AcknowledgementMismatch { .. } => {
                f.write_str("recovery-manifest delivery acknowledgement did not match")
            }
        }
    }
}

impl std::error::Error for ManifestDeliveryCoordinatorError {}

/// Resume the sole pending delivery, if any.
///
/// The envelope digest is recomputed before object-store I/O. A successful
/// create or a read-verified identical retry is then acknowledged using the
/// exact ledger identity and digest. If acknowledgement fails after the
/// durable write, the immutable pending row remains safe to retry: the next
/// pass observes `AlreadyPresent` before attempting the same acknowledgement.
pub async fn resume_pending_manifest_delivery(
    pool: &PgPool,
    store: &RecoveryManifestStore,
) -> Result<ManifestDeliveryResumeOutcome, ManifestDeliveryCoordinatorError> {
    let pending = list_pending_manifest_deliveries(pool)
        .await
        .map_err(|_| ManifestDeliveryCoordinatorError::PendingReadFailed)?;
    if pending.len() > 1 {
        return Err(ManifestDeliveryCoordinatorError::PendingInvariantViolated {
            observed_at_least: pending.len(),
        });
    }
    let Some(delivery) = pending.into_iter().next() else {
        return Ok(ManifestDeliveryResumeOutcome::NoPending);
    };

    deliver_exact_manifest_delivery(pool, store, &delivery).await
}

/// Durably create/read-verify and acknowledge one exact ledger row.
///
/// The row is supplied by the caller rather than rediscovered from the global
/// pending set. This is the post-commit half of an atomic swap-plus-ledger
/// insertion: a concurrent resume worker may race this function, but both
/// attempts target the same immutable object and exact idempotent
/// acknowledgement.
pub async fn deliver_exact_manifest_delivery(
    pool: &PgPool,
    store: &RecoveryManifestStore,
    delivery: &ChainSwapManifestDelivery,
) -> Result<ManifestDeliveryResumeOutcome, ManifestDeliveryCoordinatorError> {
    let identity = delivery.identity();
    let manifest = delivery.encrypted_envelope();
    let computed_sha256 = hex::encode(Sha256::digest(manifest.encoded().as_bytes()));
    if computed_sha256 != delivery.envelope_sha256 {
        return Err(ManifestDeliveryCoordinatorError::EnvelopeDigestMismatch {
            manifest_id: identity.manifest_id,
        });
    }

    let object_id =
        ManifestObjectId::new(identity.chain_swap_id, identity.manifest_id).map_err(|_| {
            ManifestDeliveryCoordinatorError::InvalidObjectIdentity {
                manifest_id: identity.manifest_id,
                chain_swap_id: identity.chain_swap_id,
            }
        })?;
    let storage_outcome = match store.put_v1(object_id, manifest).await {
        Ok(outcome @ (ManifestWriteOutcome::Created | ManifestWriteOutcome::AlreadyPresent)) => {
            outcome
        }
        Err(ManifestStoreError::Conflict { .. }) => {
            return Err(ManifestDeliveryCoordinatorError::StorageConflict { object_id });
        }
        Err(_) => {
            return Err(ManifestDeliveryCoordinatorError::StorageFailed { object_id });
        }
    };

    let acknowledged = mark_manifest_delivered(pool, &identity, &computed_sha256)
        .await
        .map_err(
            |_| ManifestDeliveryCoordinatorError::AcknowledgementFailed {
                manifest_id: identity.manifest_id,
            },
        )?
        .ok_or(ManifestDeliveryCoordinatorError::AcknowledgementMismatch {
            manifest_id: identity.manifest_id,
        })?;
    if acknowledged.identity() != identity
        || acknowledged.envelope_sha256 != computed_sha256
        || acknowledged.encrypted_envelope() != manifest
        || acknowledged.delivery_state != "delivered"
        || acknowledged.delivered_at_unix.is_none()
    {
        return Err(ManifestDeliveryCoordinatorError::AcknowledgementMismatch {
            manifest_id: identity.manifest_id,
        });
    }

    Ok(ManifestDeliveryResumeOutcome::Delivered {
        identity,
        storage_outcome,
    })
}
