//! Session-scoped serialization before chain-swap creation side effects.
//!
//! The permit is deliberately separate from the transaction-scoped
//! migration-052 manifest-ledger lock. It serializes the wider pre-provider
//! boundary across processes, resumes any prior pending off-host delivery, and
//! then remains held while the caller allocates keys and performs provider and
//! persistence coordination.

use std::fmt;

use sqlx::{Connection, PgConnection, PgPool};

use crate::swap_manifest_delivery::resume_pending_manifest_delivery;
use crate::swap_manifest_store::RecoveryManifestStore;

// `CSCP` (chain-swap creation permit), distinct from migration 052's `BULL`
// class plus object 87 transaction lock.
const CREATION_PERMIT_LOCK_CLASS: i32 = 1_129_530_192;
const CREATION_PERMIT_LOCK_OBJECT: i32 = 1;

/// Bounded failure classes for acquiring or releasing the creation permit.
///
/// No variant retains SQL, object-store, endpoint, credential, envelope, or
/// lower-layer error material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapCreationPermitError {
    ConnectionUnavailable,
    LockCheckFailed,
    Busy,
    PendingDeliveryFailed,
    ManifestCoverageCheckFailed,
    ManifestObligationMissing,
    ReleaseFailed,
}

impl fmt::Display for ChainSwapCreationPermitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ConnectionUnavailable => {
                "chain-swap creation permit database connection is unavailable"
            }
            Self::LockCheckFailed => "chain-swap creation permit lock check failed",
            Self::Busy => "another chain-swap creation boundary is active",
            Self::PendingDeliveryFailed => {
                "prior recovery-manifest delivery could not be completed"
            }
            Self::ManifestCoverageCheckFailed => "chain-swap manifest coverage check failed",
            Self::ManifestObligationMissing => {
                "canonical chain swap lacks a recovery manifest obligation"
            }
            Self::ReleaseFailed => "chain-swap creation permit release failed",
        })
    }
}

impl std::error::Error for ChainSwapCreationPermitError {}

/// Exclusive process-independent guard for the complete creation boundary.
///
/// The held PostgreSQL connection is detached from the pool. Dropping this
/// value therefore closes the physical session instead of returning a locked
/// session to the pool; PostgreSQL releases the session advisory lock on that
/// close. Use [`Self::release`] on normal paths for an explicit unlock and
/// graceful connection close.
pub struct ChainSwapCreationPermit {
    connection: Option<PgConnection>,
}

impl ChainSwapCreationPermit {
    /// Try to enter the global chain-swap creation boundary.
    ///
    /// This call never waits for another creator's advisory lock: contention
    /// returns [`ChainSwapCreationPermitError::Busy`]. Once the lock is held,
    /// any migration-052 pending delivery is synchronously create-or-verified
    /// and acknowledged before the permit becomes observable to the caller.
    pub async fn acquire(
        pool: &PgPool,
        store: &RecoveryManifestStore,
    ) -> Result<Self, ChainSwapCreationPermitError> {
        let pooled = pool
            .acquire()
            .await
            .map_err(|_| ChainSwapCreationPermitError::ConnectionUnavailable)?;
        // Detaching lets the pool provision a replacement for the delivery
        // coordinator while this physical session remains solely owned here.
        // Cancellation anywhere below drops and closes this connection.
        let mut connection = pooled.detach();
        let acquired =
            sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1::INTEGER, $2::INTEGER)")
                .bind(CREATION_PERMIT_LOCK_CLASS)
                .bind(CREATION_PERMIT_LOCK_OBJECT)
                .fetch_one(&mut connection)
                .await
                .map_err(|_| ChainSwapCreationPermitError::LockCheckFailed)?;
        if !acquired {
            return Err(ChainSwapCreationPermitError::Busy);
        }

        resume_pending_manifest_delivery(pool, store)
            .await
            .map_err(|_| ChainSwapCreationPermitError::PendingDeliveryFailed)?;

        // A staging/ledger refusal after a mutating provider call deliberately
        // retains the complete canonical chain-swap row. That row is a
        // blocking obligation: do not let the next caller cross the provider
        // boundary until a migration-052 ledger row exists for it. Historical
        // rows without the complete #80 creation packet remain nonblocking.
        let missing_obligation = crate::db::has_manifestless_complete_chain_swap(&mut connection)
            .await
            .map_err(|_| ChainSwapCreationPermitError::ManifestCoverageCheckFailed)?;
        if missing_obligation {
            // `connection` is detached and still owns the session advisory
            // lock. Returning drops/closes it, so PostgreSQL releases the lock
            // before any later acquisition can succeed.
            return Err(ChainSwapCreationPermitError::ManifestObligationMissing);
        }

        Ok(Self {
            connection: Some(connection),
        })
    }

    /// Explicitly unlock and close the owned physical connection.
    ///
    /// The connection is closed even if PostgreSQL refuses or cannot confirm
    /// the explicit unlock, so the session lock is not retained on an error.
    pub async fn release(mut self) -> Result<(), ChainSwapCreationPermitError> {
        let mut connection = self
            .connection
            .take()
            .expect("a live creation permit always owns its connection");
        let unlocked =
            sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1::INTEGER, $2::INTEGER)")
                .bind(CREATION_PERMIT_LOCK_CLASS)
                .bind(CREATION_PERMIT_LOCK_OBJECT)
                .fetch_one(&mut connection)
                .await;
        let closed = connection.close().await;
        if !matches!(unlocked, Ok(true)) || closed.is_err() {
            return Err(ChainSwapCreationPermitError::ReleaseFailed);
        }
        Ok(())
    }
}

impl fmt::Debug for ChainSwapCreationPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainSwapCreationPermit")
            .field("held", &self.connection.is_some())
            .finish()
    }
}

impl Drop for ChainSwapCreationPermit {
    fn drop(&mut self) {
        // Dropping the detached PgConnection closes its physical session and
        // lets PostgreSQL release every session-scoped advisory lock.
        drop(self.connection.take());
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn public_errors_are_bounded_and_source_free() {
        for error in [
            ChainSwapCreationPermitError::ConnectionUnavailable,
            ChainSwapCreationPermitError::LockCheckFailed,
            ChainSwapCreationPermitError::Busy,
            ChainSwapCreationPermitError::PendingDeliveryFailed,
            ChainSwapCreationPermitError::ManifestCoverageCheckFailed,
            ChainSwapCreationPermitError::ManifestObligationMissing,
            ChainSwapCreationPermitError::ReleaseFailed,
        ] {
            assert!(error.to_string().len() <= 72);
            assert!(format!("{error:?}").len() <= 40);
            assert!(error.source().is_none());
        }
    }
}
