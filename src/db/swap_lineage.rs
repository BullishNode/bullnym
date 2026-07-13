use std::fmt;

use sqlx::PgPool;
use uuid::Uuid;

/// Version 1 is the existing `SwapMasterKey::derive_swapkey(child_index)`
/// derivation used by Bullnym.  Persisting the version makes a future scheme
/// change explicit instead of silently reinterpreting historical indices.
pub const DERIVATION_SCHEME_VERSION: i32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKeyPurpose {
    ReverseClaim,
    ChainClaim,
    ChainRefund,
}

impl fmt::Display for SwapKeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReverseClaim => "reverse_claim",
            Self::ChainClaim => "chain_claim",
            Self::ChainRefund => "chain_refund",
        })
    }
}

pub struct NewSwapKeyAllocation<'a> {
    pub root_fingerprint: &'a str,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub child_index: i64,
    pub purpose: SwapKeyPurpose,
    pub public_key_hex: &'a str,
    pub preimage_hash_hex: Option<&'a str>,
}

/// Reserve a derived key identity in the one global namespace shared by every
/// swap type and key purpose.  Callers do this after consuming the sequence
/// value and deriving its public evidence, but before making a provider call.
pub async fn reserve_swap_key_allocation<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    allocation: &NewSwapKeyAllocation<'_>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO swap_key_allocations (\
             root_fingerprint, key_epoch, derivation_scheme_version, child_index, \
             purpose, public_key_hex, preimage_hash_hex\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id",
    )
    .bind(allocation.root_fingerprint)
    .bind(allocation.key_epoch)
    .bind(allocation.derivation_scheme_version)
    .bind(allocation.child_index)
    .bind(allocation.purpose.to_string())
    .bind(allocation.public_key_hex)
    .bind(allocation.preimage_hash_hex)
    .fetch_one(executor)
    .await
}

/// Highest durably reserved child index for the active derivation generation,
/// including orphan allocations left by provider or persistence failure.
pub async fn max_reserved_swap_key_index(
    pool: &PgPool,
    root_fingerprint: &str,
    key_epoch: i32,
    derivation_scheme_version: i32,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT MAX(child_index) FROM swap_key_allocations \
         WHERE root_fingerprint = $1 \
           AND key_epoch = $2 \
           AND derivation_scheme_version = $3",
    )
    .bind(root_fingerprint)
    .bind(key_epoch)
    .bind(derivation_scheme_version)
    .fetch_one(pool)
    .await
}

/// Conservative maximum copied from complete migration-044 identities before
/// their secret-bearing swap rows become eligible for signed user purge. The
/// ledger is scoped only by root because the historical epoch and derivation
/// scheme were not recorded.
pub async fn max_legacy_swap_key_index(
    pool: &PgPool,
    root_fingerprint: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT max_child_index FROM swap_key_legacy_high_water \
         WHERE root_fingerprint = $1",
    )
    .bind(root_fingerprint)
    .fetch_optional(pool)
    .await
}
