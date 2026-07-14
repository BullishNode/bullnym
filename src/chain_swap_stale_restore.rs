//! Bounded reconstruction of signed current-v1 chain-swap obligations.
//!
//! A stale PostgreSQL restore may omit a chain-swap row even though the
//! authenticated off-host manifest and Boltz's validated xpub restore both
//! retain the exact creation identity. This module repairs only that narrow
//! case. It never creates evidence for provider-only records, never infers a
//! legacy row, never advances the derivation sequence, and never calls a
//! mutating provider endpoint.

use std::fmt;

use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::boltz::CreateChainResponse;
use boltz_client::util::secrets::{Preimage, SwapMasterKey};
use boltz_client::PublicKey;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::boltz_restore::{
    BoltzRestoreKind, ValidatedBoltzRestoreRecord, ValidatedBoltzRestoreSet,
};
use crate::boltz_restore_fetch::BoltzRestoreFetcher;
use crate::db::DERIVATION_SCHEME_VERSION;
use crate::local_chain_swap_recovery_audit::MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1;
use crate::swap_manifest::{
    audit_manifest_set_against_boltz_restore_v1, ManifestKeyAllocationV1, SwapManifestV1,
};
use crate::swap_manifest_witness::{
    RecoveryManifestWitnessLoaderV1, MAX_RECOVERY_WITNESS_RECORDS_V1,
};

const MAX_STALE_RESTORE_RECORDS_V1: usize =
    if MAX_RECOVERY_WITNESS_RECORDS_V1 < MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1 {
        MAX_RECOVERY_WITNESS_RECORDS_V1
    } else {
        MAX_RECOVERY_AUDIT_LOCAL_RECORDS_V1
    };

// `CSRR` (chain-swap restore reconstruction). The process-wide creation permit
// remains held by the startup caller; this transaction lock serializes two
// accidental reconstruction invocations without conflicting with that permit.
const STALE_RESTORE_LOCK_CLASS: i32 = 1_129_530_194;
const STALE_RESTORE_LOCK_OBJECT: i32 = 1;

/// Identity-free result of one complete reconstruction pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSwapStaleRestoreOutcomeV1 {
    pub witnessed_records: usize,
    pub verified_existing_records: usize,
    pub reconstructed_records: usize,
}

/// Fixed, source-free failures from the stale-restore boundary.
///
/// No variant retains a provider/database identity, endpoint, manifest body,
/// destination, root fingerprint, key, preimage, or lower-layer error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapStaleRestoreErrorV1 {
    WitnessLoadFailed,
    WitnessRecordLimitExceeded,
    ProviderRestoreFetchFailed,
    ProviderRecordLimitExceeded,
    CrossSourceEvidenceMismatch,
    UnsupportedDerivationLineage,
    SecretReconstructionFailed,
    TransactionBeginFailed,
    TransactionLockFailed,
    MerchantPolicyMismatch,
    AllocationWriteFailed,
    AllocationConflict,
    ChainSwapWriteFailed,
    ChainSwapConflict,
    TransactionCommitFailed,
}

impl fmt::Display for ChainSwapStaleRestoreErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WitnessLoadFailed => "chain-swap restore witness load failed",
            Self::WitnessRecordLimitExceeded => "chain-swap restore witness exceeds its limit",
            Self::ProviderRestoreFetchFailed => "chain-swap provider restore fetch failed",
            Self::ProviderRecordLimitExceeded => "chain-swap provider restore exceeds its limit",
            Self::CrossSourceEvidenceMismatch => "chain-swap restore evidence does not agree",
            Self::UnsupportedDerivationLineage => {
                "chain-swap restore derivation lineage is unsupported"
            }
            Self::SecretReconstructionFailed => "chain-swap secret reconstruction failed",
            Self::TransactionBeginFailed => "chain-swap restore transaction could not begin",
            Self::TransactionLockFailed => "chain-swap restore transaction lock failed",
            Self::MerchantPolicyMismatch => "chain-swap restore merchant policy does not agree",
            Self::AllocationWriteFailed => "chain-swap allocation restore failed",
            Self::AllocationConflict => "chain-swap allocation restore found a conflict",
            Self::ChainSwapWriteFailed => "chain-swap row restore failed",
            Self::ChainSwapConflict => "chain-swap row restore found a conflict",
            Self::TransactionCommitFailed => "chain-swap restore transaction commit failed",
        })
    }
}

impl std::error::Error for ChainSwapStaleRestoreErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Load one authenticated, quiescent witness and one independently validated
/// Boltz restore snapshot, then atomically reconstruct every missing witnessed
/// current-v1 row. The caller must hold the global chain-swap creation permit
/// for the whole call and any following delivery-ledger rebuild/audit.
pub async fn reconstruct_missing_manifested_chain_swaps_v1(
    pool: &PgPool,
    witness: &RecoveryManifestWitnessLoaderV1,
    provider: &BoltzRestoreFetcher,
    swap_master_key: &SwapMasterKey,
) -> Result<ChainSwapStaleRestoreOutcomeV1, ChainSwapStaleRestoreErrorV1> {
    let loaded = witness
        .load_quiescent()
        .await
        .map_err(|_| ChainSwapStaleRestoreErrorV1::WitnessLoadFailed)?;
    if loaded.manifests().len() > MAX_STALE_RESTORE_RECORDS_V1 {
        return Err(ChainSwapStaleRestoreErrorV1::WitnessRecordLimitExceeded);
    }
    if loaded.manifests().is_empty() {
        return Ok(ChainSwapStaleRestoreOutcomeV1 {
            witnessed_records: 0,
            verified_existing_records: 0,
            reconstructed_records: 0,
        });
    }
    let provider = provider
        .fetch_and_validate(swap_master_key)
        .await
        .map_err(|_| ChainSwapStaleRestoreErrorV1::ProviderRestoreFetchFailed)?;
    if provider.records.len() > MAX_STALE_RESTORE_RECORDS_V1 {
        return Err(ChainSwapStaleRestoreErrorV1::ProviderRecordLimitExceeded);
    }

    reconstruct_validated_manifested_chain_swaps_v1(
        pool,
        loaded.manifests(),
        &provider,
        swap_master_key,
    )
    .await
}

/// Internal composition seam used by deterministic pure/DB tests after their
/// fixtures have independently established authentication and provider
/// validation. Production reaches this only through the loader/fetcher above.
#[doc(hidden)]
pub async fn reconstruct_validated_manifested_chain_swaps_v1(
    pool: &PgPool,
    manifests: &[SwapManifestV1],
    provider: &ValidatedBoltzRestoreSet,
    swap_master_key: &SwapMasterKey,
) -> Result<ChainSwapStaleRestoreOutcomeV1, ChainSwapStaleRestoreErrorV1> {
    if manifests.len() > MAX_STALE_RESTORE_RECORDS_V1 {
        return Err(ChainSwapStaleRestoreErrorV1::WitnessRecordLimitExceeded);
    }
    if provider.records.len() > MAX_STALE_RESTORE_RECORDS_V1 {
        return Err(ChainSwapStaleRestoreErrorV1::ProviderRecordLimitExceeded);
    }
    let prepared = prepare_reconstructions(manifests, provider, swap_master_key)?;
    restore_prepared(pool, &prepared).await
}

/// Secret-bearing reconstruction packet. It intentionally has no formatting
/// implementation and never escapes this module.
struct PreparedChainSwapReconstructionV1<'a> {
    manifest: &'a SwapManifestV1,
    preimage_hex: String,
    claim_key_hex: String,
    refund_key_hex: String,
}

fn prepare_reconstructions<'a>(
    manifests: &'a [SwapManifestV1],
    provider: &ValidatedBoltzRestoreSet,
    swap_master_key: &SwapMasterKey,
) -> Result<Vec<PreparedChainSwapReconstructionV1<'a>>, ChainSwapStaleRestoreErrorV1> {
    // This validates every manifest's closed schema, exact canonical provider
    // response, script templates/hashes, append-only topology, and exact key
    // agreement with the independently validated provider snapshot.
    audit_manifest_set_against_boltz_restore_v1(manifests, provider)
        .map_err(|_| ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch)?;

    let active_root = derive_root_fingerprint(swap_master_key)?;
    let mut prepared = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        if manifest.derivation_lineage.root_fingerprint != active_root
            || manifest.derivation_lineage.derivation_scheme_version != DERIVATION_SCHEME_VERSION
        {
            return Err(ChainSwapStaleRestoreErrorV1::UnsupportedDerivationLineage);
        }
        let matching_provider = exact_provider_record(provider, manifest)?;
        if matching_provider.kind != BoltzRestoreKind::Chain {
            return Err(ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch);
        }

        let claim_index = u64::try_from(manifest.derivation_lineage.claim.child_index)
            .map_err(|_| ChainSwapStaleRestoreErrorV1::SecretReconstructionFailed)?;
        let refund_index = u64::try_from(manifest.derivation_lineage.refund.child_index)
            .map_err(|_| ChainSwapStaleRestoreErrorV1::SecretReconstructionFailed)?;
        let claim_keypair = swap_master_key
            .derive_swapkey(claim_index)
            .map_err(|_| ChainSwapStaleRestoreErrorV1::SecretReconstructionFailed)?;
        let refund_keypair = swap_master_key
            .derive_swapkey(refund_index)
            .map_err(|_| ChainSwapStaleRestoreErrorV1::SecretReconstructionFailed)?;
        let claim_public_key = PublicKey::new(claim_keypair.public_key());
        let refund_public_key = PublicKey::new(refund_keypair.public_key());
        if claim_public_key.to_string() != manifest.derivation_lineage.claim.public_key_hex
            || refund_public_key.to_string() != manifest.derivation_lineage.refund.public_key_hex
        {
            return Err(ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch);
        }

        let preimage = Preimage::from_swap_key(&claim_keypair);
        let preimage_hash_hex = preimage.sha256.to_string();
        if manifest
            .derivation_lineage
            .claim
            .preimage_hash_hex
            .as_deref()
            != Some(preimage_hash_hex.as_str())
            || manifest
                .derivation_lineage
                .refund
                .preimage_hash_hex
                .is_some()
        {
            return Err(ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch);
        }
        let preimage_bytes = preimage
            .bytes
            .ok_or(ChainSwapStaleRestoreErrorV1::SecretReconstructionFailed)?;

        // Reparse and validate the signed canonical response against the
        // actually re-derived keys. Manifest validation already checked all
        // four exact script hashes; this closes the final secret/public seam.
        let response: CreateChainResponse =
            serde_json::from_str(&manifest.creation.canonical_provider_response_json)
                .map_err(|_| ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch)?;
        response
            .validate(
                &claim_public_key,
                &refund_public_key,
                Chain::Bitcoin(BitcoinChain::Bitcoin),
                Chain::Liquid(LiquidChain::Liquid),
            )
            .map_err(|_| ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch)?;
        if response.id != matching_provider.provider_swap_id
            || response.id != manifest.restore_identity.boltz_swap_id
            || response.lockup_details.lockup_address != manifest.creation.lockup_address
            || i64::try_from(response.lockup_details.amount).ok()
                != Some(manifest.creation.user_lock_amount_sat)
            || i64::try_from(response.claim_details.amount).ok()
                != Some(manifest.creation.server_lock_amount_sat)
        {
            return Err(ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch);
        }

        prepared.push(PreparedChainSwapReconstructionV1 {
            manifest,
            preimage_hex: hex::encode(preimage_bytes),
            claim_key_hex: hex::encode(claim_keypair.secret_bytes()),
            refund_key_hex: hex::encode(refund_keypair.secret_bytes()),
        });
    }
    Ok(prepared)
}

fn derive_root_fingerprint(
    swap_master_key: &SwapMasterKey,
) -> Result<String, ChainSwapStaleRestoreErrorV1> {
    let keypair = swap_master_key
        .derive_swapkey(0)
        .map_err(|_| ChainSwapStaleRestoreErrorV1::SecretReconstructionFailed)?;
    let digest = Sha256::digest(keypair.public_key().serialize());
    Ok(hex::encode(&digest[..8]))
}

fn exact_provider_record<'a>(
    provider: &'a ValidatedBoltzRestoreSet,
    manifest: &SwapManifestV1,
) -> Result<&'a ValidatedBoltzRestoreRecord, ChainSwapStaleRestoreErrorV1> {
    let mut matches = provider
        .records
        .iter()
        .filter(|record| record.provider_swap_id == manifest.restore_identity.boltz_swap_id);
    let record = matches
        .next()
        .ok_or(ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch)?;
    if matches.next().is_some() {
        return Err(ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch);
    }
    Ok(record)
}

async fn restore_prepared(
    pool: &PgPool,
    prepared: &[PreparedChainSwapReconstructionV1<'_>],
) -> Result<ChainSwapStaleRestoreOutcomeV1, ChainSwapStaleRestoreErrorV1> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| ChainSwapStaleRestoreErrorV1::TransactionBeginFailed)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1::INTEGER, $2::INTEGER)")
        .bind(STALE_RESTORE_LOCK_CLASS)
        .bind(STALE_RESTORE_LOCK_OBJECT)
        .execute(&mut *tx)
        .await
        .map_err(|_| ChainSwapStaleRestoreErrorV1::TransactionLockFailed)?;

    let mut reconstructed_records = 0_usize;
    for candidate in prepared {
        verify_merchant_policy(&mut tx, candidate).await?;
        restore_allocation(
            &mut tx,
            candidate,
            &candidate.manifest.derivation_lineage.claim,
            "chain_claim",
        )
        .await?;
        restore_allocation(
            &mut tx,
            candidate,
            &candidate.manifest.derivation_lineage.refund,
            "chain_refund",
        )
        .await?;
        reconstructed_records = reconstructed_records
            .checked_add(restore_chain_swap_row(&mut tx, candidate).await?)
            .ok_or(ChainSwapStaleRestoreErrorV1::ChainSwapWriteFailed)?;
    }

    let verified_existing_records = prepared
        .len()
        .checked_sub(reconstructed_records)
        .ok_or(ChainSwapStaleRestoreErrorV1::ChainSwapWriteFailed)?;
    tx.commit()
        .await
        .map_err(|_| ChainSwapStaleRestoreErrorV1::TransactionCommitFailed)?;
    Ok(ChainSwapStaleRestoreOutcomeV1 {
        witnessed_records: prepared.len(),
        verified_existing_records,
        reconstructed_records,
    })
}

async fn verify_merchant_policy(
    tx: &mut Transaction<'_, Postgres>,
    candidate: &PreparedChainSwapReconstructionV1<'_>,
) -> Result<(), ChainSwapStaleRestoreErrorV1> {
    let policy = &candidate.manifest.merchant_policy;
    let creation = &candidate.manifest.creation;
    let (Some(commitment_id), Some(emergency_address)) = (
        policy.emergency_bitcoin_commitment_id,
        policy.merchant_emergency_btc_address.as_deref(),
    ) else {
        return Err(ChainSwapStaleRestoreErrorV1::MerchantPolicyMismatch);
    };
    let exact: Option<i32> = sqlx::query_scalar(
        "SELECT 1 \
           FROM invoices AS invoice \
           JOIN users AS owner \
             ON owner.nym = $2 AND owner.npub = invoice.npub_owner \
           JOIN invoice_payment_addresses AS payment \
             ON payment.invoice_id = invoice.id \
            AND payment.rail = 'liquid' \
            AND payment.address = $3 \
           JOIN recovery_address_commitments AS commitment \
             ON commitment.commitment_id = $4 \
            AND commitment.npub = invoice.npub_owner \
            AND commitment.canonical_btc_address = $5 \
          WHERE invoice.id = $1 \
            AND invoice.nym_owner = $2 \
            AND invoice.liquid_address = $3 \
          FOR KEY SHARE OF invoice, owner, payment",
    )
    .bind(policy.invoice_id)
    .bind(&policy.merchant_nym)
    .bind(&creation.merchant_liquid_destination)
    .bind(commitment_id)
    .bind(emergency_address)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ChainSwapStaleRestoreErrorV1::MerchantPolicyMismatch)?;
    if exact.is_none()
        || creation.merchant_emergency_btc_address.as_deref() != Some(emergency_address)
    {
        return Err(ChainSwapStaleRestoreErrorV1::MerchantPolicyMismatch);
    }
    Ok(())
}

async fn restore_allocation(
    tx: &mut Transaction<'_, Postgres>,
    candidate: &PreparedChainSwapReconstructionV1<'_>,
    allocation: &ManifestKeyAllocationV1,
    purpose: &str,
) -> Result<(), ChainSwapStaleRestoreErrorV1> {
    let lineage = &candidate.manifest.derivation_lineage;
    sqlx::query(
        "INSERT INTO swap_key_allocations (\
             id, root_fingerprint, key_epoch, derivation_scheme_version, child_index, \
             purpose, public_key_hex, preimage_hash_hex\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT DO NOTHING",
    )
    .bind(allocation.allocation_id)
    .bind(&lineage.root_fingerprint)
    .bind(lineage.key_epoch)
    .bind(lineage.derivation_scheme_version)
    .bind(allocation.child_index)
    .bind(purpose)
    .bind(&allocation.public_key_hex)
    .bind(&allocation.preimage_hash_hex)
    .execute(&mut **tx)
    .await
    .map_err(|_| ChainSwapStaleRestoreErrorV1::AllocationWriteFailed)?;

    let exact: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM swap_key_allocations \
          WHERE id = $1 \
            AND root_fingerprint = $2 \
            AND key_epoch = $3 \
            AND derivation_scheme_version = $4 \
            AND child_index = $5 \
            AND purpose = $6 \
            AND public_key_hex = $7 \
            AND preimage_hash_hex IS NOT DISTINCT FROM $8",
    )
    .bind(allocation.allocation_id)
    .bind(&lineage.root_fingerprint)
    .bind(lineage.key_epoch)
    .bind(lineage.derivation_scheme_version)
    .bind(allocation.child_index)
    .bind(purpose)
    .bind(&allocation.public_key_hex)
    .bind(&allocation.preimage_hash_hex)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ChainSwapStaleRestoreErrorV1::AllocationWriteFailed)?;
    if exact.is_none() {
        return Err(ChainSwapStaleRestoreErrorV1::AllocationConflict);
    }
    Ok(())
}

async fn restore_chain_swap_row(
    tx: &mut Transaction<'_, Postgres>,
    candidate: &PreparedChainSwapReconstructionV1<'_>,
) -> Result<usize, ChainSwapStaleRestoreErrorV1> {
    let manifest = candidate.manifest;
    let identity = &manifest.restore_identity;
    let lineage = &manifest.derivation_lineage;
    let creation = &manifest.creation;
    let policy = &manifest.merchant_policy;
    let inserted = sqlx::query(
        "INSERT INTO chain_swap_records (\
             id, invoice_id, nym, boltz_swap_id, from_chain, to_chain, \
             lockup_address, lockup_bip21, user_lock_amount_sat, server_lock_amount_sat, \
             preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json, \
             claim_key_index, refund_key_index, root_fingerprint, \
             claim_key_allocation_id, refund_key_allocation_id, key_epoch, \
             derivation_scheme_version, claim_public_key_hex, refund_public_key_hex, \
             preimage_hash_hex, pinned_pair_hash, canonical_pair_quote_json, \
             creation_response_sha256, btc_claim_script_sha256, btc_refund_script_sha256, \
             liquid_claim_script_sha256, liquid_refund_script_sha256, \
             btc_timeout_height, liquid_timeout_height, btc_network, liquid_network, \
             liquid_asset_id, merchant_liquid_destination, \
             merchant_emergency_btc_address, recovery_address_commitment_id, \
             created_at, updated_at\
         ) VALUES (\
             $1,$2,$3,$4,'BTC','L-BTC',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, \
             $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31, \
             $32,$33,$34,$35,$36,$37, \
             TIMESTAMPTZ 'epoch' + ($38::BIGINT * INTERVAL '1 second'), \
             TIMESTAMPTZ 'epoch' + ($38::BIGINT * INTERVAL '1 second')\
         ) ON CONFLICT DO NOTHING",
    )
    .bind(identity.chain_swap_id)
    .bind(policy.invoice_id)
    .bind(&policy.merchant_nym)
    .bind(&identity.boltz_swap_id)
    .bind(&creation.lockup_address)
    .bind(&creation.lockup_bip21)
    .bind(creation.user_lock_amount_sat)
    .bind(creation.server_lock_amount_sat)
    .bind(&candidate.preimage_hex)
    .bind(&candidate.claim_key_hex)
    .bind(&candidate.refund_key_hex)
    .bind(&creation.canonical_provider_response_json)
    .bind(lineage.claim.child_index)
    .bind(lineage.refund.child_index)
    .bind(&lineage.root_fingerprint)
    .bind(lineage.claim.allocation_id)
    .bind(lineage.refund.allocation_id)
    .bind(lineage.key_epoch)
    .bind(lineage.derivation_scheme_version)
    .bind(&lineage.claim.public_key_hex)
    .bind(&lineage.refund.public_key_hex)
    .bind(&lineage.claim.preimage_hash_hex)
    .bind(&creation.pinned_pair_hash)
    .bind(&creation.canonical_pair_quote_json)
    .bind(&creation.creation_response_sha256)
    .bind(&creation.btc_claim_script_sha256)
    .bind(&creation.btc_refund_script_sha256)
    .bind(&creation.liquid_claim_script_sha256)
    .bind(&creation.liquid_refund_script_sha256)
    .bind(creation.btc_timeout_height)
    .bind(creation.liquid_timeout_height)
    .bind(&creation.btc_network)
    .bind(&creation.liquid_network)
    .bind(&creation.liquid_asset_id)
    .bind(&creation.merchant_liquid_destination)
    .bind(&creation.merchant_emergency_btc_address)
    .bind(policy.emergency_bitcoin_commitment_id)
    .bind(identity.created_at_unix)
    .execute(&mut **tx)
    .await
    .map_err(|_| ChainSwapStaleRestoreErrorV1::ChainSwapWriteFailed)?
    .rows_affected();

    let rows = sqlx::query_as::<_, ExistingChainSwapIdentityV1>(
        "SELECT id, invoice_id, nym, boltz_swap_id, from_chain, to_chain, \
                lockup_address, lockup_bip21, user_lock_amount_sat, server_lock_amount_sat, \
                preimage_hex, claim_key_hex, refund_key_hex, boltz_response_json, \
                claim_key_index, refund_key_index, root_fingerprint, \
                claim_key_allocation_id, refund_key_allocation_id, key_epoch, \
                derivation_scheme_version, claim_public_key_hex, refund_public_key_hex, \
                preimage_hash_hex, pinned_pair_hash, canonical_pair_quote_json, \
                creation_response_sha256, btc_claim_script_sha256, btc_refund_script_sha256, \
                liquid_claim_script_sha256, liquid_refund_script_sha256, \
                btc_timeout_height, liquid_timeout_height, btc_network, liquid_network, \
                liquid_asset_id, merchant_liquid_destination, \
                merchant_emergency_btc_address, recovery_address_commitment_id, \
                EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at_unix \
           FROM chain_swap_records \
          WHERE id = $1 OR boltz_swap_id = $2 \
          ORDER BY id \
          LIMIT 2 \
          FOR KEY SHARE",
    )
    .bind(identity.chain_swap_id)
    .bind(&identity.boltz_swap_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ChainSwapStaleRestoreErrorV1::ChainSwapWriteFailed)?;
    if rows.as_slice() != [ExistingChainSwapIdentityV1::from_candidate(candidate)] {
        return Err(ChainSwapStaleRestoreErrorV1::ChainSwapConflict);
    }
    usize::try_from(inserted).map_err(|_| ChainSwapStaleRestoreErrorV1::ChainSwapWriteFailed)
}

#[derive(PartialEq, Eq, sqlx::FromRow)]
struct ExistingChainSwapIdentityV1 {
    id: Uuid,
    invoice_id: Uuid,
    nym: Option<String>,
    boltz_swap_id: String,
    from_chain: String,
    to_chain: String,
    lockup_address: String,
    lockup_bip21: Option<String>,
    user_lock_amount_sat: i64,
    server_lock_amount_sat: i64,
    preimage_hex: String,
    claim_key_hex: String,
    refund_key_hex: String,
    boltz_response_json: String,
    claim_key_index: Option<i64>,
    refund_key_index: Option<i64>,
    root_fingerprint: Option<String>,
    claim_key_allocation_id: Option<Uuid>,
    refund_key_allocation_id: Option<Uuid>,
    key_epoch: Option<i32>,
    derivation_scheme_version: Option<i32>,
    claim_public_key_hex: Option<String>,
    refund_public_key_hex: Option<String>,
    preimage_hash_hex: Option<String>,
    pinned_pair_hash: Option<String>,
    canonical_pair_quote_json: Option<String>,
    creation_response_sha256: Option<String>,
    btc_claim_script_sha256: Option<String>,
    btc_refund_script_sha256: Option<String>,
    liquid_claim_script_sha256: Option<String>,
    liquid_refund_script_sha256: Option<String>,
    btc_timeout_height: Option<i64>,
    liquid_timeout_height: Option<i64>,
    btc_network: Option<String>,
    liquid_network: Option<String>,
    liquid_asset_id: Option<String>,
    merchant_liquid_destination: Option<String>,
    merchant_emergency_btc_address: Option<String>,
    recovery_address_commitment_id: Option<Uuid>,
    created_at_unix: i64,
}

impl ExistingChainSwapIdentityV1 {
    fn from_candidate(candidate: &PreparedChainSwapReconstructionV1<'_>) -> Self {
        let manifest = candidate.manifest;
        let identity = &manifest.restore_identity;
        let lineage = &manifest.derivation_lineage;
        let creation = &manifest.creation;
        let policy = &manifest.merchant_policy;
        Self {
            id: identity.chain_swap_id,
            invoice_id: policy.invoice_id,
            nym: Some(policy.merchant_nym.clone()),
            boltz_swap_id: identity.boltz_swap_id.clone(),
            from_chain: "BTC".into(),
            to_chain: "L-BTC".into(),
            lockup_address: creation.lockup_address.clone(),
            lockup_bip21: Some(creation.lockup_bip21.clone()),
            user_lock_amount_sat: creation.user_lock_amount_sat,
            server_lock_amount_sat: creation.server_lock_amount_sat,
            preimage_hex: candidate.preimage_hex.clone(),
            claim_key_hex: candidate.claim_key_hex.clone(),
            refund_key_hex: candidate.refund_key_hex.clone(),
            boltz_response_json: creation.canonical_provider_response_json.clone(),
            claim_key_index: Some(lineage.claim.child_index),
            refund_key_index: Some(lineage.refund.child_index),
            root_fingerprint: Some(lineage.root_fingerprint.clone()),
            claim_key_allocation_id: Some(lineage.claim.allocation_id),
            refund_key_allocation_id: Some(lineage.refund.allocation_id),
            key_epoch: Some(lineage.key_epoch),
            derivation_scheme_version: Some(lineage.derivation_scheme_version),
            claim_public_key_hex: Some(lineage.claim.public_key_hex.clone()),
            refund_public_key_hex: Some(lineage.refund.public_key_hex.clone()),
            preimage_hash_hex: lineage.claim.preimage_hash_hex.clone(),
            pinned_pair_hash: Some(creation.pinned_pair_hash.clone()),
            canonical_pair_quote_json: Some(creation.canonical_pair_quote_json.clone()),
            creation_response_sha256: Some(creation.creation_response_sha256.clone()),
            btc_claim_script_sha256: Some(creation.btc_claim_script_sha256.clone()),
            btc_refund_script_sha256: Some(creation.btc_refund_script_sha256.clone()),
            liquid_claim_script_sha256: Some(creation.liquid_claim_script_sha256.clone()),
            liquid_refund_script_sha256: Some(creation.liquid_refund_script_sha256.clone()),
            btc_timeout_height: Some(creation.btc_timeout_height),
            liquid_timeout_height: Some(creation.liquid_timeout_height),
            btc_network: Some(creation.btc_network.clone()),
            liquid_network: Some(creation.liquid_network.clone()),
            liquid_asset_id: Some(creation.liquid_asset_id.clone()),
            merchant_liquid_destination: Some(creation.merchant_liquid_destination.clone()),
            merchant_emergency_btc_address: creation.merchant_emergency_btc_address.clone(),
            recovery_address_commitment_id: policy.emergency_bitcoin_commitment_id,
            created_at_unix: identity.created_at_unix,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
    };
    use bitcoin::script::Builder;
    use boltz_client::network::Network;
    use boltz_client::swaps::boltz::{ChainSwapDetails, Leaf, Side, SwapTree, SwapType};
    use boltz_client::{BtcSwapScript, LBtcSwapScript, ZKKeyPair, ZKSecp256k1};

    use super::*;
    use crate::boltz_restore::{BoltzRestoreKeyPurpose, ValidatedBoltzRestoreKey};
    use crate::canonical_json::canonical_json_and_sha256;
    use crate::swap_manifest::{
        ImmutableChainSwapCreationV1, ManifestKeyPurposeV1, MerchantPolicyReferencesV1,
        SwapDerivationLineageV1, SwapRestoreIdentityV1,
    };

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const OTHER_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const LIQUID_DESTINATION: &str = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";
    const EMERGENCY_ADDRESS: &str =
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const BLINDING_KEY: &str = "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";

    fn master_key(mnemonic: &str) -> SwapMasterKey {
        SwapMasterKey::from_mnemonic(mnemonic, None, Network::Mainnet).unwrap()
    }

    fn claim_script(
        hashlock: bitcoin::hashes::hash160::Hash,
        receiver: &PublicKey,
    ) -> bitcoin::ScriptBuf {
        Builder::new()
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_HASH160)
            .push_slice(hashlock.to_byte_array())
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&receiver.inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn refund_script(sender: &PublicKey, timeout: u32) -> bitcoin::ScriptBuf {
        Builder::new()
            .push_x_only_key(&sender.inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_lock_time(LockTime::from_consensus(timeout))
            .push_opcode(OP_CLTV)
            .into_script()
    }

    fn leaf_sha256(leaf: &Leaf) -> String {
        hex::encode(Sha256::digest(hex::decode(&leaf.output).unwrap()))
    }

    fn provider_response(
        id: &str,
        preimage: &Preimage,
        claim_public_key: PublicKey,
        refund_public_key: PublicKey,
    ) -> CreateChainResponse {
        let bitcoin_server_key = PublicKey::from_str(
            "031c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8",
        )
        .unwrap();
        let liquid_server_key = PublicKey::from_str(
            "033009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01a",
        )
        .unwrap();
        let bitcoin_timeout = 958_033;
        let liquid_timeout = 3_972_215;
        let bitcoin_tree = SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(claim_script(preimage.hash160, &bitcoin_server_key)),
                version: 0xc0,
            },
            refund_leaf: Leaf {
                output: hex::encode(refund_script(&refund_public_key, bitcoin_timeout)),
                version: 0xc0,
            },
            covenant_claim_leaf: None,
        };
        let liquid_tree = SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(claim_script(preimage.hash160, &claim_public_key)),
                version: 0xc4,
            },
            refund_leaf: Leaf {
                output: hex::encode(refund_script(&liquid_server_key, liquid_timeout)),
                version: 0xc4,
            },
            covenant_claim_leaf: None,
        };
        let bitcoin_address = BtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Lockup),
            funding_addrs: None,
            hashlock: preimage.hash160,
            receiver_pubkey: bitcoin_server_key,
            locktime: LockTime::from_consensus(bitcoin_timeout),
            sender_pubkey: refund_public_key,
        }
        .to_address(BitcoinChain::Bitcoin)
        .unwrap()
        .to_string();
        let blinding_key = ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), BLINDING_KEY).unwrap();
        let liquid_address = LBtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Claim),
            funding_addrs: None,
            hashlock: preimage.hash160,
            receiver_pubkey: claim_public_key,
            locktime: boltz_client::elements::LockTime::from_consensus(liquid_timeout),
            sender_pubkey: liquid_server_key,
            blinding_key,
        }
        .to_address(LiquidChain::Liquid)
        .unwrap()
        .to_string();

        CreateChainResponse {
            id: id.into(),
            claim_details: ChainSwapDetails {
                swap_tree: liquid_tree,
                lockup_address: liquid_address,
                server_public_key: liquid_server_key,
                timeout_block_height: liquid_timeout,
                amount: 25_000,
                blinding_key: Some(BLINDING_KEY.into()),
                refund_address: None,
                claim_address: None,
                bip21: None,
            },
            lockup_details: ChainSwapDetails {
                swap_tree: bitcoin_tree,
                lockup_address: bitcoin_address,
                server_public_key: bitcoin_server_key,
                timeout_block_height: bitcoin_timeout,
                amount: 25_431,
                blinding_key: None,
                refund_address: None,
                claim_address: None,
                bip21: Some("bitcoin:provider-evidence-only?amount=999".into()),
            },
        }
    }

    fn fixture(master: &SwapMasterKey) -> (SwapManifestV1, ValidatedBoltzRestoreSet) {
        let claim_index = 101_u32;
        let refund_index = 102_u32;
        let claim_keypair = master.derive_swapkey(u64::from(claim_index)).unwrap();
        let refund_keypair = master.derive_swapkey(u64::from(refund_index)).unwrap();
        let claim_public_key = PublicKey::new(claim_keypair.public_key());
        let refund_public_key = PublicKey::new(refund_keypair.public_key());
        let preimage = Preimage::from_swap_key(&claim_keypair);
        let response = provider_response(
            "RestoreReconstruction01",
            &preimage,
            claim_public_key,
            refund_public_key,
        );
        let (canonical_response, response_sha256) = canonical_json_and_sha256(&response).unwrap();
        let lockup_address = response.lockup_details.lockup_address.clone();
        let preimage_hash = preimage.sha256.to_string();
        let root_fingerprint = derive_root_fingerprint(master).unwrap();
        let manifest = SwapManifestV1::new(
            SwapRestoreIdentityV1 {
                manifest_id: Uuid::from_u128(0x8701),
                manifest_sequence: 1,
                previous_manifest_id: None,
                chain_swap_id: Uuid::from_u128(0x8702),
                boltz_swap_id: response.id.clone(),
                created_at_unix: 1_784_000_000,
            },
            SwapDerivationLineageV1 {
                root_fingerprint,
                key_epoch: 1,
                derivation_scheme_version: DERIVATION_SCHEME_VERSION,
                allocation_high_water_child_index: i64::from(refund_index),
                claim: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(0x8703),
                    child_index: i64::from(claim_index),
                    purpose: ManifestKeyPurposeV1::ChainClaim,
                    public_key_hex: claim_public_key.to_string(),
                    preimage_hash_hex: Some(preimage_hash.clone()),
                },
                refund: ManifestKeyAllocationV1 {
                    allocation_id: Uuid::from_u128(0x8704),
                    child_index: i64::from(refund_index),
                    purpose: ManifestKeyPurposeV1::ChainRefund,
                    public_key_hex: refund_public_key.to_string(),
                    preimage_hash_hex: None,
                },
            },
            ImmutableChainSwapCreationV1 {
                lockup_address: lockup_address.clone(),
                lockup_bip21: format!(
                    "bitcoin:{lockup_address}?amount=0.00025431&label=Restore%20payment"
                ),
                user_lock_amount_sat: 25_431,
                server_lock_amount_sat: 25_000,
                canonical_provider_response_json: canonical_response,
                pinned_pair_hash: "22".repeat(32),
                canonical_pair_quote_json: format!(r#"{{"hash":"{}","rate":1}}"#, "22".repeat(32)),
                creation_response_sha256: response_sha256,
                btc_claim_script_sha256: leaf_sha256(&response.lockup_details.swap_tree.claim_leaf),
                btc_refund_script_sha256: leaf_sha256(
                    &response.lockup_details.swap_tree.refund_leaf,
                ),
                liquid_claim_script_sha256: leaf_sha256(
                    &response.claim_details.swap_tree.claim_leaf,
                ),
                liquid_refund_script_sha256: leaf_sha256(
                    &response.claim_details.swap_tree.refund_leaf,
                ),
                btc_timeout_height: i64::from(response.lockup_details.timeout_block_height),
                liquid_timeout_height: i64::from(response.claim_details.timeout_block_height),
                btc_network: "bitcoin".into(),
                liquid_network: "liquid".into(),
                liquid_asset_id: boltz_client::elements::AssetId::LIQUID_BTC.to_string(),
                merchant_liquid_destination: LIQUID_DESTINATION.into(),
                merchant_emergency_btc_address: Some(EMERGENCY_ADDRESS.into()),
            },
            MerchantPolicyReferencesV1::new(
                Uuid::from_u128(0x8705),
                "restore-nym",
                LIQUID_DESTINATION,
                Some((Uuid::from_u128(0x8706), EMERGENCY_ADDRESS)),
            ),
        )
        .unwrap();
        let record = ValidatedBoltzRestoreRecord {
            provider_swap_id: response.id,
            kind: BoltzRestoreKind::Chain,
            status: "transaction.server.mempool".into(),
            created_at: 1_784_000_000,
            keys: vec![
                ValidatedBoltzRestoreKey {
                    purpose: BoltzRestoreKeyPurpose::ChainClaim,
                    child_index: claim_index,
                    public_key_hex: claim_public_key.to_string(),
                    preimage_sha256_hex: Some(preimage_hash),
                },
                ValidatedBoltzRestoreKey {
                    purpose: BoltzRestoreKeyPurpose::ChainRefund,
                    child_index: refund_index,
                    public_key_hex: refund_public_key.to_string(),
                    preimage_sha256_hex: None,
                },
            ],
        };
        (
            manifest,
            ValidatedBoltzRestoreSet {
                records: vec![record],
                max_child_index: Some(refund_index),
            },
        )
    }

    #[test]
    fn pure_reconstruction_rederives_exact_secrets_from_all_three_sources() {
        let master = master_key(TEST_MNEMONIC);
        let (manifest, provider) = fixture(&master);
        let manifests = [manifest];
        let prepared = prepare_reconstructions(&manifests, &provider, &master).unwrap();
        assert_eq!(prepared.len(), 1);

        let claim = master.derive_swapkey(101).unwrap();
        let refund = master.derive_swapkey(102).unwrap();
        let preimage = Preimage::from_swap_key(&claim).bytes.unwrap();
        assert_eq!(prepared[0].claim_key_hex, hex::encode(claim.secret_bytes()));
        assert_eq!(
            prepared[0].refund_key_hex,
            hex::encode(refund.secret_bytes())
        );
        assert_eq!(prepared[0].preimage_hex, hex::encode(preimage));
    }

    #[test]
    fn pure_reconstruction_rejects_wrong_root_and_provider_key() {
        let master = master_key(TEST_MNEMONIC);
        let wrong_master = master_key(OTHER_MNEMONIC);
        let (manifest, provider) = fixture(&master);
        let manifests = [manifest];
        let wrong_root_error = match prepare_reconstructions(&manifests, &provider, &wrong_master) {
            Ok(_) => panic!("wrong root unexpectedly reconstructed secrets"),
            Err(error) => error,
        };
        assert_eq!(
            wrong_root_error,
            ChainSwapStaleRestoreErrorV1::UnsupportedDerivationLineage
        );

        let mut mismatched_provider = provider;
        mismatched_provider.records[0].keys[0].child_index += 1;
        let provider_error =
            match prepare_reconstructions(&manifests, &mismatched_provider, &master) {
                Ok(_) => panic!("mismatched provider unexpectedly reconstructed secrets"),
                Err(error) => error,
            };
        assert_eq!(
            provider_error,
            ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch
        );
    }

    #[test]
    fn public_errors_are_fixed_bounded_and_source_free() {
        use std::error::Error as _;

        let all = [
            ChainSwapStaleRestoreErrorV1::WitnessLoadFailed,
            ChainSwapStaleRestoreErrorV1::WitnessRecordLimitExceeded,
            ChainSwapStaleRestoreErrorV1::ProviderRestoreFetchFailed,
            ChainSwapStaleRestoreErrorV1::ProviderRecordLimitExceeded,
            ChainSwapStaleRestoreErrorV1::CrossSourceEvidenceMismatch,
            ChainSwapStaleRestoreErrorV1::UnsupportedDerivationLineage,
            ChainSwapStaleRestoreErrorV1::SecretReconstructionFailed,
            ChainSwapStaleRestoreErrorV1::TransactionBeginFailed,
            ChainSwapStaleRestoreErrorV1::TransactionLockFailed,
            ChainSwapStaleRestoreErrorV1::MerchantPolicyMismatch,
            ChainSwapStaleRestoreErrorV1::AllocationWriteFailed,
            ChainSwapStaleRestoreErrorV1::AllocationConflict,
            ChainSwapStaleRestoreErrorV1::ChainSwapWriteFailed,
            ChainSwapStaleRestoreErrorV1::ChainSwapConflict,
            ChainSwapStaleRestoreErrorV1::TransactionCommitFailed,
        ];
        for error in all {
            let rendered = error.to_string();
            assert!(rendered.len() <= 64);
            assert!(error.source().is_none());
            for forbidden in ["RestoreReconstruction01", "restore-nym", "bc1p", "lq1p"] {
                assert!(!rendered.contains(forbidden));
            }
        }
    }
}
