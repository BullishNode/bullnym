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

use crate::boltz::ChainSwapResult;
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

/// Persisted derivation/allocation facts already committed by the caller's
/// pre-provider allocation boundary.
///
/// Public keys and the preimage hash are intentionally absent: the adapter
/// derives those exact values from the locally created [`ChainSwapResult`]
/// instead of accepting a second, drift-prone copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatedChainSwapLineage<'a> {
    pub root_fingerprint: &'a str,
    pub key_epoch: i32,
    pub derivation_scheme_version: i32,
    pub claim_allocation_id: Uuid,
    pub refund_allocation_id: Uuid,
    pub claim_child_index: i64,
    pub refund_child_index: i64,
}

/// Exact already-created inputs for the pure persistence adapter.
///
/// This type intentionally implements neither `Clone` nor `Debug`: the Boltz
/// result contains the claim preimage and both private keys. The manifest
/// identity is caller-supplied and is never generated or replaced here, so
/// rebuilding the same request preserves retry identity deterministically.
pub struct CreatedChainSwapPersistenceInput<'a> {
    pub chain_swap: &'a ChainSwapResult,
    pub lockup_bip21: &'a str,
    pub lineage: CreatedChainSwapLineage<'a>,
    pub merchant_policy: &'a MerchantPolicyReferencesV1,
    pub manifest_id: Uuid,
}

/// Pure adapter output from which the atomic coordinator request is borrowed.
///
/// Provider and policy values remain borrowed from their canonical typed
/// sources; only the required secret/public encodings are owned. It has no
/// provider, database, object-store, address-exposure, allocation, or
/// ambient runtime-secret capability and deliberately has no formatting
/// surface.
pub struct PreparedChainSwapPersistence<'a> {
    chain_swap: &'a ChainSwapResult,
    lockup_bip21: &'a str,
    lineage: CreatedChainSwapLineage<'a>,
    merchant_policy: &'a MerchantPolicyReferencesV1,
    manifest_id: Uuid,
    user_lock_amount_sat: i64,
    server_lock_amount_sat: i64,
    preimage_hex: String,
    claim_key_hex: String,
    refund_key_hex: String,
    claim_public_key_hex: String,
    refund_public_key_hex: String,
    preimage_hash_hex: String,
}

/// Borrowed, non-runtime parts of one atomic coordinator request.
///
/// Keeping these values in a named owner lets the future invoice seam borrow
/// `swap`, `lineage`, and `creation_terms` into the existing coordinator
/// request without changing its transaction or error contract. The caller
/// supplies the opaque [`ManifestStagingCrypto`] only at that final seam.
pub struct PreparedPersistAndDeliverChainSwapRequest<'a> {
    pub swap: NewChainSwapRecord<'a>,
    pub lineage: ChainSwapLineage<'a>,
    pub creation_terms: NewChainSwapCreationTerms<'a>,
    pub manifest_id: Uuid,
    pub merchant_policy: &'a MerchantPolicyReferencesV1,
}

/// Fixed, source-free adapter failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareChainSwapPersistenceError {
    NilManifestIdentity,
    UserLockAmountOutsideDatabaseRange,
    ServerLockAmountOutsideDatabaseRange,
}

impl fmt::Display for PrepareChainSwapPersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NilManifestIdentity => f.write_str("recovery-manifest identity must not be nil"),
            Self::UserLockAmountOutsideDatabaseRange => {
                f.write_str("chain-swap user-lock amount is outside the database range")
            }
            Self::ServerLockAmountOutsideDatabaseRange => {
                f.write_str("chain-swap server-lock amount is outside the database range")
            }
        }
    }
}

impl std::error::Error for PrepareChainSwapPersistenceError {}

/// Convert one already-created, locally validated Boltz chain swap into the
/// exact values needed by the atomic coordinator.
///
/// This function is pure. It performs only checked integer conversion,
/// canonical hex encoding, and lossless field movement/copying.
pub fn prepare_created_chain_swap_persistence<'a>(
    input: CreatedChainSwapPersistenceInput<'a>,
) -> Result<PreparedChainSwapPersistence<'a>, PrepareChainSwapPersistenceError> {
    let CreatedChainSwapPersistenceInput {
        chain_swap,
        lockup_bip21,
        lineage,
        merchant_policy,
        manifest_id,
    } = input;
    if manifest_id.is_nil() {
        return Err(PrepareChainSwapPersistenceError::NilManifestIdentity);
    }
    let user_lock_amount_sat = i64::try_from(chain_swap.user_lock_amount_sat)
        .map_err(|_| PrepareChainSwapPersistenceError::UserLockAmountOutsideDatabaseRange)?;
    let server_lock_amount_sat = i64::try_from(chain_swap.server_lock_amount_sat)
        .map_err(|_| PrepareChainSwapPersistenceError::ServerLockAmountOutsideDatabaseRange)?;
    let claim_public_key_hex = hex::encode(chain_swap.claim_keypair.public_key().serialize());
    let refund_public_key_hex = hex::encode(chain_swap.refund_keypair.public_key().serialize());
    let preimage_hash_hex = hex::encode(Sha256::digest(&chain_swap.preimage));

    Ok(PreparedChainSwapPersistence {
        chain_swap,
        lockup_bip21,
        lineage,
        merchant_policy,
        manifest_id,
        user_lock_amount_sat,
        server_lock_amount_sat,
        preimage_hex: hex::encode(&chain_swap.preimage),
        claim_key_hex: hex::encode(chain_swap.claim_keypair.secret_bytes()),
        refund_key_hex: hex::encode(chain_swap.refund_keypair.secret_bytes()),
        claim_public_key_hex,
        refund_public_key_hex,
        preimage_hash_hex,
    })
}

impl PreparedChainSwapPersistence<'_> {
    /// Borrow every pure, non-runtime part of an atomic coordinator request.
    pub fn coordinator_request_parts(&self) -> PreparedPersistAndDeliverChainSwapRequest<'_> {
        let swap = self.chain_swap;
        let lineage = self.lineage;
        let terms = &swap.creation_terms;
        PreparedPersistAndDeliverChainSwapRequest {
            swap: NewChainSwapRecord {
                invoice_id: self.merchant_policy.invoice_id,
                nym: Some(&self.merchant_policy.merchant_nym),
                boltz_swap_id: &swap.swap_id,
                lockup_address: &swap.lockup_address,
                lockup_bip21: Some(self.lockup_bip21),
                user_lock_amount_sat: self.user_lock_amount_sat,
                server_lock_amount_sat: self.server_lock_amount_sat,
                preimage_hex: &self.preimage_hex,
                claim_key_hex: &self.claim_key_hex,
                refund_key_hex: &self.refund_key_hex,
                boltz_response_json: &swap.canonical_response_json,
                claim_key_index: Some(lineage.claim_child_index),
                refund_key_index: Some(lineage.refund_child_index),
                root_fingerprint: Some(lineage.root_fingerprint),
            },
            lineage: ChainSwapLineage {
                claim_allocation_id: lineage.claim_allocation_id,
                refund_allocation_id: lineage.refund_allocation_id,
                key_epoch: lineage.key_epoch,
                derivation_scheme_version: lineage.derivation_scheme_version,
                claim_public_key_hex: &self.claim_public_key_hex,
                refund_public_key_hex: &self.refund_public_key_hex,
                preimage_hash_hex: &self.preimage_hash_hex,
            },
            creation_terms: NewChainSwapCreationTerms {
                pinned_pair_hash: &terms.pinned_pair_hash,
                canonical_pair_quote_json: &terms.canonical_pair_quote_json,
                creation_response_sha256: &terms.creation_response_sha256,
                btc_claim_script_sha256: &terms.btc_claim_script_sha256,
                btc_refund_script_sha256: &terms.btc_refund_script_sha256,
                liquid_claim_script_sha256: &terms.liquid_claim_script_sha256,
                liquid_refund_script_sha256: &terms.liquid_refund_script_sha256,
                btc_timeout_height: i64::from(terms.btc_timeout_height),
                liquid_timeout_height: i64::from(terms.liquid_timeout_height),
                btc_network: terms.btc_network,
                liquid_network: terms.liquid_network,
                liquid_asset_id: &terms.liquid_asset_id,
                merchant_liquid_destination: &self.merchant_policy.merchant_liquid_destination,
                merchant_emergency_btc_address: self
                    .merchant_policy
                    .merchant_emergency_btc_address
                    .as_deref(),
            },
            manifest_id: self.manifest_id,
            merchant_policy: self.merchant_policy,
        }
    }
}

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

#[cfg(test)]
mod request_adapter_tests {
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    use super::*;
    use crate::boltz::ValidatedChainSwapCreationTerms;

    const MANIFEST_ID: Uuid = Uuid::from_u128(0x1020_3040_5060_7080_90a0_b0c0_d0e0_f001);
    const INVOICE_ID: Uuid = Uuid::from_u128(0x1020_3040_5060_7080_90a0_b0c0_d0e0_f002);
    const CLAIM_ALLOCATION_ID: Uuid = Uuid::from_u128(0x1020_3040_5060_7080_90a0_b0c0_d0e0_f003);
    const REFUND_ALLOCATION_ID: Uuid = Uuid::from_u128(0x1020_3040_5060_7080_90a0_b0c0_d0e0_f004);
    const EMERGENCY_COMMITMENT_ID: Uuid =
        Uuid::from_u128(0x1020_3040_5060_7080_90a0_b0c0_d0e0_f005);
    const LIQUID_DESTINATION: &str = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";
    const EMERGENCY_ADDRESS: &str =
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

    fn keypair(byte: u8) -> Keypair {
        Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[byte; 32]).unwrap(),
        )
    }

    fn created_chain_swap() -> ChainSwapResult {
        ChainSwapResult {
            swap_id: "CanonicalAdapter01".into(),
            lockup_address: "bc1p5cyxnuxmeuwuvkwfem96l0gdqvq98u0f9ss3u72dr5ysjr5prezqf3s9q3".into(),
            user_lock_amount_sat: 25_431,
            server_lock_amount_sat: 25_000,
            preimage: vec![0x31; 32],
            claim_keypair: keypair(0x41),
            refund_keypair: keypair(0x42),
            canonical_response_json: r#"{"claimDetails":{"amount":25000},"id":"CanonicalAdapter01","lockupDetails":{"amount":25431}}"#.into(),
            creation_terms: ValidatedChainSwapCreationTerms {
                pinned_pair_hash: "51".repeat(32),
                canonical_pair_quote_json: format!(
                    r#"{{"hash":"{}","rate":1}}"#,
                    "51".repeat(32)
                ),
                creation_response_sha256: "52".repeat(32),
                btc_claim_script_sha256: "53".repeat(32),
                btc_refund_script_sha256: "54".repeat(32),
                liquid_claim_script_sha256: "55".repeat(32),
                liquid_refund_script_sha256: "56".repeat(32),
                btc_timeout_height: 958_033,
                liquid_timeout_height: 3_972_215,
                btc_network: "bitcoin",
                liquid_network: "liquid",
                liquid_asset_id:
                    "6f0279e9ed041c3d710a9f57d0c02928416413f827c37bf6833e2407092ff84d"
                        .into(),
            },
        }
    }

    fn merchant_policy() -> MerchantPolicyReferencesV1 {
        MerchantPolicyReferencesV1::new(
            INVOICE_ID,
            "canonical-merchant",
            LIQUID_DESTINATION,
            Some((EMERGENCY_COMMITMENT_ID, EMERGENCY_ADDRESS)),
        )
    }

    fn lineage() -> CreatedChainSwapLineage<'static> {
        CreatedChainSwapLineage {
            root_fingerprint: "0123456789abcdef",
            key_epoch: 7,
            derivation_scheme_version: 3,
            claim_allocation_id: CLAIM_ALLOCATION_ID,
            refund_allocation_id: REFUND_ALLOCATION_ID,
            claim_child_index: 41_001,
            refund_child_index: 41_002,
        }
    }

    #[test]
    fn chain_swap_request_adapter_preserves_every_provider_and_recovery_field() {
        let created = created_chain_swap();
        let expected_claim_public = hex::encode(created.claim_keypair.public_key().serialize());
        let expected_refund_public = hex::encode(created.refund_keypair.public_key().serialize());
        let expected_preimage_hash = hex::encode(Sha256::digest(&created.preimage));
        let expected_claim_secret = hex::encode(created.claim_keypair.secret_bytes());
        let expected_refund_secret = hex::encode(created.refund_keypair.secret_bytes());
        let policy = merchant_policy();
        let prepared = prepare_created_chain_swap_persistence(
            CreatedChainSwapPersistenceInput {
                chain_swap: &created,
                lockup_bip21: "bitcoin:bc1p5cyxnuxmeuwuvkwfem96l0gdqvq98u0f9ss3u72dr5ysjr5prezqf3s9q3?amount=0.00025431&message=canonical",
                lineage: lineage(),
                merchant_policy: &policy,
                manifest_id: MANIFEST_ID,
            },
        )
        .unwrap();
        let parts = prepared.coordinator_request_parts();

        assert_eq!(parts.manifest_id, MANIFEST_ID);
        assert_eq!(parts.merchant_policy, &policy);
        assert_eq!(parts.swap.invoice_id, INVOICE_ID);
        assert_eq!(parts.swap.nym, Some("canonical-merchant"));
        assert_eq!(parts.swap.boltz_swap_id, created.swap_id);
        assert_eq!(parts.swap.lockup_address, created.lockup_address);
        assert_eq!(
            parts.swap.lockup_bip21,
            Some("bitcoin:bc1p5cyxnuxmeuwuvkwfem96l0gdqvq98u0f9ss3u72dr5ysjr5prezqf3s9q3?amount=0.00025431&message=canonical")
        );
        assert_eq!(parts.swap.user_lock_amount_sat, 25_431);
        assert_eq!(parts.swap.server_lock_amount_sat, 25_000);
        assert_eq!(parts.swap.preimage_hex, hex::encode(&created.preimage));
        assert_eq!(parts.swap.claim_key_hex, expected_claim_secret);
        assert_eq!(parts.swap.refund_key_hex, expected_refund_secret);
        assert_eq!(
            parts.swap.boltz_response_json,
            created.canonical_response_json
        );
        assert_eq!(parts.swap.claim_key_index, Some(41_001));
        assert_eq!(parts.swap.refund_key_index, Some(41_002));
        assert_eq!(parts.swap.root_fingerprint, Some("0123456789abcdef"));

        assert_eq!(parts.lineage.claim_allocation_id, CLAIM_ALLOCATION_ID);
        assert_eq!(parts.lineage.refund_allocation_id, REFUND_ALLOCATION_ID);
        assert_eq!(parts.lineage.key_epoch, 7);
        assert_eq!(parts.lineage.derivation_scheme_version, 3);
        assert_eq!(parts.lineage.claim_public_key_hex, expected_claim_public);
        assert_eq!(parts.lineage.refund_public_key_hex, expected_refund_public);
        assert_eq!(parts.lineage.preimage_hash_hex, expected_preimage_hash);

        let actual = &parts.creation_terms;
        let expected = &created.creation_terms;
        assert_eq!(actual.pinned_pair_hash, expected.pinned_pair_hash);
        assert_eq!(
            actual.canonical_pair_quote_json,
            expected.canonical_pair_quote_json
        );
        assert_eq!(
            actual.creation_response_sha256,
            expected.creation_response_sha256
        );
        assert_eq!(
            actual.btc_claim_script_sha256,
            expected.btc_claim_script_sha256
        );
        assert_eq!(
            actual.btc_refund_script_sha256,
            expected.btc_refund_script_sha256
        );
        assert_eq!(
            actual.liquid_claim_script_sha256,
            expected.liquid_claim_script_sha256
        );
        assert_eq!(
            actual.liquid_refund_script_sha256,
            expected.liquid_refund_script_sha256
        );
        assert_eq!(actual.btc_timeout_height, 958_033);
        assert_eq!(actual.liquid_timeout_height, 3_972_215);
        assert_eq!(actual.btc_network, "bitcoin");
        assert_eq!(actual.liquid_network, "liquid");
        assert_eq!(actual.liquid_asset_id, expected.liquid_asset_id);
        assert_eq!(actual.merchant_liquid_destination, LIQUID_DESTINATION);
        assert_eq!(
            actual.merchant_emergency_btc_address,
            Some(EMERGENCY_ADDRESS)
        );
        assert_eq!(
            parts.merchant_policy.emergency_bitcoin_commitment_id,
            Some(EMERGENCY_COMMITMENT_ID)
        );
    }

    #[test]
    fn chain_swap_request_adapter_keeps_manifest_identity_deterministic() {
        let created = created_chain_swap();
        let policy = merchant_policy();
        let prepared = prepare_created_chain_swap_persistence(CreatedChainSwapPersistenceInput {
            chain_swap: &created,
            lockup_bip21: "bitcoin:canonical?amount=0.00025431",
            lineage: lineage(),
            merchant_policy: &policy,
            manifest_id: MANIFEST_ID,
        })
        .unwrap();

        let first = prepared.coordinator_request_parts();
        let second = prepared.coordinator_request_parts();
        assert_eq!(first.manifest_id, MANIFEST_ID);
        assert_eq!(second.manifest_id, MANIFEST_ID);
        assert_eq!(first.swap.lockup_address, created.lockup_address);
        assert_eq!(
            first.swap.lockup_bip21,
            Some("bitcoin:canonical?amount=0.00025431")
        );
        assert_eq!(first.merchant_policy, &policy);

        let signing_key = keypair(0x43);
        let pinned_signer = signing_key.x_only_public_key().0;
        let encryption_key = [0x44; 32];
        let request = PersistAndDeliverChainSwapRequest {
            swap: &first.swap,
            lineage: &first.lineage,
            creation_terms: &first.creation_terms,
            manifest_id: first.manifest_id,
            merchant_policy: first.merchant_policy,
            crypto: ManifestStagingCrypto::new(
                "manifest-key-v1",
                &encryption_key,
                &signing_key,
                &pinned_signer,
            ),
        };
        assert_eq!(request.manifest_id, MANIFEST_ID);
    }

    #[test]
    fn chain_swap_request_adapter_rejects_only_unrepresentable_values_without_defaults() {
        let created = created_chain_swap();
        let policy = merchant_policy();
        let nil_identity =
            match prepare_created_chain_swap_persistence(CreatedChainSwapPersistenceInput {
                chain_swap: &created,
                lockup_bip21: "bitcoin:canonical?amount=0.00025431",
                lineage: lineage(),
                merchant_policy: &policy,
                manifest_id: Uuid::nil(),
            }) {
                Err(error) => error,
                Ok(_) => panic!("nil manifest identity must be rejected"),
            };
        assert_eq!(
            nil_identity,
            PrepareChainSwapPersistenceError::NilManifestIdentity
        );

        let mut oversized_user = created_chain_swap();
        oversized_user.user_lock_amount_sat = i64::MAX as u64 + 1;
        assert!(matches!(
            prepare_created_chain_swap_persistence(CreatedChainSwapPersistenceInput {
                chain_swap: &oversized_user,
                lockup_bip21: "bitcoin:canonical?amount=0.00025431",
                lineage: lineage(),
                merchant_policy: &policy,
                manifest_id: MANIFEST_ID,
            }),
            Err(PrepareChainSwapPersistenceError::UserLockAmountOutsideDatabaseRange)
        ));

        let mut oversized_server = created_chain_swap();
        oversized_server.server_lock_amount_sat = i64::MAX as u64 + 1;
        assert!(matches!(
            prepare_created_chain_swap_persistence(CreatedChainSwapPersistenceInput {
                chain_swap: &oversized_server,
                lockup_bip21: "bitcoin:canonical?amount=0.00025431",
                lineage: lineage(),
                merchant_policy: &policy,
                manifest_id: MANIFEST_ID,
            }),
            Err(PrepareChainSwapPersistenceError::ServerLockAmountOutsideDatabaseRange)
        ));

        for error in [
            nil_identity,
            PrepareChainSwapPersistenceError::UserLockAmountOutsideDatabaseRange,
            PrepareChainSwapPersistenceError::ServerLockAmountOutsideDatabaseRange,
        ] {
            let public = format!("{error:?} {error}");
            assert!(!public.contains(&created.canonical_response_json));
            assert!(!public.contains(&hex::encode(&created.preimage)));
        }
    }
}
