//! Restartable reconstruction of migration-052 delivery evidence.
//!
//! This boundary compares every local delivery-ledger row with one complete,
//! authenticated, creation-quiescent witness. Existing rows must be an exact
//! prefix, including the original create-only envelope bytes. A missing suffix
//! is appended one row at a time through the migration-052 pending barrier and
//! acknowledged only after the corresponding external object has been read
//! and authenticated again.
//!
//! The caller must stop or serialize manifest creation and delivery for the
//! entire call, matching [`RecoveryManifestWitnessLoaderV1::load_quiescent`].
//! A failure leaves either the original prefix or one exact pending row, both
//! safe to retry. This module deliberately does not reconstruct chain-swap or
//! merchant-policy rows, alter admission, add a migration, or wire startup.

use std::collections::BTreeSet;
use std::fmt;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::db::{
    insert_manifest_delivery, list_manifest_delivery_audit, lock_manifest_delivery_tail,
    mark_manifest_delivered, ChainSwapManifestDelivery, ManifestDeliveryIdentity,
    MAX_MANIFEST_AUDIT_PAGE,
};
use crate::swap_manifest::EncryptedSwapManifestV1;
use crate::swap_manifest_witness::{
    LoadedRecoveryWitnessRecordV1, LoadedRecoveryWitnessV1, RecoveryManifestWitnessLoaderV1,
    RecoveryWitnessLoadError, MAX_RECOVERY_WITNESS_RECORDS_V1,
};

/// Bounded result of one exact witness-to-ledger reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestDeliveryLedgerRebuildOutcomeV1 {
    pub witness_records: usize,
    pub verified_existing_records: usize,
    pub resumed_pending_records: usize,
    pub reconstructed_records: usize,
}

/// Sanitized, fail-closed reconstruction failures.
///
/// No variant retains SQL/object-store errors, identifiers, envelope bytes,
/// endpoints, credentials, or opening keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestDeliveryLedgerRebuildErrorV1 {
    WitnessLoadFailed,
    WitnessRecordLimitExceeded,
    WitnessTopologyInvalid,
    ExactWitnessReadFailed,
    LocalLedgerReadFailed,
    LocalLedgerNotExact,
    LocalLedgerStateInvalid,
    LedgerAppendFailed,
    LedgerAppendInvariantFailed,
    LedgerAcknowledgementFailed,
    LedgerAcknowledgementInvariantFailed,
    FinalLedgerVerificationFailed,
}

impl fmt::Display for ManifestDeliveryLedgerRebuildErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WitnessLoadFailed => "recovery witness load failed",
            Self::WitnessRecordLimitExceeded => "recovery witness exceeds the record limit",
            Self::WitnessTopologyInvalid => "recovery witness ledger topology is invalid",
            Self::ExactWitnessReadFailed => "exact recovery witness read failed",
            Self::LocalLedgerReadFailed => "manifest delivery ledger read failed",
            Self::LocalLedgerNotExact => "manifest delivery ledger is not an exact witness prefix",
            Self::LocalLedgerStateInvalid => "manifest delivery ledger state is invalid",
            Self::LedgerAppendFailed => "manifest delivery ledger reconstruction append failed",
            Self::LedgerAppendInvariantFailed => {
                "manifest delivery ledger reconstructed row did not match"
            }
            Self::LedgerAcknowledgementFailed => {
                "manifest delivery ledger reconstruction acknowledgement failed"
            }
            Self::LedgerAcknowledgementInvariantFailed => {
                "manifest delivery ledger acknowledged row did not match"
            }
            Self::FinalLedgerVerificationFailed => {
                "manifest delivery ledger changed during reconstruction"
            }
        })
    }
}

impl std::error::Error for ManifestDeliveryLedgerRebuildErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryStateV1 {
    Pending,
    Delivered,
}

#[derive(Clone, PartialEq, Eq)]
struct DeliveryLedgerRowV1 {
    identity: ManifestDeliveryIdentity,
    encrypted_envelope: EncryptedSwapManifestV1,
    envelope_sha256: String,
    state: DeliveryStateV1,
}

impl DeliveryLedgerRowV1 {
    fn from_database(
        row: ChainSwapManifestDelivery,
    ) -> Result<Self, ManifestDeliveryLedgerRebuildErrorV1> {
        let state = match (row.delivery_state.as_str(), row.delivered_at_unix) {
            ("pending", None) => DeliveryStateV1::Pending,
            ("delivered", Some(_)) => DeliveryStateV1::Delivered,
            _ => return Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerStateInvalid),
        };
        let identity = row.identity();
        let envelope_sha256 = row.envelope_sha256.clone();
        Ok(Self {
            identity,
            encrypted_envelope: row.into_encrypted_envelope(),
            envelope_sha256,
            state,
        })
    }
}

impl fmt::Debug for DeliveryLedgerRowV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryLedgerRowV1")
            .field("identity", &self.identity)
            .field("encrypted_envelope", &"<redacted>")
            .field("envelope_sha256", &"<redacted>")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ExactWitnessLedgerRecordV1 {
    identity: ManifestDeliveryIdentity,
    encrypted_envelope: EncryptedSwapManifestV1,
    envelope_sha256: String,
}

impl ExactWitnessLedgerRecordV1 {
    fn from_authenticated(record: LoadedRecoveryWitnessRecordV1) -> Self {
        let (manifest, encrypted_envelope) = record.into_parts();
        let restore_identity = manifest.restore_identity;
        let envelope_sha256 = hex::encode(Sha256::digest(encrypted_envelope.encoded().as_bytes()));
        Self {
            identity: ManifestDeliveryIdentity {
                manifest_id: restore_identity.manifest_id,
                chain_swap_id: restore_identity.chain_swap_id,
                manifest_sequence: restore_identity.manifest_sequence,
                previous_manifest_id: restore_identity.previous_manifest_id,
            },
            encrypted_envelope,
            envelope_sha256,
        }
    }
}

impl fmt::Debug for ExactWitnessLedgerRecordV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExactWitnessLedgerRecordV1")
            .field("identity", &self.identity)
            .field("encrypted_envelope", &"<redacted>")
            .field("envelope_sha256", &"<redacted>")
            .finish()
    }
}

#[async_trait]
trait ExactLedgerWitnessV1: Send + Sync {
    fn identities(&self) -> &[ManifestDeliveryIdentity];

    async fn load_exact(
        &self,
        index: usize,
    ) -> Result<ExactWitnessLedgerRecordV1, ManifestDeliveryLedgerRebuildErrorV1>;
}

struct LoadedExactLedgerWitnessV1<'a> {
    loader: &'a RecoveryManifestWitnessLoaderV1,
    loaded: LoadedRecoveryWitnessV1,
    identities: Vec<ManifestDeliveryIdentity>,
}

impl<'a> LoadedExactLedgerWitnessV1<'a> {
    async fn load(
        loader: &'a RecoveryManifestWitnessLoaderV1,
    ) -> Result<Self, ManifestDeliveryLedgerRebuildErrorV1> {
        let loaded = loader.load_quiescent().await.map_err(|error| match error {
            RecoveryWitnessLoadError::RecordLimitExceeded => {
                ManifestDeliveryLedgerRebuildErrorV1::WitnessRecordLimitExceeded
            }
            _ => ManifestDeliveryLedgerRebuildErrorV1::WitnessLoadFailed,
        })?;
        let identities = loaded
            .manifests()
            .iter()
            .map(|manifest| ManifestDeliveryIdentity {
                manifest_id: manifest.restore_identity.manifest_id,
                chain_swap_id: manifest.restore_identity.chain_swap_id,
                manifest_sequence: manifest.restore_identity.manifest_sequence,
                previous_manifest_id: manifest.restore_identity.previous_manifest_id,
            })
            .collect();
        Ok(Self {
            loader,
            loaded,
            identities,
        })
    }
}

#[async_trait]
impl ExactLedgerWitnessV1 for LoadedExactLedgerWitnessV1<'_> {
    fn identities(&self) -> &[ManifestDeliveryIdentity] {
        &self.identities
    }

    async fn load_exact(
        &self,
        index: usize,
    ) -> Result<ExactWitnessLedgerRecordV1, ManifestDeliveryLedgerRebuildErrorV1> {
        let manifest = self
            .loaded
            .manifests()
            .get(index)
            .ok_or(ManifestDeliveryLedgerRebuildErrorV1::WitnessTopologyInvalid)?;
        let record = self
            .loader
            .load_exact_authenticated_record(manifest)
            .await
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::ExactWitnessReadFailed)?;
        Ok(ExactWitnessLedgerRecordV1::from_authenticated(record))
    }
}

#[async_trait]
trait DeliveryLedgerDatabaseV1: Send + Sync {
    async fn read_page(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<DeliveryLedgerRowV1>, ManifestDeliveryLedgerRebuildErrorV1>;

    async fn append_pending(
        &self,
        exact: &ExactWitnessLedgerRecordV1,
    ) -> Result<DeliveryLedgerRowV1, ManifestDeliveryLedgerRebuildErrorV1>;

    async fn acknowledge(
        &self,
        exact: &ExactWitnessLedgerRecordV1,
    ) -> Result<DeliveryLedgerRowV1, ManifestDeliveryLedgerRebuildErrorV1>;
}

struct PostgresDeliveryLedgerV1<'a> {
    pool: &'a PgPool,
}

#[async_trait]
impl DeliveryLedgerDatabaseV1 for PostgresDeliveryLedgerV1<'_> {
    async fn read_page(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<DeliveryLedgerRowV1>, ManifestDeliveryLedgerRebuildErrorV1> {
        list_manifest_delivery_audit(self.pool, after_sequence, limit)
            .await
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerReadFailed)?
            .into_iter()
            .map(DeliveryLedgerRowV1::from_database)
            .collect()
    }

    async fn append_pending(
        &self,
        exact: &ExactWitnessLedgerRecordV1,
    ) -> Result<DeliveryLedgerRowV1, ManifestDeliveryLedgerRebuildErrorV1> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendFailed)?;
        let reservation = lock_manifest_delivery_tail(&mut transaction)
            .await
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendFailed)?;
        let reserved_identity = reservation
            .identity(exact.identity.manifest_id, exact.identity.chain_swap_id)
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendInvariantFailed)?;
        if reserved_identity != exact.identity {
            return Err(ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendInvariantFailed);
        }
        let inserted =
            insert_manifest_delivery(&mut transaction, &exact.identity, &exact.encrypted_envelope)
                .await
                .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendFailed)?;
        transaction
            .commit()
            .await
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendFailed)?;
        DeliveryLedgerRowV1::from_database(inserted)
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendInvariantFailed)
    }

    async fn acknowledge(
        &self,
        exact: &ExactWitnessLedgerRecordV1,
    ) -> Result<DeliveryLedgerRowV1, ManifestDeliveryLedgerRebuildErrorV1> {
        let acknowledged =
            mark_manifest_delivered(self.pool, &exact.identity, &exact.envelope_sha256)
                .await
                .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementFailed)?
                .ok_or(
                    ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementInvariantFailed,
                )?;
        DeliveryLedgerRowV1::from_database(acknowledged)
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementInvariantFailed)
    }
}

/// Verify and reconstruct the migration-052 ledger from one exact witness.
///
/// The authenticated witness is the authority only for delivery evidence.
/// Migration 052 independently requires the referenced chain-swap source row
/// to exist before a missing ledger row can be inserted. Consequently this
/// function fails closed when a separate chain-swap reconstruction has not yet
/// established that source; it never invents operational or merchant state.
pub async fn rebuild_manifest_delivery_ledger_from_quiescent_witness_v1(
    pool: &PgPool,
    loader: &RecoveryManifestWitnessLoaderV1,
) -> Result<ManifestDeliveryLedgerRebuildOutcomeV1, ManifestDeliveryLedgerRebuildErrorV1> {
    let witness = LoadedExactLedgerWitnessV1::load(loader).await?;
    let database = PostgresDeliveryLedgerV1 { pool };
    rebuild_exact_ledger(&database, &witness).await
}

async fn rebuild_exact_ledger<D, W>(
    database: &D,
    witness: &W,
) -> Result<ManifestDeliveryLedgerRebuildOutcomeV1, ManifestDeliveryLedgerRebuildErrorV1>
where
    D: DeliveryLedgerDatabaseV1,
    W: ExactLedgerWitnessV1,
{
    validate_witness_topology(witness.identities())?;

    let mut index = 0_usize;
    let mut after_sequence = 0_u64;
    let mut resumed_pending_records = 0_usize;
    let mut pending_exact = None;

    loop {
        let page = database
            .read_page(after_sequence, MAX_MANIFEST_AUDIT_PAGE)
            .await?;
        if page.len() > MAX_MANIFEST_AUDIT_PAGE {
            return Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerReadFailed);
        }
        if page.is_empty() {
            break;
        }

        for local in page {
            if pending_exact.is_some() {
                return Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerStateInvalid);
            }
            let expected_identity = witness
                .identities()
                .get(index)
                .ok_or(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerNotExact)?;
            if &local.identity != expected_identity
                || local.identity.manifest_sequence <= after_sequence
            {
                return Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerNotExact);
            }
            let exact = witness.load_exact(index).await?;
            require_exact_identity(&exact, expected_identity)?;
            require_exact_row(&local, &exact, local.state)?;

            if local.state == DeliveryStateV1::Pending {
                pending_exact = Some(exact);
            }

            after_sequence = local.identity.manifest_sequence;
            index = index.saturating_add(1);
        }
    }

    let verified_existing_records = index;
    if let Some(exact) = pending_exact {
        let acknowledged = database.acknowledge(&exact).await?;
        require_exact_row(&acknowledged, &exact, DeliveryStateV1::Delivered).map_err(|_| {
            ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementInvariantFailed
        })?;
        resumed_pending_records = 1;
    }
    let mut reconstructed_records = 0_usize;
    while index < witness.identities().len() {
        let expected_identity = &witness.identities()[index];
        let exact = witness.load_exact(index).await?;
        require_exact_identity(&exact, expected_identity)?;

        let inserted = database.append_pending(&exact).await?;
        require_exact_row(&inserted, &exact, DeliveryStateV1::Pending)
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendInvariantFailed)?;

        let acknowledged = database.acknowledge(&exact).await?;
        require_exact_row(&acknowledged, &exact, DeliveryStateV1::Delivered).map_err(|_| {
            ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementInvariantFailed
        })?;

        after_sequence = exact.identity.manifest_sequence;
        index = index.saturating_add(1);
        reconstructed_records = reconstructed_records.saturating_add(1);
    }

    if !database.read_page(after_sequence, 1).await?.is_empty() {
        return Err(ManifestDeliveryLedgerRebuildErrorV1::FinalLedgerVerificationFailed);
    }

    Ok(ManifestDeliveryLedgerRebuildOutcomeV1 {
        witness_records: witness.identities().len(),
        verified_existing_records,
        resumed_pending_records,
        reconstructed_records,
    })
}

fn validate_witness_topology(
    identities: &[ManifestDeliveryIdentity],
) -> Result<(), ManifestDeliveryLedgerRebuildErrorV1> {
    if identities.len() > MAX_RECOVERY_WITNESS_RECORDS_V1 {
        return Err(ManifestDeliveryLedgerRebuildErrorV1::WitnessRecordLimitExceeded);
    }
    let mut previous_manifest_id = None;
    let mut manifest_ids = BTreeSet::new();
    let mut chain_swap_ids = BTreeSet::new();
    for (index, identity) in identities.iter().enumerate() {
        let expected_sequence = u64::try_from(index + 1)
            .map_err(|_| ManifestDeliveryLedgerRebuildErrorV1::WitnessTopologyInvalid)?;
        if identity.manifest_id.is_nil()
            || identity.chain_swap_id.is_nil()
            || identity.manifest_sequence != expected_sequence
            || identity.previous_manifest_id != previous_manifest_id
            || !manifest_ids.insert(identity.manifest_id)
            || !chain_swap_ids.insert(identity.chain_swap_id)
        {
            return Err(ManifestDeliveryLedgerRebuildErrorV1::WitnessTopologyInvalid);
        }
        previous_manifest_id = Some(identity.manifest_id);
    }
    Ok(())
}

fn require_exact_identity(
    exact: &ExactWitnessLedgerRecordV1,
    expected_identity: &ManifestDeliveryIdentity,
) -> Result<(), ManifestDeliveryLedgerRebuildErrorV1> {
    if &exact.identity != expected_identity {
        return Err(ManifestDeliveryLedgerRebuildErrorV1::ExactWitnessReadFailed);
    }
    let digest = hex::encode(Sha256::digest(
        exact.encrypted_envelope.encoded().as_bytes(),
    ));
    if digest != exact.envelope_sha256 {
        return Err(ManifestDeliveryLedgerRebuildErrorV1::ExactWitnessReadFailed);
    }
    Ok(())
}

fn require_exact_row(
    row: &DeliveryLedgerRowV1,
    exact: &ExactWitnessLedgerRecordV1,
    expected_state: DeliveryStateV1,
) -> Result<(), ManifestDeliveryLedgerRebuildErrorV1> {
    if row.identity != exact.identity
        || row.encrypted_envelope != exact.encrypted_envelope
        || row.envelope_sha256 != exact.envelope_sha256
        || row.state != expected_state
    {
        return Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerNotExact);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    struct FakeWitness {
        identities: Vec<ManifestDeliveryIdentity>,
        records: Vec<Option<ExactWitnessLedgerRecordV1>>,
    }

    #[async_trait]
    impl ExactLedgerWitnessV1 for FakeWitness {
        fn identities(&self) -> &[ManifestDeliveryIdentity] {
            &self.identities
        }

        async fn load_exact(
            &self,
            index: usize,
        ) -> Result<ExactWitnessLedgerRecordV1, ManifestDeliveryLedgerRebuildErrorV1> {
            self.records
                .get(index)
                .and_then(Clone::clone)
                .ok_or(ManifestDeliveryLedgerRebuildErrorV1::ExactWitnessReadFailed)
        }
    }

    struct FakeDatabase {
        rows: Mutex<Vec<DeliveryLedgerRowV1>>,
        reject_append: bool,
        reject_acknowledgement: bool,
    }

    impl FakeDatabase {
        fn new(rows: Vec<DeliveryLedgerRowV1>) -> Self {
            Self {
                rows: Mutex::new(rows),
                reject_append: false,
                reject_acknowledgement: false,
            }
        }
    }

    #[async_trait]
    impl DeliveryLedgerDatabaseV1 for FakeDatabase {
        async fn read_page(
            &self,
            after_sequence: u64,
            limit: usize,
        ) -> Result<Vec<DeliveryLedgerRowV1>, ManifestDeliveryLedgerRebuildErrorV1> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|row| row.identity.manifest_sequence > after_sequence)
                .take(limit)
                .cloned()
                .collect())
        }

        async fn append_pending(
            &self,
            exact: &ExactWitnessLedgerRecordV1,
        ) -> Result<DeliveryLedgerRowV1, ManifestDeliveryLedgerRebuildErrorV1> {
            if self.reject_append {
                return Err(ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendFailed);
            }
            let mut rows = self.rows.lock().unwrap();
            let expected_sequence = u64::try_from(rows.len()).unwrap() + 1;
            let expected_previous = rows.last().map(|row| row.identity.manifest_id);
            if exact.identity.manifest_sequence != expected_sequence
                || exact.identity.previous_manifest_id != expected_previous
                || rows.iter().any(|row| row.state == DeliveryStateV1::Pending)
            {
                return Err(ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendFailed);
            }
            let row = row(exact, DeliveryStateV1::Pending);
            rows.push(row.clone());
            Ok(row)
        }

        async fn acknowledge(
            &self,
            exact: &ExactWitnessLedgerRecordV1,
        ) -> Result<DeliveryLedgerRowV1, ManifestDeliveryLedgerRebuildErrorV1> {
            if self.reject_acknowledgement {
                return Err(ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementFailed);
            }
            let mut rows = self.rows.lock().unwrap();
            let stored = rows
                .iter_mut()
                .find(|row| row.identity.manifest_id == exact.identity.manifest_id)
                .ok_or(
                    ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementInvariantFailed,
                )?;
            if stored.identity != exact.identity
                || stored.encrypted_envelope != exact.encrypted_envelope
                || stored.envelope_sha256 != exact.envelope_sha256
            {
                return Err(
                    ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementInvariantFailed,
                );
            }
            stored.state = DeliveryStateV1::Delivered;
            Ok(stored.clone())
        }
    }

    fn envelope(byte: u8) -> EncryptedSwapManifestV1 {
        let value = json!({
            "ciphertext_hex": format!("{byte:02x}").repeat(16),
            "encryption_algorithm": "xchacha20poly1305",
            "encryption_key_id": "manifest-key-test",
            "format": "bullnym-chain-swap-manifest",
            "nonce_hex": format!("{:02x}", byte.wrapping_add(1)).repeat(24),
            "signature_algorithm": "bip340-secp256k1-sha256",
            "signer_xonly_public_key":
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "version": 1,
        });
        let encoded = crate::canonical_json::canonical_json_and_sha256(&value)
            .unwrap()
            .0;
        EncryptedSwapManifestV1::parse(encoded).unwrap()
    }

    fn exact(sequence: u64, previous_manifest_id: Option<Uuid>) -> ExactWitnessLedgerRecordV1 {
        let encrypted_envelope = envelope(u8::try_from(sequence).unwrap());
        let envelope_sha256 = hex::encode(Sha256::digest(encrypted_envelope.encoded().as_bytes()));
        ExactWitnessLedgerRecordV1 {
            identity: ManifestDeliveryIdentity {
                manifest_id: Uuid::from_u128(1_000 + u128::from(sequence)),
                chain_swap_id: Uuid::from_u128(2_000 + u128::from(sequence)),
                manifest_sequence: sequence,
                previous_manifest_id,
            },
            encrypted_envelope,
            envelope_sha256,
        }
    }

    fn records(count: usize) -> Vec<ExactWitnessLedgerRecordV1> {
        let mut previous_manifest_id = None;
        (1..=count)
            .map(|sequence| {
                let record = exact(u64::try_from(sequence).unwrap(), previous_manifest_id);
                previous_manifest_id = Some(record.identity.manifest_id);
                record
            })
            .collect()
    }

    fn witness(records: &[ExactWitnessLedgerRecordV1]) -> FakeWitness {
        FakeWitness {
            identities: records.iter().map(|record| record.identity).collect(),
            records: records.iter().cloned().map(Some).collect(),
        }
    }

    fn row(exact: &ExactWitnessLedgerRecordV1, state: DeliveryStateV1) -> DeliveryLedgerRowV1 {
        DeliveryLedgerRowV1 {
            identity: exact.identity,
            encrypted_envelope: exact.encrypted_envelope.clone(),
            envelope_sha256: exact.envelope_sha256.clone(),
            state,
        }
    }

    #[tokio::test]
    async fn verifies_resumes_and_reconstructs_one_exact_prefix() {
        let records = records(3);
        let witness = witness(&records);
        let database = FakeDatabase::new(vec![
            row(&records[0], DeliveryStateV1::Delivered),
            row(&records[1], DeliveryStateV1::Pending),
        ]);

        let outcome = rebuild_exact_ledger(&database, &witness).await.unwrap();

        assert_eq!(
            outcome,
            ManifestDeliveryLedgerRebuildOutcomeV1 {
                witness_records: 3,
                verified_existing_records: 2,
                resumed_pending_records: 1,
                reconstructed_records: 1,
            }
        );
        let rows = database.rows.lock().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows
            .iter()
            .all(|row| row.state == DeliveryStateV1::Delivered));
        for (row, exact) in rows.iter().zip(records.iter()) {
            require_exact_row(row, exact, DeliveryStateV1::Delivered).unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_a_local_envelope_mismatch_before_any_mutation() {
        let records = records(2);
        let witness = witness(&records);
        let mut mismatched = row(&records[0], DeliveryStateV1::Delivered);
        mismatched.encrypted_envelope = records[1].encrypted_envelope.clone();
        let database = FakeDatabase::new(vec![mismatched.clone()]);

        assert_eq!(
            rebuild_exact_ledger(&database, &witness).await,
            Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerNotExact)
        );
        assert_eq!(*database.rows.lock().unwrap(), vec![mismatched]);
    }

    #[tokio::test]
    async fn rejects_a_local_row_beyond_the_authenticated_witness() {
        let records = records(2);
        let witness = witness(&records[..1]);
        let original = vec![
            row(&records[0], DeliveryStateV1::Delivered),
            row(&records[1], DeliveryStateV1::Delivered),
        ];
        let database = FakeDatabase::new(original.clone());

        assert_eq!(
            rebuild_exact_ledger(&database, &witness).await,
            Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerNotExact)
        );
        assert_eq!(*database.rows.lock().unwrap(), original);
    }

    #[tokio::test]
    async fn exact_read_failure_does_not_append_the_missing_suffix() {
        let records = records(2);
        let mut witness = witness(&records);
        witness.records[1] = None;
        let original = vec![row(&records[0], DeliveryStateV1::Delivered)];
        let database = FakeDatabase::new(original.clone());

        assert_eq!(
            rebuild_exact_ledger(&database, &witness).await,
            Err(ManifestDeliveryLedgerRebuildErrorV1::ExactWitnessReadFailed)
        );
        assert_eq!(*database.rows.lock().unwrap(), original);
    }

    #[tokio::test]
    async fn append_failure_keeps_the_verified_prefix_unchanged() {
        let records = records(2);
        let witness = witness(&records);
        let original = vec![row(&records[0], DeliveryStateV1::Delivered)];
        let mut database = FakeDatabase::new(original.clone());
        database.reject_append = true;

        assert_eq!(
            rebuild_exact_ledger(&database, &witness).await,
            Err(ManifestDeliveryLedgerRebuildErrorV1::LedgerAppendFailed)
        );
        assert_eq!(*database.rows.lock().unwrap(), original);
    }

    #[tokio::test]
    async fn interrupted_acknowledgement_leaves_one_exact_retryable_pending_row() {
        let records = records(1);
        let witness = witness(&records);
        let mut interrupted = FakeDatabase::new(Vec::new());
        interrupted.reject_acknowledgement = true;

        assert_eq!(
            rebuild_exact_ledger(&interrupted, &witness).await,
            Err(ManifestDeliveryLedgerRebuildErrorV1::LedgerAcknowledgementFailed)
        );
        let pending = interrupted.rows.lock().unwrap().clone();
        assert_eq!(pending, vec![row(&records[0], DeliveryStateV1::Pending)]);

        let retry = FakeDatabase::new(pending);
        assert_eq!(
            rebuild_exact_ledger(&retry, &witness).await.unwrap(),
            ManifestDeliveryLedgerRebuildOutcomeV1 {
                witness_records: 1,
                verified_existing_records: 1,
                resumed_pending_records: 1,
                reconstructed_records: 0,
            }
        );
        assert_eq!(
            *retry.rows.lock().unwrap(),
            vec![row(&records[0], DeliveryStateV1::Delivered)]
        );
    }

    #[tokio::test]
    async fn a_non_tail_pending_row_is_not_acknowledged() {
        let records = records(2);
        let witness = witness(&records);
        let original = vec![
            row(&records[0], DeliveryStateV1::Pending),
            row(&records[1], DeliveryStateV1::Delivered),
        ];
        let database = FakeDatabase::new(original.clone());

        assert_eq!(
            rebuild_exact_ledger(&database, &witness).await,
            Err(ManifestDeliveryLedgerRebuildErrorV1::LocalLedgerStateInvalid)
        );
        assert_eq!(*database.rows.lock().unwrap(), original);
    }

    #[tokio::test]
    async fn invalid_witness_topology_fails_before_reading_the_database() {
        let records = records(2);
        let mut witness = witness(&records);
        witness.identities[1].previous_manifest_id = None;
        let database = FakeDatabase::new(Vec::new());

        assert_eq!(
            rebuild_exact_ledger(&database, &witness).await,
            Err(ManifestDeliveryLedgerRebuildErrorV1::WitnessTopologyInvalid)
        );
        assert!(database.rows.lock().unwrap().is_empty());
    }
}
