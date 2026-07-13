use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{direct_payments, InvoiceAccountingTolerances};
use crate::{
    merchant_output_verifier::{
        ApprovedMerchantDestination, MerchantAsset, PersistableMerchantTransactionJournal,
    },
    merchant_settlement_adoption::{
        ConfirmedMerchantOutputEvidence, ConfirmedMerchantOutputEvidenceSnapshot,
        MerchantOutputAccountingIdentity, MerchantOutputAccountingIntent,
        MerchantSettlementContext, MerchantSettlementPath,
    },
    merchant_settlement_lifecycle::{
        SettlementAccountingState, SettlementBlock, SettlementChain, SettlementEvidenceHistory,
        SettlementFinalityPolicy, SettlementLifecycleSnapshot, SettlementState, SettlementTxid,
    },
    merchant_settlement_service::{
        MerchantSettlementAdoptionService, MerchantSettlementAdoptionSnapshot,
        MerchantSettlementPersistenceCommand, MerchantSettlementProcessingError,
        MerchantSettlementProcessingOutcome, RetainedMerchantOutputSnapshot,
    },
};

const CHECKPOINT_FORMAT_VERSION: i16 = 1;

#[derive(Debug)]
pub enum MerchantSettlementRepositoryError {
    Database(sqlx::Error),
    InvalidCheckpoint,
    InvalidCommand,
    ImmutableIdentityConflict,
    ActiveFamilyConflict,
    CheckpointConflict { expected: i64, actual: i64 },
    MissingJournal,
}

impl fmt::Display for MerchantSettlementRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "merchant settlement repository operation failed",
            Self::InvalidCheckpoint => "merchant settlement checkpoint is invalid",
            Self::InvalidCommand => "merchant settlement persistence command is invalid",
            Self::ImmutableIdentityConflict => "merchant settlement identity is immutable",
            Self::ActiveFamilyConflict => "another merchant settlement event is active",
            Self::CheckpointConflict { .. } => "merchant settlement checkpoint changed",
            Self::MissingJournal => "merchant settlement transaction journal is incomplete",
        })
    }
}

impl std::error::Error for MerchantSettlementRepositoryError {}

impl From<sqlx::Error> for MerchantSettlementRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<MerchantSettlementProcessingError> for MerchantSettlementRepositoryError {
    fn from(_: MerchantSettlementProcessingError) -> Self {
        Self::InvalidCheckpoint
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantSettlementPersistenceResult {
    pub checkpoint_version: i64,
    pub projection_changed: bool,
    pub parent_transition: MerchantSettlementParentTransition,
    /// The same transaction moved the active immutable attempt back into a
    /// state accepted by exact-byte replay.
    pub journal_rebroadcast_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantSettlementParentTransition {
    pub previous_status: String,
    pub current_status: String,
    pub changed: bool,
}

/// Owned prior-output evidence for a journal row. Workers can borrow these
/// fields into the verifier's bounded `MerchantSourcePrevout` view without a
/// second database read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerchantSettlementSourcePrevout {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MerchantSettlementJournalRow {
    pub id: Uuid,
    pub chain_swap_id: Uuid,
    pub purpose: String,
    pub replaces_txid: Option<String>,
    pub raw_transaction: Vec<u8>,
    pub txid: String,
    pub source_prevouts: Vec<MerchantSettlementSourcePrevout>,
    pub destination_address: String,
    pub destination_script_hex: String,
    pub asset: MerchantAsset,
    pub destination_amount_sat: u64,
    pub destination_vout: u32,
    pub fee_amount_sat: u64,
    pub fee_rate_sat_vb: f64,
    pub liquid_blinding_key_hex: Option<String>,
    pub status: String,
}

#[derive(Debug)]
pub struct NewLiquidMerchantSettlementJournal<'a> {
    pub chain_swap_id: Uuid,
    pub replaces_txid: Option<&'a str>,
    /// Verifier-derived owned packet. Callers cannot supply an independent
    /// amount, vout, txid, script, asset, or source set to persistence.
    pub prepared: &'a PersistableMerchantTransactionJournal,
    pub fee_amount_sat: u64,
    pub fee_rate_sat_vb: f64,
    pub liquid_blinding_key_hex: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerchantSettlementPreviousConfirmation {
    NeverObserved,
    Mempool,
    Confirmed {
        block_height: u32,
        block_hash: String,
    },
    Reorged {
        previous_block_height: u32,
        previous_block_hash: String,
    },
}

/// One repeatable-read packet for a worker. The version is the CAS token for
/// the later atomic persist, closing the observation gap without holding a
/// database transaction across chain I/O.
#[derive(Debug, Clone)]
pub struct MerchantSettlementWorkItem {
    pub checkpoint_version: i64,
    pub service: MerchantSettlementAdoptionService,
    pub original_journal: MerchantSettlementJournalRow,
    pub linked_replacement: Option<MerchantSettlementJournalRow>,
    pub approved_destination: ApprovedMerchantDestination,
    pub liquid_blinding_key_hex: Option<String>,
    pub previous_confirmation: MerchantSettlementPreviousConfirmation,
}

#[derive(Debug, sqlx::FromRow)]
struct JournalDbRow {
    id: Uuid,
    chain_swap_id: Uuid,
    purpose: String,
    replaces_txid: Option<String>,
    raw_tx_hex: String,
    txid: String,
    source_prevouts: serde_json::Value,
    destination_address: String,
    destination_script_hex: String,
    destination_asset_id: Option<String>,
    destination_amount_sat: i64,
    destination_vout: i32,
    fee_amount_sat: i64,
    fee_rate_sat_vb: f64,
    liquid_blinding_key_hex: Option<String>,
    status: String,
}

impl TryFrom<JournalDbRow> for MerchantSettlementJournalRow {
    type Error = MerchantSettlementRepositoryError;

    fn try_from(row: JournalDbRow) -> Result<Self, Self::Error> {
        let raw_transaction = hex::decode(&row.raw_tx_hex)
            .map_err(|_| MerchantSettlementRepositoryError::MissingJournal)?;
        let source_prevouts = serde_json::from_value(row.source_prevouts)
            .map_err(|_| MerchantSettlementRepositoryError::MissingJournal)?;
        let destination_amount_sat = u64::try_from(row.destination_amount_sat)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(MerchantSettlementRepositoryError::MissingJournal)?;
        let destination_vout = u32::try_from(row.destination_vout)
            .map_err(|_| MerchantSettlementRepositoryError::MissingJournal)?;
        let fee_amount_sat = u64::try_from(row.fee_amount_sat)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(MerchantSettlementRepositoryError::MissingJournal)?;
        let asset = row
            .destination_asset_id
            .map(MerchantAsset::Liquid)
            .unwrap_or(MerchantAsset::Bitcoin);
        Ok(Self {
            id: row.id,
            chain_swap_id: row.chain_swap_id,
            purpose: row.purpose,
            replaces_txid: row.replaces_txid,
            raw_transaction,
            txid: row.txid,
            source_prevouts,
            destination_address: row.destination_address,
            destination_script_hex: row.destination_script_hex,
            asset,
            destination_amount_sat,
            destination_vout,
            fee_amount_sat,
            fee_rate_sat_vb: row.fee_rate_sat_vb,
            liquid_blinding_key_hex: row.liquid_blinding_key_hex,
            status: row.status,
        })
    }
}

const JOURNAL_COLUMNS: &str = "id, chain_swap_id, purpose, replaces_txid, raw_tx_hex, txid, \
    source_prevouts, destination_address, destination_script_hex, destination_asset_id, \
    destination_amount_sat, destination_vout, fee_amount_sat, fee_rate_sat_vb, \
    liquid_blinding_key_hex, status";

/// Insert the immutable Liquid claim/replacement intent before broadcast. The
/// next migration widens migration 046's purpose constraint and adds the
/// lineage/asset/blinding columns referenced by this runtime SQL.
pub async fn insert_liquid_merchant_settlement_journal(
    connection: &mut PgConnection,
    journal: &NewLiquidMerchantSettlementJournal<'_>,
) -> Result<MerchantSettlementJournalRow, MerchantSettlementRepositoryError> {
    validate_new_liquid_journal(journal)?;
    let purpose = if journal.replaces_txid.is_some() {
        "liquid_claim_replacement"
    } else {
        "liquid_claim"
    };
    let prepared = journal.prepared;
    let source_prevouts: Vec<_> = prepared
        .source_prevouts
        .iter()
        .map(|source| MerchantSettlementSourcePrevout {
            txid: source.txid.clone(),
            vout: source.vout,
            amount_sat: source.amount_sat,
            script_pubkey_hex: source.script_pubkey_hex.clone(),
        })
        .collect();
    let source_prevouts = serde_json::to_value(source_prevouts)
        .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?;
    let MerchantAsset::Liquid(asset_id) = &prepared.asset else {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    };
    let inserted = sqlx::query_as::<_, JournalDbRow>(&format!(
        "INSERT INTO chain_swap_tx_attempts (\
             chain_swap_id, purpose, replaces_txid, raw_tx_hex, txid, source_prevouts, \
             destination_address, destination_script_hex, destination_asset_id, \
             destination_vout, destination_amount_sat, fee_amount_sat, fee_rate_sat_vb, \
             liquid_blinding_key_hex\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) \
         ON CONFLICT (chain_swap_id, purpose) DO NOTHING \
         RETURNING {JOURNAL_COLUMNS}"
    ))
    .bind(journal.chain_swap_id)
    .bind(purpose)
    .bind(journal.replaces_txid)
    .bind(&prepared.raw_transaction_hex)
    .bind(&prepared.txid)
    .bind(source_prevouts)
    .bind(&prepared.destination_address)
    .bind(&prepared.destination_script_hex)
    .bind(asset_id)
    .bind(
        i32::try_from(prepared.vout)
            .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?,
    )
    .bind(
        i64::try_from(prepared.amount_sat)
            .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?,
    )
    .bind(
        i64::try_from(journal.fee_amount_sat)
            .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?,
    )
    .bind(journal.fee_rate_sat_vb)
    .bind(journal.liquid_blinding_key_hex)
    .fetch_optional(&mut *connection)
    .await?;
    let row = match inserted {
        Some(row) => row.try_into()?,
        None => load_liquid_journal_by_purpose(connection, journal.chain_swap_id, purpose)
            .await?
            .ok_or(MerchantSettlementRepositoryError::ImmutableIdentityConflict)?,
    };
    assert_liquid_journal_matches(&row, journal, purpose)?;
    Ok(row)
}

/// Re-read and lock an already persisted claim/replacement in the caller's
/// transaction, then require byte-for-byte equality with the newly prepared
/// packet. A rebroadcaster therefore uses the journaled raw bytes or stops; it
/// cannot silently accept a reconstructed transaction with the same purpose.
pub async fn load_exact_liquid_merchant_settlement_journal(
    connection: &mut PgConnection,
    journal: &NewLiquidMerchantSettlementJournal<'_>,
) -> Result<MerchantSettlementJournalRow, MerchantSettlementRepositoryError> {
    validate_new_liquid_journal(journal)?;
    let purpose = if journal.replaces_txid.is_some() {
        "liquid_claim_replacement"
    } else {
        "liquid_claim"
    };
    let row = sqlx::query_as::<_, JournalDbRow>(&format!(
        "SELECT {JOURNAL_COLUMNS} FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND purpose = $2 FOR UPDATE"
    ))
    .bind(journal.chain_swap_id)
    .bind(purpose)
    .fetch_optional(connection)
    .await?
    .ok_or(MerchantSettlementRepositoryError::MissingJournal)?
    .try_into()?;
    assert_liquid_journal_matches(&row, journal, purpose)?;
    Ok(row)
}

async fn load_liquid_journal_by_purpose(
    connection: &mut PgConnection,
    chain_swap_id: Uuid,
    purpose: &str,
) -> Result<Option<MerchantSettlementJournalRow>, MerchantSettlementRepositoryError> {
    sqlx::query_as::<_, JournalDbRow>(&format!(
        "SELECT {JOURNAL_COLUMNS} FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND purpose = $2 FOR UPDATE"
    ))
    .bind(chain_swap_id)
    .bind(purpose)
    .fetch_optional(connection)
    .await?
    .map(TryInto::try_into)
    .transpose()
}

fn assert_liquid_journal_matches(
    row: &MerchantSettlementJournalRow,
    journal: &NewLiquidMerchantSettlementJournal<'_>,
    purpose: &str,
) -> Result<(), MerchantSettlementRepositoryError> {
    let prepared = journal.prepared;
    let expected_sources: Vec<_> = prepared
        .source_prevouts
        .iter()
        .map(|source| MerchantSettlementSourcePrevout {
            txid: source.txid.clone(),
            vout: source.vout,
            amount_sat: source.amount_sat,
            script_pubkey_hex: source.script_pubkey_hex.clone(),
        })
        .collect();
    if row.chain_swap_id != journal.chain_swap_id
        || row.purpose != purpose
        || row.replaces_txid.as_deref() != journal.replaces_txid
        || row.raw_transaction != prepared.raw_transaction
        || row.txid != prepared.txid
        || row.source_prevouts != expected_sources
        || row.destination_address != prepared.destination_address
        || row.destination_script_hex != prepared.destination_script_hex
        || row.asset != prepared.asset
        || row.destination_amount_sat != prepared.amount_sat
        || row.destination_vout != prepared.vout
        || row.fee_amount_sat != journal.fee_amount_sat
        || row.fee_rate_sat_vb.to_bits() != journal.fee_rate_sat_vb.to_bits()
        || row.liquid_blinding_key_hex.as_deref() != Some(journal.liquid_blinding_key_hex)
    {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(())
}

fn validate_new_liquid_journal(
    journal: &NewLiquidMerchantSettlementJournal<'_>,
) -> Result<(), MerchantSettlementRepositoryError> {
    let hash = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    if journal.chain_swap_id.is_nil()
        || journal.prepared.raw_transaction.is_empty()
        || journal.prepared.raw_transaction_hex != hex::encode(&journal.prepared.raw_transaction)
        || !hash(&journal.prepared.txid)
        || journal
            .replaces_txid
            .is_some_and(|txid| !hash(txid) || txid == journal.prepared.txid)
        || journal.prepared.source_prevouts.is_empty()
        || journal.prepared.source_prevouts.len() > 256
        || !matches!(&journal.prepared.asset, MerchantAsset::Liquid(asset_id) if hash(asset_id))
        || journal.prepared.amount_sat == 0
        || journal.fee_amount_sat == 0
        || !journal.fee_rate_sat_vb.is_finite()
        || journal.fee_rate_sat_vb <= 0.0
        || !hash(journal.liquid_blinding_key_hex)
    {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    }
    Ok(())
}

/// Load a complete worker packet at one repeatable-read database snapshot.
pub async fn load_merchant_settlement_work_item(
    pool: &PgPool,
    context: &MerchantSettlementContext,
    policy: SettlementFinalityPolicy,
) -> Result<Option<MerchantSettlementWorkItem>, MerchantSettlementRepositoryError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let checkpoint: Option<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT checkpoint_version, snapshot_json \
           FROM merchant_settlement_checkpoints \
          WHERE chain_swap_id = $1 AND settlement_path = $2",
    )
    .bind(context.chain_swap_id())
    .bind(path_text(context.path()))
    .fetch_optional(&mut *tx)
    .await?;
    let journals = load_journals_locked(&mut tx, context.chain_swap_id()).await?;
    if checkpoint.is_none() && journals.is_empty() {
        tx.commit().await?;
        return Ok(None);
    }
    let (original_journal, linked_replacement) = select_journals(context.path(), journals)?;
    let (checkpoint_version, service) = match checkpoint {
        Some((checkpoint_version, snapshot_json)) => {
            let service = decode_service(snapshot_json, policy)?;
            if service.context() != context {
                return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
            }
            (checkpoint_version, service)
        }
        None => (
            0,
            MerchantSettlementAdoptionService::new(
                context.clone(),
                &original_journal.txid,
                policy,
            )?,
        ),
    };
    let approved_destination = approved_from_journal(&original_journal)?;
    let liquid_blinding_key_hex = match context.path() {
        MerchantSettlementPath::LiquidClaim => Some(
            original_journal
                .liquid_blinding_key_hex
                .clone()
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
        ),
        MerchantSettlementPath::BitcoinRecovery => None,
    };
    let previous_confirmation = previous_confirmation(service.lifecycle().snapshot());
    tx.commit().await?;
    Ok(Some(MerchantSettlementWorkItem {
        checkpoint_version,
        service,
        original_journal,
        linked_replacement,
        approved_destination,
        liquid_blinding_key_hex,
        previous_confirmation,
    }))
}

/// Compatibility loader for callers that need only the restored reducer.
pub async fn load_merchant_settlement_adoption(
    pool: &PgPool,
    context: &MerchantSettlementContext,
    policy: SettlementFinalityPolicy,
) -> Result<Option<(i64, MerchantSettlementAdoptionService)>, MerchantSettlementRepositoryError> {
    Ok(load_merchant_settlement_work_item(pool, context, policy)
        .await?
        .map(|work| (work.checkpoint_version, work.service)))
}

pub async fn load_confirmed_merchant_settlement_repair_intent(
    pool: &PgPool,
    context: &MerchantSettlementContext,
    policy: SettlementFinalityPolicy,
) -> Result<Option<(i64, MerchantOutputAccountingIntent)>, MerchantSettlementRepositoryError> {
    let Some(work) = load_merchant_settlement_work_item(pool, context, policy).await? else {
        return Ok(None);
    };
    Ok(work
        .service
        .repair_accounting_intent()
        .cloned()
        .map(|intent| (work.checkpoint_version, intent)))
}

/// CAS-persist the complete validated checkpoint, retained evidence, command
/// effects, and invoice projection in one transaction.
pub async fn persist_merchant_settlement_outcome(
    pool: &PgPool,
    expected_checkpoint_version: i64,
    snapshot: &MerchantSettlementAdoptionSnapshot,
    outcome: &MerchantSettlementProcessingOutcome,
    policy: SettlementFinalityPolicy,
    tolerances: InvoiceAccountingTolerances,
) -> Result<MerchantSettlementPersistenceResult, MerchantSettlementRepositoryError> {
    if expected_checkpoint_version < 0 {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    }
    MerchantSettlementAdoptionService::restore(snapshot.clone(), policy)?;
    validate_commands(snapshot, outcome)?;
    let snapshot_json = encode_snapshot(snapshot)?;
    let context = &snapshot.context;
    let mut tx = pool.begin().await?;
    lock_invoice_and_swap(&mut tx, context).await?;
    let actual: Option<i64> = sqlx::query_scalar(
        "SELECT checkpoint_version FROM merchant_settlement_checkpoints \
          WHERE chain_swap_id = $1 AND settlement_path = $2 FOR UPDATE",
    )
    .bind(context.chain_swap_id())
    .bind(path_text(context.path()))
    .fetch_optional(&mut *tx)
    .await?;
    let actual = actual.unwrap_or(0);
    if actual != expected_checkpoint_version {
        return Err(MerchantSettlementRepositoryError::CheckpointConflict {
            expected: expected_checkpoint_version,
            actual,
        });
    }
    apply_commands(&mut tx, snapshot, outcome).await?;
    persist_retained(&mut tx, snapshot).await?;
    let checkpoint_version = expected_checkpoint_version + 1;
    let rows = sqlx::query(
        "INSERT INTO merchant_settlement_checkpoints (\
             chain_swap_id, settlement_path, invoice_id, boltz_swap_id, format_version, \
             checkpoint_version, journal_txid, snapshot_json\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
         ON CONFLICT (chain_swap_id, settlement_path) DO UPDATE SET \
             checkpoint_version = EXCLUDED.checkpoint_version, snapshot_json = EXCLUDED.snapshot_json, \
             updated_at = NOW() \
         WHERE merchant_settlement_checkpoints.invoice_id = EXCLUDED.invoice_id \
           AND merchant_settlement_checkpoints.boltz_swap_id = EXCLUDED.boltz_swap_id \
           AND merchant_settlement_checkpoints.journal_txid = EXCLUDED.journal_txid \
           AND merchant_settlement_checkpoints.format_version = EXCLUDED.format_version \
           AND merchant_settlement_checkpoints.checkpoint_version = $9",
    )
    .bind(context.chain_swap_id())
    .bind(path_text(context.path()))
    .bind(context.invoice_id())
    .bind(context.boltz_swap_id())
    .bind(CHECKPOINT_FORMAT_VERSION)
    .bind(checkpoint_version)
    .bind(snapshot.lifecycle.journal_txid.as_str())
    .bind(snapshot_json)
    .bind(expected_checkpoint_version)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if rows != 1 {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    let journal_rebroadcast_required = transition_attempt_locked(&mut tx, snapshot).await?;
    let parent_transition = transition_parent_locked(&mut tx, snapshot).await?;
    let swap_status = if snapshot.lifecycle.accounting == SettlementAccountingState::Finalized {
        "settled"
    } else {
        "pending"
    };
    let projection_changed = direct_payments::reproject_after_merchant_settlement_locked(
        &mut tx,
        context.invoice_id(),
        swap_status,
        tolerances,
    )
    .await?;
    tx.commit().await?;
    Ok(MerchantSettlementPersistenceResult {
        checkpoint_version,
        projection_changed,
        parent_transition,
        journal_rebroadcast_required,
    })
}

async fn transition_attempt_locked(
    tx: &mut Transaction<'_, Postgres>,
    snapshot: &MerchantSettlementAdoptionSnapshot,
) -> Result<bool, MerchantSettlementRepositoryError> {
    if snapshot.lifecycle.accounting != SettlementAccountingState::Demoted {
        return Ok(false);
    }
    let active_txid = snapshot.lifecycle.active_txid.as_str();
    let attempt: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, purpose, status FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND txid = $2 FOR UPDATE",
    )
    .bind(snapshot.context.chain_swap_id())
    .bind(active_txid)
    .fetch_optional(&mut **tx)
    .await?;
    let (attempt_id, purpose, status) =
        attempt.ok_or(MerchantSettlementRepositoryError::MissingJournal)?;
    let purpose_matches = match snapshot.context.path() {
        MerchantSettlementPath::LiquidClaim => {
            matches!(
                purpose.as_str(),
                "liquid_claim" | "liquid_claim_replacement"
            )
        }
        MerchantSettlementPath::BitcoinRecovery => purpose == "btc_recovery",
    };
    if !purpose_matches
        || !matches!(
            status.as_str(),
            "constructed" | "broadcast_ambiguous" | "broadcast" | "confirmed" | "finalized"
        )
    {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    if matches!(status.as_str(), "broadcast" | "confirmed" | "finalized") {
        let rows = sqlx::query(
            "UPDATE chain_swap_tx_attempts SET status = 'broadcast_ambiguous', \
                 last_broadcast_result = 'merchant settlement demoted; exact journal replay required', \
                 updated_at = NOW() \
              WHERE id = $1 AND txid = $2 AND status = $3",
        )
        .bind(attempt_id)
        .bind(active_txid)
        .bind(&status)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if rows != 1 {
            return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
        }
    }
    Ok(true)
}

async fn transition_parent_locked(
    tx: &mut Transaction<'_, Postgres>,
    snapshot: &MerchantSettlementAdoptionSnapshot,
) -> Result<MerchantSettlementParentTransition, MerchantSettlementRepositoryError> {
    let (previous_status, claim_txid, refund_txid): (String, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT status, claim_txid, refund_txid FROM chain_swap_records WHERE id = $1 FOR UPDATE",
        )
        .bind(snapshot.context.chain_swap_id())
        .fetch_one(&mut **tx)
        .await?;
    let finalized = snapshot.lifecycle.accounting == SettlementAccountingState::Finalized;
    let active_txid = snapshot.lifecycle.active_txid.as_str();
    let (current_status, allowed) = match snapshot.context.path() {
        MerchantSettlementPath::LiquidClaim => (
            if finalized { "claimed" } else { "claiming" },
            matches!(previous_status.as_str(), "claiming" | "claimed"),
        ),
        MerchantSettlementPath::BitcoinRecovery => (
            if finalized { "refunded" } else { "refunding" },
            matches!(previous_status.as_str(), "refunding" | "refunded"),
        ),
    };
    if !allowed {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    let prior_txid = match snapshot.context.path() {
        MerchantSettlementPath::LiquidClaim => claim_txid.as_deref(),
        MerchantSettlementPath::BitcoinRecovery => refund_txid.as_deref(),
    };
    if prior_txid != Some(active_txid) {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    let changed = previous_status != current_status;
    if changed {
        match snapshot.context.path() {
            MerchantSettlementPath::LiquidClaim => {
                sqlx::query(
                    "UPDATE chain_swap_records SET status = $2, \
                         claim_txid = CASE WHEN $2 = 'claimed' THEN $3 ELSE claim_txid END, \
                         updated_at = NOW() WHERE id = $1",
                )
                .bind(snapshot.context.chain_swap_id())
                .bind(current_status)
                .bind(active_txid)
                .execute(&mut **tx)
                .await?;
            }
            MerchantSettlementPath::BitcoinRecovery => {
                sqlx::query(
                    "UPDATE chain_swap_records SET status = $2, \
                         refund_txid = CASE WHEN $2 = 'refunded' THEN $3 ELSE refund_txid END, \
                         updated_at = NOW() WHERE id = $1",
                )
                .bind(snapshot.context.chain_swap_id())
                .bind(current_status)
                .bind(active_txid)
                .execute(&mut **tx)
                .await?;
            }
        }
    }
    Ok(MerchantSettlementParentTransition {
        previous_status,
        current_status: current_status.to_owned(),
        changed,
    })
}

async fn lock_invoice_and_swap(
    tx: &mut Transaction<'_, Postgres>,
    context: &MerchantSettlementContext,
) -> Result<(), MerchantSettlementRepositoryError> {
    let key = super::invoice_lightning_lock_key(context.invoice_id());
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    let invoice_exists: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM invoices WHERE id = $1 FOR UPDATE")
            .bind(context.invoice_id())
            .fetch_optional(&mut **tx)
            .await?;
    if invoice_exists.is_none() {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    let swap: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT invoice_id, boltz_swap_id FROM chain_swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(context.chain_swap_id())
    .fetch_optional(&mut **tx)
    .await?;
    if swap.as_ref() != Some(&(context.invoice_id(), context.boltz_swap_id().to_owned())) {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(())
}

fn validate_commands(
    snapshot: &MerchantSettlementAdoptionSnapshot,
    outcome: &MerchantSettlementProcessingOutcome,
) -> Result<(), MerchantSettlementRepositoryError> {
    let retained: HashMap<_, _> = snapshot
        .retained
        .iter()
        .map(|row| (row.intent.identity.event_key(), row))
        .collect();
    for command in &outcome.commands {
        let (identity, record) = match command {
            MerchantSettlementPersistenceCommand::Record(intent) => {
                let row = retained
                    .get(intent.identity.event_key())
                    .ok_or(MerchantSettlementRepositoryError::InvalidCommand)?;
                if &row.intent != intent || !row.recorded {
                    return Err(MerchantSettlementRepositoryError::InvalidCommand);
                }
                (&intent.identity, *row)
            }
            MerchantSettlementPersistenceCommand::Activate(identity) => {
                let row = retained
                    .get(identity.event_key())
                    .ok_or(MerchantSettlementRepositoryError::InvalidCommand)?;
                if !row.active {
                    return Err(MerchantSettlementRepositoryError::InvalidCommand);
                }
                (identity, *row)
            }
            MerchantSettlementPersistenceCommand::Deactivate(identity) => {
                let row = retained
                    .get(identity.event_key())
                    .ok_or(MerchantSettlementRepositoryError::InvalidCommand)?;
                if row.active || row.finalized {
                    return Err(MerchantSettlementRepositoryError::InvalidCommand);
                }
                (identity, *row)
            }
            MerchantSettlementPersistenceCommand::Finalize(identity) => {
                let row = retained
                    .get(identity.event_key())
                    .ok_or(MerchantSettlementRepositoryError::InvalidCommand)?;
                if !row.active || !row.finalized {
                    return Err(MerchantSettlementRepositoryError::InvalidCommand);
                }
                (identity, *row)
            }
        };
        if identity != &record.intent.identity
            || record.intent.invoice_id != snapshot.context.invoice_id()
            || record.intent.chain_swap_id != snapshot.context.chain_swap_id()
            || record.intent.boltz_swap_id != snapshot.context.boltz_swap_id()
            || record.intent.path != snapshot.context.path()
        {
            return Err(MerchantSettlementRepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

async fn apply_commands(
    tx: &mut Transaction<'_, Postgres>,
    snapshot: &MerchantSettlementAdoptionSnapshot,
    outcome: &MerchantSettlementProcessingOutcome,
) -> Result<(), MerchantSettlementRepositoryError> {
    for command in &outcome.commands {
        match command {
            MerchantSettlementPersistenceCommand::Record(intent) => {
                record_event(tx, intent).await?
            }
            MerchantSettlementPersistenceCommand::Activate(identity) => {
                mutate_event(tx, snapshot, identity, "active", None, Some(false)).await?
            }
            MerchantSettlementPersistenceCommand::Deactivate(identity) => {
                mutate_event(
                    tx,
                    snapshot,
                    identity,
                    "inactive",
                    Some(demotion_reason(&snapshot.lifecycle.state)),
                    Some(false),
                )
                .await?
            }
            MerchantSettlementPersistenceCommand::Finalize(identity) => {
                mutate_event(tx, snapshot, identity, "active", None, Some(true)).await?
            }
        }
    }
    Ok(())
}

async fn record_event(
    tx: &mut Transaction<'_, Postgres>,
    intent: &MerchantOutputAccountingIntent,
) -> Result<(), MerchantSettlementRepositoryError> {
    let vout = i32::try_from(intent.vout)
        .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?;
    sqlx::query(
        "INSERT INTO invoice_payment_events (\
             invoice_id, rail, source, event_key, amount_sat, txid, vout, boltz_swap_id, address, \
             accounting_state, verification_state, deactivated_at, deactivation_reason, \
             merchant_settlement_family_key, merchant_chain_swap_id, merchant_settlement_finalized\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'inactive','verified',NOW(),'not_confirmed',$10,$11,FALSE) \
         ON CONFLICT (event_key) DO NOTHING",
    )
    .bind(intent.invoice_id)
    .bind(intent.rail())
    .bind(intent.source())
    .bind(intent.identity.event_key())
    .bind(intent.actual_amount_sat)
    .bind(&intent.txid)
    .bind(vout)
    .bind(&intent.boltz_swap_id)
    .bind(&intent.destination_address)
    .bind(intent.identity.family_key())
    .bind(intent.chain_swap_id)
    .execute(&mut **tx)
    .await?;
    let exact: Option<bool> = sqlx::query_scalar(
        "SELECT invoice_id = $2 AND rail = $3 AND source = $4 AND amount_sat = $5 \
                AND txid = $6 AND vout = $7 AND boltz_swap_id = $8 AND address = $9 \
                AND merchant_settlement_family_key = $10 AND merchant_chain_swap_id = $11 \
           FROM invoice_payment_events WHERE event_key = $1 FOR UPDATE",
    )
    .bind(intent.identity.event_key())
    .bind(intent.invoice_id)
    .bind(intent.rail())
    .bind(intent.source())
    .bind(intent.actual_amount_sat)
    .bind(&intent.txid)
    .bind(vout)
    .bind(&intent.boltz_swap_id)
    .bind(&intent.destination_address)
    .bind(intent.identity.family_key())
    .bind(intent.chain_swap_id)
    .fetch_optional(&mut **tx)
    .await?;
    if exact != Some(true) {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(())
}

async fn mutate_event(
    tx: &mut Transaction<'_, Postgres>,
    snapshot: &MerchantSettlementAdoptionSnapshot,
    identity: &MerchantOutputAccountingIdentity,
    accounting_state: &str,
    reason: Option<&str>,
    finalized: Option<bool>,
) -> Result<(), MerchantSettlementRepositoryError> {
    if accounting_state == "active" {
        let conflict: Option<String> = sqlx::query_scalar(
            "SELECT event_key FROM invoice_payment_events \
              WHERE merchant_chain_swap_id = $1 AND accounting_state = 'active' AND event_key <> $2 \
              FOR UPDATE",
        )
        .bind(snapshot.context.chain_swap_id())
        .bind(identity.event_key())
        .fetch_optional(&mut **tx)
        .await?;
        if conflict.is_some() {
            return Err(MerchantSettlementRepositoryError::ActiveFamilyConflict);
        }
    }
    let rows = sqlx::query(
        "UPDATE invoice_payment_events SET accounting_state = $3, \
             last_activated_at = CASE WHEN $3 = 'active' THEN NOW() ELSE last_activated_at END, \
             deactivated_at = CASE WHEN $3 = 'inactive' THEN NOW() ELSE NULL END, \
             deactivation_reason = CASE WHEN $3 = 'inactive' THEN $4 ELSE NULL END, \
             merchant_settlement_finalized = COALESCE($5, merchant_settlement_finalized), \
             state_version = state_version + 1 \
          WHERE event_key = $1 AND merchant_settlement_family_key = $2",
    )
    .bind(identity.event_key())
    .bind(identity.family_key())
    .bind(accounting_state)
    .bind(reason)
    .bind(finalized)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if rows != 1 {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(())
}

async fn persist_retained(
    tx: &mut Transaction<'_, Postgres>,
    snapshot: &MerchantSettlementAdoptionSnapshot,
) -> Result<(), MerchantSettlementRepositoryError> {
    for retained in &snapshot.retained {
        let evidence = retained.evidence.snapshot();
        let asset_id = match &evidence.asset {
            MerchantAsset::Bitcoin => None,
            MerchantAsset::Liquid(asset_id) => Some(asset_id.as_str()),
        };
        let rows = sqlx::query(
            "INSERT INTO merchant_settlement_retained_outputs (\
                 event_key, family_key, invoice_id, chain_swap_id, boltz_swap_id, settlement_path, \
                 journal_txid, txid, destination_address, destination_script_hex, asset_id, \
                 actual_amount_sat, vout, confirmations, block_height, block_hash, linked_replacement, \
                 recorded, active, finalized\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) \
             ON CONFLICT (event_key) DO UPDATE SET confirmations = EXCLUDED.confirmations, \
                 block_height = EXCLUDED.block_height, block_hash = EXCLUDED.block_hash, \
                 recorded = EXCLUDED.recorded, active = EXCLUDED.active, finalized = EXCLUDED.finalized, \
                 updated_at = NOW() \
             WHERE merchant_settlement_retained_outputs.family_key = EXCLUDED.family_key \
               AND merchant_settlement_retained_outputs.invoice_id = EXCLUDED.invoice_id \
               AND merchant_settlement_retained_outputs.chain_swap_id = EXCLUDED.chain_swap_id \
               AND merchant_settlement_retained_outputs.boltz_swap_id = EXCLUDED.boltz_swap_id \
               AND merchant_settlement_retained_outputs.settlement_path = EXCLUDED.settlement_path \
               AND merchant_settlement_retained_outputs.journal_txid = EXCLUDED.journal_txid \
               AND merchant_settlement_retained_outputs.txid = EXCLUDED.txid \
               AND merchant_settlement_retained_outputs.destination_address = EXCLUDED.destination_address \
               AND merchant_settlement_retained_outputs.destination_script_hex = EXCLUDED.destination_script_hex \
               AND merchant_settlement_retained_outputs.asset_id IS NOT DISTINCT FROM EXCLUDED.asset_id \
               AND merchant_settlement_retained_outputs.actual_amount_sat = EXCLUDED.actual_amount_sat \
               AND merchant_settlement_retained_outputs.vout = EXCLUDED.vout \
               AND merchant_settlement_retained_outputs.linked_replacement = EXCLUDED.linked_replacement",
        )
        .bind(&evidence.event_key)
        .bind(&evidence.family_key)
        .bind(evidence.invoice_id)
        .bind(evidence.chain_swap_id)
        .bind(&evidence.boltz_swap_id)
        .bind(path_text(evidence.path))
        .bind(&evidence.journal_txid)
        .bind(&evidence.txid)
        .bind(&evidence.destination_address)
        .bind(&evidence.destination_script_hex)
        .bind(asset_id)
        .bind(evidence.actual_amount_sat)
        .bind(i32::try_from(evidence.vout).map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)?)
        .bind(i32::try_from(evidence.confirmations).map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)?)
        .bind(i32::try_from(evidence.block_height).map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)?)
        .bind(&evidence.block_hash)
        .bind(evidence.linked_replacement)
        .bind(retained.recorded)
        .bind(retained.active)
        .bind(retained.finalized)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if rows != 1 {
            return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
        }
    }
    Ok(())
}

async fn load_journals_locked(
    tx: &mut Transaction<'_, Postgres>,
    chain_swap_id: Uuid,
) -> Result<Vec<MerchantSettlementJournalRow>, MerchantSettlementRepositoryError> {
    let rows = sqlx::query_as::<_, JournalDbRow>(&format!(
        "SELECT {JOURNAL_COLUMNS} FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND purpose IN ('btc_recovery','liquid_claim','liquid_claim_replacement') \
          ORDER BY constructed_at ASC, id ASC"
    ))
    .bind(chain_swap_id)
    .fetch_all(&mut **tx)
    .await?;
    rows.into_iter().map(TryInto::try_into).collect()
}

fn select_journals(
    path: MerchantSettlementPath,
    journals: Vec<MerchantSettlementJournalRow>,
) -> Result<
    (
        MerchantSettlementJournalRow,
        Option<MerchantSettlementJournalRow>,
    ),
    MerchantSettlementRepositoryError,
> {
    let original_purpose = match path {
        MerchantSettlementPath::LiquidClaim => "liquid_claim",
        MerchantSettlementPath::BitcoinRecovery => "btc_recovery",
    };
    let mut original = None;
    let mut replacement = None;
    for row in journals {
        if row.purpose == original_purpose {
            if original.replace(row).is_some() {
                return Err(MerchantSettlementRepositoryError::MissingJournal);
            }
        } else if path == MerchantSettlementPath::LiquidClaim
            && row.purpose == "liquid_claim_replacement"
        {
            if replacement.replace(row).is_some() {
                return Err(MerchantSettlementRepositoryError::MissingJournal);
            }
        } else {
            // A swap may retain only the journal family selected by its
            // settlement context. Silently preferring one of two cross-path
            // journals would create ambiguous double-settlement authority.
            return Err(MerchantSettlementRepositoryError::MissingJournal);
        }
    }
    let original = original.ok_or(MerchantSettlementRepositoryError::MissingJournal)?;
    if let Some(replacement) = &replacement {
        if replacement.replaces_txid.as_deref() != Some(original.txid.as_str())
            || replacement.destination_address != original.destination_address
            || replacement.destination_script_hex != original.destination_script_hex
            || replacement.asset != original.asset
            || replacement.liquid_blinding_key_hex != original.liquid_blinding_key_hex
        {
            return Err(MerchantSettlementRepositoryError::MissingJournal);
        }
    }
    Ok((original, replacement))
}

fn approved_from_journal(
    journal: &MerchantSettlementJournalRow,
) -> Result<ApprovedMerchantDestination, MerchantSettlementRepositoryError> {
    Ok(match &journal.asset {
        MerchantAsset::Bitcoin => ApprovedMerchantDestination::bitcoin(
            journal.destination_address.clone(),
            journal.destination_script_hex.clone(),
        ),
        MerchantAsset::Liquid(asset_id) => ApprovedMerchantDestination::liquid(
            journal.destination_address.clone(),
            journal.destination_script_hex.clone(),
            asset_id.clone(),
        ),
    })
}

fn previous_confirmation(
    snapshot: SettlementLifecycleSnapshot,
) -> MerchantSettlementPreviousConfirmation {
    let last_reorged_block = snapshot.last_reorged_block;
    match snapshot.state {
        SettlementState::Confirmed { block, .. } | SettlementState::Finalized { block, .. } => {
            MerchantSettlementPreviousConfirmation::Confirmed {
                block_height: block.height(),
                block_hash: block.hash().to_owned(),
            }
        }
        SettlementState::Reorged { previous_block } => {
            MerchantSettlementPreviousConfirmation::Reorged {
                previous_block_height: previous_block.height(),
                previous_block_hash: previous_block.hash().to_owned(),
            }
        }
        SettlementState::Mempool => match last_reorged_block {
            Some(block) => MerchantSettlementPreviousConfirmation::Reorged {
                previous_block_height: block.height(),
                previous_block_hash: block.hash().to_owned(),
            },
            None => MerchantSettlementPreviousConfirmation::Mempool,
        },
        SettlementState::Broadcast => match last_reorged_block {
            Some(block) => MerchantSettlementPreviousConfirmation::Reorged {
                previous_block_height: block.height(),
                previous_block_hash: block.hash().to_owned(),
            },
            None => MerchantSettlementPreviousConfirmation::NeverObserved,
        },
        _ => MerchantSettlementPreviousConfirmation::NeverObserved,
    }
}

fn demotion_reason(state: &SettlementState) -> &'static str {
    match state {
        SettlementState::Replaced { .. } => "replaced",
        SettlementState::Evicted => "evicted",
        SettlementState::Reorged { .. } => "reorged",
        _ => "not_confirmed",
    }
}

fn path_text(path: MerchantSettlementPath) -> &'static str {
    match path {
        MerchantSettlementPath::LiquidClaim => "liquid_claim",
        MerchantSettlementPath::BitcoinRecovery => "bitcoin_recovery",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredCheckpoint {
    format_version: i16,
    context: StoredContext,
    lifecycle: StoredLifecycle,
    retained: Vec<StoredRetained>,
    active_event_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredContext {
    invoice_id: Uuid,
    chain_swap_id: Uuid,
    boltz_swap_id: String,
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRetained {
    evidence: StoredEvidence,
    recorded: bool,
    active: bool,
    finalized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEvidence {
    invoice_id: Uuid,
    chain_swap_id: Uuid,
    boltz_swap_id: String,
    path: String,
    family_key: String,
    event_key: String,
    journal_txid: String,
    txid: String,
    destination_address: String,
    destination_script_hex: String,
    asset_id: Option<String>,
    actual_amount_sat: i64,
    vout: u32,
    confirmations: u32,
    block_height: u32,
    block_hash: String,
    linked_replacement: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredLifecycle {
    chain: String,
    journal_txid: String,
    active_txid: String,
    state: StoredState,
    accounting: String,
    history: [bool; 8],
    linked_replacement: Option<(String, String)>,
    last_confirmed_block: Option<StoredBlock>,
    last_reorged_block: Option<StoredBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredBlock {
    height: u32,
    hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredState {
    Constructed,
    Broadcast,
    Mempool,
    Confirmed {
        block: StoredBlock,
        confirmations: u32,
        required_confirmations: u32,
    },
    Finalized {
        block: StoredBlock,
        confirmations: u32,
        required_confirmations: u32,
    },
    Replaced {
        replaced_txid: String,
        replacement_txid: String,
    },
    Evicted,
    Reorged {
        previous_block: StoredBlock,
    },
}

fn encode_snapshot(
    snapshot: &MerchantSettlementAdoptionSnapshot,
) -> Result<serde_json::Value, MerchantSettlementRepositoryError> {
    serde_json::to_value(StoredCheckpoint::from(snapshot))
        .map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)
}

fn decode_service(
    value: serde_json::Value,
    policy: SettlementFinalityPolicy,
) -> Result<MerchantSettlementAdoptionService, MerchantSettlementRepositoryError> {
    let stored: StoredCheckpoint = serde_json::from_value(value)
        .map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)?;
    let snapshot = stored.into_snapshot()?;
    MerchantSettlementAdoptionService::restore(snapshot, policy).map_err(Into::into)
}

impl From<&MerchantSettlementAdoptionSnapshot> for StoredCheckpoint {
    fn from(snapshot: &MerchantSettlementAdoptionSnapshot) -> Self {
        Self {
            format_version: CHECKPOINT_FORMAT_VERSION,
            context: StoredContext {
                invoice_id: snapshot.context.invoice_id(),
                chain_swap_id: snapshot.context.chain_swap_id(),
                boltz_swap_id: snapshot.context.boltz_swap_id().to_owned(),
                path: path_text(snapshot.context.path()).to_owned(),
            },
            lifecycle: StoredLifecycle::from(&snapshot.lifecycle),
            retained: snapshot.retained.iter().map(StoredRetained::from).collect(),
            active_event_key: snapshot.active_event_key.clone(),
        }
    }
}

impl StoredCheckpoint {
    fn into_snapshot(
        self,
    ) -> Result<MerchantSettlementAdoptionSnapshot, MerchantSettlementRepositoryError> {
        if self.format_version != CHECKPOINT_FORMAT_VERSION {
            return Err(MerchantSettlementRepositoryError::InvalidCheckpoint);
        }
        let path = parse_path(&self.context.path)?;
        let context = MerchantSettlementContext::new(
            self.context.invoice_id,
            self.context.chain_swap_id,
            self.context.boltz_swap_id,
            path,
        )
        .map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)?;
        let mut retained = Vec::with_capacity(self.retained.len());
        for row in self.retained {
            let evidence = ConfirmedMerchantOutputEvidence::restore(row.evidence.into_snapshot()?)
                .map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)?;
            let intent = evidence
                .accounting_intent(&context)
                .map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)?;
            retained.push(RetainedMerchantOutputSnapshot {
                evidence,
                intent,
                recorded: row.recorded,
                active: row.active,
                finalized: row.finalized,
            });
        }
        Ok(MerchantSettlementAdoptionSnapshot {
            context,
            lifecycle: self.lifecycle.into_snapshot()?,
            retained,
            active_event_key: self.active_event_key,
        })
    }
}

impl From<&RetainedMerchantOutputSnapshot> for StoredRetained {
    fn from(row: &RetainedMerchantOutputSnapshot) -> Self {
        Self {
            evidence: StoredEvidence::from(row.evidence.snapshot()),
            recorded: row.recorded,
            active: row.active,
            finalized: row.finalized,
        }
    }
}

impl From<ConfirmedMerchantOutputEvidenceSnapshot> for StoredEvidence {
    fn from(evidence: ConfirmedMerchantOutputEvidenceSnapshot) -> Self {
        let asset_id = match evidence.asset {
            MerchantAsset::Bitcoin => None,
            MerchantAsset::Liquid(asset_id) => Some(asset_id),
        };
        Self {
            invoice_id: evidence.invoice_id,
            chain_swap_id: evidence.chain_swap_id,
            boltz_swap_id: evidence.boltz_swap_id,
            path: path_text(evidence.path).to_owned(),
            family_key: evidence.family_key,
            event_key: evidence.event_key,
            journal_txid: evidence.journal_txid,
            txid: evidence.txid,
            destination_address: evidence.destination_address,
            destination_script_hex: evidence.destination_script_hex,
            asset_id,
            actual_amount_sat: evidence.actual_amount_sat,
            vout: evidence.vout,
            confirmations: evidence.confirmations,
            block_height: evidence.block_height,
            block_hash: evidence.block_hash,
            linked_replacement: evidence.linked_replacement,
        }
    }
}

impl StoredEvidence {
    fn into_snapshot(
        self,
    ) -> Result<ConfirmedMerchantOutputEvidenceSnapshot, MerchantSettlementRepositoryError> {
        Ok(ConfirmedMerchantOutputEvidenceSnapshot {
            invoice_id: self.invoice_id,
            chain_swap_id: self.chain_swap_id,
            boltz_swap_id: self.boltz_swap_id,
            path: parse_path(&self.path)?,
            family_key: self.family_key,
            event_key: self.event_key,
            journal_txid: self.journal_txid,
            txid: self.txid,
            destination_address: self.destination_address,
            destination_script_hex: self.destination_script_hex,
            asset: self
                .asset_id
                .map(MerchantAsset::Liquid)
                .unwrap_or(MerchantAsset::Bitcoin),
            actual_amount_sat: self.actual_amount_sat,
            vout: self.vout,
            confirmations: self.confirmations,
            block_height: self.block_height,
            block_hash: self.block_hash,
            linked_replacement: self.linked_replacement,
        })
    }
}

impl From<&SettlementLifecycleSnapshot> for StoredLifecycle {
    fn from(snapshot: &SettlementLifecycleSnapshot) -> Self {
        let block = |block: &SettlementBlock| StoredBlock {
            height: block.height(),
            hash: block.hash().to_owned(),
        };
        let state = match &snapshot.state {
            SettlementState::Constructed => StoredState::Constructed,
            SettlementState::Broadcast => StoredState::Broadcast,
            SettlementState::Mempool => StoredState::Mempool,
            SettlementState::Confirmed {
                block: b,
                confirmations,
                required_confirmations,
            } => StoredState::Confirmed {
                block: block(b),
                confirmations: *confirmations,
                required_confirmations: *required_confirmations,
            },
            SettlementState::Finalized {
                block: b,
                confirmations,
                required_confirmations,
            } => StoredState::Finalized {
                block: block(b),
                confirmations: *confirmations,
                required_confirmations: *required_confirmations,
            },
            SettlementState::Replaced {
                replaced_txid,
                replacement_txid,
            } => StoredState::Replaced {
                replaced_txid: replaced_txid.as_str().to_owned(),
                replacement_txid: replacement_txid.as_str().to_owned(),
            },
            SettlementState::Evicted => StoredState::Evicted,
            SettlementState::Reorged { previous_block } => StoredState::Reorged {
                previous_block: block(previous_block),
            },
        };
        let h = snapshot.history;
        Self {
            chain: match snapshot.chain {
                SettlementChain::Liquid => "liquid",
                SettlementChain::Bitcoin => "bitcoin",
            }
            .to_owned(),
            journal_txid: snapshot.journal_txid.as_str().to_owned(),
            active_txid: snapshot.active_txid.as_str().to_owned(),
            state,
            accounting: match snapshot.accounting {
                SettlementAccountingState::Unrecorded => "unrecorded",
                SettlementAccountingState::Confirmed => "confirmed",
                SettlementAccountingState::Finalized => "finalized",
                SettlementAccountingState::Demoted => "demoted",
            }
            .to_owned(),
            history: [
                h.constructed,
                h.broadcast,
                h.mempool,
                h.confirmed,
                h.finalized,
                h.replaced,
                h.evicted,
                h.reorged,
            ],
            linked_replacement: snapshot
                .linked_replacement
                .as_ref()
                .map(|(a, b)| (a.as_str().to_owned(), b.as_str().to_owned())),
            last_confirmed_block: snapshot.last_confirmed_block.as_ref().map(block),
            last_reorged_block: snapshot.last_reorged_block.as_ref().map(block),
        }
    }
}

impl StoredLifecycle {
    fn into_snapshot(
        self,
    ) -> Result<SettlementLifecycleSnapshot, MerchantSettlementRepositoryError> {
        let parse_block = |block: StoredBlock| {
            SettlementBlock::new(block.height, &block.hash)
                .map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)
        };
        let state = match self.state {
            StoredState::Constructed => SettlementState::Constructed,
            StoredState::Broadcast => SettlementState::Broadcast,
            StoredState::Mempool => SettlementState::Mempool,
            StoredState::Confirmed {
                block,
                confirmations,
                required_confirmations,
            } => SettlementState::Confirmed {
                block: parse_block(block)?,
                confirmations,
                required_confirmations,
            },
            StoredState::Finalized {
                block,
                confirmations,
                required_confirmations,
            } => SettlementState::Finalized {
                block: parse_block(block)?,
                confirmations,
                required_confirmations,
            },
            StoredState::Replaced {
                replaced_txid,
                replacement_txid,
            } => SettlementState::Replaced {
                replaced_txid: parse_txid(&replaced_txid)?,
                replacement_txid: parse_txid(&replacement_txid)?,
            },
            StoredState::Evicted => SettlementState::Evicted,
            StoredState::Reorged { previous_block } => SettlementState::Reorged {
                previous_block: parse_block(previous_block)?,
            },
        };
        let [constructed, broadcast, mempool, confirmed, finalized, replaced, evicted, reorged] =
            self.history;
        let linked_replacement = match self.linked_replacement {
            Some((parent, child)) => Some((parse_txid(&parent)?, parse_txid(&child)?)),
            None => None,
        };
        Ok(SettlementLifecycleSnapshot {
            chain: match self.chain.as_str() {
                "liquid" => SettlementChain::Liquid,
                "bitcoin" => SettlementChain::Bitcoin,
                _ => return Err(MerchantSettlementRepositoryError::InvalidCheckpoint),
            },
            journal_txid: parse_txid(&self.journal_txid)?,
            active_txid: parse_txid(&self.active_txid)?,
            state,
            accounting: match self.accounting.as_str() {
                "unrecorded" => SettlementAccountingState::Unrecorded,
                "confirmed" => SettlementAccountingState::Confirmed,
                "finalized" => SettlementAccountingState::Finalized,
                "demoted" => SettlementAccountingState::Demoted,
                _ => return Err(MerchantSettlementRepositoryError::InvalidCheckpoint),
            },
            history: SettlementEvidenceHistory {
                constructed,
                broadcast,
                mempool,
                confirmed,
                finalized,
                replaced,
                evicted,
                reorged,
            },
            linked_replacement,
            last_confirmed_block: self.last_confirmed_block.map(parse_block).transpose()?,
            last_reorged_block: self.last_reorged_block.map(parse_block).transpose()?,
        })
    }
}

fn parse_path(path: &str) -> Result<MerchantSettlementPath, MerchantSettlementRepositoryError> {
    match path {
        "liquid_claim" => Ok(MerchantSettlementPath::LiquidClaim),
        "bitcoin_recovery" => Ok(MerchantSettlementPath::BitcoinRecovery),
        _ => Err(MerchantSettlementRepositoryError::InvalidCheckpoint),
    }
}

fn parse_txid(txid: &str) -> Result<SettlementTxid, MerchantSettlementRepositoryError> {
    SettlementTxid::parse(txid).map_err(|_| MerchantSettlementRepositoryError::InvalidCheckpoint)
}
