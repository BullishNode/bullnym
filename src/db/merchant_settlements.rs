use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{direct_payments, InvoiceAccountingTolerances};
use crate::{
    fee_decision_record::{FeeConstructionPurpose, FeeDecisionRecord},
    merchant_output_verifier::{
        ApprovedMerchantDestination, MerchantAsset, PersistableMerchantTransactionJournal,
    },
    merchant_settlement_adoption::{
        ConfirmedMerchantOutputEvidence, ConfirmedMerchantOutputEvidenceSnapshot,
        MerchantOutputAccountingIdentity, MerchantOutputAccountingIntent,
        MerchantSettlementContext, MerchantSettlementPath,
    },
    merchant_settlement_lifecycle::{
        MerchantSettlementLifecycle, SettlementAccountingState, SettlementBlock, SettlementChain,
        SettlementEvidenceHistory, SettlementFinalityPolicy, SettlementLifecycleSnapshot,
        SettlementState, SettlementTxid,
    },
    merchant_settlement_service::{
        MerchantSettlementAdoptionService, MerchantSettlementAdoptionSnapshot,
        MerchantSettlementPersistenceCommand, MerchantSettlementProcessingError,
        MerchantSettlementProcessingOutcome, RetainedMerchantOutputSnapshot,
    },
};

const CHECKPOINT_FORMAT_VERSION: i16 = 1;
const LIQUID_BROADCAST_START_PARENT_STATUS: &str = "claiming";

/// Outcome of the atomic parent/attempt lock taken immediately before a
/// Liquid claim network call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidMerchantSettlementBroadcastStartDisposition {
    /// The exact attempt was durably marked ambiguous and may be broadcast.
    Started,
    /// Exact confirmation/finality won the race; no broadcast is necessary.
    AlreadySettled,
    /// Another worker published a terminal claim failure; no broadcast may run.
    Superseded,
}

/// Result of reloading a reconstructed immutable Liquid journal packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactLiquidMerchantSettlementJournalDisposition {
    /// The exact packet remains eligible for same-byte broadcast or redrive.
    Broadcastable,
    /// Independent observation already confirmed or finalized the exact packet.
    AlreadySettled,
}

fn exact_liquid_journal_disposition(
    status: &str,
) -> Result<ExactLiquidMerchantSettlementJournalDisposition, MerchantSettlementRepositoryError> {
    match status {
        "constructed" | "broadcast_ambiguous" | "broadcast" => {
            Ok(ExactLiquidMerchantSettlementJournalDisposition::Broadcastable)
        }
        "confirmed" | "finalized" => {
            Ok(ExactLiquidMerchantSettlementJournalDisposition::AlreadySettled)
        }
        _ => Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiquidBroadcastStartAction {
    Start,
    AlreadySettled,
    Superseded,
}

fn liquid_broadcast_start_action(
    expected_txid: &str,
    attempt_txid: &str,
    attempt_status: &str,
    parent_claim_txid: Option<&str>,
    parent_status: &str,
) -> Result<LiquidBroadcastStartAction, MerchantSettlementRepositoryError> {
    if attempt_txid != expected_txid || parent_claim_txid != Some(expected_txid) {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    match (attempt_status, parent_status) {
        ("integrity_hold", _) => Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict),
        ("confirmed", "claiming") | ("finalized", "claimed") => {
            Ok(LiquidBroadcastStartAction::AlreadySettled)
        }
        (
            "constructed" | "broadcast_ambiguous" | "broadcast",
            LIQUID_BROADCAST_START_PARENT_STATUS,
        ) => Ok(LiquidBroadcastStartAction::Start),
        ("constructed" | "broadcast_ambiguous" | "broadcast", "claim_failed" | "claim_stuck") => {
            Ok(LiquidBroadcastStartAction::Superseded)
        }
        _ => Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointWriteKind {
    InsertInitial,
    UpdateExisting,
}

fn checkpoint_write_kind(
    expected_checkpoint_version: i64,
) -> Result<CheckpointWriteKind, MerchantSettlementRepositoryError> {
    match expected_checkpoint_version {
        value if value < 0 => Err(MerchantSettlementRepositoryError::InvalidCommand),
        0 => Ok(CheckpointWriteKind::InsertInitial),
        _ => Ok(CheckpointWriteKind::UpdateExisting),
    }
}

fn next_checkpoint_version(
    expected_checkpoint_version: i64,
) -> Result<i64, MerchantSettlementRepositoryError> {
    expected_checkpoint_version
        .checked_add(1)
        .ok_or(MerchantSettlementRepositoryError::InvalidCheckpoint)
}

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
    pub fee_authority: Option<MerchantSettlementFeeAuthority>,
    pub status: String,
}

#[derive(Clone, PartialEq)]
pub struct MerchantSettlementFeeAuthority {
    pub purpose: String,
    pub rail: String,
    pub target: String,
    pub source: String,
    pub rate_sat_vb: f64,
    pub quoted_at_unix: i64,
    pub evaluated_at_unix: i64,
    pub freshness_age_secs: i64,
    pub freshness_max_age_secs: i64,
    pub provenance: String,
    pub policy_floor_sat_vb: f64,
    pub policy_cap_sat_vb: f64,
    pub policy_version: String,
}

impl fmt::Debug for MerchantSettlementFeeAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MerchantSettlementFeeAuthority")
            .field("purpose", &self.purpose)
            .field("rail", &self.rail)
            .field("target", &self.target)
            .field("source", &self.source)
            .field("rate_sat_vb", &self.rate_sat_vb)
            .field("quoted_at_unix", &self.quoted_at_unix)
            .field("evaluated_at_unix", &self.evaluated_at_unix)
            .field("freshness_age_secs", &self.freshness_age_secs)
            .field("freshness_max_age_secs", &self.freshness_max_age_secs)
            .field("provenance", &"<redacted>")
            .field("policy_floor_sat_vb", &self.policy_floor_sat_vb)
            .field("policy_cap_sat_vb", &self.policy_cap_sat_vb)
            .field("policy_version", &self.policy_version)
            .finish()
    }
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
    /// Present only while making new bytes durable. Exact-byte redrive loads
    /// the already-persisted authority and never asks for a new decision.
    pub fee_authority: Option<&'a FeeDecisionRecord>,
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

/// Exact database facts consumed by the shared chain-swap execution reducer.
///
/// The caller already owns the per-swap advisory transaction. Loading these
/// rows with `FOR UPDATE` makes a newly journaled recovery, a settlement
/// checkpoint transition, and a claim replay mutually visible at one database
/// boundary. Chain observations are deliberately not represented here.
#[derive(Debug, Clone)]
pub struct LiquidClaimExecutionFacts {
    pub journal_txid: Option<String>,
    pub journal_raw_transaction: Option<Vec<u8>>,
    pub journal_source_prevouts: Option<Vec<MerchantSettlementSourcePrevout>>,
    pub journal_status: Option<String>,
    pub lifecycle: Option<MerchantSettlementLifecycle>,
    pub replacement_present: bool,
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
    fee_decision_purpose: Option<String>,
    fee_decision_rail: Option<String>,
    fee_decision_target: Option<String>,
    fee_decision_source: Option<String>,
    fee_decision_rate_sat_vb: Option<f64>,
    fee_decision_quoted_at_unix: Option<i64>,
    fee_decision_evaluated_at_unix: Option<i64>,
    fee_decision_freshness_age_secs: Option<i64>,
    fee_decision_freshness_max_age_secs: Option<i64>,
    fee_decision_provenance: Option<String>,
    fee_decision_policy_floor_sat_vb: Option<f64>,
    fee_decision_policy_cap_sat_vb: Option<f64>,
    fee_decision_policy_version: Option<String>,
    status: String,
}

impl JournalDbRow {
    fn fee_authority(
        &self,
    ) -> Result<Option<MerchantSettlementFeeAuthority>, MerchantSettlementRepositoryError> {
        let present = [
            self.fee_decision_purpose.is_some(),
            self.fee_decision_rail.is_some(),
            self.fee_decision_target.is_some(),
            self.fee_decision_source.is_some(),
            self.fee_decision_rate_sat_vb.is_some(),
            self.fee_decision_quoted_at_unix.is_some(),
            self.fee_decision_evaluated_at_unix.is_some(),
            self.fee_decision_freshness_age_secs.is_some(),
            self.fee_decision_freshness_max_age_secs.is_some(),
            self.fee_decision_provenance.is_some(),
            self.fee_decision_policy_floor_sat_vb.is_some(),
            self.fee_decision_policy_cap_sat_vb.is_some(),
            self.fee_decision_policy_version.is_some(),
        ]
        .into_iter()
        .filter(|is_present| *is_present)
        .count();
        if present == 0 {
            return Ok(None);
        }
        if present != 13 {
            return Err(MerchantSettlementRepositoryError::MissingJournal);
        }
        Ok(Some(MerchantSettlementFeeAuthority {
            purpose: self
                .fee_decision_purpose
                .clone()
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            rail: self
                .fee_decision_rail
                .clone()
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            target: self
                .fee_decision_target
                .clone()
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            source: self
                .fee_decision_source
                .clone()
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            rate_sat_vb: self
                .fee_decision_rate_sat_vb
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            quoted_at_unix: self
                .fee_decision_quoted_at_unix
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            evaluated_at_unix: self
                .fee_decision_evaluated_at_unix
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            freshness_age_secs: self
                .fee_decision_freshness_age_secs
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            freshness_max_age_secs: self
                .fee_decision_freshness_max_age_secs
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            provenance: self
                .fee_decision_provenance
                .clone()
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            policy_floor_sat_vb: self
                .fee_decision_policy_floor_sat_vb
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            policy_cap_sat_vb: self
                .fee_decision_policy_cap_sat_vb
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
            policy_version: self
                .fee_decision_policy_version
                .clone()
                .ok_or(MerchantSettlementRepositoryError::MissingJournal)?,
        }))
    }
}

impl TryFrom<JournalDbRow> for MerchantSettlementJournalRow {
    type Error = MerchantSettlementRepositoryError;

    fn try_from(row: JournalDbRow) -> Result<Self, Self::Error> {
        let fee_authority = row.fee_authority()?;
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
            fee_authority,
            status: row.status,
        })
    }
}

const JOURNAL_COLUMNS: &str = "id, chain_swap_id, purpose, replaces_txid, raw_tx_hex, txid, \
    source_prevouts, destination_address, destination_script_hex, destination_asset_id, \
    destination_amount_sat, destination_vout, fee_amount_sat, fee_rate_sat_vb, \
    liquid_blinding_key_hex, fee_decision_purpose, fee_decision_rail, \
    fee_decision_target, fee_decision_source, fee_decision_rate_sat_vb, \
    fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
    fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
    fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
    fee_decision_policy_cap_sat_vb, fee_decision_policy_version, status";

/// Insert the immutable Liquid claim/replacement intent before broadcast. The
/// next migration widens migration 046's purpose constraint and adds the
/// lineage/asset/blinding columns referenced by this runtime SQL.
pub async fn insert_liquid_merchant_settlement_journal(
    connection: &mut PgConnection,
    journal: &NewLiquidMerchantSettlementJournal<'_>,
) -> Result<MerchantSettlementJournalRow, MerchantSettlementRepositoryError> {
    validate_new_liquid_journal(journal)?;
    let fee_authority = persisted_liquid_fee_authority(journal.fee_authority)?;
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
             liquid_blinding_key_hex, fee_decision_purpose, fee_decision_rail, \
             fee_decision_target, fee_decision_source, fee_decision_rate_sat_vb, \
             fee_decision_quoted_at_unix, fee_decision_evaluated_at_unix, \
             fee_decision_freshness_age_secs, fee_decision_freshness_max_age_secs, \
             fee_decision_provenance, fee_decision_policy_floor_sat_vb, \
             fee_decision_policy_cap_sat_vb, fee_decision_policy_version\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,\
                   $18,$19,$20,$21,$22,$23,$24,$25,$26,$27) \
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
    .bind(&fee_authority.purpose)
    .bind(&fee_authority.rail)
    .bind(&fee_authority.target)
    .bind(&fee_authority.source)
    .bind(fee_authority.rate_sat_vb)
    .bind(fee_authority.quoted_at_unix)
    .bind(fee_authority.evaluated_at_unix)
    .bind(fee_authority.freshness_age_secs)
    .bind(fee_authority.freshness_max_age_secs)
    .bind(&fee_authority.provenance)
    .bind(fee_authority.policy_floor_sat_vb)
    .bind(fee_authority.policy_cap_sat_vb)
    .bind(&fee_authority.policy_version)
    .fetch_optional(&mut *connection)
    .await?;
    let row = match inserted {
        Some(row) => row.try_into()?,
        None => load_liquid_journal_by_purpose(connection, journal.chain_swap_id, purpose)
            .await?
            .ok_or(MerchantSettlementRepositoryError::ImmutableIdentityConflict)?,
    };
    assert_liquid_journal_matches(&row, journal, purpose)?;
    if !liquid_attempt_is_broadcastable(&row.status) {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    if !matches!(
        row.fee_authority.as_ref(),
        Some(persisted) if fee_authority_matches(persisted, &fee_authority)
    ) {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(row)
}

/// Re-read and lock an already persisted claim/replacement in the caller's
/// transaction, then require byte-for-byte equality with the newly prepared
/// packet. A rebroadcaster therefore uses the journaled raw bytes or stops; it
/// cannot silently accept a reconstructed transaction with the same purpose.
pub async fn load_exact_liquid_merchant_settlement_journal(
    connection: &mut PgConnection,
    journal: &NewLiquidMerchantSettlementJournal<'_>,
) -> Result<ExactLiquidMerchantSettlementJournalDisposition, MerchantSettlementRepositoryError> {
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
    if row.fee_authority.is_none() {
        return Err(MerchantSettlementRepositoryError::MissingJournal);
    }
    exact_liquid_journal_disposition(&row.status)
}

/// Load the immutable Liquid-claim journal family and its adoption lifecycle
/// from the caller's already-open advisory transaction.
///
/// This is intentionally narrower than [`load_merchant_settlement_work_item`]:
/// an execution gate needs only locked identity/lifecycle facts and must not
/// open a second repeatable-read transaction while the parent row is locked.
pub async fn load_liquid_claim_execution_facts_for_update(
    connection: &mut PgConnection,
    chain_swap_id: Uuid,
    invoice_id: Uuid,
    boltz_swap_id: &str,
    policy: SettlementFinalityPolicy,
) -> Result<LiquidClaimExecutionFacts, MerchantSettlementRepositoryError> {
    if chain_swap_id.is_nil() || invoice_id.is_nil() || boltz_swap_id.is_empty() {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    }

    let original =
        load_liquid_journal_by_purpose(connection, chain_swap_id, "liquid_claim").await?;
    let replacement =
        load_liquid_journal_by_purpose(connection, chain_swap_id, "liquid_claim_replacement")
            .await?;
    let checkpoint: Option<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT journal_txid, snapshot_json \
           FROM merchant_settlement_checkpoints \
          WHERE chain_swap_id = $1 AND settlement_path = 'liquid_claim' \
          FOR UPDATE",
    )
    .bind(chain_swap_id)
    .fetch_optional(&mut *connection)
    .await?;

    let Some(original) = original else {
        if replacement.is_some() || checkpoint.is_some() {
            return Err(MerchantSettlementRepositoryError::MissingJournal);
        }
        return Ok(LiquidClaimExecutionFacts {
            journal_txid: None,
            journal_raw_transaction: None,
            journal_source_prevouts: None,
            journal_status: None,
            lifecycle: None,
            replacement_present: false,
        });
    };

    if let Some(replacement) = replacement.as_ref() {
        if replacement.replaces_txid.as_deref() != Some(original.txid.as_str()) {
            return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
        }
    }

    let lifecycle = match checkpoint {
        None => None,
        Some((checkpoint_journal_txid, snapshot_json)) => {
            if checkpoint_journal_txid != original.txid {
                return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
            }
            let service = decode_service(snapshot_json, policy)?;
            let context = service.context();
            if context.chain_swap_id() != chain_swap_id
                || context.invoice_id() != invoice_id
                || context.boltz_swap_id() != boltz_swap_id
                || context.path() != MerchantSettlementPath::LiquidClaim
            {
                return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
            }
            let snapshot = service.lifecycle().snapshot();
            validate_checkpoint_journal_family(
                snapshot.journal_txid.as_str(),
                snapshot
                    .linked_replacement
                    .as_ref()
                    .map(|(parent, child)| (parent.as_str(), child.as_str())),
                &original,
                replacement.as_ref(),
            )?;
            Some(service.lifecycle().clone())
        }
    };

    Ok(LiquidClaimExecutionFacts {
        journal_txid: Some(original.txid),
        journal_raw_transaction: Some(original.raw_transaction),
        journal_source_prevouts: Some(original.source_prevouts),
        journal_status: Some(original.status),
        lifecycle,
        replacement_present: replacement.is_some(),
    })
}

/// Durably record that an exact Liquid claim broadcast is about to start. If
/// the process dies after this commit, restart sees an ambiguous immutable
/// attempt and can only replay the same bytes.
pub async fn mark_liquid_merchant_settlement_broadcast_started(
    pool: &PgPool,
    chain_swap_id: Uuid,
    txid: &str,
    purpose: &str,
) -> Result<LiquidMerchantSettlementBroadcastStartDisposition, MerchantSettlementRepositoryError> {
    let mut transaction = pool.begin().await?;
    let disposition = mark_liquid_merchant_settlement_broadcast_started_locked(
        &mut transaction,
        chain_swap_id,
        txid,
        purpose,
    )
    .await?;
    transaction.commit().await?;
    Ok(disposition)
}

/// Transaction-scoped form used by the ClaimLiquid executor after its second
/// complete-evidence recheck. The caller holds the shared advisory lock and
/// commits this write immediately before the network call, leaving no unlocked
/// database interval between fresh authorization and durable broadcast intent.
pub async fn mark_liquid_merchant_settlement_broadcast_started_locked(
    connection: &mut PgConnection,
    chain_swap_id: Uuid,
    txid: &str,
    purpose: &str,
) -> Result<LiquidMerchantSettlementBroadcastStartDisposition, MerchantSettlementRepositoryError> {
    if chain_swap_id.is_nil()
        || !matches!(purpose, "liquid_claim" | "liquid_claim_replacement")
        || !canonical_hash(txid)
    {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    }
    let parent: Option<(Option<String>, String)> = sqlx::query_as(
        "SELECT claim_txid, status FROM chain_swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(chain_swap_id)
    .fetch_optional(&mut *connection)
    .await?;
    let (parent_claim_txid, parent_status) =
        parent.ok_or(MerchantSettlementRepositoryError::MissingJournal)?;
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, txid, status FROM chain_swap_tx_attempts \
          WHERE chain_swap_id = $1 AND txid = $2 AND purpose = $3 FOR UPDATE",
    )
    .bind(chain_swap_id)
    .bind(txid)
    .bind(purpose)
    .fetch_optional(&mut *connection)
    .await?;
    let (attempt_id, attempt_txid, attempt_status) =
        row.ok_or(MerchantSettlementRepositoryError::MissingJournal)?;
    match liquid_broadcast_start_action(
        txid,
        &attempt_txid,
        &attempt_status,
        parent_claim_txid.as_deref(),
        &parent_status,
    )? {
        LiquidBroadcastStartAction::AlreadySettled => {
            return Ok(LiquidMerchantSettlementBroadcastStartDisposition::AlreadySettled)
        }
        LiquidBroadcastStartAction::Superseded => {
            return Ok(LiquidMerchantSettlementBroadcastStartDisposition::Superseded)
        }
        LiquidBroadcastStartAction::Start => {}
    }
    let rows = sqlx::query(
        "UPDATE chain_swap_tx_attempts SET \
             status = CASE WHEN status IN ('constructed','broadcast_ambiguous') \
                           THEN 'broadcast_ambiguous' ELSE status END, \
             broadcast_attempts = broadcast_attempts + 1, \
             first_broadcast_attempt_at = COALESCE(first_broadcast_attempt_at, NOW()), \
             last_broadcast_attempt_at = NOW(), \
             last_broadcast_result = 'broadcast attempt started; outcome unknown', \
             updated_at = NOW() \
         WHERE id = $1 AND txid = $2 AND status = $3",
    )
    .bind(attempt_id)
    .bind(txid)
    .bind(&attempt_status)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if rows != 1 {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(LiquidMerchantSettlementBroadcastStartDisposition::Started)
}

/// Finalize a successful or already-known Liquid broadcast only when the
/// journal and parent still identify the same exact, durably-started attempt.
pub async fn mark_liquid_merchant_settlement_broadcast(
    pool: &PgPool,
    chain_swap_id: Uuid,
    txid: &str,
    purpose: &str,
    result: &str,
) -> Result<(), MerchantSettlementRepositoryError> {
    if chain_swap_id.is_nil()
        || !matches!(purpose, "liquid_claim" | "liquid_claim_replacement")
        || !canonical_hash(txid)
        || result.is_empty()
    {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    }
    let rows = sqlx::query(
        "UPDATE chain_swap_tx_attempts attempt SET \
             status = CASE WHEN attempt.status IN ('confirmed','finalized') \
                           THEN attempt.status ELSE 'broadcast' END, \
             broadcast_at = COALESCE(attempt.broadcast_at, NOW()), \
             last_broadcast_result = $4, updated_at = NOW() \
          FROM chain_swap_records parent \
         WHERE attempt.chain_swap_id = $1 AND attempt.txid = $2 AND attempt.purpose = $3 \
           AND attempt.status IN ('broadcast_ambiguous','broadcast','confirmed','finalized') \
           AND attempt.broadcast_attempts > 0 \
           AND parent.id = attempt.chain_swap_id AND parent.claim_txid = attempt.txid",
    )
    .bind(chain_swap_id)
    .bind(txid)
    .bind(purpose)
    .bind(result)
    .execute(pool)
    .await?
    .rows_affected();
    if rows != 1 {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(())
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

fn persisted_liquid_fee_authority(
    record: Option<&FeeDecisionRecord>,
) -> Result<MerchantSettlementFeeAuthority, MerchantSettlementRepositoryError> {
    let record = record.ok_or(MerchantSettlementRepositoryError::InvalidCommand)?;
    if record.purpose() != FeeConstructionPurpose::ChainLiquidClaim {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    }
    Ok(MerchantSettlementFeeAuthority {
        purpose: record.purpose().as_str().to_owned(),
        rail: record.rail().as_str().to_owned(),
        target: record.target().as_str().to_owned(),
        source: record.source().as_str().to_owned(),
        rate_sat_vb: record.rate().as_f64(),
        quoted_at_unix: i64::try_from(record.quoted_at_unix())
            .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?,
        evaluated_at_unix: i64::try_from(record.evaluated_at_unix())
            .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?,
        freshness_age_secs: i64::try_from(record.freshness_age_secs())
            .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?,
        freshness_max_age_secs: i64::try_from(record.freshness_max_age_secs())
            .map_err(|_| MerchantSettlementRepositoryError::InvalidCommand)?,
        provenance: record.provenance_for_persistence().to_owned(),
        policy_floor_sat_vb: record.policy_floor().as_f64(),
        policy_cap_sat_vb: record.policy_cap().as_f64(),
        policy_version: record.policy_version().to_owned(),
    })
}

fn fee_authority_matches(
    persisted: &MerchantSettlementFeeAuthority,
    expected: &MerchantSettlementFeeAuthority,
) -> bool {
    persisted.purpose == expected.purpose
        && persisted.rail == expected.rail
        && persisted.target == expected.target
        && persisted.source == expected.source
        && persisted.rate_sat_vb.to_bits() == expected.rate_sat_vb.to_bits()
        && persisted.quoted_at_unix == expected.quoted_at_unix
        && persisted.evaluated_at_unix == expected.evaluated_at_unix
        && persisted.freshness_age_secs == expected.freshness_age_secs
        && persisted.freshness_max_age_secs == expected.freshness_max_age_secs
        && persisted.provenance == expected.provenance
        && persisted.policy_floor_sat_vb.to_bits() == expected.policy_floor_sat_vb.to_bits()
        && persisted.policy_cap_sat_vb.to_bits() == expected.policy_cap_sat_vb.to_bits()
        && persisted.policy_version == expected.policy_version
}

fn liquid_attempt_is_broadcastable(status: &str) -> bool {
    matches!(status, "constructed" | "broadcast_ambiguous" | "broadcast")
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
    let service_snapshot = service.snapshot();
    let lifecycle_linked_replacement = service_snapshot
        .lifecycle
        .linked_replacement
        .as_ref()
        .map(|(parent, child)| (parent.as_str(), child.as_str()));
    validate_checkpoint_journal_family(
        service_snapshot.lifecycle.journal_txid.as_str(),
        lifecycle_linked_replacement,
        &original_journal,
        linked_replacement.as_ref(),
    )?;
    for retained in &service_snapshot.retained {
        validate_retained_journal_commitment(
            &retained.evidence.snapshot(),
            lifecycle_linked_replacement,
            &original_journal,
            linked_replacement.as_ref(),
        )?;
    }
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
    let previous_confirmation = previous_confirmation(service_snapshot.lifecycle);
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
    let checkpoint_write = checkpoint_write_kind(expected_checkpoint_version)?;
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
    let checkpoint_version = next_checkpoint_version(expected_checkpoint_version)?;
    apply_commands(&mut tx, snapshot, outcome).await?;
    persist_retained(&mut tx, snapshot).await?;
    let rows = match checkpoint_write {
        CheckpointWriteKind::InsertInitial => sqlx::query(
            "INSERT INTO merchant_settlement_checkpoints (\
                 chain_swap_id, settlement_path, invoice_id, boltz_swap_id, format_version, \
                 checkpoint_version, journal_txid, snapshot_json\
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(context.chain_swap_id())
        .bind(path_text(context.path()))
        .bind(context.invoice_id())
        .bind(context.boltz_swap_id())
        .bind(CHECKPOINT_FORMAT_VERSION)
        .bind(checkpoint_version)
        .bind(snapshot.lifecycle.journal_txid.as_str())
        .bind(&snapshot_json)
        .execute(&mut *tx)
        .await?
        .rows_affected(),
        CheckpointWriteKind::UpdateExisting => sqlx::query(
            "UPDATE merchant_settlement_checkpoints \
                SET checkpoint_version = $6, snapshot_json = $8, updated_at = NOW() \
              WHERE chain_swap_id = $1 AND settlement_path = $2 \
                AND invoice_id = $3 AND boltz_swap_id = $4 AND format_version = $5 \
                AND journal_txid = $7 AND checkpoint_version = $9",
        )
        .bind(context.chain_swap_id())
        .bind(path_text(context.path()))
        .bind(context.invoice_id())
        .bind(context.boltz_swap_id())
        .bind(CHECKPOINT_FORMAT_VERSION)
        .bind(checkpoint_version)
        .bind(snapshot.lifecycle.journal_txid.as_str())
        .bind(&snapshot_json)
        .bind(expected_checkpoint_version)
        .execute(&mut *tx)
        .await?
        .rows_affected(),
    };
    if rows != 1 {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    let journal_rebroadcast_required =
        transition_attempt_locked(&mut tx, snapshot, outcome.rebroadcast_journaled).await?;
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
    rebroadcast_journaled: bool,
) -> Result<bool, MerchantSettlementRepositoryError> {
    let accounting = snapshot.lifecycle.accounting;
    if accounting == SettlementAccountingState::Unrecorded && !rebroadcast_journaled {
        return Ok(false);
    }
    if accounting == SettlementAccountingState::Unrecorded
        && !matches!(&snapshot.lifecycle.state, SettlementState::Evicted)
    {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
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
    match accounting {
        SettlementAccountingState::Demoted => {
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
        SettlementAccountingState::Confirmed => {
            if !matches!(status.as_str(), "confirmed" | "finalized") {
                let rows = sqlx::query(
                    "UPDATE chain_swap_tx_attempts SET status = 'confirmed', \
                         confirmed_at = COALESCE(confirmed_at, NOW()), updated_at = NOW() \
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
            Ok(false)
        }
        SettlementAccountingState::Finalized => {
            if status != "finalized" {
                let rows = sqlx::query(
                    "UPDATE chain_swap_tx_attempts SET status = 'finalized', \
                         confirmed_at = COALESCE(confirmed_at, NOW()), \
                         finalized_at = COALESCE(finalized_at, NOW()), updated_at = NOW() \
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
            Ok(false)
        }
        SettlementAccountingState::Unrecorded => {
            let Some(update_required) =
                unrecorded_rebroadcast_update_required(rebroadcast_journaled, &status)?
            else {
                return Ok(false);
            };
            if update_required {
                let rows = sqlx::query(
                    "UPDATE chain_swap_tx_attempts SET status = 'broadcast_ambiguous', \
                         last_broadcast_result = 'merchant settlement evicted before accounting; exact journal replay required', \
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
    }
}

/// `None` means an ordinary unrecorded observation must not even rewrite the
/// attempt. `Some(false)` means an eviction already left the exact attempt in
/// its replay-safe ambiguous state; the caller still reports a redrive.
fn unrecorded_rebroadcast_update_required(
    rebroadcast_journaled: bool,
    status: &str,
) -> Result<Option<bool>, MerchantSettlementRepositoryError> {
    if !rebroadcast_journaled {
        return Ok(None);
    }
    match status {
        "constructed" | "broadcast" => Ok(Some(true)),
        "broadcast_ambiguous" => Ok(Some(false)),
        _ => Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict),
    }
}

fn parent_transition_target(
    path: MerchantSettlementPath,
    previous_status: &str,
    finalized: bool,
    exact_stuck_liquid_journal: bool,
) -> Option<&'static str> {
    match path {
        MerchantSettlementPath::LiquidClaim
            if matches!(previous_status, "claiming" | "claimed" | "claim_failed")
                || (previous_status == "claim_stuck" && exact_stuck_liquid_journal) =>
        {
            Some(if finalized { "claimed" } else { "claiming" })
        }
        MerchantSettlementPath::BitcoinRecovery
            if matches!(previous_status, "refunding" | "refunded") =>
        {
            Some(if finalized { "refunded" } else { "refunding" })
        }
        _ => None,
    }
}

async fn transition_parent_locked(
    tx: &mut Transaction<'_, Postgres>,
    snapshot: &MerchantSettlementAdoptionSnapshot,
) -> Result<MerchantSettlementParentTransition, MerchantSettlementRepositoryError> {
    let (previous_status, claim_txid, claim_tx_hex, refund_txid): (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT status, claim_txid, claim_tx_hex, refund_txid \
           FROM chain_swap_records WHERE id = $1 FOR UPDATE",
    )
    .bind(snapshot.context.chain_swap_id())
    .fetch_one(&mut **tx)
    .await?;
    let finalized = snapshot.lifecycle.accounting == SettlementAccountingState::Finalized;
    let active_txid = snapshot.lifecycle.active_txid.as_str();
    let exact_stuck_liquid_journal = if snapshot.context.path()
        == MerchantSettlementPath::LiquidClaim
        && previous_status == "claim_stuck"
    {
        let Some(claim_tx_hex) = claim_tx_hex.as_deref() else {
            return Err(MerchantSettlementRepositoryError::MissingJournal);
        };
        sqlx::query_scalar::<_, bool>(
            "SELECT TRUE FROM chain_swap_tx_attempts \
              WHERE chain_swap_id = $1 AND txid = $2 \
                AND purpose IN ('liquid_claim','liquid_claim_replacement') \
                AND raw_tx_hex = $3 AND status <> 'integrity_hold' \
              FOR UPDATE",
        )
        .bind(snapshot.context.chain_swap_id())
        .bind(active_txid)
        .bind(claim_tx_hex)
        .fetch_optional(&mut **tx)
        .await?
        .unwrap_or(false)
    } else {
        false
    };
    let current_status = parent_transition_target(
        snapshot.context.path(),
        &previous_status,
        finalized,
        exact_stuck_liquid_journal,
    )
    .ok_or(MerchantSettlementRepositoryError::ImmutableIdentityConflict)?;
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
                         last_claim_error = NULL, last_claim_error_at = NULL, \
                         next_claim_attempt_at = NULL, \
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
                let deactivated_txid = snapshot
                    .retained
                    .iter()
                    .find(|retained| &retained.intent.identity == identity)
                    .map(|retained| retained.evidence.txid())
                    .ok_or(MerchantSettlementRepositoryError::InvalidCommand)?;
                let linked_replacement = snapshot
                    .lifecycle
                    .linked_replacement
                    .as_ref()
                    .map(|(parent, child)| (parent.as_str(), child.as_str()));
                let reason = deactivation_reason(
                    &snapshot.lifecycle.state,
                    linked_replacement,
                    snapshot.lifecycle.active_txid.as_str(),
                    deactivated_txid,
                )?;
                mutate_event(
                    tx,
                    snapshot,
                    identity,
                    "inactive",
                    Some(reason),
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
    let attribution: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT chain_swap.invoice_quote_version_id, \
                chain_swap.invoice_quote_offer_id \
           FROM chain_swap_records chain_swap \
          WHERE chain_swap.id = $1 \
            AND chain_swap.invoice_id = $2 \
            AND chain_swap.boltz_swap_id = $3 \
            AND ( \
              (chain_swap.invoice_quote_version_id IS NULL \
               AND chain_swap.invoice_quote_offer_id IS NULL) \
              OR EXISTS ( \
                SELECT 1 FROM invoice_quote_offers offer \
                 WHERE offer.id = chain_swap.invoice_quote_offer_id \
                   AND offer.quote_version_id = chain_swap.invoice_quote_version_id \
                   AND offer.invoice_id = chain_swap.invoice_id \
                   AND offer.rail = 'bitcoin' \
                   AND offer.offer_kind = 'boltz_chain' \
                   AND offer.provider = 'boltz' \
                   AND offer.provider_offer_id = chain_swap.boltz_swap_id \
              ) \
            )",
    )
    .bind(intent.chain_swap_id)
    .bind(intent.invoice_id)
    .bind(&intent.boltz_swap_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((quote_version_id, quote_offer_id)) = attribution else {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    };
    if quote_version_id.is_some() != quote_offer_id.is_some() {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    sqlx::query(
        "INSERT INTO invoice_payment_events (\
             invoice_id, rail, source, event_key, amount_sat, txid, vout, boltz_swap_id, address, \
             accounting_state, verification_state, deactivated_at, deactivation_reason, \
             merchant_settlement_family_key, merchant_chain_swap_id, merchant_settlement_finalized, \
             invoice_quote_version_id, invoice_quote_offer_id, quote_first_observed_at\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'inactive','verified',NOW(),'not_confirmed', \
                   $10,$11,FALSE,$12,$13, \
                   CASE WHEN $12::UUID IS NULL THEN NULL ELSE clock_timestamp() END) \
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
    .bind(quote_version_id)
    .bind(quote_offer_id)
    .execute(&mut **tx)
    .await?;
    let exact: Option<bool> = sqlx::query_scalar(
        "SELECT invoice_id = $2 AND rail = $3 AND source = $4 AND amount_sat = $5 \
                AND txid = $6 AND vout = $7 AND boltz_swap_id = $8 AND address = $9 \
                AND merchant_settlement_family_key = $10 AND merchant_chain_swap_id = $11 \
                AND invoice_quote_version_id IS NOT DISTINCT FROM $12::UUID \
                AND invoice_quote_offer_id IS NOT DISTINCT FROM $13::UUID \
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
    .bind(quote_version_id)
    .bind(quote_offer_id)
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

fn validate_checkpoint_journal_family(
    lifecycle_journal_txid: &str,
    lifecycle_linked_replacement: Option<(&str, &str)>,
    original: &MerchantSettlementJournalRow,
    selected_replacement: Option<&MerchantSettlementJournalRow>,
) -> Result<(), MerchantSettlementRepositoryError> {
    if lifecycle_journal_txid != original.txid {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    let Some((parent_txid, child_txid)) = lifecycle_linked_replacement else {
        // A replacement may already be journaled before its independently
        // observed lineage is adopted into the durable lifecycle checkpoint.
        return Ok(());
    };
    let replacement =
        selected_replacement.ok_or(MerchantSettlementRepositoryError::ImmutableIdentityConflict)?;
    if parent_txid != original.txid
        || replacement.replaces_txid.as_deref() != Some(parent_txid)
        || replacement.txid != child_txid
    {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(())
}

fn validate_retained_journal_commitment(
    evidence: &ConfirmedMerchantOutputEvidenceSnapshot,
    lifecycle_linked_replacement: Option<(&str, &str)>,
    original: &MerchantSettlementJournalRow,
    selected_replacement: Option<&MerchantSettlementJournalRow>,
) -> Result<(), MerchantSettlementRepositoryError> {
    if evidence.journal_txid != original.txid {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    let journal = if evidence.txid == original.txid && !evidence.linked_replacement {
        original
    } else if let Some((parent_txid, child_txid)) = lifecycle_linked_replacement {
        let replacement = selected_replacement
            .ok_or(MerchantSettlementRepositoryError::ImmutableIdentityConflict)?;
        if !evidence.linked_replacement
            || parent_txid != original.txid
            || child_txid != replacement.txid
            || replacement.replaces_txid.as_deref() != Some(parent_txid)
            || evidence.txid != replacement.txid
        {
            return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
        }
        replacement
    } else {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    };
    if evidence.destination_address != journal.destination_address
        || evidence.destination_script_hex != journal.destination_script_hex
        || evidence.asset != journal.asset
        || u64::try_from(evidence.actual_amount_sat).ok() != Some(journal.destination_amount_sat)
        || evidence.vout != journal.destination_vout
    {
        return Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict);
    }
    Ok(())
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

fn deactivation_reason(
    state: &SettlementState,
    linked_replacement: Option<(&str, &str)>,
    active_txid: &str,
    deactivated_txid: &str,
) -> Result<&'static str, MerchantSettlementRepositoryError> {
    if linked_replacement
        .is_some_and(|(parent, child)| parent == deactivated_txid && child == active_txid)
    {
        return Ok("replaced");
    }
    if deactivated_txid != active_txid {
        return Err(MerchantSettlementRepositoryError::InvalidCommand);
    }
    match state {
        SettlementState::Evicted => Ok("evicted"),
        SettlementState::Reorged { .. } => Ok("reorged"),
        _ => Err(MerchantSettlementRepositoryError::InvalidCommand),
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

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_policy::{FeeProvenance, LiquidFeePolicy, LiveLiquid, SatPerVbyte};
    use crate::merchant_settlement_lifecycle::{
        apply_settlement_evidence, MerchantSettlementLifecycle, SettlementEvidence,
    };

    const TXID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const BLOCK_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BLOCK_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ASSET: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const BLINDING_KEY: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn liquid_fee_record(purpose: FeeConstructionPurpose) -> FeeDecisionRecord {
        let policy = LiquidFeePolicy::default();
        let live = LiveLiquid::new(
            SatPerVbyte::try_from(0.5).unwrap(),
            1_000,
            FeeProvenance::new("merchant-settlement-unit-live").unwrap(),
        );
        let decision = policy.decide_typed(Some(&live), None, 1_005).unwrap();
        FeeDecisionRecord::from_liquid(purpose, &decision, &policy, 1_005).unwrap()
    }

    fn journal(purpose: &str, txid: &str) -> MerchantSettlementJournalRow {
        MerchantSettlementJournalRow {
            id: Uuid::from_u128(if purpose == "liquid_claim_replacement" {
                2
            } else {
                1
            }),
            chain_swap_id: Uuid::from_u128(3),
            purpose: purpose.to_owned(),
            replaces_txid: (purpose == "liquid_claim_replacement").then(|| TXID.to_owned()),
            raw_transaction: vec![1, 2, 3],
            txid: txid.to_owned(),
            source_prevouts: Vec::new(),
            destination_address: "el1qqmerchant".to_owned(),
            destination_script_hex: "0014abcd".to_owned(),
            asset: MerchantAsset::Liquid(ASSET.to_owned()),
            destination_amount_sat: 50_000,
            destination_vout: 0,
            fee_amount_sat: 200,
            fee_rate_sat_vb: 1.5,
            liquid_blinding_key_hex: Some(BLINDING_KEY.to_owned()),
            fee_authority: None,
            status: "constructed".to_owned(),
        }
    }

    fn retained_evidence(
        journal: &MerchantSettlementJournalRow,
        journal_txid: &str,
        linked_replacement: bool,
    ) -> ConfirmedMerchantOutputEvidenceSnapshot {
        let family_key = format!(
            "chain_swap_merchant_output:{}:{journal_txid}",
            journal.chain_swap_id
        );
        ConfirmedMerchantOutputEvidenceSnapshot {
            invoice_id: Uuid::from_u128(4),
            chain_swap_id: journal.chain_swap_id,
            boltz_swap_id: "merchant-settlement-unit".to_owned(),
            path: MerchantSettlementPath::LiquidClaim,
            event_key: format!("{family_key}:{}:{}", journal.txid, journal.destination_vout),
            family_key,
            journal_txid: journal_txid.to_owned(),
            txid: journal.txid.clone(),
            destination_address: journal.destination_address.clone(),
            destination_script_hex: journal.destination_script_hex.clone(),
            asset: journal.asset.clone(),
            actual_amount_sat: i64::try_from(journal.destination_amount_sat).unwrap(),
            vout: journal.destination_vout,
            confirmations: 1,
            block_height: 1,
            block_hash: BLOCK_A.to_owned(),
            linked_replacement,
        }
    }

    #[test]
    fn new_liquid_journal_requires_exact_chain_claim_fee_authority() {
        assert!(matches!(
            persisted_liquid_fee_authority(None),
            Err(MerchantSettlementRepositoryError::InvalidCommand)
        ));
        let reverse = liquid_fee_record(FeeConstructionPurpose::ReverseLiquidClaim);
        assert!(matches!(
            persisted_liquid_fee_authority(Some(&reverse)),
            Err(MerchantSettlementRepositoryError::InvalidCommand)
        ));

        let chain = liquid_fee_record(FeeConstructionPurpose::ChainLiquidClaim);
        let authority = persisted_liquid_fee_authority(Some(&chain)).unwrap();
        assert_eq!(authority.purpose, "chain_liquid_claim");
        assert_eq!(authority.rail, "liquid");
        assert_eq!(authority.target, "1");
        assert_eq!(authority.source, "liquid_live");
        assert_eq!(authority.rate_sat_vb, 0.5);
        assert_eq!(authority.quoted_at_unix, 1_000);
        assert_eq!(authority.evaluated_at_unix, 1_005);
        assert_eq!(authority.freshness_age_secs, 5);
        assert_eq!(authority.policy_version, "review25-v1");
        assert!(fee_authority_matches(&authority, &authority));

        let mut changed = authority.clone();
        changed.provenance.push_str("-changed");
        assert!(!fee_authority_matches(&authority, &changed));
    }

    #[test]
    fn unrecorded_eviction_requests_exact_journal_rebroadcast() {
        for status in ["constructed", "broadcast"] {
            assert!(matches!(
                unrecorded_rebroadcast_update_required(true, status),
                Ok(Some(true))
            ));
            assert!(matches!(
                unrecorded_rebroadcast_update_required(false, status),
                Ok(None)
            ));
        }
        assert!(matches!(
            unrecorded_rebroadcast_update_required(true, "broadcast_ambiguous"),
            Ok(Some(false))
        ));
        assert!(matches!(
            unrecorded_rebroadcast_update_required(false, "broadcast_ambiguous"),
            Ok(None)
        ));
        for status in ["confirmed", "finalized", "integrity_hold"] {
            assert!(matches!(
                unrecorded_rebroadcast_update_required(true, status),
                Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
            ));
        }
    }

    #[test]
    fn liquid_redrive_accepts_only_broadcastable_attempt_states() {
        for status in ["constructed", "broadcast_ambiguous", "broadcast"] {
            assert!(liquid_attempt_is_broadcastable(status));
        }
        for status in ["confirmed", "finalized", "integrity_hold"] {
            assert!(!liquid_attempt_is_broadcastable(status));
        }
    }

    #[test]
    fn exact_liquid_journal_status_is_terminal_aware_and_fail_closed() {
        for status in ["constructed", "broadcast_ambiguous", "broadcast"] {
            assert_eq!(
                exact_liquid_journal_disposition(status).unwrap(),
                ExactLiquidMerchantSettlementJournalDisposition::Broadcastable
            );
        }
        for status in ["confirmed", "finalized"] {
            assert_eq!(
                exact_liquid_journal_disposition(status).unwrap(),
                ExactLiquidMerchantSettlementJournalDisposition::AlreadySettled
            );
        }
        for status in ["integrity_hold", "failed", "unknown"] {
            assert!(matches!(
                exact_liquid_journal_disposition(status),
                Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
            ));
        }
    }

    #[test]
    fn parent_transition_accepts_only_exact_liquid_failure_recovery() {
        for previous in ["claiming", "claimed", "claim_failed"] {
            assert_eq!(
                parent_transition_target(
                    MerchantSettlementPath::LiquidClaim,
                    previous,
                    false,
                    false,
                ),
                Some("claiming")
            );
            assert_eq!(
                parent_transition_target(
                    MerchantSettlementPath::LiquidClaim,
                    previous,
                    true,
                    false,
                ),
                Some("claimed")
            );
        }
        assert_eq!(
            parent_transition_target(
                MerchantSettlementPath::LiquidClaim,
                "claim_stuck",
                false,
                true,
            ),
            Some("claiming")
        );
        assert_eq!(
            parent_transition_target(
                MerchantSettlementPath::LiquidClaim,
                "claim_stuck",
                true,
                true,
            ),
            Some("claimed")
        );
        assert_eq!(
            parent_transition_target(
                MerchantSettlementPath::LiquidClaim,
                "claim_stuck",
                true,
                false,
            ),
            None
        );
        for previous in ["pending", "refunding", "refunded", "expired"] {
            assert_eq!(
                parent_transition_target(MerchantSettlementPath::LiquidClaim, previous, true, true,),
                None,
                "{previous}"
            );
        }

        for previous in ["refunding", "refunded"] {
            assert_eq!(
                parent_transition_target(
                    MerchantSettlementPath::BitcoinRecovery,
                    previous,
                    false,
                    true,
                ),
                Some("refunding")
            );
            assert_eq!(
                parent_transition_target(
                    MerchantSettlementPath::BitcoinRecovery,
                    previous,
                    true,
                    true,
                ),
                Some("refunded")
            );
        }
        for previous in ["claim_failed", "claim_stuck", "claiming", "claimed"] {
            assert_eq!(
                parent_transition_target(
                    MerchantSettlementPath::BitcoinRecovery,
                    previous,
                    true,
                    true,
                ),
                None,
                "{previous}"
            );
        }
    }

    #[test]
    fn liquid_broadcast_start_requires_claiming_parent() {
        const CHILD: &str = "2222222222222222222222222222222222222222222222222222222222222222";

        assert_eq!(LIQUID_BROADCAST_START_PARENT_STATUS, "claiming");
        for attempt_status in ["constructed", "broadcast_ambiguous", "broadcast"] {
            assert_eq!(
                liquid_broadcast_start_action(TXID, TXID, attempt_status, Some(TXID), "claiming",)
                    .unwrap(),
                LiquidBroadcastStartAction::Start
            );
            for parent_status in ["claim_failed", "claim_stuck"] {
                assert_eq!(
                    liquid_broadcast_start_action(
                        TXID,
                        TXID,
                        attempt_status,
                        Some(TXID),
                        parent_status,
                    )
                    .unwrap(),
                    LiquidBroadcastStartAction::Superseded
                );
            }
        }
        assert_eq!(
            liquid_broadcast_start_action(TXID, TXID, "confirmed", Some(TXID), "claiming").unwrap(),
            LiquidBroadcastStartAction::AlreadySettled
        );
        assert_eq!(
            liquid_broadcast_start_action(TXID, TXID, "finalized", Some(TXID), "claimed").unwrap(),
            LiquidBroadcastStartAction::AlreadySettled
        );
        for (attempt_txid, attempt_status, parent_txid, parent_status) in [
            (CHILD, "constructed", Some(TXID), "claiming"),
            (TXID, "constructed", Some(CHILD), "claiming"),
            (TXID, "constructed", None, "claiming"),
            (TXID, "integrity_hold", Some(TXID), "claim_failed"),
            (TXID, "constructed", Some(TXID), "claimed"),
            (TXID, "confirmed", Some(TXID), "claimed"),
            (TXID, "finalized", Some(TXID), "claiming"),
        ] {
            assert!(matches!(
                liquid_broadcast_start_action(
                    TXID,
                    attempt_txid,
                    attempt_status,
                    parent_txid,
                    parent_status,
                ),
                Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
            ));
        }
    }

    #[test]
    fn checkpoint_write_splits_initial_insert_from_existing_cas_update() {
        assert!(matches!(
            checkpoint_write_kind(0),
            Ok(CheckpointWriteKind::InsertInitial)
        ));
        for version in [1, 2, i64::MAX] {
            assert!(matches!(
                checkpoint_write_kind(version),
                Ok(CheckpointWriteKind::UpdateExisting)
            ));
        }
        assert!(matches!(
            checkpoint_write_kind(-1),
            Err(MerchantSettlementRepositoryError::InvalidCommand)
        ));
        assert!(matches!(next_checkpoint_version(0), Ok(1)));
        assert!(matches!(next_checkpoint_version(1), Ok(2)));
        assert!(matches!(
            next_checkpoint_version(i64::MAX),
            Err(MerchantSettlementRepositoryError::InvalidCheckpoint)
        ));
    }

    #[test]
    fn checkpoint_journal_binding_requires_exact_adopted_lineage() {
        const CHILD: &str = "2222222222222222222222222222222222222222222222222222222222222222";
        const OTHER: &str = "3333333333333333333333333333333333333333333333333333333333333333";
        let original = journal("liquid_claim", TXID);
        let replacement = journal("liquid_claim_replacement", CHILD);
        let wrong_original = journal("liquid_claim", CHILD);

        assert!(matches!(
            validate_checkpoint_journal_family(TXID, None, &wrong_original, None),
            Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
        ));
        assert!(validate_checkpoint_journal_family(TXID, None, &original, None).is_ok());
        assert!(
            validate_checkpoint_journal_family(TXID, None, &original, Some(&replacement)).is_ok()
        );
        assert!(matches!(
            validate_checkpoint_journal_family(TXID, Some((TXID, CHILD)), &original, None),
            Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
        ));

        let mut wrong_parent = replacement.clone();
        wrong_parent.replaces_txid = Some(OTHER.to_owned());
        assert!(matches!(
            validate_checkpoint_journal_family(
                TXID,
                Some((TXID, CHILD)),
                &original,
                Some(&wrong_parent)
            ),
            Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
        ));
        let wrong_child = journal("liquid_claim_replacement", OTHER);
        assert!(matches!(
            validate_checkpoint_journal_family(
                TXID,
                Some((TXID, CHILD)),
                &original,
                Some(&wrong_child)
            ),
            Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
        ));
        assert!(validate_checkpoint_journal_family(
            TXID,
            Some((TXID, CHILD)),
            &original,
            Some(&replacement)
        )
        .is_ok());
    }

    #[test]
    fn checkpoint_journal_binding_rejects_retained_value_substitution() {
        const CHILD: &str = "2222222222222222222222222222222222222222222222222222222222222222";
        let original = journal("liquid_claim", TXID);
        let replacement = journal("liquid_claim_replacement", CHILD);
        let valid = retained_evidence(&original, TXID, false);
        assert!(validate_retained_journal_commitment(&valid, None, &original, None).is_ok());

        let mut corruptions = Vec::new();
        let mut amount = valid.clone();
        amount.actual_amount_sat += 1;
        corruptions.push(amount);
        let mut vout = valid.clone();
        vout.vout += 1;
        corruptions.push(vout);
        let mut address = valid.clone();
        address.destination_address.push_str("-wrong");
        corruptions.push(address);
        let mut script = valid.clone();
        script.destination_script_hex = "0014dcba".to_owned();
        corruptions.push(script);
        let mut asset = valid;
        asset.asset = MerchantAsset::Liquid(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
        );
        corruptions.push(asset);
        for corrupted in corruptions {
            assert!(matches!(
                validate_retained_journal_commitment(&corrupted, None, &original, None),
                Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
            ));
        }

        let linked = retained_evidence(&replacement, TXID, true);
        assert!(validate_retained_journal_commitment(
            &linked,
            Some((TXID, CHILD)),
            &original,
            Some(&replacement)
        )
        .is_ok());
        let original_history = retained_evidence(&original, TXID, false);
        assert!(validate_retained_journal_commitment(
            &original_history,
            Some((TXID, CHILD)),
            &original,
            Some(&replacement)
        )
        .is_ok());

        let child_without_link_flag = retained_evidence(&replacement, TXID, false);
        let original_with_link_flag = retained_evidence(&original, TXID, true);
        let wrong_journal = retained_evidence(&original, CHILD, false);
        for corrupted in [
            child_without_link_flag,
            original_with_link_flag,
            wrong_journal,
        ] {
            assert!(matches!(
                validate_retained_journal_commitment(
                    &corrupted,
                    Some((TXID, CHILD)),
                    &original,
                    Some(&replacement)
                ),
                Err(MerchantSettlementRepositoryError::ImmutableIdentityConflict)
            ));
        }
    }

    #[test]
    fn select_journals_rejects_cross_path_families() {
        let liquid = journal("liquid_claim", TXID);
        let bitcoin = journal(
            "btc_recovery",
            "2222222222222222222222222222222222222222222222222222222222222222",
        );

        assert!(matches!(
            select_journals(
                MerchantSettlementPath::LiquidClaim,
                vec![liquid.clone(), bitcoin.clone()]
            ),
            Err(MerchantSettlementRepositoryError::MissingJournal)
        ));
        assert!(matches!(
            select_journals(
                MerchantSettlementPath::BitcoinRecovery,
                vec![bitcoin, liquid]
            ),
            Err(MerchantSettlementRepositoryError::MissingJournal)
        ));
    }

    #[test]
    fn select_journals_rejects_replacement_destination_and_confidential_identity_changes() {
        let original = journal("liquid_claim", TXID);
        let replacement_txid = "2222222222222222222222222222222222222222222222222222222222222222";
        let valid_replacement = journal("liquid_claim_replacement", replacement_txid);
        assert!(select_journals(
            MerchantSettlementPath::LiquidClaim,
            vec![original.clone(), valid_replacement.clone()]
        )
        .is_ok());

        let mut mismatches = Vec::new();
        let mut address = valid_replacement.clone();
        address.destination_address = "el1qqdifferent".to_owned();
        mismatches.push(address);
        let mut script = valid_replacement.clone();
        script.destination_script_hex = "0014dcba".to_owned();
        mismatches.push(script);
        let mut asset = valid_replacement.clone();
        asset.asset = MerchantAsset::Liquid(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned(),
        );
        mismatches.push(asset);
        let mut blinding = valid_replacement;
        blinding.liquid_blinding_key_hex =
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned());
        mismatches.push(blinding);

        for replacement in mismatches {
            assert!(matches!(
                select_journals(
                    MerchantSettlementPath::LiquidClaim,
                    vec![original.clone(), replacement]
                ),
                Err(MerchantSettlementRepositoryError::MissingJournal)
            ));
        }
    }

    #[test]
    fn deactivation_reason_preserves_replacement_lineage_after_child_progress() {
        const CHILD: &str = "2222222222222222222222222222222222222222222222222222222222222222";

        for state in [
            SettlementState::Mempool,
            SettlementState::Confirmed {
                block: SettlementBlock::new(100, BLOCK_A).unwrap(),
                confirmations: 1,
                required_confirmations: 2,
            },
        ] {
            assert_eq!(
                deactivation_reason(&state, Some((TXID, CHILD)), CHILD, TXID).unwrap(),
                "replaced"
            );
        }

        assert_eq!(
            deactivation_reason(&SettlementState::Evicted, None, TXID, TXID).unwrap(),
            "evicted"
        );
        assert_eq!(
            deactivation_reason(
                &SettlementState::Reorged {
                    previous_block: SettlementBlock::new(100, BLOCK_A).unwrap(),
                },
                Some((TXID, CHILD)),
                CHILD,
                CHILD,
            )
            .unwrap(),
            "reorged"
        );

        assert!(matches!(
            deactivation_reason(&SettlementState::Mempool, None, CHILD, TXID),
            Err(MerchantSettlementRepositoryError::InvalidCommand)
        ));
    }

    #[test]
    fn previous_confirmation_uses_new_block_after_reconfirmation() {
        let policy = SettlementFinalityPolicy::new(2, 3).unwrap();
        let txid = SettlementTxid::parse(TXID).unwrap();
        let lifecycle = MerchantSettlementLifecycle::new(SettlementChain::Liquid, txid.clone());
        let block_a = SettlementBlock::new(100, BLOCK_A).unwrap();
        let confirmed = apply_settlement_evidence(
            &lifecycle,
            &SettlementEvidence::Confirmed {
                txid: txid.clone(),
                block: block_a.clone(),
                confirmations: 1,
            },
            policy,
        )
        .unwrap()
        .lifecycle;
        let reorged = apply_settlement_evidence(
            &confirmed,
            &SettlementEvidence::Reorged {
                txid: txid.clone(),
                previous_block: block_a,
            },
            policy,
        )
        .unwrap()
        .lifecycle;
        assert_eq!(
            previous_confirmation(reorged.snapshot()),
            MerchantSettlementPreviousConfirmation::Reorged {
                previous_block_height: 100,
                previous_block_hash: BLOCK_A.to_owned(),
            }
        );

        let reconfirmed = apply_settlement_evidence(
            &reorged,
            &SettlementEvidence::Confirmed {
                txid,
                block: SettlementBlock::new(101, BLOCK_B).unwrap(),
                confirmations: 1,
            },
            policy,
        )
        .unwrap()
        .lifecycle;
        assert_eq!(
            previous_confirmation(reconfirmed.snapshot()),
            MerchantSettlementPreviousConfirmation::Confirmed {
                block_height: 101,
                block_hash: BLOCK_B.to_owned(),
            }
        );
    }
}
