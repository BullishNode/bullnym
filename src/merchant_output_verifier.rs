//! Fail-closed verification of a confirmed chain-swap merchant output.
//!
//! This module has no accounting or lifecycle writes. Its successful output is
//! the narrow evidence packet a later, atomic accounting transition may
//! consume. Callers remain responsible for sourcing `Authoritative` evidence
//! from locally verified raw transaction and chain-inclusion data.

use std::{fmt, str::FromStr};

use bitcoin::{consensus::deserialize, Address, Network, Transaction};
use lwk_wollet::elements::{self, Address as LiquidAddress, AddressParams};

use crate::{
    chain_recovery::{
        BitcoinRecoveryEvidence, BitcoinRecoveryStatusSnapshot, BitcoinRecoveryTransactionStatus,
    },
    db::ChainSwapTxAttempt,
    error::AppError,
    utxo::{
        LiquidHistoryEntry, LiquidHistorySnapshot, LiquidHistorySnapshotLimits,
        LiquidHistorySnapshotOutcome, UtxoBackend,
    },
};

/// The chain asset paid by the candidate transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerchantAsset {
    Bitcoin,
    Liquid(String),
}

/// The immutable merchant destination approved before transaction
/// construction. Address and script are both retained so a journal cannot
/// substitute a text destination whose decoded output differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedMerchantDestination {
    address: String,
    script_pubkey_hex: String,
    asset: MerchantAsset,
}

impl ApprovedMerchantDestination {
    pub fn bitcoin(address: impl Into<String>, script_pubkey_hex: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            script_pubkey_hex: script_pubkey_hex.into(),
            asset: MerchantAsset::Bitcoin,
        }
    }

    pub fn liquid(
        address: impl Into<String>,
        script_pubkey_hex: impl Into<String>,
        asset_id: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            script_pubkey_hex: script_pubkey_hex.into(),
            asset: MerchantAsset::Liquid(asset_id.into()),
        }
    }
}

/// Exact output commitment from the transaction journal selected for
/// verification. A replacement is authoritative only when its persisted row
/// explicitly names the original journal txid supplied to
/// [`verify_merchant_output`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournaledMerchantTransaction {
    txid: String,
    replaces_txid: Option<String>,
    destination_address: String,
    destination_script_hex: String,
    destination_asset: MerchantAsset,
    destination_amount_sat: i64,
    destination_vout: i32,
}

impl JournaledMerchantTransaction {
    pub fn original(
        txid: impl Into<String>,
        destination_address: impl Into<String>,
        destination_script_hex: impl Into<String>,
        destination_asset: MerchantAsset,
        destination_amount_sat: i64,
        destination_vout: i32,
    ) -> Self {
        Self {
            txid: txid.into(),
            replaces_txid: None,
            destination_address: destination_address.into(),
            destination_script_hex: destination_script_hex.into(),
            destination_asset,
            destination_amount_sat,
            destination_vout,
        }
    }

    /// Constructs the pure view of an explicitly persisted replacement row.
    /// A caller must not infer this link from a shared input or backend hint.
    pub fn linked_replacement(
        txid: impl Into<String>,
        replaces_txid: impl Into<String>,
        destination_address: impl Into<String>,
        destination_script_hex: impl Into<String>,
        destination_asset: MerchantAsset,
        destination_amount_sat: i64,
        destination_vout: i32,
    ) -> Self {
        Self {
            txid: txid.into(),
            replaces_txid: Some(replaces_txid.into()),
            destination_address: destination_address.into(),
            destination_script_hex: destination_script_hex.into(),
            destination_asset,
            destination_amount_sat,
            destination_vout,
        }
    }

    /// Revalidates the existing immutable Bitcoin recovery journal row against
    /// its raw bytes before it can become verification authority.
    pub fn from_bitcoin_recovery_attempt(
        attempt: &ChainSwapTxAttempt,
    ) -> Result<Self, MerchantOutputVerificationError> {
        if attempt.purpose != "btc_recovery" {
            return Err(MerchantOutputVerificationError::InvalidJournal);
        }
        if attempt.status == "integrity_hold" {
            return Err(MerchantOutputVerificationError::JournalIntegrityHold);
        }
        if !matches!(
            attempt.status.as_str(),
            "constructed" | "broadcast_ambiguous" | "broadcast" | "confirmed" | "finalized"
        ) {
            return Err(MerchantOutputVerificationError::InvalidJournal);
        }

        let raw = hex::decode(&attempt.raw_tx_hex)
            .map_err(|_| MerchantOutputVerificationError::InvalidJournal)?;
        let transaction: Transaction =
            deserialize(&raw).map_err(|_| MerchantOutputVerificationError::InvalidJournal)?;
        let actual_txid = canonical_hash(&transaction.compute_txid().to_string())
            .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
        let journal_txid =
            canonical_hash(&attempt.txid).ok_or(MerchantOutputVerificationError::InvalidJournal)?;
        if actual_txid != journal_txid || transaction.output.len() != 1 {
            return Err(MerchantOutputVerificationError::InvalidJournal);
        }

        let destination_vout = u32::try_from(attempt.destination_vout)
            .map_err(|_| MerchantOutputVerificationError::InvalidJournal)?;
        let destination_amount_sat = u64::try_from(attempt.destination_amount_sat)
            .ok()
            .filter(|amount| *amount > 0)
            .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
        let output = transaction
            .output
            .get(destination_vout as usize)
            .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
        let journal_script = decode_script(&attempt.destination_script_hex)
            .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
        let derived_destination_script =
            derive_destination_script(&attempt.destination_address, &MerchantAsset::Bitcoin)
                .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
        if journal_script != derived_destination_script
            || output.script_pubkey.as_bytes() != journal_script
            || output.value.to_sat() != destination_amount_sat
        {
            return Err(MerchantOutputVerificationError::InvalidJournal);
        }

        if attempt.source_prevouts.is_empty()
            || transaction.input.len() != attempt.source_prevouts.len()
            || transaction
                .input
                .iter()
                .zip(attempt.source_prevouts.iter())
                .any(|(input, source)| {
                    !input
                        .previous_output
                        .txid
                        .to_string()
                        .eq_ignore_ascii_case(&source.txid)
                        || input.previous_output.vout != source.vout
                })
        {
            return Err(MerchantOutputVerificationError::InvalidJournal);
        }

        Ok(Self::original(
            journal_txid,
            attempt.destination_address.clone(),
            hex::encode(journal_script),
            MerchantAsset::Bitcoin,
            attempt.destination_amount_sat,
            attempt.destination_vout,
        ))
    }
}

/// Output and inclusion facts decoded from authoritative raw transaction and
/// chain evidence. The verifier intentionally accepts no provider status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedMerchantOutput {
    txid: String,
    destination_script_hex: String,
    asset: MerchantAsset,
    amount_sat: u64,
    vout: u32,
    confirmations: u32,
    block_height: Option<u32>,
    block_hash: Option<String>,
}

impl ObservedMerchantOutput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        txid: impl Into<String>,
        destination_script_hex: impl Into<String>,
        asset: MerchantAsset,
        amount_sat: u64,
        vout: u32,
        confirmations: u32,
        block_height: Option<u32>,
        block_hash: Option<String>,
    ) -> Self {
        Self {
            txid: txid.into(),
            destination_script_hex: destination_script_hex.into(),
            asset,
            amount_sat,
            vout,
            confirmations,
            block_height,
            block_hash,
        }
    }

    pub fn txid(&self) -> &str {
        &self.txid
    }

    pub fn destination_script_hex(&self) -> &str {
        &self.destination_script_hex
    }

    pub fn asset(&self) -> &MerchantAsset {
        &self.asset
    }

    pub const fn amount_sat(&self) -> u64 {
        self.amount_sat
    }

    pub const fn vout(&self) -> u32 {
        self.vout
    }

    pub const fn confirmations(&self) -> u32 {
        self.confirmations
    }

    pub const fn block_height(&self) -> Option<u32> {
        self.block_height
    }

    pub fn block_hash(&self) -> Option<&str> {
        self.block_hash.as_deref()
    }
}

/// Maximum raw transaction size accepted by the production observation
/// adapters. Bullnym-created settlement transactions are far smaller; this
/// bound prevents an untrusted backend response from driving unbounded decode
/// work.
pub const MAX_MERCHANT_OUTPUT_RAW_TRANSACTION_BYTES: usize = 1_000_000;
/// Maximum number of inputs or outputs retained by one adapted transaction.
pub const MAX_MERCHANT_OUTPUT_TRANSACTION_ITEMS: usize = 256;
/// Maximum number of immutable source prevouts accepted from a journal row.
pub const MAX_MERCHANT_OUTPUT_SOURCE_PREVOUTS: usize = 256;
/// Maximum script size accepted from journal evidence.
pub const MAX_MERCHANT_OUTPUT_SCRIPT_BYTES: usize = 10_000;

/// Immutable prior-output identity and metadata read from the transaction
/// journal. A spending transaction proves the outpoint relationship, not the
/// amount or script of the previous output, so callers must source those two
/// fields from separately verified journal evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MerchantSourcePrevout<'a> {
    pub txid: &'a str,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: &'a str,
}

impl fmt::Debug for MerchantSourcePrevout<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MerchantSourcePrevout(<redacted>)")
    }
}

/// Immutable merchant output selected before transaction construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MerchantOutputCommitment<'a> {
    pub destination_address: &'a str,
    pub destination_script_hex: &'a str,
    pub asset: &'a MerchantAsset,
    pub amount_sat: u64,
    pub vout: u32,
}

impl fmt::Debug for MerchantOutputCommitment<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MerchantOutputCommitment(<redacted>)")
    }
}

/// Read-only production view of one persisted transaction-journal row.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MerchantTransactionJournalEvidence<'a> {
    pub raw_transaction: &'a [u8],
    pub txid: &'a str,
    pub source_prevouts: &'a [MerchantSourcePrevout<'a>],
    pub merchant: MerchantOutputCommitment<'a>,
}

/// Owned source evidence ready for atomic journal persistence before a claim
/// transaction is broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistableMerchantSourcePrevout {
    pub txid: String,
    pub vout: u32,
    pub amount_sat: u64,
    pub script_pubkey_hex: String,
}

/// Complete Liquid merchant-output journal derived from constructed raw bytes.
/// No requested, quoted, or provider amount is accepted by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistableMerchantTransactionJournal {
    pub raw_transaction: Vec<u8>,
    pub raw_transaction_hex: String,
    pub txid: String,
    pub source_prevouts: Vec<PersistableMerchantSourcePrevout>,
    pub destination_address: String,
    pub destination_script_hex: String,
    pub asset: MerchantAsset,
    pub amount_sat: u64,
    pub vout: u32,
}

/// Validate constructed Liquid claim bytes and derive the exact merchant
/// output packet that must be persisted before broadcast. The only amount and
/// vout authority is the unique output opened from the transaction itself.
pub fn prepare_liquid_claim_journal(
    raw_transaction: &[u8],
    source_prevouts: &[MerchantSourcePrevout<'_>],
    approved_destination_address: &str,
    approved_destination_script_hex: &str,
    liquid_asset_id: &str,
    stored_blinding_key_hex: &str,
) -> Result<PersistableMerchantTransactionJournal, MerchantOutputAdapterError> {
    validate_source_prevouts(source_prevouts)?;
    let asset = canonical_asset(&MerchantAsset::Liquid(liquid_asset_id.to_owned()))
        .ok_or(MerchantOutputAdapterError::InvalidCommitment)?;
    let destination_script =
        decode_bounded_script(approved_destination_script_hex).map_err(|exceeded| {
            if exceeded {
                MerchantOutputAdapterError::InputBoundsExceeded
            } else {
                MerchantOutputAdapterError::InvalidCommitment
            }
        })?;
    let derived_script = derive_destination_script(approved_destination_address, &asset)
        .ok_or(MerchantOutputAdapterError::InvalidCommitment)?;
    if destination_script != derived_script {
        return Err(MerchantOutputAdapterError::InvalidCommitment);
    }

    let address = LiquidAddress::from_str(approved_destination_address)
        .map_err(|_| MerchantOutputAdapterError::InvalidCommitment)?;
    let blinding_key = elements::secp256k1_zkp::SecretKey::from_str(stored_blinding_key_hex)
        .map_err(|_| MerchantOutputAdapterError::ConfidentialOutputUnverified)?;
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    let blinding_pubkey = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_key);
    if address.blinding_pubkey != Some(blinding_pubkey) {
        return Err(MerchantOutputAdapterError::ConfidentialOutputUnverified);
    }

    let transaction = decode_merchant_transaction(
        MerchantRail::Liquid,
        raw_transaction,
        MerchantTransactionRole::Journal,
    )?;
    if !transaction.inputs_match(source_prevouts) {
        return Err(MerchantOutputAdapterError::JournalSourceMismatch);
    }
    let output = transaction.unique_output_for_script(&destination_script, Some(&blinding_key))?;
    if output.asset != asset
        || output.amount_sat == 0
        || output.amount_sat > i64::MAX as u64
        || output.vout > i32::MAX as u32
    {
        return Err(MerchantOutputAdapterError::JournalOutputMismatch);
    }

    Ok(PersistableMerchantTransactionJournal {
        raw_transaction: raw_transaction.to_vec(),
        raw_transaction_hex: hex::encode(raw_transaction),
        txid: transaction.txid(),
        source_prevouts: source_prevouts
            .iter()
            .map(|source| PersistableMerchantSourcePrevout {
                txid: source.txid.to_ascii_lowercase(),
                vout: source.vout,
                amount_sat: source.amount_sat,
                script_pubkey_hex: source.script_pubkey_hex.to_ascii_lowercase(),
            })
            .collect(),
        destination_address: approved_destination_address.to_owned(),
        destination_script_hex: hex::encode(destination_script),
        asset,
        amount_sat: output.amount_sat,
        vout: output.vout,
    })
}

impl fmt::Debug for MerchantTransactionJournalEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MerchantTransactionJournalEvidence(<redacted>)")
    }
}

/// Full persisted replacement row plus its explicit direct parent relation.
/// A shared input or backend hint is never enough to construct this type's
/// authority at the adapter boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinkedReplacementJournalEvidence<'a> {
    pub replaces_txid: &'a str,
    pub replacement: MerchantTransactionJournalEvidence<'a>,
}

impl fmt::Debug for LinkedReplacementJournalEvidence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LinkedReplacementJournalEvidence(<redacted>)")
    }
}

/// Chain position supplied by the independently anchored observation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantConfirmationEvidence<'a> {
    Mempool,
    Confirmed {
        confirmations: u32,
        block_height: u32,
        block_hash: &'a str,
    },
    Evicted,
    ReorgDemoted,
}

/// Raw transaction and chain identity fetched independently of the journal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MerchantTransactionObservation<'a> {
    pub raw_transaction: &'a [u8],
    pub txid: &'a str,
    pub confirmation: MerchantConfirmationEvidence<'a>,
}

impl fmt::Debug for MerchantTransactionObservation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MerchantTransactionObservation")
            .field("raw_transaction", &"<redacted>")
            .field("txid", &"<redacted>")
            .field("confirmation", &self.confirmation)
            .finish()
    }
}

/// Journal candidate and independently constructed chain observation. The
/// fields remain private so callers cannot mix evidence from different
/// adapter runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptedMerchantOutputEvidence {
    original_journal_txid: String,
    journal: JournaledMerchantTransaction,
    evidence: MerchantOutputEvidence,
}

impl AdaptedMerchantOutputEvidence {
    pub fn original_journal_txid(&self) -> &str {
        &self.original_journal_txid
    }

    /// Candidate identity is available before confirmation so the lifecycle
    /// can durably retain mempool/reorg state without constructing verified
    /// accounting authority.
    pub fn candidate_txid(&self) -> &str {
        self.observed().txid()
    }

    pub fn is_linked_replacement(&self) -> bool {
        self.journal.replaces_txid.is_some()
    }

    pub fn journal(&self) -> &JournaledMerchantTransaction {
        &self.journal
    }

    pub fn evidence(&self) -> &MerchantOutputEvidence {
        &self.evidence
    }

    pub fn observed(&self) -> &ObservedMerchantOutput {
        match &self.evidence {
            MerchantOutputEvidence::Authoritative(observed) => observed,
            MerchantOutputEvidence::Unknown => {
                unreachable!("production adapters never construct unknown evidence")
            }
        }
    }

    pub fn verify(
        &self,
        approved_destination: &ApprovedMerchantDestination,
        required_confirmations: u32,
    ) -> Result<VerifiedMerchantOutput, MerchantOutputVerificationError> {
        verify_merchant_output(
            &self.original_journal_txid,
            &self.journal,
            approved_destination,
            &self.evidence,
            required_confirmations,
        )
    }
}

/// Fail-closed adapter failures. Variants deliberately carry no raw bytes,
/// identifiers, addresses, or provider-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantOutputAdapterError {
    InputBoundsExceeded,
    InvalidCommitment,
    InvalidSourcePrevouts,
    MalformedJournalTransaction,
    JournalTxidMismatch,
    JournalSourceMismatch,
    JournalOutputMismatch,
    InvalidReplacementLink,
    UnlinkedObservedTransaction,
    ReplacementSourceMismatch,
    ReplacementDestinationMismatch,
    MalformedObservedTransaction,
    ObservedTxidMismatch,
    ObservedSourceMismatch,
    ObservedOutputMissing,
    MultipleObservedOutputs,
    ConfidentialOutputUnverified,
    IncompleteConfirmationIdentity,
    ObservationDemoted,
}

impl fmt::Display for MerchantOutputAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputBoundsExceeded => "merchant-output adapter input exceeds its bound",
            Self::InvalidCommitment => "merchant-output journal commitment is invalid",
            Self::InvalidSourcePrevouts => "merchant-output source evidence is invalid",
            Self::MalformedJournalTransaction => "merchant-output journal bytes are invalid",
            Self::JournalTxidMismatch => "merchant-output journal bytes do not match their txid",
            Self::JournalSourceMismatch => "merchant-output journal inputs do not match sources",
            Self::JournalOutputMismatch => "merchant-output journal output does not match",
            Self::InvalidReplacementLink => "merchant-output replacement link is invalid",
            Self::UnlinkedObservedTransaction => {
                "merchant-output observation is not journal-linked"
            }
            Self::ReplacementSourceMismatch => "merchant-output replacement sources differ",
            Self::ReplacementDestinationMismatch => {
                "merchant-output replacement destination differs"
            }
            Self::MalformedObservedTransaction => "merchant-output observation bytes are invalid",
            Self::ObservedTxidMismatch => "merchant-output observation txid does not match bytes",
            Self::ObservedSourceMismatch => "merchant-output observation inputs differ",
            Self::ObservedOutputMissing => "merchant-output observation has no candidate output",
            Self::MultipleObservedOutputs => {
                "merchant-output observation has multiple candidate outputs"
            }
            Self::ConfidentialOutputUnverified => {
                "merchant-output confidential value could not be verified"
            }
            Self::IncompleteConfirmationIdentity => {
                "merchant-output confirmation identity is incomplete"
            }
            Self::ObservationDemoted => "merchant-output observation is evicted or reorged",
        })
    }
}

impl std::error::Error for MerchantOutputAdapterError {}

/// `Unknown` includes unavailable or disagreeing backends and unverified raw
/// transaction bytes. Such evidence can never become accounting authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerchantOutputEvidence {
    Unknown,
    Authoritative(ObservedMerchantOutput),
}

/// Fully checked facts suitable for a later exactly-once accounting
/// transition. Constructing this type directly is intentionally impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMerchantOutput {
    journal_txid: String,
    txid: String,
    destination_address: String,
    destination_script_hex: String,
    asset: MerchantAsset,
    amount_sat: u64,
    vout: u32,
    confirmations: u32,
    block_height: u32,
    block_hash: String,
    linked_replacement: bool,
}

impl VerifiedMerchantOutput {
    pub fn journal_txid(&self) -> &str {
        &self.journal_txid
    }

    pub fn txid(&self) -> &str {
        &self.txid
    }

    pub fn destination_address(&self) -> &str {
        &self.destination_address
    }

    pub fn destination_script_hex(&self) -> &str {
        &self.destination_script_hex
    }

    pub fn asset(&self) -> &MerchantAsset {
        &self.asset
    }

    pub const fn amount_sat(&self) -> u64 {
        self.amount_sat
    }

    pub const fn vout(&self) -> u32 {
        self.vout
    }

    pub const fn confirmations(&self) -> u32 {
        self.confirmations
    }

    pub const fn block_height(&self) -> u32 {
        self.block_height
    }

    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    pub const fn is_linked_replacement(&self) -> bool {
        self.linked_replacement
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantOutputVerificationError {
    InvalidJournal,
    JournalIntegrityHold,
    InvalidApprovedDestination,
    InvalidConfirmationPolicy,
    UnknownEvidence,
    UnlinkedTransaction,
    InvalidEvidence,
    EvidenceTransactionMismatch,
    DestinationMismatch,
    AssetMismatch,
    AmountMismatch,
    VoutMismatch,
    InsufficientConfirmations,
    IncompleteConfirmationEvidence,
}

impl fmt::Display for MerchantOutputVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJournal => "merchant-output journal evidence is invalid",
            Self::JournalIntegrityHold => "merchant-output journal is on integrity hold",
            Self::InvalidApprovedDestination => "approved merchant destination is invalid",
            Self::InvalidConfirmationPolicy => "merchant-output confirmation policy is invalid",
            Self::UnknownEvidence => "merchant-output evidence is unknown",
            Self::UnlinkedTransaction => "observed transaction is not linked to the journal",
            Self::InvalidEvidence => "merchant-output evidence is invalid",
            Self::EvidenceTransactionMismatch => {
                "merchant-output evidence names a different transaction"
            }
            Self::DestinationMismatch => "merchant destination does not match",
            Self::AssetMismatch => "merchant output asset does not match",
            Self::AmountMismatch => "merchant output amount does not match",
            Self::VoutMismatch => "merchant output index does not match",
            Self::InsufficientConfirmations => "merchant output has insufficient confirmations",
            Self::IncompleteConfirmationEvidence => {
                "merchant-output confirmation evidence is incomplete"
            }
        })
    }
}

impl std::error::Error for MerchantOutputVerificationError {}

/// Convenience seam for the existing immutable Bitcoin recovery journal.
pub fn verify_bitcoin_recovery_output(
    attempt: &ChainSwapTxAttempt,
    approved_destination: &ApprovedMerchantDestination,
    evidence: &MerchantOutputEvidence,
    required_confirmations: u32,
) -> Result<VerifiedMerchantOutput, MerchantOutputVerificationError> {
    let candidate = JournaledMerchantTransaction::from_bitcoin_recovery_attempt(attempt)?;
    verify_merchant_output(
        &attempt.txid,
        &candidate,
        approved_destination,
        evidence,
        required_confirmations,
    )
}

/// Verifies an original journaled transaction or one explicit replacement
/// row. It performs no database or accounting mutation.
pub fn verify_merchant_output(
    original_journal_txid: &str,
    candidate: &JournaledMerchantTransaction,
    approved_destination: &ApprovedMerchantDestination,
    evidence: &MerchantOutputEvidence,
    required_confirmations: u32,
) -> Result<VerifiedMerchantOutput, MerchantOutputVerificationError> {
    if required_confirmations == 0 {
        return Err(MerchantOutputVerificationError::InvalidConfirmationPolicy);
    }

    let original_journal_txid = canonical_hash(original_journal_txid)
        .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
    let candidate_txid =
        canonical_hash(&candidate.txid).ok_or(MerchantOutputVerificationError::InvalidJournal)?;
    let linked_replacement = match candidate.replaces_txid.as_deref() {
        None if candidate_txid == original_journal_txid => false,
        Some(parent)
            if candidate_txid != original_journal_txid
                && canonical_hash(parent).as_deref() == Some(original_journal_txid.as_str()) =>
        {
            true
        }
        _ => return Err(MerchantOutputVerificationError::UnlinkedTransaction),
    };

    let journal_script = decode_script(&candidate.destination_script_hex)
        .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
    let journal_asset = canonical_asset(&candidate.destination_asset)
        .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
    let derived_journal_script =
        derive_destination_script(&candidate.destination_address, &journal_asset)
            .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
    if journal_script != derived_journal_script {
        return Err(MerchantOutputVerificationError::InvalidJournal);
    }
    let journal_amount = u64::try_from(candidate.destination_amount_sat)
        .ok()
        .filter(|amount| *amount > 0)
        .ok_or(MerchantOutputVerificationError::InvalidJournal)?;
    let journal_vout = u32::try_from(candidate.destination_vout)
        .map_err(|_| MerchantOutputVerificationError::InvalidJournal)?;

    let approved_script = decode_script(&approved_destination.script_pubkey_hex)
        .ok_or(MerchantOutputVerificationError::InvalidApprovedDestination)?;
    let approved_asset = canonical_asset(&approved_destination.asset)
        .ok_or(MerchantOutputVerificationError::InvalidApprovedDestination)?;
    let derived_approved_script =
        derive_destination_script(&approved_destination.address, &approved_asset)
            .ok_or(MerchantOutputVerificationError::InvalidApprovedDestination)?;
    if approved_script != derived_approved_script {
        return Err(MerchantOutputVerificationError::InvalidApprovedDestination);
    }
    if candidate.destination_address != approved_destination.address
        || journal_script != approved_script
    {
        return Err(MerchantOutputVerificationError::DestinationMismatch);
    }
    if journal_asset != approved_asset {
        return Err(MerchantOutputVerificationError::AssetMismatch);
    }

    let MerchantOutputEvidence::Authoritative(observed) = evidence else {
        return Err(MerchantOutputVerificationError::UnknownEvidence);
    };
    let observed_txid =
        canonical_hash(&observed.txid).ok_or(MerchantOutputVerificationError::InvalidEvidence)?;
    if observed_txid != candidate_txid {
        return Err(MerchantOutputVerificationError::EvidenceTransactionMismatch);
    }
    let observed_script = decode_script(&observed.destination_script_hex)
        .ok_or(MerchantOutputVerificationError::InvalidEvidence)?;
    if observed_script != journal_script {
        return Err(MerchantOutputVerificationError::DestinationMismatch);
    }
    let observed_asset =
        canonical_asset(&observed.asset).ok_or(MerchantOutputVerificationError::InvalidEvidence)?;
    if observed_asset != journal_asset {
        return Err(MerchantOutputVerificationError::AssetMismatch);
    }
    if observed.amount_sat != journal_amount {
        return Err(MerchantOutputVerificationError::AmountMismatch);
    }
    if observed.vout != journal_vout {
        return Err(MerchantOutputVerificationError::VoutMismatch);
    }
    if observed.confirmations < required_confirmations {
        return Err(MerchantOutputVerificationError::InsufficientConfirmations);
    }
    let block_height = observed
        .block_height
        .filter(|height| *height > 0)
        .ok_or(MerchantOutputVerificationError::IncompleteConfirmationEvidence)?;
    let block_hash = observed
        .block_hash
        .as_deref()
        .and_then(canonical_hash)
        .ok_or(MerchantOutputVerificationError::IncompleteConfirmationEvidence)?;

    Ok(VerifiedMerchantOutput {
        journal_txid: original_journal_txid,
        txid: candidate_txid,
        destination_address: candidate.destination_address.clone(),
        destination_script_hex: hex::encode(journal_script),
        asset: journal_asset,
        amount_sat: journal_amount,
        vout: journal_vout,
        confirmations: observed.confirmations,
        block_height,
        block_hash,
        linked_replacement,
    })
}

/// Construct Bitcoin journal and observation evidence from bounded raw
/// transactions. When `replacement` is present it must be a complete persisted
/// replacement row whose direct parent is the supplied original journal.
pub fn adapt_bitcoin_merchant_output(
    original: &MerchantTransactionJournalEvidence<'_>,
    replacement: Option<&LinkedReplacementJournalEvidence<'_>>,
    observed: &MerchantTransactionObservation<'_>,
) -> Result<AdaptedMerchantOutputEvidence, MerchantOutputAdapterError> {
    adapt_merchant_output(MerchantRail::Bitcoin, original, replacement, observed, None)
}

/// Construct Liquid journal and observation evidence. Explicit outputs are
/// decoded directly; confidential outputs are accepted only when the supplied
/// merchant blinding key successfully opens the exact raw transaction output.
pub fn adapt_liquid_merchant_output(
    original: &MerchantTransactionJournalEvidence<'_>,
    replacement: Option<&LinkedReplacementJournalEvidence<'_>>,
    observed: &MerchantTransactionObservation<'_>,
    merchant_blinding_key: &elements::secp256k1_zkp::SecretKey,
) -> Result<AdaptedMerchantOutputEvidence, MerchantOutputAdapterError> {
    adapt_merchant_output(
        MerchantRail::Liquid,
        original,
        replacement,
        observed,
        Some(merchant_blinding_key),
    )
}

/// Last durable lifecycle identity for the candidate transaction. A prior
/// confirmed block is fed back into the same-authority snapshot so absence can
/// never be mistaken for a reorg without a canonical replacement anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviousLiquidMerchantConfirmation<'a> {
    NeverObserved,
    Mempool,
    Confirmed {
        block_height: u32,
        block_hash: &'a str,
    },
    /// The lifecycle has already durably applied the demotion for this old
    /// block. The source must keep anchoring it, but must not emit the same
    /// demotion again while it discovers the candidate's new chain position.
    Reorged {
        previous_block_height: u32,
        previous_block_hash: &'a str,
    },
}

/// Production observation delivered to the settlement lifecycle. Positive
/// chain evidence carries the adapter packet that can produce a
/// `VerifiedMerchantOutput`; explicit negative evidence carries only the
/// candidate identity and the prior canonical block needed by the lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiquidMerchantOutputObservation {
    Observed(AdaptedMerchantOutputEvidence),
    Evicted {
        txid: String,
    },
    ReorgDemoted {
        txid: String,
        previous_block_height: u32,
        previous_block_hash: String,
    },
}

/// Fail-closed production-source failures. An incomplete or contradictory
/// backend view is deliberately distinct from positive eviction/reorg proof.
#[derive(Debug)]
pub enum LiquidMerchantObservationError {
    Backend(AppError),
    SnapshotIncomplete,
    InvalidSnapshot,
    CandidateNotObserved,
    InvalidBlindingKey,
    Adapter(MerchantOutputAdapterError),
}

impl fmt::Display for LiquidMerchantObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Backend(_) => "merchant-output Liquid backend observation failed",
            Self::SnapshotIncomplete => "merchant-output Liquid snapshot is incomplete",
            Self::InvalidSnapshot => "merchant-output Liquid snapshot is contradictory",
            Self::CandidateNotObserved => {
                "merchant-output Liquid candidate is not authoritatively observed"
            }
            Self::InvalidBlindingKey => "merchant-output stored Liquid blinding key is invalid",
            Self::Adapter(_) => "merchant-output Liquid adapter rejected chain evidence",
        })
    }
}

impl std::error::Error for LiquidMerchantObservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Adapter(error) => Some(error),
            _ => None,
        }
    }
}

const LIQUID_MERCHANT_OBSERVATION_LIMITS: LiquidHistorySnapshotLimits =
    LiquidHistorySnapshotLimits {
        max_history_entries: MAX_MERCHANT_OUTPUT_TRANSACTION_ITEMS,
        max_block_heights: MAX_MERCHANT_OUTPUT_TRANSACTION_ITEMS,
    };

/// Fetch one same-authority Liquid history/tip/block snapshot plus the exact
/// raw candidate transaction and construct the adapter evidence consumed by
/// the merchant-settlement lifecycle. This is the production vertical entry
/// point: callers do not manufacture `MerchantTransactionObservation` from
/// provider hints.
pub async fn observe_liquid_merchant_output<B: UtxoBackend + ?Sized>(
    backend: &B,
    original: &MerchantTransactionJournalEvidence<'_>,
    replacement: Option<&LinkedReplacementJournalEvidence<'_>>,
    stored_blinding_key_hex: &str,
    previous: PreviousLiquidMerchantConfirmation<'_>,
) -> Result<LiquidMerchantOutputObservation, LiquidMerchantObservationError> {
    let candidate = replacement
        .map(|linked| &linked.replacement)
        .unwrap_or(original);
    let candidate_txid = canonical_hash(candidate.txid).ok_or(
        LiquidMerchantObservationError::Adapter(MerchantOutputAdapterError::JournalTxidMismatch),
    )?;
    let candidate_script = validate_output_commitment(&candidate.merchant)
        .map_err(LiquidMerchantObservationError::Adapter)?;
    if !matches!(candidate.merchant.asset, MerchantAsset::Liquid(_)) {
        return Err(LiquidMerchantObservationError::Adapter(
            MerchantOutputAdapterError::InvalidCommitment,
        ));
    }
    let blinding_key = elements::secp256k1_zkp::SecretKey::from_str(stored_blinding_key_hex)
        .map_err(|_| LiquidMerchantObservationError::InvalidBlindingKey)?;
    let script = elements::Script::from(candidate_script);
    let previous_block = previous_liquid_block(previous)?;
    let prior_block_heights = previous_block
        .as_ref()
        .map(|block| vec![block.height])
        .unwrap_or_default();
    let snapshot = match backend
        .liquid_history_snapshot(
            &script,
            &prior_block_heights,
            LIQUID_MERCHANT_OBSERVATION_LIMITS,
        )
        .await
        .map_err(LiquidMerchantObservationError::Backend)?
    {
        LiquidHistorySnapshotOutcome::Complete(snapshot) => snapshot,
        LiquidHistorySnapshotOutcome::Incomplete(_) => {
            return Err(LiquidMerchantObservationError::SnapshotIncomplete);
        }
    };
    validate_liquid_snapshot_shape(&snapshot)?;

    let prior_anchor_status = previous_block
        .as_ref()
        .map(|block| prior_liquid_anchor_status(&snapshot, block.height, &block.hash))
        .transpose()?;
    if let Some(block) = previous_block.as_ref() {
        match (block.already_reorged, prior_anchor_status) {
            (false, Some(PriorLiquidAnchorStatus::Reorged)) => {
                return Ok(LiquidMerchantOutputObservation::ReorgDemoted {
                    txid: candidate_txid,
                    previous_block_height: block.public_height,
                    previous_block_hash: block.hash.clone(),
                });
            }
            (true, Some(PriorLiquidAnchorStatus::Reorged))
            | (false, Some(PriorLiquidAnchorStatus::Canonical)) => {}
            // A previously demoted block becoming canonical again is a new
            // contradictory view, never permission to replay old authority.
            (true, Some(PriorLiquidAnchorStatus::Canonical))
            | (_, Some(PriorLiquidAnchorStatus::Unavailable))
            | (_, None) => return Err(LiquidMerchantObservationError::InvalidSnapshot),
        }
    }

    let mut entries = snapshot
        .entries
        .iter()
        .filter(|entry| entry.txid.eq_ignore_ascii_case(&candidate_txid));
    let entry = entries.next();
    if entries.next().is_some() {
        return Err(LiquidMerchantObservationError::InvalidSnapshot);
    }
    let Some(entry) = entry else {
        return match previous {
            PreviousLiquidMerchantConfirmation::Mempool => {
                Ok(LiquidMerchantOutputObservation::Evicted {
                    txid: candidate_txid,
                })
            }
            PreviousLiquidMerchantConfirmation::NeverObserved
            | PreviousLiquidMerchantConfirmation::Confirmed { .. }
            | PreviousLiquidMerchantConfirmation::Reorged { .. } => {
                Err(LiquidMerchantObservationError::CandidateNotObserved)
            }
        };
    };

    if let Some(block) = previous_block.as_ref() {
        let matches_old_block = entry_matches_previous_block(entry, block);
        if (!block.already_reorged && !matches_old_block)
            || (block.already_reorged && matches_old_block)
        {
            return Err(LiquidMerchantObservationError::InvalidSnapshot);
        }
    }
    let confirmation = liquid_confirmation_from_snapshot(entry, &snapshot)?;
    let raw_transaction = backend
        .get_raw_tx(&candidate_txid)
        .await
        .map_err(LiquidMerchantObservationError::Backend)?;
    let observation = MerchantTransactionObservation {
        raw_transaction: &raw_transaction,
        txid: &candidate_txid,
        confirmation,
    };
    let adapted = adapt_liquid_merchant_output(original, replacement, &observation, &blinding_key)
        .map_err(LiquidMerchantObservationError::Adapter)?;
    Ok(LiquidMerchantOutputObservation::Observed(adapted))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PriorLiquidAnchorStatus {
    Canonical,
    Reorged,
    Unavailable,
}

struct PreviousLiquidBlock {
    height: i32,
    hash: String,
    public_height: u32,
    already_reorged: bool,
}

fn previous_liquid_block(
    previous: PreviousLiquidMerchantConfirmation<'_>,
) -> Result<Option<PreviousLiquidBlock>, LiquidMerchantObservationError> {
    let (block_height, block_hash, already_reorged) = match previous {
        PreviousLiquidMerchantConfirmation::NeverObserved
        | PreviousLiquidMerchantConfirmation::Mempool => return Ok(None),
        PreviousLiquidMerchantConfirmation::Confirmed {
            block_height,
            block_hash,
        } => (block_height, block_hash, false),
        PreviousLiquidMerchantConfirmation::Reorged {
            previous_block_height,
            previous_block_hash,
        } => (previous_block_height, previous_block_hash, true),
    };
    let height = i32::try_from(block_height)
        .ok()
        .filter(|height| *height > 0)
        .ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
    let hash = canonical_hash(block_hash).ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
    Ok(Some(PreviousLiquidBlock {
        height,
        hash,
        public_height: block_height,
        already_reorged,
    }))
}

fn validate_liquid_snapshot_shape(
    snapshot: &LiquidHistorySnapshot,
) -> Result<(), LiquidMerchantObservationError> {
    if snapshot.tip_height <= 0
        || snapshot.authority.is_empty()
        || snapshot.authority.len() > 200
        || snapshot.authority.chars().any(char::is_whitespace)
        || snapshot.entries.len() > LIQUID_MERCHANT_OBSERVATION_LIMITS.max_history_entries
        || snapshot.anchored_block_hashes.len()
            > LIQUID_MERCHANT_OBSERVATION_LIMITS.max_block_heights
    {
        return Err(LiquidMerchantObservationError::InvalidSnapshot);
    }
    let mut seen_txids = std::collections::BTreeSet::new();
    for entry in &snapshot.entries {
        let txid =
            canonical_hash(&entry.txid).ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
        if !seen_txids.insert(txid) || entry.height > snapshot.tip_height {
            return Err(LiquidMerchantObservationError::InvalidSnapshot);
        }
        if entry.height <= 0 {
            if entry.block_hash.is_some() {
                return Err(LiquidMerchantObservationError::InvalidSnapshot);
            }
            continue;
        }
        let entry_hash = entry
            .block_hash
            .as_deref()
            .and_then(canonical_hash)
            .ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
        let anchor_hash = snapshot
            .anchored_block_hashes
            .get(&entry.height)
            .and_then(|hash| canonical_hash(hash))
            .ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
        if entry_hash != anchor_hash {
            return Err(LiquidMerchantObservationError::InvalidSnapshot);
        }
    }
    for (height, hash) in &snapshot.anchored_block_hashes {
        if *height <= 0 || *height > snapshot.tip_height || canonical_hash(hash).is_none() {
            return Err(LiquidMerchantObservationError::InvalidSnapshot);
        }
    }
    Ok(())
}

fn prior_liquid_anchor_status(
    snapshot: &LiquidHistorySnapshot,
    height: i32,
    previous_hash: &str,
) -> Result<PriorLiquidAnchorStatus, LiquidMerchantObservationError> {
    if height > snapshot.tip_height {
        return Ok(PriorLiquidAnchorStatus::Unavailable);
    }
    let Some(current_hash) = snapshot.anchored_block_hashes.get(&height) else {
        return Ok(PriorLiquidAnchorStatus::Unavailable);
    };
    let current_hash =
        canonical_hash(current_hash).ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
    Ok(if current_hash == previous_hash {
        PriorLiquidAnchorStatus::Canonical
    } else {
        PriorLiquidAnchorStatus::Reorged
    })
}

fn entry_matches_previous_block(
    entry: &LiquidHistoryEntry,
    previous_block: &PreviousLiquidBlock,
) -> bool {
    entry.height == previous_block.height
        && entry
            .block_hash
            .as_deref()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&previous_block.hash))
}

fn liquid_confirmation_from_snapshot<'a>(
    entry: &'a LiquidHistoryEntry,
    snapshot: &'a LiquidHistorySnapshot,
) -> Result<MerchantConfirmationEvidence<'a>, LiquidMerchantObservationError> {
    if entry.height <= 0 {
        if entry.block_hash.is_some() {
            return Err(LiquidMerchantObservationError::InvalidSnapshot);
        }
        return Ok(MerchantConfirmationEvidence::Mempool);
    }
    if entry.height > snapshot.tip_height {
        return Err(LiquidMerchantObservationError::InvalidSnapshot);
    }
    let block_hash_text = entry
        .block_hash
        .as_deref()
        .ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
    let block_hash =
        canonical_hash(block_hash_text).ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
    let anchored_hash = snapshot
        .anchored_block_hashes
        .get(&entry.height)
        .and_then(|hash| canonical_hash(hash))
        .ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
    if block_hash != anchored_hash {
        return Err(LiquidMerchantObservationError::InvalidSnapshot);
    }
    let confirmations = snapshot
        .tip_height
        .checked_sub(entry.height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|confirmations| u32::try_from(confirmations).ok())
        .ok_or(LiquidMerchantObservationError::InvalidSnapshot)?;
    let block_height =
        u32::try_from(entry.height).map_err(|_| LiquidMerchantObservationError::InvalidSnapshot)?;
    Ok(MerchantConfirmationEvidence::Confirmed {
        confirmations,
        block_height,
        block_hash: block_hash_text,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviousBitcoinMerchantConfirmation<'a> {
    NeverObserved,
    Mempool,
    Confirmed {
        block_height: u32,
        block_hash: &'a str,
    },
    Reorged {
        previous_block_height: u32,
        previous_block_hash: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinMerchantOutputObservation {
    Observed(AdaptedMerchantOutputEvidence),
    Evicted {
        txid: String,
    },
    ReorgDemoted {
        txid: String,
        previous_block_height: u32,
        previous_block_hash: String,
    },
}

#[derive(Debug)]
pub enum BitcoinMerchantObservationError {
    Backend(AppError),
    InvalidSnapshot,
    CandidateNotObserved,
    Journal(MerchantOutputVerificationError),
    Adapter(MerchantOutputAdapterError),
}

impl fmt::Display for BitcoinMerchantObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Backend(_) => "merchant-output Bitcoin backend observation failed",
            Self::InvalidSnapshot => "merchant-output Bitcoin snapshot is contradictory",
            Self::CandidateNotObserved => {
                "merchant-output Bitcoin candidate is not authoritatively observed"
            }
            Self::Journal(_) => "merchant-output Bitcoin journal is invalid",
            Self::Adapter(_) => "merchant-output Bitcoin adapter rejected chain evidence",
        })
    }
}

impl std::error::Error for BitcoinMerchantObservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Adapter(error) => Some(error),
            _ => None,
        }
    }
}

/// Observe the immutable Bitcoin recovery journal through the anchored
/// `BitcoinRecoveryEvidence` contract and return the exact adapter packet used
/// by the settlement lifecycle. Confirmation depth is reported, not promoted
/// to finality here: accounting starts at one confirmation and the lifecycle's
/// Bitcoin policy decides the three-confirmation finalization boundary.
pub async fn observe_bitcoin_recovery_merchant_output(
    evidence: &dyn BitcoinRecoveryEvidence,
    attempt: &ChainSwapTxAttempt,
    replacement: Option<&LinkedReplacementJournalEvidence<'_>>,
    previous: PreviousBitcoinMerchantConfirmation<'_>,
) -> Result<BitcoinMerchantOutputObservation, BitcoinMerchantObservationError> {
    JournaledMerchantTransaction::from_bitcoin_recovery_attempt(attempt)
        .map_err(BitcoinMerchantObservationError::Journal)?;
    let raw_transaction = hex::decode(&attempt.raw_tx_hex).map_err(|_| {
        BitcoinMerchantObservationError::Journal(MerchantOutputVerificationError::InvalidJournal)
    })?;
    let source_prevouts = attempt
        .source_prevouts
        .iter()
        .map(|source| MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat,
            script_pubkey_hex: &source.script_pubkey_hex,
        })
        .collect::<Vec<_>>();
    let amount_sat = u64::try_from(attempt.destination_amount_sat).map_err(|_| {
        BitcoinMerchantObservationError::Journal(MerchantOutputVerificationError::InvalidJournal)
    })?;
    let vout = u32::try_from(attempt.destination_vout).map_err(|_| {
        BitcoinMerchantObservationError::Journal(MerchantOutputVerificationError::InvalidJournal)
    })?;
    let asset = MerchantAsset::Bitcoin;
    let original = MerchantTransactionJournalEvidence {
        raw_transaction: &raw_transaction,
        txid: &attempt.txid,
        source_prevouts: &source_prevouts,
        merchant: MerchantOutputCommitment {
            destination_address: &attempt.destination_address,
            destination_script_hex: &attempt.destination_script_hex,
            asset: &asset,
            amount_sat,
            vout,
        },
    };
    let candidate = replacement
        .map(|linked| &linked.replacement)
        .unwrap_or(&original);
    let candidate_txid = canonical_hash(candidate.txid).ok_or(
        BitcoinMerchantObservationError::Adapter(MerchantOutputAdapterError::JournalTxidMismatch),
    )?;
    let previous_block = previous_bitcoin_block(previous)?;
    let snapshot = evidence
        .status_snapshot(
            &candidate_txid,
            previous_block.as_ref().map(|block| block.height),
        )
        .await
        .map_err(BitcoinMerchantObservationError::Backend)?;
    validate_bitcoin_snapshot(&snapshot)?;
    if previous_block.is_none() && snapshot.prior_block_hash.is_some() {
        return Err(BitcoinMerchantObservationError::InvalidSnapshot);
    }

    if let Some(block) = previous_block.as_ref() {
        let anchor_reorged = match snapshot
            .prior_block_hash
            .as_deref()
            .map(|hash| {
                canonical_hash(hash).ok_or(BitcoinMerchantObservationError::InvalidSnapshot)
            })
            .transpose()?
        {
            Some(current_anchor) => current_anchor != block.hash,
            None if block.height > snapshot.tip_height => true,
            None => return Err(BitcoinMerchantObservationError::InvalidSnapshot),
        };
        match (block.already_reorged, anchor_reorged) {
            (false, true) => {
                return Ok(BitcoinMerchantOutputObservation::ReorgDemoted {
                    txid: candidate_txid,
                    previous_block_height: block.height,
                    previous_block_hash: block.hash.clone(),
                });
            }
            (true, true) | (false, false) => {}
            (true, false) => return Err(BitcoinMerchantObservationError::InvalidSnapshot),
        }
    }

    let confirmation = match &snapshot.status {
        BitcoinRecoveryTransactionStatus::Absent => {
            return match previous {
                PreviousBitcoinMerchantConfirmation::Mempool => {
                    Ok(BitcoinMerchantOutputObservation::Evicted {
                        txid: candidate_txid,
                    })
                }
                PreviousBitcoinMerchantConfirmation::NeverObserved
                | PreviousBitcoinMerchantConfirmation::Confirmed { .. }
                | PreviousBitcoinMerchantConfirmation::Reorged { .. } => {
                    Err(BitcoinMerchantObservationError::CandidateNotObserved)
                }
            };
        }
        BitcoinRecoveryTransactionStatus::Mempool => {
            if previous_block
                .as_ref()
                .is_some_and(|block| !block.already_reorged)
            {
                return Err(BitcoinMerchantObservationError::InvalidSnapshot);
            }
            MerchantConfirmationEvidence::Mempool
        }
        BitcoinRecoveryTransactionStatus::Confirmed {
            block_height,
            block_hash,
        } => {
            let confirmations = snapshot
                .tip_height
                .checked_sub(*block_height)
                .and_then(|distance| distance.checked_add(1))
                .ok_or(BitcoinMerchantObservationError::InvalidSnapshot)?;
            if let Some(block) = previous_block.as_ref() {
                let matches_old =
                    *block_height == block.height && block_hash.eq_ignore_ascii_case(&block.hash);
                if (!block.already_reorged && !matches_old)
                    || (block.already_reorged && matches_old)
                {
                    return Err(BitcoinMerchantObservationError::InvalidSnapshot);
                }
            }
            MerchantConfirmationEvidence::Confirmed {
                confirmations,
                block_height: *block_height,
                block_hash,
            }
        }
    };
    let observed_raw = evidence
        .raw_transaction(&candidate_txid)
        .await
        .map_err(BitcoinMerchantObservationError::Backend)?
        .ok_or(BitcoinMerchantObservationError::CandidateNotObserved)?;
    let observation = MerchantTransactionObservation {
        raw_transaction: &observed_raw,
        txid: &candidate_txid,
        confirmation,
    };
    let adapted = adapt_bitcoin_merchant_output(&original, replacement, &observation)
        .map_err(BitcoinMerchantObservationError::Adapter)?;
    Ok(BitcoinMerchantOutputObservation::Observed(adapted))
}

struct PreviousBitcoinBlock {
    height: u32,
    hash: String,
    already_reorged: bool,
}

fn previous_bitcoin_block(
    previous: PreviousBitcoinMerchantConfirmation<'_>,
) -> Result<Option<PreviousBitcoinBlock>, BitcoinMerchantObservationError> {
    let (height, hash, already_reorged) = match previous {
        PreviousBitcoinMerchantConfirmation::NeverObserved
        | PreviousBitcoinMerchantConfirmation::Mempool => return Ok(None),
        PreviousBitcoinMerchantConfirmation::Confirmed {
            block_height,
            block_hash,
        } => (block_height, block_hash, false),
        PreviousBitcoinMerchantConfirmation::Reorged {
            previous_block_height,
            previous_block_hash,
        } => (previous_block_height, previous_block_hash, true),
    };
    if height == 0 {
        return Err(BitcoinMerchantObservationError::InvalidSnapshot);
    }
    let hash = canonical_hash(hash).ok_or(BitcoinMerchantObservationError::InvalidSnapshot)?;
    Ok(Some(PreviousBitcoinBlock {
        height,
        hash,
        already_reorged,
    }))
}

fn validate_bitcoin_snapshot(
    snapshot: &BitcoinRecoveryStatusSnapshot,
) -> Result<(), BitcoinMerchantObservationError> {
    if snapshot.tip_height == 0 {
        return Err(BitcoinMerchantObservationError::InvalidSnapshot);
    }
    if let Some(hash) = &snapshot.prior_block_hash {
        if canonical_hash(hash).is_none() {
            return Err(BitcoinMerchantObservationError::InvalidSnapshot);
        }
    }
    match &snapshot.status {
        BitcoinRecoveryTransactionStatus::Absent | BitcoinRecoveryTransactionStatus::Mempool => {}
        BitcoinRecoveryTransactionStatus::Confirmed {
            block_height,
            block_hash,
        } => {
            if *block_height == 0
                || *block_height > snapshot.tip_height
                || canonical_hash(block_hash).is_none()
            {
                return Err(BitcoinMerchantObservationError::InvalidSnapshot);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum MerchantRail {
    Bitcoin,
    Liquid,
}

#[derive(Clone)]
struct ValidatedJournal {
    txid: String,
    destination_address: String,
    destination_script: Vec<u8>,
    asset: MerchantAsset,
    amount_sat: u64,
    vout: u32,
}

fn adapt_merchant_output(
    rail: MerchantRail,
    original: &MerchantTransactionJournalEvidence<'_>,
    replacement: Option<&LinkedReplacementJournalEvidence<'_>>,
    observed: &MerchantTransactionObservation<'_>,
    merchant_blinding_key: Option<&elements::secp256k1_zkp::SecretKey>,
) -> Result<AdaptedMerchantOutputEvidence, MerchantOutputAdapterError> {
    let original_validated = validate_journal(rail, original, merchant_blinding_key)?;
    let (candidate_validated, linked_replacement) = if let Some(linked) = replacement {
        let replaces_txid = canonical_hash(linked.replaces_txid)
            .ok_or(MerchantOutputAdapterError::InvalidReplacementLink)?;
        if replaces_txid != original_validated.txid {
            return Err(MerchantOutputAdapterError::InvalidReplacementLink);
        }
        let replacement_validated =
            validate_journal(rail, &linked.replacement, merchant_blinding_key)?;
        if replacement_validated.txid == original_validated.txid {
            return Err(MerchantOutputAdapterError::InvalidReplacementLink);
        }
        if !source_evidence_sets_match(original.source_prevouts, linked.replacement.source_prevouts)
        {
            return Err(MerchantOutputAdapterError::ReplacementSourceMismatch);
        }
        if replacement_validated.destination_address != original_validated.destination_address
            || replacement_validated.destination_script != original_validated.destination_script
            || replacement_validated.asset != original_validated.asset
        {
            return Err(MerchantOutputAdapterError::ReplacementDestinationMismatch);
        }
        (replacement_validated, true)
    } else {
        (original_validated.clone(), false)
    };

    let observed_transaction = decode_merchant_transaction(
        rail,
        observed.raw_transaction,
        MerchantTransactionRole::Observed,
    )?;
    let observed_txid =
        canonical_hash(observed.txid).ok_or(MerchantOutputAdapterError::ObservedTxidMismatch)?;
    if observed_transaction.txid() != observed_txid {
        return Err(MerchantOutputAdapterError::ObservedTxidMismatch);
    }
    if observed_txid != candidate_validated.txid {
        return Err(if replacement.is_none() {
            MerchantOutputAdapterError::UnlinkedObservedTransaction
        } else {
            MerchantOutputAdapterError::ObservedTxidMismatch
        });
    }
    if !observed_transaction.inputs_match(original.source_prevouts) {
        return Err(MerchantOutputAdapterError::ObservedSourceMismatch);
    }

    let observed_output = observed_transaction.unique_output_for_script(
        &candidate_validated.destination_script,
        merchant_blinding_key,
    )?;
    let (confirmations, block_height, block_hash) = adapt_confirmation(observed.confirmation)?;

    let destination_amount_sat = i64::try_from(candidate_validated.amount_sat)
        .map_err(|_| MerchantOutputAdapterError::InvalidCommitment)?;
    let destination_vout = i32::try_from(candidate_validated.vout)
        .map_err(|_| MerchantOutputAdapterError::InvalidCommitment)?;
    let journal = if linked_replacement {
        JournaledMerchantTransaction::linked_replacement(
            &candidate_validated.txid,
            &original_validated.txid,
            &candidate_validated.destination_address,
            hex::encode(&candidate_validated.destination_script),
            candidate_validated.asset.clone(),
            destination_amount_sat,
            destination_vout,
        )
    } else {
        JournaledMerchantTransaction::original(
            &candidate_validated.txid,
            &candidate_validated.destination_address,
            hex::encode(&candidate_validated.destination_script),
            candidate_validated.asset.clone(),
            destination_amount_sat,
            destination_vout,
        )
    };
    let evidence = MerchantOutputEvidence::Authoritative(ObservedMerchantOutput::new(
        observed_txid,
        hex::encode(&observed_output.script),
        observed_output.asset,
        observed_output.amount_sat,
        observed_output.vout,
        confirmations,
        block_height,
        block_hash,
    ));

    Ok(AdaptedMerchantOutputEvidence {
        original_journal_txid: original_validated.txid,
        journal,
        evidence,
    })
}

fn validate_journal(
    rail: MerchantRail,
    journal: &MerchantTransactionJournalEvidence<'_>,
    merchant_blinding_key: Option<&elements::secp256k1_zkp::SecretKey>,
) -> Result<ValidatedJournal, MerchantOutputAdapterError> {
    validate_source_prevouts(journal.source_prevouts)?;
    let destination_script = validate_output_commitment(&journal.merchant)?;
    let asset = canonical_asset(journal.merchant.asset)
        .ok_or(MerchantOutputAdapterError::InvalidCommitment)?;
    match (rail, &asset) {
        (MerchantRail::Bitcoin, MerchantAsset::Bitcoin)
        | (MerchantRail::Liquid, MerchantAsset::Liquid(_)) => {}
        _ => return Err(MerchantOutputAdapterError::InvalidCommitment),
    }
    if matches!(rail, MerchantRail::Liquid) {
        let blinding_key = merchant_blinding_key
            .ok_or(MerchantOutputAdapterError::ConfidentialOutputUnverified)?;
        let address = LiquidAddress::from_str(journal.merchant.destination_address)
            .map_err(|_| MerchantOutputAdapterError::InvalidCommitment)?;
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let blinding_pubkey =
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, blinding_key);
        if address.blinding_pubkey != Some(blinding_pubkey) {
            return Err(MerchantOutputAdapterError::ConfidentialOutputUnverified);
        }
    }
    let txid =
        canonical_hash(journal.txid).ok_or(MerchantOutputAdapterError::JournalTxidMismatch)?;
    let transaction = decode_merchant_transaction(
        rail,
        journal.raw_transaction,
        MerchantTransactionRole::Journal,
    )?;
    if transaction.txid() != txid {
        return Err(MerchantOutputAdapterError::JournalTxidMismatch);
    }
    if !transaction.inputs_match(journal.source_prevouts) {
        return Err(MerchantOutputAdapterError::JournalSourceMismatch);
    }
    let output = transaction
        .output_at(journal.merchant.vout, merchant_blinding_key)?
        .ok_or(MerchantOutputAdapterError::JournalOutputMismatch)?;
    if output.script != destination_script
        || output.asset != asset
        || output.amount_sat != journal.merchant.amount_sat
    {
        return Err(MerchantOutputAdapterError::JournalOutputMismatch);
    }

    Ok(ValidatedJournal {
        txid,
        destination_address: journal.merchant.destination_address.to_owned(),
        destination_script,
        asset,
        amount_sat: journal.merchant.amount_sat,
        vout: journal.merchant.vout,
    })
}

fn validate_output_commitment(
    commitment: &MerchantOutputCommitment<'_>,
) -> Result<Vec<u8>, MerchantOutputAdapterError> {
    if commitment.amount_sat == 0
        || commitment.amount_sat > i64::MAX as u64
        || commitment.vout > i32::MAX as u32
    {
        return Err(MerchantOutputAdapterError::InvalidCommitment);
    }
    let asset =
        canonical_asset(commitment.asset).ok_or(MerchantOutputAdapterError::InvalidCommitment)?;
    let script = decode_bounded_script(commitment.destination_script_hex).map_err(|exceeded| {
        if exceeded {
            MerchantOutputAdapterError::InputBoundsExceeded
        } else {
            MerchantOutputAdapterError::InvalidCommitment
        }
    })?;
    let derived = derive_destination_script(commitment.destination_address, &asset)
        .ok_or(MerchantOutputAdapterError::InvalidCommitment)?;
    if script != derived {
        return Err(MerchantOutputAdapterError::InvalidCommitment);
    }
    Ok(script)
}

fn validate_source_prevouts(
    sources: &[MerchantSourcePrevout<'_>],
) -> Result<(), MerchantOutputAdapterError> {
    if sources.is_empty() || sources.len() > MAX_MERCHANT_OUTPUT_SOURCE_PREVOUTS {
        return Err(MerchantOutputAdapterError::InputBoundsExceeded);
    }
    for (index, source) in sources.iter().enumerate() {
        if canonical_hash(source.txid).is_none() || source.amount_sat == 0 {
            return Err(MerchantOutputAdapterError::InvalidSourcePrevouts);
        }
        decode_bounded_script(source.script_pubkey_hex).map_err(|exceeded| {
            if exceeded {
                MerchantOutputAdapterError::InputBoundsExceeded
            } else {
                MerchantOutputAdapterError::InvalidSourcePrevouts
            }
        })?;
        if sources[..index]
            .iter()
            .any(|prior| prior.txid.eq_ignore_ascii_case(source.txid) && prior.vout == source.vout)
        {
            return Err(MerchantOutputAdapterError::InvalidSourcePrevouts);
        }
    }
    Ok(())
}

fn source_evidence_sets_match(
    left: &[MerchantSourcePrevout<'_>],
    right: &[MerchantSourcePrevout<'_>],
) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let canonical = |source: &MerchantSourcePrevout<'_>| {
        (
            source.txid.to_ascii_lowercase(),
            source.vout,
            source.amount_sat,
            source.script_pubkey_hex.to_ascii_lowercase(),
        )
    };
    let mut left = left.iter().map(canonical).collect::<Vec<_>>();
    let mut right = right.iter().map(canonical).collect::<Vec<_>>();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

fn adapt_confirmation(
    confirmation: MerchantConfirmationEvidence<'_>,
) -> Result<(u32, Option<u32>, Option<String>), MerchantOutputAdapterError> {
    match confirmation {
        MerchantConfirmationEvidence::Mempool => Ok((0, None, None)),
        MerchantConfirmationEvidence::Confirmed {
            confirmations,
            block_height,
            block_hash,
        } => {
            if confirmations == 0 || block_height == 0 {
                return Err(MerchantOutputAdapterError::IncompleteConfirmationIdentity);
            }
            let block_hash = canonical_hash(block_hash)
                .ok_or(MerchantOutputAdapterError::IncompleteConfirmationIdentity)?;
            Ok((confirmations, Some(block_height), Some(block_hash)))
        }
        MerchantConfirmationEvidence::Evicted | MerchantConfirmationEvidence::ReorgDemoted => {
            Err(MerchantOutputAdapterError::ObservationDemoted)
        }
    }
}

#[derive(Clone, Copy)]
enum MerchantTransactionRole {
    Journal,
    Observed,
}

enum DecodedMerchantTransaction {
    Bitcoin(Transaction),
    Liquid(elements::Transaction),
}

struct DecodedMerchantOutput {
    script: Vec<u8>,
    asset: MerchantAsset,
    amount_sat: u64,
    vout: u32,
}

impl DecodedMerchantTransaction {
    fn txid(&self) -> String {
        match self {
            Self::Bitcoin(transaction) => transaction.compute_txid().to_string(),
            Self::Liquid(transaction) => transaction.txid().to_string(),
        }
    }

    fn inputs_match(&self, sources: &[MerchantSourcePrevout<'_>]) -> bool {
        let observed = match self {
            Self::Bitcoin(transaction) => transaction
                .input
                .iter()
                .map(|input| {
                    (
                        false,
                        input.previous_output.txid.to_string(),
                        input.previous_output.vout,
                    )
                })
                .collect(),
            Self::Liquid(transaction) => transaction
                .input
                .iter()
                .map(|input| {
                    (
                        input.is_pegin,
                        input.previous_output.txid.to_string(),
                        input.previous_output.vout,
                    )
                })
                .collect(),
        };
        exact_outpoint_set_matches(observed, sources)
    }

    fn output_at(
        &self,
        vout: u32,
        merchant_blinding_key: Option<&elements::secp256k1_zkp::SecretKey>,
    ) -> Result<Option<DecodedMerchantOutput>, MerchantOutputAdapterError> {
        let index =
            usize::try_from(vout).map_err(|_| MerchantOutputAdapterError::InvalidCommitment)?;
        match self {
            Self::Bitcoin(transaction) => transaction
                .output
                .get(index)
                .map(|output| decode_bitcoin_output(output, vout))
                .transpose(),
            Self::Liquid(transaction) => transaction
                .output
                .get(index)
                .map(|output| decode_liquid_output(output, vout, merchant_blinding_key))
                .transpose(),
        }
    }

    fn unique_output_for_script(
        &self,
        expected_script: &[u8],
        merchant_blinding_key: Option<&elements::secp256k1_zkp::SecretKey>,
    ) -> Result<DecodedMerchantOutput, MerchantOutputAdapterError> {
        let matching_indices = match self {
            Self::Bitcoin(transaction) => transaction
                .output
                .iter()
                .enumerate()
                .filter(|(_, output)| output.script_pubkey.as_bytes() == expected_script)
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
            Self::Liquid(transaction) => transaction
                .output
                .iter()
                .enumerate()
                .filter(|(_, output)| output.script_pubkey.as_bytes() == expected_script)
                .map(|(index, _)| index)
                .collect::<Vec<_>>(),
        };
        let [index] = matching_indices.as_slice() else {
            return Err(if matching_indices.is_empty() {
                MerchantOutputAdapterError::ObservedOutputMissing
            } else {
                MerchantOutputAdapterError::MultipleObservedOutputs
            });
        };
        let vout =
            u32::try_from(*index).map_err(|_| MerchantOutputAdapterError::InputBoundsExceeded)?;
        self.output_at(vout, merchant_blinding_key)?
            .ok_or(MerchantOutputAdapterError::ObservedOutputMissing)
    }
}

fn decode_merchant_transaction(
    rail: MerchantRail,
    raw_transaction: &[u8],
    role: MerchantTransactionRole,
) -> Result<DecodedMerchantTransaction, MerchantOutputAdapterError> {
    if raw_transaction.is_empty() {
        return Err(malformed_transaction(role));
    }
    if raw_transaction.len() > MAX_MERCHANT_OUTPUT_RAW_TRANSACTION_BYTES {
        return Err(MerchantOutputAdapterError::InputBoundsExceeded);
    }
    let transaction = match rail {
        MerchantRail::Bitcoin => DecodedMerchantTransaction::Bitcoin(
            deserialize(raw_transaction).map_err(|_| malformed_transaction(role))?,
        ),
        MerchantRail::Liquid => DecodedMerchantTransaction::Liquid(
            elements::encode::deserialize(raw_transaction)
                .map_err(|_| malformed_transaction(role))?,
        ),
    };
    let (inputs, outputs) = match &transaction {
        DecodedMerchantTransaction::Bitcoin(transaction) => {
            (transaction.input.len(), transaction.output.len())
        }
        DecodedMerchantTransaction::Liquid(transaction) => {
            (transaction.input.len(), transaction.output.len())
        }
    };
    if inputs == 0
        || outputs == 0
        || inputs > MAX_MERCHANT_OUTPUT_TRANSACTION_ITEMS
        || outputs > MAX_MERCHANT_OUTPUT_TRANSACTION_ITEMS
    {
        return Err(MerchantOutputAdapterError::InputBoundsExceeded);
    }
    Ok(transaction)
}

fn malformed_transaction(role: MerchantTransactionRole) -> MerchantOutputAdapterError {
    match role {
        MerchantTransactionRole::Journal => MerchantOutputAdapterError::MalformedJournalTransaction,
        MerchantTransactionRole::Observed => {
            MerchantOutputAdapterError::MalformedObservedTransaction
        }
    }
}

fn exact_outpoint_set_matches(
    mut observed: Vec<(bool, String, u32)>,
    sources: &[MerchantSourcePrevout<'_>],
) -> bool {
    if observed.len() != sources.len() {
        return false;
    }
    let mut expected = sources
        .iter()
        .map(|source| (false, source.txid.to_ascii_lowercase(), source.vout))
        .collect::<Vec<_>>();
    for (_, txid, _) in &mut observed {
        txid.make_ascii_lowercase();
    }
    observed.sort_unstable();
    expected.sort_unstable();
    observed == expected
}

fn decode_bitcoin_output(
    output: &bitcoin::TxOut,
    vout: u32,
) -> Result<DecodedMerchantOutput, MerchantOutputAdapterError> {
    if output.script_pubkey.len() > MAX_MERCHANT_OUTPUT_SCRIPT_BYTES {
        return Err(MerchantOutputAdapterError::InputBoundsExceeded);
    }
    Ok(DecodedMerchantOutput {
        script: output.script_pubkey.as_bytes().to_vec(),
        asset: MerchantAsset::Bitcoin,
        amount_sat: output.value.to_sat(),
        vout,
    })
}

fn decode_liquid_output(
    output: &elements::TxOut,
    vout: u32,
    merchant_blinding_key: Option<&elements::secp256k1_zkp::SecretKey>,
) -> Result<DecodedMerchantOutput, MerchantOutputAdapterError> {
    if output.script_pubkey.len() > MAX_MERCHANT_OUTPUT_SCRIPT_BYTES {
        return Err(MerchantOutputAdapterError::InputBoundsExceeded);
    }
    let (asset, amount_sat) = match (output.asset.explicit(), output.value.explicit()) {
        (Some(asset), Some(value)) => (asset, value),
        (None, None) => {
            let key = merchant_blinding_key
                .ok_or(MerchantOutputAdapterError::ConfidentialOutputUnverified)?;
            let secp = elements::secp256k1_zkp::Secp256k1::new();
            let secrets = output
                .unblind(&secp, *key)
                .map_err(|_| MerchantOutputAdapterError::ConfidentialOutputUnverified)?;
            (secrets.asset, secrets.value)
        }
        _ => return Err(MerchantOutputAdapterError::ConfidentialOutputUnverified),
    };
    Ok(DecodedMerchantOutput {
        script: output.script_pubkey.as_bytes().to_vec(),
        asset: MerchantAsset::Liquid(asset.to_string()),
        amount_sat,
        vout,
    })
}

/// Decode a bounded script. The error value is `true` only for a size-bound
/// violation and `false` for malformed hexadecimal.
fn decode_bounded_script(value: &str) -> Result<Vec<u8>, bool> {
    if value.len() > MAX_MERCHANT_OUTPUT_SCRIPT_BYTES.saturating_mul(2) {
        return Err(true);
    }
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(false);
    }
    hex::decode(value).map_err(|_| false)
}

fn canonical_hash(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn decode_script(value: &str) -> Option<Vec<u8>> {
    (!value.is_empty() && value.len().is_multiple_of(2))
        .then(|| hex::decode(value).ok())
        .flatten()
}

fn canonical_asset(asset: &MerchantAsset) -> Option<MerchantAsset> {
    match asset {
        MerchantAsset::Bitcoin => Some(MerchantAsset::Bitcoin),
        MerchantAsset::Liquid(asset_id) => canonical_hash(asset_id).map(MerchantAsset::Liquid),
    }
}

fn has_bounded_address_text(address: &str) -> bool {
    !address.is_empty() && address.len() <= 512 && !address.chars().any(char::is_whitespace)
}

fn derive_destination_script(address: &str, asset: &MerchantAsset) -> Option<Vec<u8>> {
    if !has_bounded_address_text(address) {
        return None;
    }
    match asset {
        MerchantAsset::Bitcoin => Address::from_str(address)
            .ok()?
            .require_network(Network::Bitcoin)
            .ok()
            .map(|address| address.script_pubkey().into_bytes()),
        MerchantAsset::Liquid(_) => {
            let address = LiquidAddress::from_str(address).ok()?;
            (address.params == &AddressParams::LIQUID && address.blinding_pubkey.is_some())
                .then(|| address.script_pubkey().into_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute, consensus::serialize, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn,
        TxOut, Txid, Witness,
    };
    use std::{collections::BTreeMap, sync::Mutex};
    use uuid::Uuid;

    const APPROVED_ADDRESS: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const APPROVED_SCRIPT: &str =
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const OTHER_BITCOIN_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const BLOCK_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LIQUID_ASSET: &str = "6f0279e9ed041c3d710a9f57d0c02928416453c0e87cbbe43c8ca792a3b6e499";
    const LIQUID_ADDRESS: &str =
        "lq1qqvxk052kf3qtkxmrakx50a9gc3smqad2ync54hzntjt980kfej9kkfe0247rp5h4yzmdftsahhw64uy8pzfe7cpg4fgykm7cv";
    type AttemptMutation = Box<dyn Fn(&mut ChainSwapTxAttempt)>;

    fn recovery_attempt() -> ChainSwapTxAttempt {
        let source_txid =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let destination_script = ScriptBuf::from_bytes(hex::decode(APPROVED_SCRIPT).unwrap());
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: source_txid,
                    vout: 2,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(97_000),
                script_pubkey: destination_script,
            }],
        };
        let txid = transaction.compute_txid().to_string();

        ChainSwapTxAttempt {
            id: Uuid::nil(),
            chain_swap_id: Uuid::nil(),
            purpose: "btc_recovery".into(),
            raw_tx_hex: hex::encode(serialize(&transaction)),
            txid,
            source_prevouts: sqlx::types::Json(vec![crate::db::RecoverySourcePrevout {
                txid: source_txid.to_string(),
                vout: 2,
                amount_sat: 100_000,
                script_pubkey_hex: "51".into(),
            }]),
            destination_address: APPROVED_ADDRESS.into(),
            destination_script_hex: APPROVED_SCRIPT.into(),
            destination_vout: 0,
            destination_amount_sat: 97_000,
            fee_amount_sat: 3_000,
            fee_rate_sat_vb: 2.0,
            status: "broadcast".into(),
            broadcast_attempts: 1,
            last_broadcast_result: None,
            integrity_reason: None,
            constructed_at_unix: 1,
            first_broadcast_attempt_at_unix: Some(2),
            last_broadcast_attempt_at_unix: Some(2),
            broadcast_at_unix: Some(2),
            confirmed_at_unix: None,
            finalized_at_unix: None,
            integrity_hold_at_unix: None,
            updated_at_unix: 2,
        }
    }

    struct LiquidBackendFixture {
        raw_transaction: Vec<u8>,
        txid: String,
        source_txid: String,
        destination_address: String,
        destination_script_hex: String,
        asset: MerchantAsset,
        blinding_key_hex: String,
    }

    impl LiquidBackendFixture {
        fn journal<'a>(
            &'a self,
            source_prevouts: &'a [MerchantSourcePrevout<'a>],
        ) -> MerchantTransactionJournalEvidence<'a> {
            MerchantTransactionJournalEvidence {
                raw_transaction: &self.raw_transaction,
                txid: &self.txid,
                source_prevouts,
                merchant: MerchantOutputCommitment {
                    destination_address: &self.destination_address,
                    destination_script_hex: &self.destination_script_hex,
                    asset: &self.asset,
                    amount_sat: 88_000,
                    vout: 0,
                },
            }
        }

        fn approved_destination(&self) -> ApprovedMerchantDestination {
            ApprovedMerchantDestination::liquid(
                &self.destination_address,
                &self.destination_script_hex,
                LIQUID_ASSET,
            )
        }
    }

    fn liquid_backend_fixture() -> LiquidBackendFixture {
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let blinding_key = elements::secp256k1_zkp::SecretKey::new(&mut rng);
        let blinding_pubkey =
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_key);
        let destination_address = LiquidAddress::from_str(LIQUID_ADDRESS)
            .unwrap()
            .to_unconfidential()
            .to_confidential(blinding_pubkey);
        let script = destination_address.script_pubkey();
        let source_txid = elements::Txid::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let liquid_asset = elements::AssetId::from_str(LIQUID_ASSET).unwrap();
        let input_secrets = elements::TxOutSecrets::new(
            liquid_asset,
            elements::confidential::AssetBlindingFactor::new(&mut rng),
            88_000,
            elements::confidential::ValueBlindingFactor::new(&mut rng),
        );
        let confidential_output = elements::TxOut::new_last_confidential(
            &mut rng,
            &secp,
            88_000,
            liquid_asset,
            script.clone(),
            blinding_pubkey,
            &[input_secrets],
            &[],
        )
        .unwrap()
        .0;
        let transaction = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(source_txid, 4),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::MAX,
                asset_issuance: elements::AssetIssuance::default(),
                witness: elements::TxInWitness::default(),
            }],
            output: vec![confidential_output],
        };
        LiquidBackendFixture {
            raw_transaction: elements::encode::serialize(&transaction),
            txid: transaction.txid().to_string(),
            source_txid: source_txid.to_string(),
            destination_address: destination_address.to_string(),
            destination_script_hex: hex::encode(script.as_bytes()),
            asset: MerchantAsset::Liquid(LIQUID_ASSET.into()),
            blinding_key_hex: blinding_key.display_secret().to_string(),
        }
    }

    fn liquid_backend_sources(fixture: &LiquidBackendFixture) -> [MerchantSourcePrevout<'_>; 1] {
        [MerchantSourcePrevout {
            txid: &fixture.source_txid,
            vout: 4,
            amount_sat: 91_000,
            script_pubkey_hex: "51",
        }]
    }

    struct MockLiquidMerchantBackend {
        snapshot: Option<LiquidHistorySnapshotOutcome>,
        snapshot_failure: bool,
        raw_transaction: Option<Vec<u8>>,
        raw_failure: bool,
        raw_requests: Mutex<Vec<String>>,
        prior_height_requests: Mutex<Vec<Vec<i32>>>,
    }

    struct MockBitcoinMerchantEvidence {
        snapshot: Option<BitcoinRecoveryStatusSnapshot>,
        snapshot_failure: bool,
        raw_transaction: Option<Vec<u8>>,
        raw_failure: bool,
        raw_requests: Mutex<Vec<String>>,
        prior_height_requests: Mutex<Vec<Option<u32>>>,
    }

    impl MockBitcoinMerchantEvidence {
        fn successful(
            snapshot: BitcoinRecoveryStatusSnapshot,
            raw_transaction: Option<Vec<u8>>,
        ) -> Self {
            Self {
                snapshot: Some(snapshot),
                snapshot_failure: false,
                raw_transaction,
                raw_failure: false,
                raw_requests: Mutex::new(Vec::new()),
                prior_height_requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl BitcoinRecoveryEvidence for MockBitcoinMerchantEvidence {
        async fn raw_transaction(&self, txid: &str) -> Result<Option<Vec<u8>>, AppError> {
            self.raw_requests.lock().unwrap().push(txid.to_owned());
            if self.raw_failure {
                return Err(AppError::ElectrumError("mock Bitcoin raw failure".into()));
            }
            Ok(self.raw_transaction.clone())
        }

        async fn outspend(
            &self,
            _txid: &str,
            _vout: u32,
        ) -> Result<crate::chain_recovery::BitcoinOutspend, AppError> {
            unreachable!("merchant observation does not query recovery source outspends")
        }

        async fn status_snapshot(
            &self,
            _txid: &str,
            prior_block_height: Option<u32>,
        ) -> Result<BitcoinRecoveryStatusSnapshot, AppError> {
            self.prior_height_requests
                .lock()
                .unwrap()
                .push(prior_block_height);
            if self.snapshot_failure {
                return Err(AppError::ElectrumError(
                    "mock Bitcoin status failure".into(),
                ));
            }
            self.snapshot
                .clone()
                .ok_or_else(|| AppError::ElectrumError("mock Bitcoin snapshot missing".into()))
        }
    }

    impl MockLiquidMerchantBackend {
        fn successful(snapshot: LiquidHistorySnapshot, raw_transaction: Option<Vec<u8>>) -> Self {
            Self {
                snapshot: Some(LiquidHistorySnapshotOutcome::Complete(snapshot)),
                snapshot_failure: false,
                raw_transaction,
                raw_failure: false,
                raw_requests: Mutex::new(Vec::new()),
                prior_height_requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl UtxoBackend for MockLiquidMerchantBackend {
        async fn get_raw_tx(&self, txid_hex: &str) -> Result<Vec<u8>, AppError> {
            self.raw_requests.lock().unwrap().push(txid_hex.to_owned());
            if self.raw_failure {
                return Err(AppError::ElectrumError(
                    "mock raw transaction failure".into(),
                ));
            }
            self.raw_transaction.clone().ok_or(AppError::UtxoNotFound)
        }

        async fn is_unspent(
            &self,
            _script_pubkey: &elements::Script,
            _txid_hex: &str,
            _vout: u32,
        ) -> Result<bool, AppError> {
            unreachable!("merchant observation does not query unspent state")
        }

        async fn script_history(
            &self,
            _script_pubkey: &elements::Script,
        ) -> Result<crate::utxo::LiquidScriptHistory, AppError> {
            unreachable!("merchant observation uses the authoritative snapshot")
        }

        async fn history_txids(
            &self,
            _script_pubkey: &elements::Script,
        ) -> Result<Vec<String>, AppError> {
            unreachable!("merchant observation uses the authoritative snapshot")
        }

        async fn liquid_history_snapshot(
            &self,
            _script_pubkey: &elements::Script,
            prior_block_heights: &[i32],
            _limits: LiquidHistorySnapshotLimits,
        ) -> Result<LiquidHistorySnapshotOutcome, AppError> {
            self.prior_height_requests
                .lock()
                .unwrap()
                .push(prior_block_heights.to_vec());
            if self.snapshot_failure {
                return Err(AppError::ElectrumError("mock snapshot failure".into()));
            }
            self.snapshot
                .clone()
                .ok_or_else(|| AppError::ElectrumError("mock snapshot missing".into()))
        }

        async fn find_spending_txid(
            &self,
            _script_pubkey: &elements::Script,
            _txid_hex: &str,
            _vout: u32,
        ) -> Result<Option<String>, AppError> {
            unreachable!("merchant observation does not search arbitrary spenders")
        }
    }

    fn liquid_snapshot(
        tip_height: i32,
        entries: Vec<LiquidHistoryEntry>,
        anchors: &[(i32, &str)],
    ) -> LiquidHistorySnapshot {
        LiquidHistorySnapshot {
            authority: "mock-liquid-authority".into(),
            tip_height,
            entries,
            anchored_block_hashes: anchors
                .iter()
                .map(|(height, hash)| (*height, (*hash).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn approved_bitcoin() -> ApprovedMerchantDestination {
        bitcoin_destination(APPROVED_ADDRESS)
    }

    fn bitcoin_destination(address: &str) -> ApprovedMerchantDestination {
        let address = Address::from_str(address)
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        ApprovedMerchantDestination::bitcoin(
            address.to_string(),
            hex::encode(address.script_pubkey().as_bytes()),
        )
    }

    fn approved_liquid() -> ApprovedMerchantDestination {
        let address = LiquidAddress::from_str(LIQUID_ADDRESS).unwrap();
        ApprovedMerchantDestination::liquid(
            LIQUID_ADDRESS,
            hex::encode(address.script_pubkey().as_bytes()),
            LIQUID_ASSET,
        )
    }

    fn authoritative(
        txid: &str,
        script: &str,
        asset: MerchantAsset,
        amount_sat: u64,
        vout: u32,
        confirmations: u32,
    ) -> MerchantOutputEvidence {
        MerchantOutputEvidence::Authoritative(ObservedMerchantOutput::new(
            txid,
            script,
            asset,
            amount_sat,
            vout,
            confirmations,
            Some(900_000),
            Some(BLOCK_HASH.into()),
        ))
    }

    fn valid_recovery_evidence(attempt: &ChainSwapTxAttempt) -> MerchantOutputEvidence {
        authoritative(
            &attempt.txid,
            APPROVED_SCRIPT,
            MerchantAsset::Bitcoin,
            97_000,
            0,
            3,
        )
    }

    #[test]
    fn existing_journal_exact_output_becomes_typed_accounting_evidence() {
        let attempt = recovery_attempt();

        let verified = verify_bitcoin_recovery_output(
            &attempt,
            &approved_bitcoin(),
            &valid_recovery_evidence(&attempt),
            3,
        )
        .unwrap();

        assert_eq!(verified.journal_txid(), attempt.txid);
        assert_eq!(verified.txid(), attempt.txid);
        assert_eq!(verified.destination_address(), APPROVED_ADDRESS);
        assert_eq!(verified.destination_script_hex(), APPROVED_SCRIPT);
        assert_eq!(verified.asset(), &MerchantAsset::Bitcoin);
        assert_eq!(verified.amount_sat(), 97_000);
        assert_eq!(verified.vout(), 0);
        assert_eq!(verified.confirmations(), 3);
        assert_eq!(verified.block_height(), 900_000);
        assert_eq!(verified.block_hash(), BLOCK_HASH);
        assert!(!verified.is_linked_replacement());
    }

    #[test]
    fn explicit_linked_replacement_uses_its_own_exact_output() {
        let original_txid = "11".repeat(32);
        let replacement_txid = "22".repeat(32);
        let approved = approved_liquid();
        let candidate = JournaledMerchantTransaction::linked_replacement(
            &replacement_txid,
            &original_txid,
            approved.address.clone(),
            approved.script_pubkey_hex.clone(),
            MerchantAsset::Liquid(LIQUID_ASSET.into()),
            88_000,
            1,
        );
        let evidence = authoritative(
            &replacement_txid,
            &approved.script_pubkey_hex,
            MerchantAsset::Liquid(LIQUID_ASSET.to_ascii_uppercase()),
            88_000,
            1,
            2,
        );

        let verified =
            verify_merchant_output(&original_txid, &candidate, &approved, &evidence, 2).unwrap();

        assert_eq!(verified.journal_txid(), original_txid);
        assert_eq!(verified.txid(), replacement_txid);
        assert_eq!(verified.amount_sat(), 88_000);
        assert!(verified.is_linked_replacement());
    }

    #[test]
    fn liquid_candidate_and_approval_each_bind_address_to_script() {
        let txid = "11".repeat(32);
        let approved = approved_liquid();
        let candidate = JournaledMerchantTransaction::original(
            &txid,
            approved.address.clone(),
            approved.script_pubkey_hex.clone(),
            MerchantAsset::Liquid(LIQUID_ASSET.into()),
            88_000,
            0,
        );
        let evidence = authoritative(
            &txid,
            &approved.script_pubkey_hex,
            MerchantAsset::Liquid(LIQUID_ASSET.into()),
            88_000,
            0,
            2,
        );

        let mut bad_candidate_script = candidate.clone();
        bad_candidate_script.destination_script_hex = "51".into();
        assert_eq!(
            verify_merchant_output(&txid, &bad_candidate_script, &approved, &evidence, 2,),
            Err(MerchantOutputVerificationError::InvalidJournal)
        );

        let mut bad_candidate_address = candidate.clone();
        bad_candidate_address.destination_address = APPROVED_ADDRESS.into();
        assert_eq!(
            verify_merchant_output(&txid, &bad_candidate_address, &approved, &evidence, 2,),
            Err(MerchantOutputVerificationError::InvalidJournal)
        );

        let mut bad_approved_script = approved.clone();
        bad_approved_script.script_pubkey_hex = "51".into();
        assert_eq!(
            verify_merchant_output(&txid, &candidate, &bad_approved_script, &evidence, 2,),
            Err(MerchantOutputVerificationError::InvalidApprovedDestination)
        );

        let mut bad_approved_address = approved;
        bad_approved_address.address = APPROVED_ADDRESS.into();
        assert_eq!(
            verify_merchant_output(&txid, &candidate, &bad_approved_address, &evidence, 2,),
            Err(MerchantOutputVerificationError::InvalidApprovedDestination)
        );
    }

    #[test]
    fn unknown_or_unlinked_evidence_never_verifies() {
        let attempt = recovery_attempt();
        assert_eq!(
            verify_bitcoin_recovery_output(
                &attempt,
                &approved_bitcoin(),
                &MerchantOutputEvidence::Unknown,
                3,
            ),
            Err(MerchantOutputVerificationError::UnknownEvidence)
        );

        let different_txid = "22".repeat(32);
        let unlinked = JournaledMerchantTransaction::original(
            &different_txid,
            APPROVED_ADDRESS,
            APPROVED_SCRIPT,
            MerchantAsset::Bitcoin,
            97_000,
            0,
        );
        assert_eq!(
            verify_merchant_output(
                &attempt.txid,
                &unlinked,
                &approved_bitcoin(),
                &authoritative(
                    &different_txid,
                    APPROVED_SCRIPT,
                    MerchantAsset::Bitcoin,
                    97_000,
                    0,
                    3,
                ),
                3,
            ),
            Err(MerchantOutputVerificationError::UnlinkedTransaction)
        );

        let wrong_parent = JournaledMerchantTransaction::linked_replacement(
            &different_txid,
            "33".repeat(32),
            APPROVED_ADDRESS,
            APPROVED_SCRIPT,
            MerchantAsset::Bitcoin,
            97_000,
            0,
        );
        assert_eq!(
            verify_merchant_output(
                &attempt.txid,
                &wrong_parent,
                &approved_bitcoin(),
                &authoritative(
                    &different_txid,
                    APPROVED_SCRIPT,
                    MerchantAsset::Bitcoin,
                    97_000,
                    0,
                    3,
                ),
                3,
            ),
            Err(MerchantOutputVerificationError::UnlinkedTransaction)
        );
    }

    #[test]
    fn every_output_mismatch_fails_closed() {
        let attempt = recovery_attempt();
        let fixtures = [
            (
                authoritative(&attempt.txid, "52", MerchantAsset::Bitcoin, 97_000, 0, 3),
                MerchantOutputVerificationError::DestinationMismatch,
            ),
            (
                authoritative(
                    &attempt.txid,
                    APPROVED_SCRIPT,
                    MerchantAsset::Liquid(LIQUID_ASSET.into()),
                    97_000,
                    0,
                    3,
                ),
                MerchantOutputVerificationError::AssetMismatch,
            ),
            (
                authoritative(
                    &attempt.txid,
                    APPROVED_SCRIPT,
                    MerchantAsset::Bitcoin,
                    96_999,
                    0,
                    3,
                ),
                MerchantOutputVerificationError::AmountMismatch,
            ),
            (
                authoritative(
                    &attempt.txid,
                    APPROVED_SCRIPT,
                    MerchantAsset::Bitcoin,
                    97_000,
                    1,
                    3,
                ),
                MerchantOutputVerificationError::VoutMismatch,
            ),
            (
                authoritative(
                    &"44".repeat(32),
                    APPROVED_SCRIPT,
                    MerchantAsset::Bitcoin,
                    97_000,
                    0,
                    3,
                ),
                MerchantOutputVerificationError::EvidenceTransactionMismatch,
            ),
        ];

        for (evidence, expected) in fixtures {
            assert_eq!(
                verify_bitcoin_recovery_output(&attempt, &approved_bitcoin(), &evidence, 3,),
                Err(expected)
            );
        }
    }

    #[test]
    fn journal_must_match_the_immutable_approved_destination() {
        let attempt = recovery_attempt();
        let evidence = valid_recovery_evidence(&attempt);
        assert_eq!(
            verify_bitcoin_recovery_output(
                &attempt,
                &bitcoin_destination(OTHER_BITCOIN_ADDRESS),
                &evidence,
                3,
            ),
            Err(MerchantOutputVerificationError::DestinationMismatch)
        );
        assert_eq!(
            verify_bitcoin_recovery_output(
                &attempt,
                &ApprovedMerchantDestination::bitcoin(APPROVED_ADDRESS, "52"),
                &evidence,
                3,
            ),
            Err(MerchantOutputVerificationError::InvalidApprovedDestination)
        );

        let approved = approved_liquid();
        let liquid_candidate = JournaledMerchantTransaction::original(
            &attempt.txid,
            approved.address.clone(),
            approved.script_pubkey_hex.clone(),
            MerchantAsset::Liquid(LIQUID_ASSET.into()),
            97_000,
            0,
        );
        let wrong_asset = ApprovedMerchantDestination::liquid(
            approved.address,
            approved.script_pubkey_hex,
            "bb".repeat(32),
        );
        assert_eq!(
            verify_merchant_output(&attempt.txid, &liquid_candidate, &wrong_asset, &evidence, 3,),
            Err(MerchantOutputVerificationError::AssetMismatch)
        );
    }

    #[test]
    fn confirmation_policy_and_complete_block_identity_are_mandatory() {
        let attempt = recovery_attempt();
        let mut observed = match valid_recovery_evidence(&attempt) {
            MerchantOutputEvidence::Authoritative(observed) => observed,
            MerchantOutputEvidence::Unknown => unreachable!(),
        };

        assert_eq!(
            verify_bitcoin_recovery_output(
                &attempt,
                &approved_bitcoin(),
                &MerchantOutputEvidence::Authoritative(observed.clone()),
                0,
            ),
            Err(MerchantOutputVerificationError::InvalidConfirmationPolicy)
        );
        observed.confirmations = 2;
        assert_eq!(
            verify_bitcoin_recovery_output(
                &attempt,
                &approved_bitcoin(),
                &MerchantOutputEvidence::Authoritative(observed.clone()),
                3,
            ),
            Err(MerchantOutputVerificationError::InsufficientConfirmations)
        );

        observed.confirmations = 3;
        observed.block_height = None;
        assert_eq!(
            verify_bitcoin_recovery_output(
                &attempt,
                &approved_bitcoin(),
                &MerchantOutputEvidence::Authoritative(observed.clone()),
                3,
            ),
            Err(MerchantOutputVerificationError::IncompleteConfirmationEvidence)
        );
        observed.block_height = Some(900_000);
        observed.block_hash = Some("not-a-hash".into());
        assert_eq!(
            verify_bitcoin_recovery_output(
                &attempt,
                &approved_bitcoin(),
                &MerchantOutputEvidence::Authoritative(observed),
                3,
            ),
            Err(MerchantOutputVerificationError::IncompleteConfirmationEvidence)
        );
    }

    #[test]
    fn corrupt_or_held_existing_journal_never_becomes_authority() {
        let base = recovery_attempt();
        let mutations: Vec<AttemptMutation> = vec![
            Box::new(|attempt| attempt.raw_tx_hex = "00".into()),
            Box::new(|attempt| attempt.txid = "22".repeat(32)),
            Box::new(|attempt| attempt.destination_script_hex = "52".into()),
            Box::new(|attempt| attempt.destination_amount_sat -= 1),
            Box::new(|attempt| attempt.destination_vout = 1),
            Box::new(|attempt| attempt.destination_address = OTHER_BITCOIN_ADDRESS.into()),
            Box::new(|attempt| attempt.source_prevouts[0].vout += 1),
            Box::new(|attempt| attempt.purpose = "liquid_claim".into()),
        ];
        for mutate in mutations {
            let mut attempt = base.clone();
            mutate(&mut attempt);
            assert_eq!(
                JournaledMerchantTransaction::from_bitcoin_recovery_attempt(&attempt),
                Err(MerchantOutputVerificationError::InvalidJournal)
            );
        }

        let mut held = base;
        held.status = "integrity_hold".into();
        assert_eq!(
            JournaledMerchantTransaction::from_bitcoin_recovery_attempt(&held),
            Err(MerchantOutputVerificationError::JournalIntegrityHold)
        );
    }

    #[test]
    fn invalid_shapes_and_assets_fail_before_accounting_output_exists() {
        let original_txid = "11".repeat(32);
        let evidence = authoritative(
            &original_txid,
            "51",
            MerchantAsset::Liquid(LIQUID_ASSET.into()),
            1,
            0,
            2,
        );

        for candidate in [
            JournaledMerchantTransaction::original(
                "bad-txid",
                "lq1merchant",
                "51",
                MerchantAsset::Liquid(LIQUID_ASSET.into()),
                1,
                0,
            ),
            JournaledMerchantTransaction::original(
                &original_txid,
                "",
                "51",
                MerchantAsset::Liquid(LIQUID_ASSET.into()),
                1,
                0,
            ),
            JournaledMerchantTransaction::original(
                &original_txid,
                "lq1merchant",
                "not-hex",
                MerchantAsset::Liquid(LIQUID_ASSET.into()),
                1,
                0,
            ),
            JournaledMerchantTransaction::original(
                &original_txid,
                "lq1merchant",
                "51",
                MerchantAsset::Liquid("bad-asset".into()),
                1,
                0,
            ),
            JournaledMerchantTransaction::original(
                &original_txid,
                "lq1merchant",
                "51",
                MerchantAsset::Liquid(LIQUID_ASSET.into()),
                0,
                0,
            ),
            JournaledMerchantTransaction::original(
                &original_txid,
                "lq1merchant",
                "51",
                MerchantAsset::Liquid(LIQUID_ASSET.into()),
                1,
                -1,
            ),
            JournaledMerchantTransaction::original(
                &original_txid,
                APPROVED_ADDRESS,
                "51",
                MerchantAsset::Bitcoin,
                1,
                0,
            ),
            JournaledMerchantTransaction::original(
                &original_txid,
                OTHER_BITCOIN_ADDRESS,
                APPROVED_SCRIPT,
                MerchantAsset::Bitcoin,
                1,
                0,
            ),
        ] {
            assert_eq!(
                verify_merchant_output(
                    &original_txid,
                    &candidate,
                    &ApprovedMerchantDestination::liquid("lq1merchant", "51", LIQUID_ASSET,),
                    &evidence,
                    2,
                ),
                Err(MerchantOutputVerificationError::InvalidJournal)
            );
        }
    }

    #[test]
    fn repeated_identical_evidence_is_pure_and_deterministic() {
        let attempt = recovery_attempt();
        let evidence = valid_recovery_evidence(&attempt);

        let first =
            verify_bitcoin_recovery_output(&attempt, &approved_bitcoin(), &evidence, 3).unwrap();
        let repeated =
            verify_bitcoin_recovery_output(&attempt, &approved_bitcoin(), &evidence, 3).unwrap();

        assert_eq!(first, repeated);
    }

    #[test]
    fn production_bitcoin_adapter_uses_actual_output_and_is_idempotent() {
        let attempt = recovery_attempt();
        let raw_transaction = hex::decode(&attempt.raw_tx_hex).unwrap();
        let source = &attempt.source_prevouts.0[0];
        let source_prevouts = [MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat.try_into().unwrap(),
            script_pubkey_hex: &source.script_pubkey_hex,
        }];
        let asset = MerchantAsset::Bitcoin;
        let journal = MerchantTransactionJournalEvidence {
            raw_transaction: &raw_transaction,
            txid: &attempt.txid,
            source_prevouts: &source_prevouts,
            merchant: MerchantOutputCommitment {
                destination_address: APPROVED_ADDRESS,
                destination_script_hex: APPROVED_SCRIPT,
                asset: &asset,
                amount_sat: 97_000,
                vout: 0,
            },
        };
        let observation = MerchantTransactionObservation {
            raw_transaction: &raw_transaction,
            txid: &attempt.txid,
            confirmation: MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 900_000,
                block_hash: BLOCK_HASH,
            },
        };

        let first = adapt_bitcoin_merchant_output(&journal, None, &observation).unwrap();
        let repeated = adapt_bitcoin_merchant_output(&journal, None, &observation).unwrap();

        assert_eq!(first, repeated);
        assert_eq!(first.observed().amount_sat(), 97_000);
        assert_ne!(first.observed().amount_sat(), source.amount_sat as u64);
        let verified = first.verify(&approved_bitcoin(), 1).unwrap();
        assert_eq!(verified.amount_sat(), 97_000);
        assert_eq!(verified.txid(), attempt.txid);
        assert!(!verified.is_linked_replacement());
    }

    #[test]
    fn production_bitcoin_adapter_rejects_wrong_txid_and_unlinked_replacement() {
        let attempt = recovery_attempt();
        let raw_transaction = hex::decode(&attempt.raw_tx_hex).unwrap();
        let transaction: Transaction = deserialize(&raw_transaction).unwrap();
        let mut replacement_transaction = transaction.clone();
        replacement_transaction.input[0].sequence = Sequence::ZERO;
        replacement_transaction.output[0].value = Amount::from_sat(96_500);
        let replacement_raw = serialize(&replacement_transaction);
        let replacement_txid = replacement_transaction.compute_txid().to_string();
        let source = &attempt.source_prevouts.0[0];
        let source_prevouts = [MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat.try_into().unwrap(),
            script_pubkey_hex: &source.script_pubkey_hex,
        }];
        let asset = MerchantAsset::Bitcoin;
        let journal = MerchantTransactionJournalEvidence {
            raw_transaction: &raw_transaction,
            txid: &attempt.txid,
            source_prevouts: &source_prevouts,
            merchant: MerchantOutputCommitment {
                destination_address: APPROVED_ADDRESS,
                destination_script_hex: APPROVED_SCRIPT,
                asset: &asset,
                amount_sat: 97_000,
                vout: 0,
            },
        };
        let wrong_txid = "22".repeat(32);
        let wrong_txid_observation = MerchantTransactionObservation {
            raw_transaction: &raw_transaction,
            txid: &wrong_txid,
            confirmation: MerchantConfirmationEvidence::Mempool,
        };
        let unlinked_observation = MerchantTransactionObservation {
            raw_transaction: &replacement_raw,
            txid: &replacement_txid,
            confirmation: MerchantConfirmationEvidence::Mempool,
        };

        assert_eq!(
            adapt_bitcoin_merchant_output(&journal, None, &wrong_txid_observation),
            Err(MerchantOutputAdapterError::ObservedTxidMismatch)
        );
        assert_eq!(
            adapt_bitcoin_merchant_output(&journal, None, &unlinked_observation),
            Err(MerchantOutputAdapterError::UnlinkedObservedTransaction)
        );
    }

    #[test]
    fn production_bitcoin_adapter_requires_full_linked_replacement_evidence() {
        let attempt = recovery_attempt();
        let original_raw = hex::decode(&attempt.raw_tx_hex).unwrap();
        let mut replacement_transaction: Transaction = deserialize(&original_raw).unwrap();
        replacement_transaction.input[0].sequence = Sequence::ZERO;
        replacement_transaction.output[0].value = Amount::from_sat(96_500);
        let replacement_raw = serialize(&replacement_transaction);
        let replacement_txid = replacement_transaction.compute_txid().to_string();
        let source = &attempt.source_prevouts.0[0];
        let original_sources = [MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat.try_into().unwrap(),
            script_pubkey_hex: &source.script_pubkey_hex,
        }];
        let replacement_sources = original_sources;
        let asset = MerchantAsset::Bitcoin;
        let original = MerchantTransactionJournalEvidence {
            raw_transaction: &original_raw,
            txid: &attempt.txid,
            source_prevouts: &original_sources,
            merchant: MerchantOutputCommitment {
                destination_address: APPROVED_ADDRESS,
                destination_script_hex: APPROVED_SCRIPT,
                asset: &asset,
                amount_sat: 97_000,
                vout: 0,
            },
        };
        let replacement = MerchantTransactionJournalEvidence {
            raw_transaction: &replacement_raw,
            txid: &replacement_txid,
            source_prevouts: &replacement_sources,
            merchant: MerchantOutputCommitment {
                destination_address: APPROVED_ADDRESS,
                destination_script_hex: APPROVED_SCRIPT,
                asset: &asset,
                amount_sat: 96_500,
                vout: 0,
            },
        };
        let linked = LinkedReplacementJournalEvidence {
            replaces_txid: &attempt.txid,
            replacement,
        };
        let observation = MerchantTransactionObservation {
            raw_transaction: &replacement_raw,
            txid: &replacement_txid,
            confirmation: MerchantConfirmationEvidence::Confirmed {
                confirmations: 2,
                block_height: 900_001,
                block_hash: BLOCK_HASH,
            },
        };

        let adapted =
            adapt_bitcoin_merchant_output(&original, Some(&linked), &observation).unwrap();
        let verified = adapted.verify(&approved_bitcoin(), 2).unwrap();
        assert_eq!(verified.journal_txid(), attempt.txid);
        assert_eq!(verified.txid(), replacement_txid);
        assert_eq!(verified.amount_sat(), 96_500);
        assert!(verified.is_linked_replacement());

        let wrong_parent = "33".repeat(32);
        let incorrectly_linked = LinkedReplacementJournalEvidence {
            replaces_txid: &wrong_parent,
            replacement,
        };
        assert_eq!(
            adapt_bitcoin_merchant_output(&original, Some(&incorrectly_linked), &observation),
            Err(MerchantOutputAdapterError::InvalidReplacementLink)
        );
    }

    #[test]
    fn production_adapter_rejects_wrong_destination_and_multiple_candidates() {
        let attempt = recovery_attempt();
        let original_raw = hex::decode(&attempt.raw_tx_hex).unwrap();
        let mut multiple_transaction: Transaction = deserialize(&original_raw).unwrap();
        multiple_transaction
            .output
            .push(multiple_transaction.output[0].clone());
        let multiple_raw = serialize(&multiple_transaction);
        let multiple_txid = multiple_transaction.compute_txid().to_string();
        let source = &attempt.source_prevouts.0[0];
        let sources = [MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat.try_into().unwrap(),
            script_pubkey_hex: &source.script_pubkey_hex,
        }];
        let asset = MerchantAsset::Bitcoin;
        let other_script_hex = {
            let address = Address::from_str(OTHER_BITCOIN_ADDRESS)
                .unwrap()
                .require_network(Network::Bitcoin)
                .unwrap();
            hex::encode(address.script_pubkey().as_bytes())
        };
        let bad_destination = MerchantTransactionJournalEvidence {
            raw_transaction: &original_raw,
            txid: &attempt.txid,
            source_prevouts: &sources,
            merchant: MerchantOutputCommitment {
                destination_address: OTHER_BITCOIN_ADDRESS,
                destination_script_hex: APPROVED_SCRIPT,
                asset: &asset,
                amount_sat: 97_000,
                vout: 0,
            },
        };
        let bad_script = MerchantTransactionJournalEvidence {
            raw_transaction: &original_raw,
            txid: &attempt.txid,
            source_prevouts: &sources,
            merchant: MerchantOutputCommitment {
                destination_address: APPROVED_ADDRESS,
                destination_script_hex: &other_script_hex,
                asset: &asset,
                amount_sat: 97_000,
                vout: 0,
            },
        };
        let multiple = MerchantTransactionJournalEvidence {
            raw_transaction: &multiple_raw,
            txid: &multiple_txid,
            source_prevouts: &sources,
            merchant: MerchantOutputCommitment {
                destination_address: APPROVED_ADDRESS,
                destination_script_hex: APPROVED_SCRIPT,
                asset: &asset,
                amount_sat: 97_000,
                vout: 0,
            },
        };
        let original_observation = MerchantTransactionObservation {
            raw_transaction: &original_raw,
            txid: &attempt.txid,
            confirmation: MerchantConfirmationEvidence::Mempool,
        };
        let multiple_observation = MerchantTransactionObservation {
            raw_transaction: &multiple_raw,
            txid: &multiple_txid,
            confirmation: MerchantConfirmationEvidence::Mempool,
        };

        assert_eq!(
            adapt_bitcoin_merchant_output(&bad_destination, None, &original_observation),
            Err(MerchantOutputAdapterError::InvalidCommitment)
        );
        assert_eq!(
            adapt_bitcoin_merchant_output(&bad_script, None, &original_observation),
            Err(MerchantOutputAdapterError::InvalidCommitment)
        );
        assert_eq!(
            adapt_bitcoin_merchant_output(&multiple, None, &multiple_observation),
            Err(MerchantOutputAdapterError::MultipleObservedOutputs)
        );
    }

    #[test]
    fn production_liquid_adapter_reads_actual_value_and_rejects_wrong_asset() {
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let blinding_key = elements::secp256k1_zkp::SecretKey::from_slice(&[1; 32]).unwrap();
        let blinding_pubkey =
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_key);
        let address = LiquidAddress::from_str(LIQUID_ADDRESS)
            .unwrap()
            .to_unconfidential()
            .to_confidential(blinding_pubkey);
        let address_text = address.to_string();
        let script = address.script_pubkey();
        let source_txid = elements::Txid::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let source_txid_text = source_txid.to_string();
        let source_prevouts = [MerchantSourcePrevout {
            txid: &source_txid_text,
            vout: 3,
            amount_sat: 91_000,
            script_pubkey_hex: "51",
        }];
        let liquid_asset = elements::AssetId::from_str(LIQUID_ASSET).unwrap();
        let liquid_transaction = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(source_txid, 3),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::MAX,
                asset_issuance: elements::AssetIssuance::default(),
                witness: elements::TxInWitness::default(),
            }],
            output: vec![elements::TxOut {
                asset: elements::confidential::Asset::Explicit(liquid_asset),
                value: elements::confidential::Value::Explicit(88_000),
                nonce: elements::confidential::Nonce::Null,
                script_pubkey: script.clone(),
                witness: elements::TxOutWitness::default(),
            }],
        };
        let raw_transaction = elements::encode::serialize(&liquid_transaction);
        let txid = liquid_transaction.txid().to_string();
        let asset = MerchantAsset::Liquid(LIQUID_ASSET.into());
        let destination_script_hex = hex::encode(script.as_bytes());
        let journal = MerchantTransactionJournalEvidence {
            raw_transaction: &raw_transaction,
            txid: &txid,
            source_prevouts: &source_prevouts,
            merchant: MerchantOutputCommitment {
                destination_address: &address_text,
                destination_script_hex: &destination_script_hex,
                asset: &asset,
                amount_sat: 88_000,
                vout: 0,
            },
        };
        let observation = MerchantTransactionObservation {
            raw_transaction: &raw_transaction,
            txid: &txid,
            confirmation: MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_000,
                block_hash: BLOCK_HASH,
            },
        };
        let approved = ApprovedMerchantDestination::liquid(
            &address_text,
            &destination_script_hex,
            LIQUID_ASSET,
        );

        let adapted =
            adapt_liquid_merchant_output(&journal, None, &observation, &blinding_key).unwrap();
        assert_eq!(adapted.observed().amount_sat(), 88_000);
        assert_eq!(adapted.verify(&approved, 1).unwrap().amount_sat(), 88_000);

        let wrong_asset_id = elements::AssetId::from_str(&"22".repeat(32)).unwrap();
        let mut wrong_asset_transaction = liquid_transaction;
        wrong_asset_transaction.output[0].asset =
            elements::confidential::Asset::Explicit(wrong_asset_id);
        let wrong_asset_raw = elements::encode::serialize(&wrong_asset_transaction);
        let wrong_asset_txid = wrong_asset_transaction.txid().to_string();
        let wrong_asset_journal = MerchantTransactionJournalEvidence {
            raw_transaction: &wrong_asset_raw,
            txid: &wrong_asset_txid,
            source_prevouts: &source_prevouts,
            merchant: journal.merchant,
        };
        let wrong_asset_observation = MerchantTransactionObservation {
            raw_transaction: &wrong_asset_raw,
            txid: &wrong_asset_txid,
            confirmation: MerchantConfirmationEvidence::Mempool,
        };
        assert_eq!(
            adapt_liquid_merchant_output(
                &wrong_asset_journal,
                None,
                &wrong_asset_observation,
                &blinding_key,
            ),
            Err(MerchantOutputAdapterError::JournalOutputMismatch)
        );
    }

    #[test]
    fn production_liquid_adapter_unblinds_with_stored_key_and_rejects_wrong_key() {
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let blinding_key = elements::secp256k1_zkp::SecretKey::new(&mut rng);
        let blinding_pubkey =
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_key);
        let address = LiquidAddress::from_str(LIQUID_ADDRESS)
            .unwrap()
            .to_unconfidential()
            .to_confidential(blinding_pubkey);
        let address_text = address.to_string();
        let script = address.script_pubkey();
        let destination_script_hex = hex::encode(script.as_bytes());
        let source_txid = elements::Txid::from_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let source_txid_text = source_txid.to_string();
        let source_prevouts = [MerchantSourcePrevout {
            txid: &source_txid_text,
            vout: 4,
            amount_sat: 91_000,
            script_pubkey_hex: "51",
        }];
        let liquid_asset = elements::AssetId::from_str(LIQUID_ASSET).unwrap();
        let input_secrets = elements::TxOutSecrets::new(
            liquid_asset,
            elements::confidential::AssetBlindingFactor::new(&mut rng),
            88_000,
            elements::confidential::ValueBlindingFactor::new(&mut rng),
        );
        let confidential_output = elements::TxOut::new_last_confidential(
            &mut rng,
            &secp,
            88_000,
            liquid_asset,
            script,
            blinding_pubkey,
            &[input_secrets],
            &[],
        )
        .unwrap()
        .0;
        assert!(confidential_output.asset.explicit().is_none());
        assert!(confidential_output.value.explicit().is_none());
        let transaction = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(source_txid, 4),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::MAX,
                asset_issuance: elements::AssetIssuance::default(),
                witness: elements::TxInWitness::default(),
            }],
            output: vec![confidential_output],
        };
        let raw_transaction = elements::encode::serialize(&transaction);
        let txid = transaction.txid().to_string();
        let asset = MerchantAsset::Liquid(LIQUID_ASSET.into());
        let journal = MerchantTransactionJournalEvidence {
            raw_transaction: &raw_transaction,
            txid: &txid,
            source_prevouts: &source_prevouts,
            merchant: MerchantOutputCommitment {
                destination_address: &address_text,
                destination_script_hex: &destination_script_hex,
                asset: &asset,
                amount_sat: 88_000,
                vout: 0,
            },
        };
        let observation = MerchantTransactionObservation {
            raw_transaction: &raw_transaction,
            txid: &txid,
            confirmation: MerchantConfirmationEvidence::Confirmed {
                confirmations: 1,
                block_height: 700_001,
                block_hash: BLOCK_HASH,
            },
        };
        let approved = ApprovedMerchantDestination::liquid(
            &address_text,
            &destination_script_hex,
            LIQUID_ASSET,
        );

        let adapted =
            adapt_liquid_merchant_output(&journal, None, &observation, &blinding_key).unwrap();
        assert_eq!(adapted.observed().asset(), &asset);
        assert_eq!(adapted.observed().amount_sat(), 88_000);
        assert_eq!(adapted.verify(&approved, 1).unwrap().amount_sat(), 88_000);

        let wrong_key = elements::secp256k1_zkp::SecretKey::from_slice(&[2; 32]).unwrap();
        assert_eq!(
            adapt_liquid_merchant_output(&journal, None, &observation, &wrong_key),
            Err(MerchantOutputAdapterError::ConfidentialOutputUnverified)
        );
    }

    #[test]
    fn prepare_liquid_claim_journal_derives_owned_exact_output_from_raw_bytes() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let prepared = prepare_liquid_claim_journal(
            &fixture.raw_transaction,
            &sources,
            &fixture.destination_address,
            &fixture.destination_script_hex,
            LIQUID_ASSET,
            &fixture.blinding_key_hex,
        )
        .unwrap();

        assert_eq!(prepared.raw_transaction, fixture.raw_transaction);
        assert_eq!(
            prepared.raw_transaction_hex,
            hex::encode(&prepared.raw_transaction)
        );
        assert_eq!(prepared.txid, fixture.txid);
        assert_eq!(prepared.source_prevouts.len(), 1);
        assert_eq!(prepared.source_prevouts[0].txid, fixture.source_txid);
        assert_eq!(prepared.source_prevouts[0].vout, 4);
        assert_eq!(prepared.source_prevouts[0].amount_sat, 91_000);
        assert_eq!(prepared.source_prevouts[0].script_pubkey_hex, "51");
        assert_eq!(prepared.destination_address, fixture.destination_address);
        assert_eq!(
            prepared.destination_script_hex,
            fixture.destination_script_hex
        );
        assert_eq!(prepared.asset, MerchantAsset::Liquid(LIQUID_ASSET.into()));
        assert_eq!(prepared.amount_sat, 88_000);
        assert_eq!(prepared.vout, 0);
    }

    #[test]
    fn prepare_liquid_claim_journal_rejects_wrong_key_and_source_set() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let wrong_key = elements::secp256k1_zkp::SecretKey::from_slice(&[2; 32])
            .unwrap()
            .display_secret()
            .to_string();
        assert_eq!(
            prepare_liquid_claim_journal(
                &fixture.raw_transaction,
                &sources,
                &fixture.destination_address,
                &fixture.destination_script_hex,
                LIQUID_ASSET,
                &wrong_key,
            ),
            Err(MerchantOutputAdapterError::ConfidentialOutputUnverified)
        );

        let mut wrong_sources = sources;
        wrong_sources[0].vout += 1;
        assert_eq!(
            prepare_liquid_claim_journal(
                &fixture.raw_transaction,
                &wrong_sources,
                &fixture.destination_address,
                &fixture.destination_script_hex,
                LIQUID_ASSET,
                &fixture.blinding_key_hex,
            ),
            Err(MerchantOutputAdapterError::JournalSourceMismatch)
        );
    }

    #[test]
    fn prepare_liquid_claim_journal_rejects_multiple_matching_outputs() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let mut transaction: elements::Transaction =
            elements::encode::deserialize(&fixture.raw_transaction).unwrap();
        transaction.output.push(transaction.output[0].clone());
        let raw_transaction = elements::encode::serialize(&transaction);

        assert_eq!(
            prepare_liquid_claim_journal(
                &raw_transaction,
                &sources,
                &fixture.destination_address,
                &fixture.destination_script_hex,
                LIQUID_ASSET,
                &fixture.blinding_key_hex,
            ),
            Err(MerchantOutputAdapterError::MultipleObservedOutputs)
        );
    }

    #[tokio::test]
    async fn production_liquid_source_returns_confirmed_actual_output_evidence() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let journal = fixture.journal(&sources);
        let snapshot = liquid_snapshot(
            700_001,
            vec![LiquidHistoryEntry {
                txid: fixture.txid.clone(),
                height: 700_000,
                block_hash: Some(BLOCK_HASH.into()),
            }],
            &[(700_000, BLOCK_HASH)],
        );
        let backend =
            MockLiquidMerchantBackend::successful(snapshot, Some(fixture.raw_transaction.clone()));

        let result = observe_liquid_merchant_output(
            &backend,
            &journal,
            None,
            &fixture.blinding_key_hex,
            PreviousLiquidMerchantConfirmation::NeverObserved,
        )
        .await
        .unwrap();
        let LiquidMerchantOutputObservation::Observed(adapted) = result else {
            panic!("confirmed snapshot must return positive adapter evidence");
        };

        assert_eq!(adapted.observed().txid(), fixture.txid);
        assert_eq!(adapted.observed().amount_sat(), 88_000);
        assert_eq!(adapted.observed().confirmations(), 2);
        assert_eq!(adapted.observed().block_height(), Some(700_000));
        assert_eq!(adapted.observed().block_hash(), Some(BLOCK_HASH));
        assert_eq!(
            adapted
                .verify(&fixture.approved_destination(), 2)
                .unwrap()
                .amount_sat(),
            88_000
        );
        assert_eq!(
            backend.raw_requests.lock().unwrap().as_slice(),
            &[fixture.txid]
        );
        assert_eq!(
            backend.prior_height_requests.lock().unwrap().as_slice(),
            &[Vec::<i32>::new()]
        );
    }

    #[tokio::test]
    async fn production_liquid_source_keeps_mempool_evidence_non_accounting() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let journal = fixture.journal(&sources);
        let snapshot = liquid_snapshot(
            700_001,
            vec![LiquidHistoryEntry {
                txid: fixture.txid.clone(),
                height: 0,
                block_hash: None,
            }],
            &[],
        );
        let backend =
            MockLiquidMerchantBackend::successful(snapshot, Some(fixture.raw_transaction.clone()));

        let result = observe_liquid_merchant_output(
            &backend,
            &journal,
            None,
            &fixture.blinding_key_hex,
            PreviousLiquidMerchantConfirmation::Mempool,
        )
        .await
        .unwrap();
        let LiquidMerchantOutputObservation::Observed(adapted) = result else {
            panic!("present mempool transaction must remain positive observation evidence");
        };

        assert_eq!(adapted.observed().confirmations(), 0);
        assert_eq!(adapted.observed().block_height(), None);
        assert_eq!(adapted.observed().block_hash(), None);
        assert_eq!(
            adapted.verify(&fixture.approved_destination(), 1),
            Err(MerchantOutputVerificationError::InsufficientConfirmations)
        );
    }

    #[tokio::test]
    async fn production_liquid_source_proves_mempool_eviction_without_raw_fetch() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let journal = fixture.journal(&sources);
        let backend =
            MockLiquidMerchantBackend::successful(liquid_snapshot(700_001, Vec::new(), &[]), None);

        let result = observe_liquid_merchant_output(
            &backend,
            &journal,
            None,
            &fixture.blinding_key_hex,
            PreviousLiquidMerchantConfirmation::Mempool,
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            LiquidMerchantOutputObservation::Evicted {
                txid: fixture.txid.clone(),
            }
        );
        assert!(backend.raw_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn production_liquid_source_reorg_demotion_redrives_to_new_block_without_loop() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let journal = fixture.journal(&sources);
        let previous_hash = "bb".repeat(32);
        let backend = MockLiquidMerchantBackend::successful(
            liquid_snapshot(700_001, Vec::new(), &[(700_000, BLOCK_HASH)]),
            None,
        );

        let result = observe_liquid_merchant_output(
            &backend,
            &journal,
            None,
            &fixture.blinding_key_hex,
            PreviousLiquidMerchantConfirmation::Confirmed {
                block_height: 700_000,
                block_hash: &previous_hash,
            },
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            LiquidMerchantOutputObservation::ReorgDemoted {
                txid: fixture.txid.clone(),
                previous_block_height: 700_000,
                previous_block_hash: previous_hash.clone(),
            }
        );
        assert_eq!(
            backend.prior_height_requests.lock().unwrap().as_slice(),
            &[vec![700_000]]
        );
        assert!(backend.raw_requests.lock().unwrap().is_empty());

        let new_block_hash = "cc".repeat(32);
        let redrive_backend = MockLiquidMerchantBackend::successful(
            liquid_snapshot(
                700_002,
                vec![LiquidHistoryEntry {
                    txid: fixture.txid.clone(),
                    height: 700_001,
                    block_hash: Some(new_block_hash.clone()),
                }],
                &[(700_000, BLOCK_HASH), (700_001, &new_block_hash)],
            ),
            Some(fixture.raw_transaction.clone()),
        );
        let redriven = observe_liquid_merchant_output(
            &redrive_backend,
            &journal,
            None,
            &fixture.blinding_key_hex,
            PreviousLiquidMerchantConfirmation::Reorged {
                previous_block_height: 700_000,
                previous_block_hash: &previous_hash,
            },
        )
        .await
        .unwrap();
        let LiquidMerchantOutputObservation::Observed(adapted) = redriven else {
            panic!("already-applied demotion must redrive current positive evidence");
        };
        assert_eq!(adapted.observed().block_height(), Some(700_001));
        assert_eq!(
            adapted.observed().block_hash(),
            Some(new_block_hash.as_str())
        );
        assert_eq!(adapted.observed().confirmations(), 2);
        assert_eq!(
            redrive_backend
                .prior_height_requests
                .lock()
                .unwrap()
                .as_slice(),
            &[vec![700_000]]
        );

        let old_block_again = MockLiquidMerchantBackend::successful(
            liquid_snapshot(
                700_002,
                vec![LiquidHistoryEntry {
                    txid: fixture.txid.clone(),
                    height: 700_000,
                    block_hash: Some(previous_hash.clone()),
                }],
                &[(700_000, &previous_hash)],
            ),
            Some(fixture.raw_transaction.clone()),
        );
        assert!(matches!(
            observe_liquid_merchant_output(
                &old_block_again,
                &journal,
                None,
                &fixture.blinding_key_hex,
                PreviousLiquidMerchantConfirmation::Reorged {
                    previous_block_height: 700_000,
                    previous_block_hash: &previous_hash,
                },
            )
            .await,
            Err(LiquidMerchantObservationError::InvalidSnapshot)
        ));
        assert!(old_block_again.raw_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn production_liquid_source_defers_backend_incomplete_and_raw_failures() {
        let fixture = liquid_backend_fixture();
        let sources = liquid_backend_sources(&fixture);
        let journal = fixture.journal(&sources);
        let mempool_snapshot = liquid_snapshot(
            700_001,
            vec![LiquidHistoryEntry {
                txid: fixture.txid.clone(),
                height: -1,
                block_hash: None,
            }],
            &[],
        );

        let mut snapshot_failure = MockLiquidMerchantBackend::successful(
            mempool_snapshot.clone(),
            Some(fixture.raw_transaction.clone()),
        );
        snapshot_failure.snapshot_failure = true;
        assert!(matches!(
            observe_liquid_merchant_output(
                &snapshot_failure,
                &journal,
                None,
                &fixture.blinding_key_hex,
                PreviousLiquidMerchantConfirmation::NeverObserved,
            )
            .await,
            Err(LiquidMerchantObservationError::Backend(_))
        ));

        let mut raw_failure = MockLiquidMerchantBackend::successful(
            mempool_snapshot.clone(),
            Some(fixture.raw_transaction.clone()),
        );
        raw_failure.raw_failure = true;
        assert!(matches!(
            observe_liquid_merchant_output(
                &raw_failure,
                &journal,
                None,
                &fixture.blinding_key_hex,
                PreviousLiquidMerchantConfirmation::NeverObserved,
            )
            .await,
            Err(LiquidMerchantObservationError::Backend(_))
        ));

        let malformed_raw =
            MockLiquidMerchantBackend::successful(mempool_snapshot, Some(vec![0x00]));
        assert!(matches!(
            observe_liquid_merchant_output(
                &malformed_raw,
                &journal,
                None,
                &fixture.blinding_key_hex,
                PreviousLiquidMerchantConfirmation::NeverObserved,
            )
            .await,
            Err(LiquidMerchantObservationError::Adapter(
                MerchantOutputAdapterError::MalformedObservedTransaction
            ))
        ));

        let incomplete = MockLiquidMerchantBackend {
            snapshot: Some(LiquidHistorySnapshotOutcome::Incomplete(
                crate::utxo::LiquidHistorySnapshotLimit::HistoryEntries {
                    observed: 257,
                    limit: 256,
                },
            )),
            snapshot_failure: false,
            raw_transaction: Some(fixture.raw_transaction.clone()),
            raw_failure: false,
            raw_requests: Mutex::new(Vec::new()),
            prior_height_requests: Mutex::new(Vec::new()),
        };
        assert!(matches!(
            observe_liquid_merchant_output(
                &incomplete,
                &journal,
                None,
                &fixture.blinding_key_hex,
                PreviousLiquidMerchantConfirmation::NeverObserved,
            )
            .await,
            Err(LiquidMerchantObservationError::SnapshotIncomplete)
        ));
        assert!(incomplete.raw_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn production_bitcoin_source_preserves_one_and_three_confirmation_boundaries() {
        let attempt = recovery_attempt();
        let raw_transaction = hex::decode(&attempt.raw_tx_hex).unwrap();
        let one_confirmation = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 900_000,
                status: BitcoinRecoveryTransactionStatus::Confirmed {
                    block_height: 900_000,
                    block_hash: BLOCK_HASH.into(),
                },
                prior_block_hash: None,
            },
            Some(raw_transaction.clone()),
        );

        let result = observe_bitcoin_recovery_merchant_output(
            &one_confirmation,
            &attempt,
            None,
            PreviousBitcoinMerchantConfirmation::NeverObserved,
        )
        .await
        .unwrap();
        let BitcoinMerchantOutputObservation::Observed(adapted) = result else {
            panic!("one confirmation must return positive adapter evidence");
        };
        assert_eq!(adapted.observed().confirmations(), 1);
        assert_eq!(
            adapted.verify(&approved_bitcoin(), 1).unwrap().amount_sat(),
            97_000
        );
        assert_eq!(
            adapted.verify(&approved_bitcoin(), 3),
            Err(MerchantOutputVerificationError::InsufficientConfirmations)
        );

        let three_confirmations = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 900_002,
                status: BitcoinRecoveryTransactionStatus::Confirmed {
                    block_height: 900_000,
                    block_hash: BLOCK_HASH.into(),
                },
                prior_block_hash: None,
            },
            Some(raw_transaction),
        );
        let result = observe_bitcoin_recovery_merchant_output(
            &three_confirmations,
            &attempt,
            None,
            PreviousBitcoinMerchantConfirmation::NeverObserved,
        )
        .await
        .unwrap();
        let BitcoinMerchantOutputObservation::Observed(adapted) = result else {
            panic!("three confirmations must return positive adapter evidence");
        };
        assert_eq!(adapted.observed().confirmations(), 3);
        assert_eq!(
            adapted.verify(&approved_bitcoin(), 3).unwrap().amount_sat(),
            97_000
        );
    }

    #[tokio::test]
    async fn production_bitcoin_source_separates_absence_uncertainty_and_wrong_raw_txid() {
        let attempt = recovery_attempt();
        let absent_snapshot = BitcoinRecoveryStatusSnapshot {
            tip_height: 900_000,
            status: BitcoinRecoveryTransactionStatus::Absent,
            prior_block_hash: None,
        };
        let never_seen = MockBitcoinMerchantEvidence::successful(absent_snapshot.clone(), None);
        assert!(matches!(
            observe_bitcoin_recovery_merchant_output(
                &never_seen,
                &attempt,
                None,
                PreviousBitcoinMerchantConfirmation::NeverObserved,
            )
            .await,
            Err(BitcoinMerchantObservationError::CandidateNotObserved)
        ));

        let evicted = MockBitcoinMerchantEvidence::successful(absent_snapshot.clone(), None);
        assert_eq!(
            observe_bitcoin_recovery_merchant_output(
                &evicted,
                &attempt,
                None,
                PreviousBitcoinMerchantConfirmation::Mempool,
            )
            .await
            .unwrap(),
            BitcoinMerchantOutputObservation::Evicted {
                txid: attempt.txid.clone(),
            }
        );
        assert!(evicted.raw_requests.lock().unwrap().is_empty());

        let mut uncertain = MockBitcoinMerchantEvidence::successful(absent_snapshot, None);
        uncertain.snapshot_failure = true;
        assert!(matches!(
            observe_bitcoin_recovery_merchant_output(
                &uncertain,
                &attempt,
                None,
                PreviousBitcoinMerchantConfirmation::Mempool,
            )
            .await,
            Err(BitcoinMerchantObservationError::Backend(_))
        ));

        let raw_transaction = hex::decode(&attempt.raw_tx_hex).unwrap();
        let mut wrong_transaction: Transaction = deserialize(&raw_transaction).unwrap();
        wrong_transaction.output[0].value = Amount::from_sat(96_999);
        let wrong_raw = serialize(&wrong_transaction);
        let wrong_txid = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 900_000,
                status: BitcoinRecoveryTransactionStatus::Mempool,
                prior_block_hash: None,
            },
            Some(wrong_raw),
        );
        assert!(matches!(
            observe_bitcoin_recovery_merchant_output(
                &wrong_txid,
                &attempt,
                None,
                PreviousBitcoinMerchantConfirmation::NeverObserved,
            )
            .await,
            Err(BitcoinMerchantObservationError::Adapter(
                MerchantOutputAdapterError::ObservedTxidMismatch
            ))
        ));
    }

    #[tokio::test]
    async fn production_bitcoin_source_reorg_redrives_new_block_without_loop() {
        let attempt = recovery_attempt();
        let old_block_hash = "bb".repeat(32);
        let current_old_height_hash = "cc".repeat(32);
        let first_tick = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 900_001,
                status: BitcoinRecoveryTransactionStatus::Absent,
                prior_block_hash: Some(current_old_height_hash.clone()),
            },
            None,
        );
        let demoted = observe_bitcoin_recovery_merchant_output(
            &first_tick,
            &attempt,
            None,
            PreviousBitcoinMerchantConfirmation::Confirmed {
                block_height: 900_000,
                block_hash: &old_block_hash,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            demoted,
            BitcoinMerchantOutputObservation::ReorgDemoted {
                txid: attempt.txid.clone(),
                previous_block_height: 900_000,
                previous_block_hash: old_block_hash.clone(),
            }
        );

        let raw_transaction = hex::decode(&attempt.raw_tx_hex).unwrap();
        let new_block_hash = "dd".repeat(32);
        let redrive = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 900_003,
                status: BitcoinRecoveryTransactionStatus::Confirmed {
                    block_height: 900_002,
                    block_hash: new_block_hash.clone(),
                },
                prior_block_hash: Some(current_old_height_hash),
            },
            Some(raw_transaction),
        );
        let redriven = observe_bitcoin_recovery_merchant_output(
            &redrive,
            &attempt,
            None,
            PreviousBitcoinMerchantConfirmation::Reorged {
                previous_block_height: 900_000,
                previous_block_hash: &old_block_hash,
            },
        )
        .await
        .unwrap();
        let BitcoinMerchantOutputObservation::Observed(adapted) = redriven else {
            panic!("durable reorg state must redrive the candidate's new block");
        };
        assert_eq!(adapted.observed().block_height(), Some(900_002));
        assert_eq!(
            adapted.observed().block_hash(),
            Some(new_block_hash.as_str())
        );
        assert_eq!(adapted.observed().confirmations(), 2);
        assert_eq!(
            redrive.prior_height_requests.lock().unwrap().as_slice(),
            &[Some(900_000)]
        );
    }

    #[tokio::test]
    async fn production_bitcoin_source_tip_regression_demotes_once_then_redrives() {
        let attempt = recovery_attempt();
        let old_block_hash = "bb".repeat(32);
        let regressed_tip = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 899_999,
                status: BitcoinRecoveryTransactionStatus::Absent,
                prior_block_hash: None,
            },
            None,
        );
        let demoted = observe_bitcoin_recovery_merchant_output(
            &regressed_tip,
            &attempt,
            None,
            PreviousBitcoinMerchantConfirmation::Confirmed {
                block_height: 900_000,
                block_hash: &old_block_hash,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            demoted,
            BitcoinMerchantOutputObservation::ReorgDemoted {
                txid: attempt.txid.clone(),
                previous_block_height: 900_000,
                previous_block_hash: old_block_hash.clone(),
            }
        );

        let redrive = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 899_999,
                status: BitcoinRecoveryTransactionStatus::Mempool,
                prior_block_hash: None,
            },
            Some(hex::decode(&attempt.raw_tx_hex).unwrap()),
        );
        let redriven = observe_bitcoin_recovery_merchant_output(
            &redrive,
            &attempt,
            None,
            PreviousBitcoinMerchantConfirmation::Reorged {
                previous_block_height: 900_000,
                previous_block_hash: &old_block_hash,
            },
        )
        .await
        .unwrap();
        let BitcoinMerchantOutputObservation::Observed(adapted) = redriven else {
            panic!("durable tip-regression demotion must redrive mempool evidence");
        };
        assert_eq!(adapted.observed().confirmations(), 0);
        assert_eq!(adapted.candidate_txid(), attempt.txid);
    }

    #[tokio::test]
    async fn production_bitcoin_source_observes_only_full_linked_replacement_journal() {
        let attempt = recovery_attempt();
        let original_raw = hex::decode(&attempt.raw_tx_hex).unwrap();
        let mut replacement_transaction: Transaction = deserialize(&original_raw).unwrap();
        replacement_transaction.input[0].sequence = Sequence::ZERO;
        replacement_transaction.output[0].value = Amount::from_sat(96_500);
        let replacement_raw = serialize(&replacement_transaction);
        let replacement_txid = replacement_transaction.compute_txid().to_string();
        let source = &attempt.source_prevouts.0[0];
        let replacement_sources = [MerchantSourcePrevout {
            txid: &source.txid,
            vout: source.vout,
            amount_sat: source.amount_sat,
            script_pubkey_hex: &source.script_pubkey_hex,
        }];
        let asset = MerchantAsset::Bitcoin;
        let replacement_journal = MerchantTransactionJournalEvidence {
            raw_transaction: &replacement_raw,
            txid: &replacement_txid,
            source_prevouts: &replacement_sources,
            merchant: MerchantOutputCommitment {
                destination_address: APPROVED_ADDRESS,
                destination_script_hex: APPROVED_SCRIPT,
                asset: &asset,
                amount_sat: 96_500,
                vout: 0,
            },
        };
        let linked = LinkedReplacementJournalEvidence {
            replaces_txid: &attempt.txid,
            replacement: replacement_journal,
        };
        let backend = MockBitcoinMerchantEvidence::successful(
            BitcoinRecoveryStatusSnapshot {
                tip_height: 900_000,
                status: BitcoinRecoveryTransactionStatus::Mempool,
                prior_block_hash: None,
            },
            Some(replacement_raw.clone()),
        );

        let result = observe_bitcoin_recovery_merchant_output(
            &backend,
            &attempt,
            Some(&linked),
            PreviousBitcoinMerchantConfirmation::NeverObserved,
        )
        .await
        .unwrap();
        let BitcoinMerchantOutputObservation::Observed(adapted) = result else {
            panic!("persisted linked replacement must return positive evidence");
        };
        assert_eq!(adapted.original_journal_txid(), attempt.txid);
        assert_eq!(adapted.candidate_txid(), replacement_txid);
        assert!(adapted.is_linked_replacement());
        assert_eq!(adapted.observed().amount_sat(), 96_500);
    }
}
