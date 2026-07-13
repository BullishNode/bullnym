//! Fail-closed verification of a confirmed chain-swap merchant output.
//!
//! This module has no accounting or lifecycle writes. Its successful output is
//! the narrow evidence packet a later, atomic accounting transition may
//! consume. Callers remain responsible for sourcing `Authoritative` evidence
//! from locally verified raw transaction and chain-inclusion data.

use std::{fmt, str::FromStr};

use bitcoin::{consensus::deserialize, Address, Network, Transaction};
use lwk_wollet::elements::{Address as LiquidAddress, AddressParams};

use crate::db::ChainSwapTxAttempt;

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
}

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
}
