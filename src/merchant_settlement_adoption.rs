//! Runtime-facing identities and exact accounting intents for chain-swap
//! merchant settlement.
//!
//! The confirmation lifecycle decides *when* accounting changes. This module
//! owns the narrower adoption boundary: only a [`VerifiedMerchantOutput`] can
//! supply an amount, transaction, output, asset, and destination to invoice
//! accounting. The original journal identifies the replacement family while
//! the observed transaction and vout identify one immutable accounting event.
//! A replacement therefore never rewrites the original event's txid.

use std::fmt;

use uuid::Uuid;

use crate::merchant_output_verifier::{
    verify_merchant_output, ApprovedMerchantDestination, JournaledMerchantTransaction,
    MerchantAsset, MerchantOutputEvidence, ObservedMerchantOutput, VerifiedMerchantOutput,
};

const MAX_BOLTZ_SWAP_ID_LEN: usize = 200;

/// Which merchant settlement executor produced the verified output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantSettlementPath {
    /// Bullnym claimed the Liquid server lock to the merchant destination.
    LiquidClaim,
    /// Bullnym recovered the Bitcoin user lock to the committed destination.
    BitcoinRecovery,
}

impl MerchantSettlementPath {
    pub const fn accounting_source(self) -> &'static str {
        match self {
            Self::LiquidClaim => "bitcoin_boltz_chain",
            Self::BitcoinRecovery => "bitcoin_boltz_recovery",
        }
    }

    const fn accepts(self, asset: &MerchantAsset) -> bool {
        matches!(
            (self, asset),
            (Self::LiquidClaim, MerchantAsset::Liquid(_))
                | (Self::BitcoinRecovery, MerchantAsset::Bitcoin)
        )
    }
}

/// Stable invoice/swap context supplied by the claim, recovery, or repair
/// service. It contains no requested/provider amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantSettlementContext {
    invoice_id: Uuid,
    chain_swap_id: Uuid,
    boltz_swap_id: String,
    path: MerchantSettlementPath,
}

impl MerchantSettlementContext {
    pub fn new(
        invoice_id: Uuid,
        chain_swap_id: Uuid,
        boltz_swap_id: impl Into<String>,
        path: MerchantSettlementPath,
    ) -> Result<Self, MerchantSettlementAdoptionError> {
        let boltz_swap_id = boltz_swap_id.into();
        if invoice_id.is_nil() || chain_swap_id.is_nil() {
            return Err(MerchantSettlementAdoptionError::InvalidContext);
        }
        if boltz_swap_id.is_empty()
            || boltz_swap_id.len() > MAX_BOLTZ_SWAP_ID_LEN
            || boltz_swap_id.chars().any(char::is_whitespace)
        {
            return Err(MerchantSettlementAdoptionError::InvalidContext);
        }
        Ok(Self {
            invoice_id,
            chain_swap_id,
            boltz_swap_id,
            path,
        })
    }

    pub const fn invoice_id(&self) -> Uuid {
        self.invoice_id
    }

    pub const fn chain_swap_id(&self) -> Uuid {
        self.chain_swap_id
    }

    pub fn boltz_swap_id(&self) -> &str {
        &self.boltz_swap_id
    }

    pub const fn path(&self) -> MerchantSettlementPath {
        self.path
    }
}

/// Two-level immutable identity for accounting.
///
/// `family_key` is stable across an explicitly linked replacement. `event_key`
/// is specific to the actual observed output, so an original and replacement
/// can both remain in history while at most one is active.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MerchantOutputAccountingIdentity {
    family_key: String,
    event_key: String,
}

impl MerchantOutputAccountingIdentity {
    fn new(context: &MerchantSettlementContext, output: &VerifiedMerchantOutput) -> Self {
        let family_key = format!(
            "chain_swap_merchant_output:{}:{}",
            context.chain_swap_id(),
            output.journal_txid()
        );
        let event_key = format!("{family_key}:{}:{}", output.txid(), output.vout());
        Self {
            family_key,
            event_key,
        }
    }

    pub fn family_key(&self) -> &str {
        &self.family_key
    }

    pub fn event_key(&self) -> &str {
        &self.event_key
    }
}

/// Retained, confirmed verifier evidence. This is the only object from which
/// settlement repair may reconstruct an accounting intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedMerchantOutputEvidence {
    invoice_id: Uuid,
    chain_swap_id: Uuid,
    boltz_swap_id: String,
    path: MerchantSettlementPath,
    identity: MerchantOutputAccountingIdentity,
    journal_txid: String,
    txid: String,
    destination_address: String,
    destination_script_hex: String,
    asset: MerchantAsset,
    actual_amount_sat: i64,
    vout: u32,
    confirmations: u32,
    block_height: u32,
    block_hash: String,
    linked_replacement: bool,
}

/// Storage-safe representation of retained verifier evidence. Repository
/// adapters persist these primitive fields and must call
/// [`ConfirmedMerchantOutputEvidence::restore`] before the data regains runtime
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedMerchantOutputEvidenceSnapshot {
    pub invoice_id: Uuid,
    pub chain_swap_id: Uuid,
    pub boltz_swap_id: String,
    pub path: MerchantSettlementPath,
    pub family_key: String,
    pub event_key: String,
    pub journal_txid: String,
    pub txid: String,
    pub destination_address: String,
    pub destination_script_hex: String,
    pub asset: MerchantAsset,
    pub actual_amount_sat: i64,
    pub vout: u32,
    pub confirmations: u32,
    pub block_height: u32,
    pub block_hash: String,
    pub linked_replacement: bool,
}

impl ConfirmedMerchantOutputEvidence {
    /// Copy exact verified evidence into a schema-independent persistence
    /// packet. Requested, quoted, provider, and broadcast amounts are absent by
    /// construction.
    pub fn from_verified(
        context: &MerchantSettlementContext,
        output: &VerifiedMerchantOutput,
    ) -> Result<Self, MerchantSettlementAdoptionError> {
        if !context.path().accepts(output.asset()) {
            return Err(MerchantSettlementAdoptionError::PathAssetMismatch);
        }
        let actual_amount_sat = i64::try_from(output.amount_sat())
            .ok()
            .filter(|amount| *amount > 0)
            .ok_or(MerchantSettlementAdoptionError::InvalidVerifiedAmount)?;
        Ok(Self {
            invoice_id: context.invoice_id(),
            chain_swap_id: context.chain_swap_id(),
            boltz_swap_id: context.boltz_swap_id().to_owned(),
            path: context.path(),
            identity: MerchantOutputAccountingIdentity::new(context, output),
            journal_txid: output.journal_txid().to_owned(),
            txid: output.txid().to_owned(),
            destination_address: output.destination_address().to_owned(),
            destination_script_hex: output.destination_script_hex().to_owned(),
            asset: output.asset().clone(),
            actual_amount_sat,
            vout: output.vout(),
            confirmations: output.confirmations(),
            block_height: output.block_height(),
            block_hash: output.block_hash().to_owned(),
            linked_replacement: output.is_linked_replacement(),
        })
    }

    pub fn snapshot(&self) -> ConfirmedMerchantOutputEvidenceSnapshot {
        ConfirmedMerchantOutputEvidenceSnapshot {
            invoice_id: self.invoice_id,
            chain_swap_id: self.chain_swap_id,
            boltz_swap_id: self.boltz_swap_id.clone(),
            path: self.path,
            family_key: self.identity.family_key.clone(),
            event_key: self.identity.event_key.clone(),
            journal_txid: self.journal_txid.clone(),
            txid: self.txid.clone(),
            destination_address: self.destination_address.clone(),
            destination_script_hex: self.destination_script_hex.clone(),
            asset: self.asset.clone(),
            actual_amount_sat: self.actual_amount_sat,
            vout: self.vout,
            confirmations: self.confirmations,
            block_height: self.block_height,
            block_hash: self.block_hash.clone(),
            linked_replacement: self.linked_replacement,
        }
    }

    /// Rehydrate immutable evidence only after checking its complete context,
    /// family/event identity, chain shape, and positive exact amount. This is a
    /// corruption boundary, not a verifier: only repository rows originally
    /// produced by [`Self::from_verified`] may be supplied.
    pub fn restore(
        snapshot: ConfirmedMerchantOutputEvidenceSnapshot,
    ) -> Result<Self, MerchantSettlementAdoptionError> {
        let context = MerchantSettlementContext::new(
            snapshot.invoice_id,
            snapshot.chain_swap_id,
            snapshot.boltz_swap_id.clone(),
            snapshot.path,
        )?;
        let canonical_hash = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        };
        let script_valid = !snapshot.destination_script_hex.is_empty()
            && snapshot.destination_script_hex.len() % 2 == 0
            && snapshot
                .destination_script_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        let asset_valid = snapshot.path.accepts(&snapshot.asset)
            && match &snapshot.asset {
                MerchantAsset::Bitcoin => true,
                MerchantAsset::Liquid(asset_id) => canonical_hash(asset_id),
            };
        let expected_family = format!(
            "chain_swap_merchant_output:{}:{}",
            context.chain_swap_id(),
            snapshot.journal_txid
        );
        let expected_event = format!("{expected_family}:{}:{}", snapshot.txid, snapshot.vout);
        if !canonical_hash(&snapshot.journal_txid)
            || !canonical_hash(&snapshot.txid)
            || !canonical_hash(&snapshot.block_hash)
            || snapshot.destination_address.is_empty()
            || snapshot.destination_address.len() > 200
            || !script_valid
            || !asset_valid
            || snapshot.actual_amount_sat <= 0
            || snapshot.confirmations == 0
            || snapshot.block_height == 0
            || snapshot.linked_replacement == (snapshot.txid == snapshot.journal_txid)
            || snapshot.family_key != expected_family
            || snapshot.event_key != expected_event
        {
            return Err(MerchantSettlementAdoptionError::InvalidPersistedEvidence);
        }
        let approved = match &snapshot.asset {
            MerchantAsset::Bitcoin => ApprovedMerchantDestination::bitcoin(
                snapshot.destination_address.clone(),
                snapshot.destination_script_hex.clone(),
            ),
            MerchantAsset::Liquid(asset_id) => ApprovedMerchantDestination::liquid(
                snapshot.destination_address.clone(),
                snapshot.destination_script_hex.clone(),
                asset_id.clone(),
            ),
        };
        let destination_vout = i32::try_from(snapshot.vout)
            .map_err(|_| MerchantSettlementAdoptionError::InvalidPersistedEvidence)?;
        let candidate = if snapshot.linked_replacement {
            JournaledMerchantTransaction::linked_replacement(
                snapshot.txid.clone(),
                snapshot.journal_txid.clone(),
                snapshot.destination_address.clone(),
                snapshot.destination_script_hex.clone(),
                snapshot.asset.clone(),
                snapshot.actual_amount_sat,
                destination_vout,
            )
        } else {
            JournaledMerchantTransaction::original(
                snapshot.txid.clone(),
                snapshot.destination_address.clone(),
                snapshot.destination_script_hex.clone(),
                snapshot.asset.clone(),
                snapshot.actual_amount_sat,
                destination_vout,
            )
        };
        let amount_sat = u64::try_from(snapshot.actual_amount_sat)
            .map_err(|_| MerchantSettlementAdoptionError::InvalidPersistedEvidence)?;
        let observed = ObservedMerchantOutput::new(
            snapshot.txid.clone(),
            snapshot.destination_script_hex.clone(),
            snapshot.asset.clone(),
            amount_sat,
            snapshot.vout,
            snapshot.confirmations,
            Some(snapshot.block_height),
            Some(snapshot.block_hash.clone()),
        );
        let verified = verify_merchant_output(
            &snapshot.journal_txid,
            &candidate,
            &approved,
            &MerchantOutputEvidence::Authoritative(observed),
            1,
        )
        .map_err(|_| MerchantSettlementAdoptionError::InvalidPersistedEvidence)?;
        let restored = Self::from_verified(&context, &verified)?;
        if restored.snapshot() != snapshot {
            return Err(MerchantSettlementAdoptionError::InvalidPersistedEvidence);
        }
        Ok(restored)
    }

    pub fn identity(&self) -> &MerchantOutputAccountingIdentity {
        &self.identity
    }

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

    pub const fn actual_amount_sat(&self) -> i64 {
        self.actual_amount_sat
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

    /// Exact idempotent invoice-accounting intent used by first-confirmation
    /// handling and by restart repair.
    pub fn accounting_intent(
        &self,
        context: &MerchantSettlementContext,
    ) -> Result<MerchantOutputAccountingIntent, MerchantSettlementAdoptionError> {
        if self.invoice_id != context.invoice_id()
            || self.chain_swap_id != context.chain_swap_id()
            || self.boltz_swap_id != context.boltz_swap_id()
            || self.path != context.path()
        {
            return Err(MerchantSettlementAdoptionError::ContextMismatch);
        }
        Ok(MerchantOutputAccountingIntent {
            invoice_id: context.invoice_id(),
            chain_swap_id: context.chain_swap_id(),
            boltz_swap_id: context.boltz_swap_id().to_owned(),
            path: context.path(),
            identity: self.identity.clone(),
            txid: self.txid.clone(),
            vout: self.vout,
            actual_amount_sat: self.actual_amount_sat,
            destination_address: self.destination_address.clone(),
            asset: self.asset.clone(),
        })
    }
}

/// Complete immutable accounting insertion/upsert intent. The future
/// repository adapter applies this together with the lifecycle transition in
/// one database transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantOutputAccountingIntent {
    pub invoice_id: Uuid,
    pub chain_swap_id: Uuid,
    pub boltz_swap_id: String,
    pub path: MerchantSettlementPath,
    pub identity: MerchantOutputAccountingIdentity,
    pub txid: String,
    pub vout: u32,
    pub actual_amount_sat: i64,
    pub destination_address: String,
    pub asset: MerchantAsset,
}

impl MerchantOutputAccountingIntent {
    pub const fn rail(&self) -> &'static str {
        "bitcoin"
    }

    pub const fn source(&self) -> &'static str {
        self.path.accounting_source()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantSettlementAdoptionError {
    InvalidContext,
    PathAssetMismatch,
    InvalidVerifiedAmount,
    ContextMismatch,
    InvalidPersistedEvidence,
}

impl fmt::Display for MerchantSettlementAdoptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContext => "merchant settlement context is invalid",
            Self::PathAssetMismatch => "verified merchant asset does not match the settlement path",
            Self::InvalidVerifiedAmount => "verified merchant amount cannot be accounted",
            Self::ContextMismatch => "merchant settlement context does not own the evidence",
            Self::InvalidPersistedEvidence => "persisted merchant settlement evidence is invalid",
        })
    }
}

impl std::error::Error for MerchantSettlementAdoptionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use crate::merchant_output_verifier::{
        verify_merchant_output, ApprovedMerchantDestination, JournaledMerchantTransaction,
        MerchantOutputEvidence, ObservedMerchantOutput,
    };
    use lwk_wollet::elements::Address as LiquidAddress;

    const ADDRESS: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const SCRIPT: &str = "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ORIGINAL_TXID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const REPLACEMENT_TXID: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const BLOCK_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LIQUID_ASSET: &str = "6f0279e9ed041c3d710a9f57d0c02928416453c0e87cbbe43c8ca792a3b6e499";
    const LIQUID_ADDRESS: &str =
        "lq1qqvxk052kf3qtkxmrakx50a9gc3smqad2ync54hzntjt980kfej9kkfe0247rp5h4yzmdftsahhw64uy8pzfe7cpg4fgykm7cv";

    fn context(path: MerchantSettlementPath) -> MerchantSettlementContext {
        MerchantSettlementContext::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            "swap-issue83-adoption",
            path,
        )
        .unwrap()
    }

    fn verified(
        txid: &str,
        replacement: bool,
        amount_sat: u64,
        asset: MerchantAsset,
    ) -> VerifiedMerchantOutput {
        let (address, script) = match &asset {
            MerchantAsset::Bitcoin => (ADDRESS.to_owned(), SCRIPT.to_owned()),
            MerchantAsset::Liquid(_) => {
                let address = LiquidAddress::from_str(LIQUID_ADDRESS).unwrap();
                (
                    LIQUID_ADDRESS.to_owned(),
                    hex::encode(address.script_pubkey().as_bytes()),
                )
            }
        };
        let approved = match &asset {
            MerchantAsset::Bitcoin => {
                ApprovedMerchantDestination::bitcoin(address.clone(), script.clone())
            }
            MerchantAsset::Liquid(asset_id) => ApprovedMerchantDestination::liquid(
                address.clone(),
                script.clone(),
                asset_id.clone(),
            ),
        };
        let candidate = if replacement {
            JournaledMerchantTransaction::linked_replacement(
                txid,
                ORIGINAL_TXID,
                address.clone(),
                script.clone(),
                asset.clone(),
                i64::try_from(amount_sat).unwrap(),
                0,
            )
        } else {
            JournaledMerchantTransaction::original(
                txid,
                address.clone(),
                script.clone(),
                asset.clone(),
                i64::try_from(amount_sat).unwrap(),
                0,
            )
        };
        verify_merchant_output(
            ORIGINAL_TXID,
            &candidate,
            &approved,
            &MerchantOutputEvidence::Authoritative(ObservedMerchantOutput::new(
                txid,
                script,
                asset,
                amount_sat,
                0,
                1,
                Some(840_000),
                Some(BLOCK_HASH.to_owned()),
            )),
            1,
        )
        .unwrap()
    }

    #[test]
    fn original_and_replacement_share_family_but_keep_immutable_event_txids() {
        let context = context(MerchantSettlementPath::BitcoinRecovery);
        let original = ConfirmedMerchantOutputEvidence::from_verified(
            &context,
            &verified(ORIGINAL_TXID, false, 97_000, MerchantAsset::Bitcoin),
        )
        .unwrap();
        let replacement = ConfirmedMerchantOutputEvidence::from_verified(
            &context,
            &verified(REPLACEMENT_TXID, true, 96_000, MerchantAsset::Bitcoin),
        )
        .unwrap();

        assert_eq!(
            original.identity().family_key(),
            replacement.identity().family_key()
        );
        assert_ne!(
            original.identity().event_key(),
            replacement.identity().event_key()
        );
        assert!(original.identity().event_key().contains(ORIGINAL_TXID));
        assert!(replacement
            .identity()
            .event_key()
            .contains(REPLACEMENT_TXID));
        assert!(!original.is_linked_replacement());
        assert!(replacement.is_linked_replacement());
    }

    #[test]
    fn accounting_intent_uses_only_the_verified_actual_output() {
        let context = context(MerchantSettlementPath::LiquidClaim);
        let evidence = ConfirmedMerchantOutputEvidence::from_verified(
            &context,
            &verified(
                ORIGINAL_TXID,
                false,
                73_219,
                MerchantAsset::Liquid(LIQUID_ASSET.to_owned()),
            ),
        )
        .unwrap();
        let intent = evidence.accounting_intent(&context).unwrap();

        assert_eq!(intent.actual_amount_sat, 73_219);
        assert_eq!(intent.txid, ORIGINAL_TXID);
        assert_eq!(intent.vout, 0);
        assert_eq!(intent.destination_address, LIQUID_ADDRESS);
        assert_eq!(intent.asset, MerchantAsset::Liquid(LIQUID_ASSET.to_owned()));
        assert_eq!(intent.rail(), "bitcoin");
        assert_eq!(intent.source(), "bitcoin_boltz_chain");
        assert_eq!(intent.identity, evidence.identity);
    }

    #[test]
    fn persisted_evidence_restore_rederives_destination_script() {
        let context = context(MerchantSettlementPath::BitcoinRecovery);
        let evidence = ConfirmedMerchantOutputEvidence::from_verified(
            &context,
            &verified(ORIGINAL_TXID, false, 73_219, MerchantAsset::Bitcoin),
        )
        .unwrap();

        let mut wrong_script = evidence.snapshot();
        wrong_script.destination_script_hex = "51".to_owned();
        assert_eq!(
            ConfirmedMerchantOutputEvidence::restore(wrong_script),
            Err(MerchantSettlementAdoptionError::InvalidPersistedEvidence)
        );

        let mut wrong_address = evidence.snapshot();
        wrong_address.destination_address = LIQUID_ADDRESS.to_owned();
        assert_eq!(
            ConfirmedMerchantOutputEvidence::restore(wrong_address),
            Err(MerchantSettlementAdoptionError::InvalidPersistedEvidence)
        );
    }

    #[test]
    fn invalid_or_cross_swap_context_cannot_create_an_accounting_intent() {
        assert_eq!(
            MerchantSettlementContext::new(
                Uuid::nil(),
                Uuid::from_u128(2),
                "swap",
                MerchantSettlementPath::LiquidClaim,
            ),
            Err(MerchantSettlementAdoptionError::InvalidContext)
        );
        assert_eq!(
            MerchantSettlementContext::new(
                Uuid::from_u128(1),
                Uuid::from_u128(2),
                "contains whitespace",
                MerchantSettlementPath::LiquidClaim,
            ),
            Err(MerchantSettlementAdoptionError::InvalidContext)
        );

        let owning = context(MerchantSettlementPath::LiquidClaim);
        let other = MerchantSettlementContext::new(
            owning.invoice_id(),
            Uuid::from_u128(3),
            owning.boltz_swap_id(),
            owning.path(),
        )
        .unwrap();
        let evidence = ConfirmedMerchantOutputEvidence::from_verified(
            &owning,
            &verified(
                ORIGINAL_TXID,
                false,
                51_234,
                MerchantAsset::Liquid(LIQUID_ASSET.to_owned()),
            ),
        )
        .unwrap();
        assert_eq!(
            evidence.accounting_intent(&other),
            Err(MerchantSettlementAdoptionError::ContextMismatch)
        );
    }

    #[test]
    fn settlement_path_rejects_verified_evidence_from_the_other_chain() {
        let bitcoin = verified(ORIGINAL_TXID, false, 42_000, MerchantAsset::Bitcoin);
        assert_eq!(
            ConfirmedMerchantOutputEvidence::from_verified(
                &context(MerchantSettlementPath::LiquidClaim),
                &bitcoin,
            ),
            Err(MerchantSettlementAdoptionError::PathAssetMismatch)
        );

        let liquid = verified(
            ORIGINAL_TXID,
            false,
            42_000,
            MerchantAsset::Liquid(LIQUID_ASSET.to_owned()),
        );
        assert_eq!(
            ConfirmedMerchantOutputEvidence::from_verified(
                &context(MerchantSettlementPath::BitcoinRecovery),
                &liquid,
            ),
            Err(MerchantSettlementAdoptionError::PathAssetMismatch)
        );
    }
}
