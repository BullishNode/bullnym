use boltz_client::bitcoin::secp256k1::Keypair;
use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::boltz::{
    BoltzApiClientV2, ChainSwapStates, CreateChainRequest, CreateChainResponse,
    CreateReverseRequest, CreateReverseResponse, RevSwapStates, Webhook,
};
use boltz_client::util::secrets::{Preimage, SwapMasterKey};
use boltz_client::PublicKey;

use crate::error::AppError;

pub struct SwapResult {
    pub swap_id: String,
    pub invoice: String,
    pub preimage: Vec<u8>,
    pub claim_public_key: PublicKey,
    pub claim_keypair: Keypair,
    pub boltz_response: CreateReverseResponse,
}

pub struct ChainSwapResult {
    pub swap_id: String,
    pub lockup_address: String,
    pub lockup_bip21: Option<String>,
    pub user_lock_amount_sat: u64,
    pub server_lock_amount_sat: u64,
    pub preimage: Vec<u8>,
    pub claim_keypair: Keypair,
    pub refund_keypair: Keypair,
    pub boltz_response: CreateChainResponse,
}

pub struct BoltzService {
    api: BoltzApiClientV2,
    swap_master_key: SwapMasterKey,
    webhook_url: Option<String>,
}

impl BoltzService {
    pub fn new(
        boltz_url: &str,
        swap_master_key: SwapMasterKey,
        webhook_url: Option<String>,
    ) -> Self {
        Self {
            api: BoltzApiClientV2::new(boltz_url.to_string(), None),
            swap_master_key,
            webhook_url,
        }
    }

    pub async fn create_reverse_swap(
        &self,
        swap_key_index: u64,
        amount_sat: u64,
        description: Option<&str>,
        description_hash: Option<&str>,
    ) -> Result<SwapResult, AppError> {
        let keypair = self
            .swap_master_key
            .derive_swapkey(swap_key_index)
            .map_err(|e| AppError::BoltzError(format!("key derivation failed: {e}")))?;
        let preimage = Preimage::from_swap_key(&keypair);

        let claim_public_key = PublicKey::new(keypair.public_key());

        // No `address` / `address_signature`: bullnym deprecates Magic Routing
        // Hint to keep descriptor allocation off the unauthenticated callback
        // path. See docs/lud-22-vs-mrh-research.md.
        let request = CreateReverseRequest {
            from: "BTC".to_string(),
            to: "L-BTC".to_string(),
            claim_public_key,
            invoice: None,
            invoice_amount: Some(amount_sat),
            preimage_hash: Some(preimage.sha256),
            description: description.map(str::to_owned),
            description_hash: description_hash.map(str::to_owned),
            address: None,
            address_signature: None,
            referral_id: None,
            webhook: self.webhook_url.as_ref().map(|url| Webhook {
                url: url.clone(),
                hash_swap_id: None,
                status: Some(vec![
                    RevSwapStates::TransactionMempool,
                    RevSwapStates::TransactionConfirmed,
                    RevSwapStates::InvoiceSettled,
                    RevSwapStates::SwapExpired,
                    RevSwapStates::TransactionFailed,
                ]),
            }),
        };

        let response: CreateReverseResponse = self
            .api
            .post_reverse_req(request)
            .await
            .map_err(|e| AppError::BoltzError(format!("{e}")))?;

        let invoice = response
            .invoice
            .clone()
            .ok_or_else(|| AppError::BoltzError("no invoice returned".to_string()))?;

        Ok(SwapResult {
            swap_id: response.id.clone(),
            invoice,
            preimage: preimage.bytes.map(|b| b.to_vec()).unwrap_or_default(),
            claim_public_key,
            claim_keypair: keypair,
            boltz_response: response,
        })
    }

    pub async fn create_btc_to_lbtc_chain_swap(
        &self,
        claim_key_index: u64,
        refund_key_index: u64,
        amount_sat: u64,
    ) -> Result<ChainSwapResult, AppError> {
        let claim_keypair = self
            .swap_master_key
            .derive_swapkey(claim_key_index)
            .map_err(|e| AppError::BoltzError(format!("claim key derivation failed: {e}")))?;
        let refund_keypair = self
            .swap_master_key
            .derive_swapkey(refund_key_index)
            .map_err(|e| AppError::BoltzError(format!("refund key derivation failed: {e}")))?;
        let preimage = Preimage::from_swap_key(&claim_keypair);

        let claim_public_key = PublicKey::new(claim_keypair.public_key());
        let refund_public_key = PublicKey::new(refund_keypair.public_key());

        let request = CreateChainRequest {
            from: "BTC".to_string(),
            to: "L-BTC".to_string(),
            preimage_hash: preimage.sha256,
            claim_public_key: Some(claim_public_key),
            refund_public_key: Some(refund_public_key),
            user_lock_amount: Some(amount_sat),
            server_lock_amount: None,
            pair_hash: None,
            referral_id: None,
            webhook: self.webhook_url.as_ref().map(|url| Webhook {
                url: url.clone(),
                hash_swap_id: None,
                status: Some(vec![
                    ChainSwapStates::Created,
                    ChainSwapStates::TransactionZeroConfRejected,
                    ChainSwapStates::TransactionMempool,
                    ChainSwapStates::TransactionConfirmed,
                    ChainSwapStates::TransactionServerMempool,
                    ChainSwapStates::TransactionServerConfirmed,
                    ChainSwapStates::TransactionClaimed,
                    ChainSwapStates::TransactionLockupFailed,
                    ChainSwapStates::SwapExpired,
                    ChainSwapStates::TransactionFailed,
                    ChainSwapStates::TransactionRefunded,
                ]),
            }),
        };

        let response: CreateChainResponse = self
            .api
            .post_chain_req(request)
            .await
            .map_err(|e| AppError::BoltzError(format!("{e}")))?;

        response
            .validate(
                &claim_public_key,
                &refund_public_key,
                Chain::Bitcoin(BitcoinChain::Bitcoin),
                Chain::Liquid(LiquidChain::Liquid),
            )
            .map_err(|e| AppError::BoltzError(format!("invalid chain swap response: {e}")))?;

        Ok(ChainSwapResult {
            swap_id: response.id.clone(),
            lockup_address: response.lockup_details.lockup_address.clone(),
            lockup_bip21: response.lockup_details.bip21.clone(),
            user_lock_amount_sat: response.lockup_details.amount,
            server_lock_amount_sat: response.claim_details.amount,
            preimage: preimage.bytes.map(|b| b.to_vec()).unwrap_or_default(),
            claim_keypair,
            refund_keypair,
            boltz_response: response,
        })
    }
}
