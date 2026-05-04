use boltz_client::bitcoin::secp256k1::Keypair;
use boltz_client::swaps::boltz::{
    BoltzApiClientV2, CreateReverseRequest, CreateReverseResponse, RevSwapStates, Webhook,
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

pub struct BoltzService {
    api: BoltzApiClientV2,
    swap_master_key: SwapMasterKey,
    webhook_url: Option<String>,
}

impl BoltzService {
    pub fn new(boltz_url: &str, swap_master_key: SwapMasterKey, webhook_url: Option<String>) -> Self {
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
        description_hash: &str,
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
            description: None,
            description_hash: Some(description_hash.to_string()),
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
            claim_covenant: None,
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
}
