use std::sync::Mutex;

use boltz_client::bitcoin::secp256k1::Keypair;
use boltz_client::swaps::boltz::{
    BoltzApiClientV2, CreateReverseRequest, CreateReverseResponse,
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
    next_swap_index: Mutex<u64>,
}

impl BoltzService {
    pub fn new(boltz_url: &str, swap_master_key: SwapMasterKey) -> Self {
        Self {
            api: BoltzApiClientV2::new(boltz_url.to_string(), None),
            swap_master_key,
            next_swap_index: Mutex::new(0),
        }
    }

    fn next_keypair(&self) -> Result<(u64, Keypair), AppError> {
        let mut index = self.next_swap_index.lock().unwrap();
        let keypair = self
            .swap_master_key
            .derive_swapkey(*index)
            .map_err(|e| AppError::BoltzError(format!("key derivation failed: {e}")))?;
        let current = *index;
        *index += 1;
        Ok((current, keypair))
    }

    pub async fn create_reverse_swap(
        &self,
        amount_sat: u64,
        address: &str,
        description_hash: &str,
    ) -> Result<SwapResult, AppError> {
        let (_, keypair) = self.next_keypair()?;
        let preimage = Preimage::from_swap_key(&keypair);

        let claim_public_key = PublicKey::new(keypair.public_key());

        let request = CreateReverseRequest {
            from: "BTC".to_string(),
            to: "L-BTC".to_string(),
            claim_public_key,
            invoice: None,
            invoice_amount: Some(amount_sat),
            preimage_hash: Some(preimage.sha256),
            description: None,
            description_hash: Some(description_hash.to_string()),
            address: Some(address.to_string()),
            address_signature: None,
            referral_id: None,
            webhook: None,
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
