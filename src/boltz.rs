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
    /// Fast-fails user-facing swap creation during a Boltz outage instead of
    /// letting every call stall to the client timeout. See issue #31.
    breaker: crate::boltz_breaker::BoltzBreaker,
}

impl BoltzService {
    pub fn new(
        boltz_url: &str,
        swap_master_key: SwapMasterKey,
        webhook_url: Option<String>,
    ) -> Self {
        Self {
            // Bound request-path Boltz calls: Boltz normally answers in <2s, so
            // a 10s ceiling fails fast with a clean error when Boltz hangs
            // (e.g. degraded under load) instead of blocking past nginx's
            // upstream timeout and surfacing a 504 to the caller. Combined with
            // the best-effort Lightning-offer handling in invoice.rs, a Boltz
            // outage degrades to "Liquid rail available" rather than a hang.
            api: BoltzApiClientV2::new(
                boltz_url.to_string(),
                Some(std::time::Duration::from_secs(10)),
            ),
            swap_master_key,
            webhook_url,
            breaker: crate::boltz_breaker::BoltzBreaker::default(),
        }
    }

    pub async fn create_reverse_swap(
        &self,
        swap_key_index: u64,
        amount_sat: u64,
        description: Option<&str>,
        description_hash: Option<&str>,
    ) -> Result<SwapResult, AppError> {
        if let crate::boltz_breaker::Gate::Reject = self.breaker.gate() {
            return Err(AppError::BoltzError(
                "boltz temporarily unavailable (circuit breaker open)".to_string(),
            ));
        }
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
            claim_covenant: None,
        };

        let response: CreateReverseResponse = {
            let result = self
                .api
                .post_reverse_req(request)
                .await
                .map_err(|e| AppError::BoltzError(format!("{e}")));
            self.breaker.record(
                result
                    .as_ref()
                    .err()
                    .is_some_and(crate::boltz_breaker::is_transport_failure),
            );
            result?
        };

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
        if let crate::boltz_breaker::Gate::Reject = self.breaker.gate() {
            return Err(AppError::BoltzError(
                "boltz temporarily unavailable (circuit breaker open)".to_string(),
            ));
        }
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
            // Payer-pays pricing: pin the SERVER lockup (the L-BTC we claim to
            // the merchant) to the invoice amount, and let Boltz gross UP the
            // user's BTC `expectedAmount` to cover the swap overhead. The
            // merchant therefore always nets the invoice; the payer bears the
            // rail cost they chose. (Previously user_lock=invoice, so Boltz
            // deducted the swap fee from the swap and the merchant under-netted.)
            // The response's claim_details.amount = invoice = server_lock_amount_sat
            // (what we credit), and lockup_details.amount = grossed-up payer
            // amount = user_lock_amount_sat.
            user_lock_amount: None,
            server_lock_amount: Some(amount_sat),
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

        let response: CreateChainResponse = {
            let result = self
                .api
                .post_chain_req(request)
                .await
                .map_err(|e| AppError::BoltzError(format!("{e}")));
            self.breaker.record(
                result
                    .as_ref()
                    .err()
                    .is_some_and(crate::boltz_breaker::is_transport_failure),
            );
            result?
        };

        response
            .validate(
                &claim_public_key,
                &refund_public_key,
                Chain::Bitcoin(BitcoinChain::Bitcoin),
                Chain::Liquid(LiquidChain::Liquid),
            )
            .map_err(|e| AppError::BoltzError(format!("invalid chain swap response: {e}")))?;

        // Money-safety invariant: we pin the SERVER lockup to the invoice amount,
        // so Boltz MUST echo claim_details.amount == amount_sat. `validate()`
        // only checks scripts/addresses, never amounts. If Boltz mis-prices, the
        // fork drifts, or a compromised endpoint returns a different server-lock
        // amount, we would silently credit the merchant the wrong number — so
        // fail creation instead (the caller omits the BTC offer gracefully;
        // LN/Liquid rails are unaffected). The merchant physically receives
        // server_lock minus our own Liquid claim-tx fee (~11-20 sats), a
        // merchant-side network cost within the Liquid accounting tolerance and
        // consistent with the Lightning rail — accepted, not grossed up further.
        if response.claim_details.amount != amount_sat {
            return Err(AppError::BoltzError(format!(
                "chain swap server-lock amount mismatch: requested {amount_sat}, Boltz returned claim_details.amount {}",
                response.claim_details.amount
            )));
        }

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

    /// Phase 3 refund-waterfall step 1: ask Boltz for the server-lockup amount
    /// it will settle a mis-funded chain swap at, given the amount actually
    /// locked. Boltz returns an error when the swap is no longer renegotiable
    /// (too close to expiry, or a refund signature already exists) — the caller
    /// treats that as "not renegotiable" and falls through to `refund_due`.
    pub async fn get_chain_swap_quote(&self, swap_id: &str) -> Result<u64, AppError> {
        let quote = self
            .api
            .get_quote(swap_id)
            .await
            .map_err(|e| AppError::BoltzError(format!("chain swap get_quote failed: {e}")))?;
        Ok(quote.amount)
    }

    /// Phase 3 refund-waterfall step 2: accept a quote returned by
    /// [`Self::get_chain_swap_quote`] so Boltz proceeds to create its server
    /// lockup and the swap settles at `amount_sat`.
    pub async fn accept_chain_swap_quote(
        &self,
        swap_id: &str,
        amount_sat: u64,
    ) -> Result<(), AppError> {
        self.api
            .accept_quote(swap_id, amount_sat)
            .await
            .map_err(|e| AppError::BoltzError(format!("chain swap accept_quote failed: {e}")))?;
        Ok(())
    }
}
