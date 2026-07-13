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

/// One deterministically derived swap key plus its claim preimage.  This type
/// intentionally does not implement `Debug`: both fields contain signing or
/// claim secrets.  Callers can inspect only the non-secret evidence needed to
/// reserve the key before sending it to Boltz.
pub struct DerivedSwapKey {
    keypair: Keypair,
    preimage: Preimage,
}

impl DerivedSwapKey {
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keypair.public_key().serialize())
    }

    pub fn preimage_hash_hex(&self) -> String {
        self.preimage.sha256.to_string()
    }
}

pub struct BoltzService {
    api: Option<BoltzApiClientV2>,
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
        let api = crate::config::valid_http_endpoint(boltz_url)
            .then(|| reqwest::Client::builder().build().ok())
            .flatten()
            .map(|client| {
                // Bound request-path Boltz calls: Boltz normally answers in
                // <2s, so a 10s ceiling fails fast with a clean error when
                // Boltz hangs instead of blocking past nginx's timeout.
                BoltzApiClientV2::with_client(
                    boltz_url.to_string(),
                    client,
                    Some(std::time::Duration::from_secs(10)),
                )
            });
        Self {
            api,
            swap_master_key,
            webhook_url,
            breaker: crate::boltz_breaker::BoltzBreaker::default(),
        }
    }

    pub fn client_ready(&self) -> bool {
        self.api.is_some()
    }

    fn api(&self) -> Result<&BoltzApiClientV2, AppError> {
        self.api
            .as_ref()
            .ok_or_else(|| AppError::BoltzError("Boltz client is unavailable".to_string()))
    }

    /// Stable, non-secret identifier of the master seed behind this service's
    /// swap keys: first 8 bytes of SHA-256 over the pubkey derived at the
    /// reserved index 0, hex-encoded. Real swaps allocate from `swap_key_seq`
    /// (START WITH 100), so index 0 is never used to sign and only serves as a
    /// deterministic seed fingerprint. Persisted alongside each swap so a
    /// database restore that rewinds the key sequence can be detected. See
    /// migrations 044/050.
    pub fn derivation_root_fingerprint(&self) -> Result<String, AppError> {
        use sha2::{Digest, Sha256};
        let keypair = self
            .swap_master_key
            .derive_swapkey(0)
            .map_err(|e| AppError::BoltzError(format!("fingerprint derivation failed: {e}")))?;
        let digest = Sha256::digest(keypair.public_key().serialize());
        Ok(hex::encode(&digest[..8]))
    }

    pub fn derive_swap_key(&self, child_index: u64) -> Result<DerivedSwapKey, AppError> {
        let keypair = self
            .swap_master_key
            .derive_swapkey(child_index)
            .map_err(|e| AppError::BoltzError(format!("key derivation failed: {e}")))?;
        let preimage = Preimage::from_swap_key(&keypair);
        Ok(DerivedSwapKey { keypair, preimage })
    }

    pub async fn create_reverse_swap(
        &self,
        derived_key: DerivedSwapKey,
        amount_sat: u64,
        description: Option<&str>,
        description_hash: Option<&str>,
    ) -> Result<SwapResult, AppError> {
        if let crate::boltz_breaker::Gate::Reject = self.breaker.gate() {
            return Err(AppError::BoltzError(
                "boltz temporarily unavailable (circuit breaker open)".to_string(),
            ));
        }
        let DerivedSwapKey { keypair, preimage } = derived_key;

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
                .api()?
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
        claim_key: DerivedSwapKey,
        refund_key: DerivedSwapKey,
        amount_sat: u64,
    ) -> Result<ChainSwapResult, AppError> {
        if let crate::boltz_breaker::Gate::Reject = self.breaker.gate() {
            return Err(AppError::BoltzError(
                "boltz temporarily unavailable (circuit breaker open)".to_string(),
            ));
        }
        let DerivedSwapKey {
            keypair: claim_keypair,
            preimage,
        } = claim_key;
        let DerivedSwapKey {
            keypair: refund_keypair,
            ..
        } = refund_key;

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
                .api()?
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
            .api()?
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
        self.api()?
            .accept_quote(swap_id, amount_sat)
            .await
            .map_err(|e| AppError::BoltzError(format!("chain swap accept_quote failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boltz_client::network::Network;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_service(mnemonic: &str) -> BoltzService {
        let key = SwapMasterKey::from_mnemonic(mnemonic, None, Network::Mainnet).unwrap();
        BoltzService::new("http://127.0.0.1:1", key, None)
    }

    #[test]
    fn root_fingerprint_is_deterministic_and_stable() {
        let svc = test_service(TEST_MNEMONIC);
        let fp = svc.derivation_root_fingerprint().unwrap();
        // 8 bytes -> 16 lowercase hex chars.
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        // Same seed -> same fingerprint across calls.
        assert_eq!(fp, svc.derivation_root_fingerprint().unwrap());
        // Same seed via a fresh service -> same fingerprint.
        assert_eq!(
            fp,
            test_service(TEST_MNEMONIC)
                .derivation_root_fingerprint()
                .unwrap()
        );
    }

    #[test]
    fn root_fingerprint_differs_across_seeds() {
        let a = test_service(TEST_MNEMONIC)
            .derivation_root_fingerprint()
            .unwrap();
        let b = test_service(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .derivation_root_fingerprint()
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn derived_swap_key_exposes_stable_nonsecret_lineage_evidence() {
        let first = test_service(TEST_MNEMONIC).derive_swap_key(123).unwrap();
        let same = test_service(TEST_MNEMONIC).derive_swap_key(123).unwrap();
        let next = test_service(TEST_MNEMONIC).derive_swap_key(124).unwrap();

        assert_eq!(first.public_key_hex().len(), 66);
        assert!(matches!(&first.public_key_hex()[..2], "02" | "03"));
        assert_eq!(first.preimage_hash_hex().len(), 64);
        assert_eq!(first.public_key_hex(), same.public_key_hex());
        assert_eq!(first.preimage_hash_hex(), same.preimage_hash_hex());
        assert_ne!(first.public_key_hex(), next.public_key_hex());
        assert_ne!(first.preimage_hash_hex(), next.preimage_hash_hex());
    }

    #[test]
    fn client_readiness_requires_a_valid_http_base_url() {
        assert!(test_service(TEST_MNEMONIC).client_ready());

        for url in [
            "not-a-url",
            "https://api.boltz.exchange:0/v2",
            "https://user@api.boltz.exchange/v2",
            "https://api.boltz.exchange/v2?query=1",
            "https://api.boltz.exchange/v2#fragment",
        ] {
            let key = SwapMasterKey::from_mnemonic(TEST_MNEMONIC, None, Network::Mainnet).unwrap();
            let invalid = BoltzService::new(url, key, None);
            assert!(!invalid.client_ready(), "accepted {url}");
            assert!(invalid.api().is_err());
            assert!(invalid.derivation_root_fingerprint().is_ok());
        }
    }
}
