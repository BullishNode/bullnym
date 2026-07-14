use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
};
use bitcoin::script::Builder;
use bitcoin::{Address, AddressType, Network, ScriptBuf};
use boltz_client::bitcoin::secp256k1::Keypair;
use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::boltz::{
    BoltzApiClientV2, ChainPair, ChainSwapStates, CreateChainRequest, CreateChainResponse,
    CreateReverseRequest, CreateReverseResponse, GetQuoteResponse, HeightResponse, Leaf,
    RevSwapStates, Side, Webhook,
};
use boltz_client::util::secrets::{Preimage, SwapMasterKey};
use boltz_client::{BtcSwapScript, LBtcSwapScript, PublicKey};
use sha2::{Digest, Sha256};

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
    pub user_lock_amount_sat: u64,
    pub server_lock_amount_sat: u64,
    pub preimage: Vec<u8>,
    pub claim_keypair: Keypair,
    pub refund_keypair: Keypair,
    /// Exact canonical response bytes whose digest is included in
    /// `creation_terms`. This is what recovery code reads after restart.
    pub canonical_response_json: String,
    pub creation_terms: ValidatedChainSwapCreationTerms,
}

/// Fresh provider hints consumed by the chain-swap evidence reducer.
///
/// Neither field is chain authority. The status selects a reducer branch and
/// the optional transaction id may only select a transaction independently
/// found by the configured Bitcoin evidence source.
pub struct FreshChainSwapProviderHint {
    status: String,
    transaction_txid: Option<String>,
}

impl FreshChainSwapProviderHint {
    pub fn status(&self) -> &str {
        &self.status
    }

    pub fn transaction_txid(&self) -> Option<&str> {
        self.transaction_txid.as_deref()
    }
}

/// Canonical provider quote evidence for one wrong-amount chain swap.
///
/// The pinned Boltz client decodes the response before returning it. Preserve
/// the canonical digest at this adapter boundary so the caller can journal the
/// exact typed response it validated before any `accept_quote` mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSwapQuote {
    pub amount_sat: u64,
    pub response_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSwapQuoteProviderErrorKind {
    RefundAlreadySigned,
    FundingNotAmountRejected,
    ExpiryMarginTooShort,
    AboveMaximum,
    BelowMinimum,
    InvalidOrStaleQuote,
    Timeout,
    Transport,
    ProviderServerError,
    MalformedResponse,
    UnknownProviderOutcome,
}

impl ChainSwapQuoteProviderErrorKind {
    pub fn is_explicit_non_eligibility(self) -> bool {
        matches!(
            self,
            Self::RefundAlreadySigned
                | Self::FundingNotAmountRejected
                | Self::ExpiryMarginTooShort
                | Self::AboveMaximum
                | Self::BelowMinimum
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSwapQuoteProviderError {
    pub kind: ChainSwapQuoteProviderErrorKind,
    /// Canonical digest of a decoded, pinned positive protocol outcome. Raw
    /// response bodies, URLs, and unknown error text are never retained.
    pub terminal_evidence_sha256: Option<String>,
}

impl std::fmt::Display for ChainSwapQuoteProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.kind {
            ChainSwapQuoteProviderErrorKind::RefundAlreadySigned => {
                "provider reports the refund was already signed"
            }
            ChainSwapQuoteProviderErrorKind::FundingNotAmountRejected => {
                "provider reports primary funding was not rejected for its amount"
            }
            ChainSwapQuoteProviderErrorKind::ExpiryMarginTooShort => {
                "provider reports insufficient expiry margin"
            }
            ChainSwapQuoteProviderErrorKind::AboveMaximum => {
                "provider reports the amount is above its maximum"
            }
            ChainSwapQuoteProviderErrorKind::BelowMinimum => {
                "provider reports the amount is below its minimum"
            }
            ChainSwapQuoteProviderErrorKind::InvalidOrStaleQuote => {
                "provider reports the quote is invalid or stale"
            }
            ChainSwapQuoteProviderErrorKind::Timeout => "provider request timed out",
            ChainSwapQuoteProviderErrorKind::Transport => "provider transport failed",
            ChainSwapQuoteProviderErrorKind::ProviderServerError => {
                "provider server request failed"
            }
            ChainSwapQuoteProviderErrorKind::MalformedResponse => {
                "provider returned a malformed response"
            }
            ChainSwapQuoteProviderErrorKind::UnknownProviderOutcome => {
                "provider outcome is unknown"
            }
        })
    }
}

impl std::error::Error for ChainSwapQuoteProviderError {}

/// Complete non-secret provider evidence approved before a payer can see the
/// Bitcoin address. The database copies this packet into immutable columns.
#[derive(Debug)]
pub struct ValidatedChainSwapCreationTerms {
    pub pinned_pair_hash: String,
    pub canonical_pair_quote_json: String,
    pub creation_response_sha256: String,
    pub btc_claim_script_sha256: String,
    pub btc_refund_script_sha256: String,
    pub liquid_claim_script_sha256: String,
    pub liquid_refund_script_sha256: String,
    pub btc_timeout_height: u32,
    pub liquid_timeout_height: u32,
    pub btc_network: &'static str,
    pub liquid_network: &'static str,
    pub liquid_asset_id: String,
}

const BTC_NETWORK_NAME: &str = "bitcoin";
const LIQUID_NETWORK_NAME: &str = "liquid";
const BTC_TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;
// Elements currently reserves 0xc4 for its tapscript leaf version. This is
// intentionally distinct from Bitcoin's BIP342 0xc0 version.
const LIQUID_TAPSCRIPT_LEAF_VERSION: u8 = 0xc4;
const BITCOIN_TARGET_BLOCK_SECS: u64 = 600;
const LIQUID_TARGET_BLOCK_SECS: u64 = 60;
const LOCK_TIME_TIMESTAMP_THRESHOLD: u32 = 500_000_000;

fn invalid_chain_response(reason: impl Into<String>) -> AppError {
    AppError::BoltzError(format!("invalid chain swap response: {}", reason.into()))
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn x_only_role_keys_are_distinct(keys: &[&PublicKey]) -> bool {
    keys.iter().enumerate().all(|(index, key)| {
        let x_only = key.inner.x_only_public_key().0;
        keys[index + 1..]
            .iter()
            .all(|other| other.inner.x_only_public_key().0 != x_only)
    })
}

fn expected_claim_script(hashlock: hash160::Hash, receiver: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_HASH160)
        .push_slice(hashlock.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&receiver.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn expected_refund_script(sender: &PublicKey, timeout_height: u32) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&sender.inner.x_only_public_key().0)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_lock_time(LockTime::from_consensus(timeout_height))
        .push_opcode(OP_CLTV)
        .into_script()
}

fn validate_exact_leaf(
    name: &str,
    actual: &Leaf,
    expected_version: u8,
    expected_script: &ScriptBuf,
) -> Result<String, AppError> {
    if actual.version != expected_version {
        return Err(invalid_chain_response(format!(
            "{name} leaf version mismatch: expected {expected_version}, got {}",
            actual.version
        )));
    }

    let actual_script = hex::decode(&actual.output)
        .map_err(|error| invalid_chain_response(format!("{name} leaf is not hex: {error}")))?;
    if actual_script != expected_script.as_bytes() {
        return Err(invalid_chain_response(format!(
            "{name} leaf does not match the exact expected template"
        )));
    }

    Ok(hex::encode(Sha256::digest(expected_script.as_bytes())))
}

fn expected_chain_user_lock_amount(
    pair: &ChainPair,
    server_lock_amount_sat: u64,
) -> Result<u64, AppError> {
    let percentage = pair.fees.percentage;
    if !percentage.is_finite() || !(0.0..100.0).contains(&percentage) {
        return Err(invalid_chain_response(format!(
            "pair percentage fee is outside [0, 100): {percentage}"
        )));
    }

    // Boltz's documented server-lock pricing is:
    // ceil((server lock + server miner fee) / (1 - percentage rate)).
    let numerator = server_lock_amount_sat
        .checked_add(pair.fees.miner_fees.server)
        .ok_or_else(|| invalid_chain_response("server-lock quote overflows u64"))?;
    let quoted = (numerator as f64 / (1.0 - percentage / 100.0)).ceil();
    if !quoted.is_finite() || quoted < 0.0 || quoted > u64::MAX as f64 {
        return Err(invalid_chain_response(
            "calculated user-lock quote is outside u64",
        ));
    }
    Ok(quoted as u64)
}

#[allow(clippy::too_many_arguments)]
fn validate_chain_creation_response(
    pair: &ChainPair,
    heights: &HeightResponse,
    expected_hashlock: hash160::Hash,
    claim_public_key: &PublicKey,
    refund_public_key: &PublicKey,
    server_lock_amount_sat: u64,
    response: &CreateChainResponse,
) -> Result<(ValidatedChainSwapCreationTerms, String), AppError> {
    if !is_lower_hex_32(&pair.hash) {
        return Err(invalid_chain_response(
            "pair hash is not 32-byte lowercase hex",
        ));
    }
    if !pair.rate.is_finite() || pair.rate != 1.0 {
        return Err(invalid_chain_response(format!(
            "BTC/L-BTC pair rate must be exactly 1, got {}",
            pair.rate
        )));
    }
    if pair.limits.minimal == 0
        || pair.limits.maximal < pair.limits.minimal
        || pair.limits.maximal_zero_conf > pair.limits.maximal
    {
        return Err(invalid_chain_response("pair limits are internally invalid"));
    }
    for (name, fee) in [
        ("server", pair.fees.miner_fees.server),
        ("user claim", pair.fees.miner_fees.user.claim),
        ("user lockup", pair.fees.miner_fees.user.lockup),
    ] {
        if fee > pair.limits.maximal {
            return Err(invalid_chain_response(format!(
                "pair {name} miner fee exceeds the maximal swap amount"
            )));
        }
    }
    if response.id.is_empty()
        || response.id.len() > 128
        || !response.id.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(invalid_chain_response("provider swap id is malformed"));
    }
    if !x_only_role_keys_are_distinct(&[claim_public_key, refund_public_key]) {
        return Err(invalid_chain_response(
            "local claim and refund x-only keys must be distinct",
        ));
    }

    response
        .validate(
            claim_public_key,
            refund_public_key,
            Chain::Bitcoin(BitcoinChain::Bitcoin),
            Chain::Liquid(LiquidChain::Liquid),
        )
        .map_err(|error| invalid_chain_response(error.to_string()))?;

    let expected_user_lock_amount = expected_chain_user_lock_amount(pair, server_lock_amount_sat)?;
    pair.limits
        .within(expected_user_lock_amount)
        .map_err(|error| invalid_chain_response(format!("pair limits rejected quote: {error}")))?;
    if response.claim_details.amount != server_lock_amount_sat {
        return Err(invalid_chain_response(format!(
            "server-lock amount mismatch: requested {server_lock_amount_sat}, got {}",
            response.claim_details.amount
        )));
    }
    if response.lockup_details.amount != expected_user_lock_amount {
        return Err(invalid_chain_response(format!(
            "user-lock amount mismatch: quote requires {expected_user_lock_amount}, got {}",
            response.lockup_details.amount
        )));
    }

    if response.lockup_details.blinding_key.is_some() {
        return Err(invalid_chain_response(
            "Bitcoin lockup unexpectedly contains a blinding key",
        ));
    }
    if response.claim_details.blinding_key.is_none() {
        return Err(invalid_chain_response(
            "Liquid lockup is missing its blinding key",
        ));
    }
    if response.claim_details.bip21.is_some()
        || response.claim_details.claim_address.is_some()
        || response.claim_details.refund_address.is_some()
        || response.lockup_details.claim_address.is_some()
        || response.lockup_details.refund_address.is_some()
    {
        return Err(invalid_chain_response(
            "provider returned unrequested destination fields",
        ));
    }
    if response
        .lockup_details
        .swap_tree
        .covenant_claim_leaf
        .is_some()
        || response
            .claim_details
            .swap_tree
            .covenant_claim_leaf
            .is_some()
    {
        return Err(invalid_chain_response(
            "chain-swap trees contain an unexpected covenant leaf",
        ));
    }

    let btc_address = Address::from_str(&response.lockup_details.lockup_address)
        .map_err(|error| invalid_chain_response(format!("invalid Bitcoin address: {error}")))?
        .require_network(Network::Bitcoin)
        .map_err(|error| invalid_chain_response(format!("wrong Bitcoin network: {error}")))?;
    if btc_address.address_type() != Some(AddressType::P2tr) {
        return Err(invalid_chain_response(
            "Bitcoin lockup address is not Taproot",
        ));
    }
    let liquid_address =
        boltz_client::elements::Address::from_str(&response.claim_details.lockup_address)
            .map_err(|error| invalid_chain_response(format!("invalid Liquid address: {error}")))?;
    if !liquid_address.is_liquid() || !liquid_address.is_blinded() {
        return Err(invalid_chain_response(
            "Liquid lockup address must be blinded mainnet Liquid",
        ));
    }

    let btc_script = BtcSwapScript::chain_from_swap_resp(
        Side::Lockup,
        response.lockup_details.clone(),
        *refund_public_key,
    )
    .map_err(|error| invalid_chain_response(format!("invalid Bitcoin tree: {error}")))?;
    let liquid_script = LBtcSwapScript::chain_from_swap_resp(
        Side::Claim,
        response.claim_details.clone(),
        *claim_public_key,
    )
    .map_err(|error| invalid_chain_response(format!("invalid Liquid tree: {error}")))?;
    if btc_script.hashlock.to_byte_array() != expected_hashlock.to_byte_array()
        || liquid_script.hashlock.to_byte_array() != expected_hashlock.to_byte_array()
        || btc_script.hashlock.to_byte_array() != liquid_script.hashlock.to_byte_array()
    {
        return Err(invalid_chain_response(
            "Bitcoin and Liquid hashlocks must both equal the local preimage hash",
        ));
    }
    if btc_script.sender_pubkey != *refund_public_key
        || btc_script.receiver_pubkey != response.lockup_details.server_public_key
        || liquid_script.sender_pubkey != response.claim_details.server_public_key
        || liquid_script.receiver_pubkey != *claim_public_key
    {
        return Err(invalid_chain_response(
            "chain-swap key roles are inconsistent",
        ));
    }
    if !x_only_role_keys_are_distinct(&[
        claim_public_key,
        refund_public_key,
        &response.lockup_details.server_public_key,
        &response.claim_details.server_public_key,
    ]) {
        return Err(invalid_chain_response(
            "provider and local chain-swap x-only keys are not role-distinct",
        ));
    }

    let btc_timeout = response.lockup_details.timeout_block_height;
    let liquid_timeout = response.claim_details.timeout_block_height;
    if btc_timeout >= LOCK_TIME_TIMESTAMP_THRESHOLD
        || liquid_timeout >= LOCK_TIME_TIMESTAMP_THRESHOLD
        || heights.btc >= LOCK_TIME_TIMESTAMP_THRESHOLD
        || heights.lbtc >= LOCK_TIME_TIMESTAMP_THRESHOLD
    {
        return Err(invalid_chain_response(
            "chain timeout values must be block heights, not timestamps",
        ));
    }
    if btc_script.locktime.to_consensus_u32() != btc_timeout
        || liquid_script.locktime.to_consensus_u32() != liquid_timeout
    {
        return Err(invalid_chain_response(
            "refund scripts do not commit their advertised timeout heights",
        ));
    }
    let btc_remaining = btc_timeout
        .checked_sub(heights.btc)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| invalid_chain_response("Bitcoin timeout is not in the future"))?;
    let liquid_remaining = liquid_timeout
        .checked_sub(heights.lbtc)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| invalid_chain_response("Liquid timeout is not in the future"))?;
    let btc_window_secs = u64::from(btc_remaining)
        .checked_mul(BITCOIN_TARGET_BLOCK_SECS)
        .ok_or_else(|| invalid_chain_response("Bitcoin timeout window overflows"))?;
    let liquid_window_secs = u64::from(liquid_remaining)
        .checked_mul(LIQUID_TARGET_BLOCK_SECS)
        .ok_or_else(|| invalid_chain_response("Liquid timeout window overflows"))?;
    if liquid_window_secs >= btc_window_secs {
        return Err(invalid_chain_response(format!(
            "Liquid claim window ({liquid_window_secs}s) must close before the Bitcoin refund window ({btc_window_secs}s)"
        )));
    }

    let btc_claim_script = expected_claim_script(
        expected_hashlock,
        &response.lockup_details.server_public_key,
    );
    let btc_refund_script = expected_refund_script(refund_public_key, btc_timeout);
    let liquid_claim_script = expected_claim_script(expected_hashlock, claim_public_key);
    let liquid_refund_script =
        expected_refund_script(&response.claim_details.server_public_key, liquid_timeout);
    let btc_claim_script_sha256 = validate_exact_leaf(
        "Bitcoin claim",
        &response.lockup_details.swap_tree.claim_leaf,
        BTC_TAPSCRIPT_LEAF_VERSION,
        &btc_claim_script,
    )?;
    let btc_refund_script_sha256 = validate_exact_leaf(
        "Bitcoin refund",
        &response.lockup_details.swap_tree.refund_leaf,
        BTC_TAPSCRIPT_LEAF_VERSION,
        &btc_refund_script,
    )?;
    let liquid_claim_script_sha256 = validate_exact_leaf(
        "Liquid claim",
        &response.claim_details.swap_tree.claim_leaf,
        LIQUID_TAPSCRIPT_LEAF_VERSION,
        &liquid_claim_script,
    )?;
    let liquid_refund_script_sha256 = validate_exact_leaf(
        "Liquid refund",
        &response.claim_details.swap_tree.refund_leaf,
        LIQUID_TAPSCRIPT_LEAF_VERSION,
        &liquid_refund_script,
    )?;

    let (canonical_pair_quote_json, _) = crate::canonical_json::canonical_json_and_sha256(pair)
        .map_err(|error| invalid_chain_response(format!("cannot canonicalize pair: {error}")))?;
    let (canonical_response_json, creation_response_sha256) =
        crate::canonical_json::canonical_json_and_sha256(response).map_err(|error| {
            invalid_chain_response(format!("cannot canonicalize creation response: {error}"))
        })?;

    Ok((
        ValidatedChainSwapCreationTerms {
            pinned_pair_hash: pair.hash.clone(),
            canonical_pair_quote_json,
            creation_response_sha256,
            btc_claim_script_sha256,
            btc_refund_script_sha256,
            liquid_claim_script_sha256,
            liquid_refund_script_sha256,
            btc_timeout_height: btc_timeout,
            liquid_timeout_height: liquid_timeout,
            btc_network: BTC_NETWORK_NAME,
            liquid_network: LIQUID_NETWORK_NAME,
            liquid_asset_id: boltz_client::elements::AssetId::LIQUID_BTC.to_string(),
        },
        canonical_response_json,
    ))
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
    quote_api_url: Option<String>,
    quote_http_client: Option<reqwest::Client>,
    swap_master_key: SwapMasterKey,
    webhook_url: Option<String>,
    provider_limits: crate::provider_limits_runtime::ProviderLimitsRuntime,
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
        let quote_http_client = crate::config::valid_http_endpoint(boltz_url)
            .then(|| reqwest::Client::builder().build().ok())
            .flatten();
        let api = quote_http_client.clone().map(|client| {
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
            quote_api_url: quote_http_client.as_ref().map(|_| boltz_url.to_string()),
            quote_http_client,
            swap_master_key,
            webhook_url,
            provider_limits: crate::provider_limits_runtime::ProviderLimitsRuntime::new(),
            breaker: crate::boltz_breaker::BoltzBreaker::default(),
        }
    }

    pub fn client_ready(&self) -> bool {
        self.api.is_some()
    }

    /// Shared provider-limit reader. Calls on this value are in-memory only.
    pub fn provider_limits(&self) -> &crate::provider_limits_runtime::ProviderLimitsRuntime {
        &self.provider_limits
    }

    /// Re-read the provider hints needed by an under-lock chain-swap decision
    /// from one typed response. Transport and decode failures are returned so
    /// callers classify them as incomplete evidence.
    pub async fn fresh_chain_swap_provider_hint(
        &self,
        swap_id: &str,
    ) -> Result<FreshChainSwapProviderHint, AppError> {
        let api = self.api.as_ref().ok_or_else(|| {
            AppError::BoltzError("Boltz client unavailable for chain-swap evidence".to_string())
        })?;
        let swap = api.get_swap(swap_id).await.map_err(|error| {
            AppError::BoltzError(format!("fetch fresh chain-swap status: {error}"))
        })?;
        Ok(FreshChainSwapProviderHint {
            status: swap.status,
            transaction_txid: swap.transaction.map(|transaction| transaction.id),
        })
    }

    async fn fetch_btc_to_lbtc_reverse_pair(
        &self,
    ) -> Result<Option<boltz_client::swaps::boltz::ReversePair>, ()> {
        let Some(api) = self.api.as_ref() else {
            return Err(());
        };
        api.get_reverse_pairs()
            .await
            .map(|pairs| pairs.get_btc_to_lbtc_pair())
            .map_err(|_| ())
    }

    /// Perform the startup refresh and timestamp it only after the response
    /// future has completed. Error details are deliberately not retained.
    pub async fn refresh_provider_limits(
        &self,
    ) -> crate::provider_limits_runtime::ProviderLimitRefreshOutcome {
        let result = self.fetch_btc_to_lbtc_reverse_pair().await;
        self.provider_limits
            .record_fetch_result(result, std::time::Instant::now())
    }

    /// Spawn the sole periodic reverse-pair refresh loop for this service.
    pub fn spawn_provider_limits_refresh(
        self: &std::sync::Arc<Self>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let service = std::sync::Arc::clone(self);
        let runtime = self.provider_limits.clone();
        tokio::spawn(async move {
            let fetch_service = std::sync::Arc::clone(&service);
            crate::provider_limits_runtime::run_periodic_refresh(
                runtime,
                cancel,
                move || {
                    let service = std::sync::Arc::clone(&fetch_service);
                    async move { service.fetch_btc_to_lbtc_reverse_pair().await }
                },
                std::time::Instant::now,
            )
            .await;
        })
    }

    /// Private in-process operations snapshot for #68. This state is not part
    /// of the public readiness response and remains scoped to new provider-
    /// dependent offer creation.
    pub fn creation_circuit_snapshot(&self) -> crate::boltz_breaker::CreationCircuitSnapshot {
        self.breaker.snapshot()
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
            let provider_result = self.api()?.post_reverse_req(request).await;
            self.breaker.record(
                provider_result
                    .as_ref()
                    .err()
                    .is_some_and(crate::boltz_breaker::is_qualified_boltz_failure),
            );
            provider_result.map_err(|error| AppError::BoltzError(format!("{error}")))?
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

        // Pin the exact fee/limit quote before creation. Boltz rejects the
        // request if that quote changes between these calls, so no payer can
        // receive an address priced against stale terms.
        let pairs_result = self.api()?.get_chain_pairs().await;
        self.breaker.record(
            pairs_result
                .as_ref()
                .err()
                .is_some_and(crate::boltz_breaker::is_qualified_boltz_failure),
        );
        let pair = pairs_result
            .map_err(|error| AppError::BoltzError(format!("chain pair fetch failed: {error}")))?
            .get_btc_to_lbtc_pair()
            .ok_or_else(|| AppError::BoltzError("BTC/L-BTC chain pair is unavailable".into()))?;

        // Heights are captured before the mutating request and bound the
        // timeout-order validation. A block arriving during the request only
        // makes the resulting windows more conservative by one block.
        let heights_result = self.api()?.get_height().await;
        self.breaker.record(
            heights_result
                .as_ref()
                .err()
                .is_some_and(crate::boltz_breaker::is_qualified_boltz_failure),
        );
        let heights = heights_result
            .map_err(|error| AppError::BoltzError(format!("chain height fetch failed: {error}")))?;

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
            pair_hash: Some(pair.hash.clone()),
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
            let provider_result = self.api()?.post_chain_req(request).await;
            self.breaker.record(
                provider_result
                    .as_ref()
                    .err()
                    .is_some_and(crate::boltz_breaker::is_qualified_boltz_failure),
            );
            provider_result.map_err(|error| AppError::BoltzError(format!("{error}")))?
        };

        let (creation_terms, canonical_response_json) = validate_chain_creation_response(
            &pair,
            &heights,
            preimage.hash160,
            &claim_public_key,
            &refund_public_key,
            amount_sat,
            &response,
        )?;
        let preimage = preimage
            .bytes
            .ok_or_else(|| invalid_chain_response("locally derived claim preimage is absent"))?
            .to_vec();

        Ok(ChainSwapResult {
            swap_id: response.id.clone(),
            lockup_address: response.lockup_details.lockup_address.clone(),
            user_lock_amount_sat: response.lockup_details.amount,
            server_lock_amount_sat: response.claim_details.amount,
            preimage,
            claim_keypair,
            refund_keypair,
            canonical_response_json,
            creation_terms,
        })
    }

    /// Ask Boltz for the server-lockup amount it will settle a verified
    /// wrong-amount chain swap at. Exact pinned protocol refusals are distinct
    /// from timeout, transport, 5xx, malformed, and unknown outcomes; only the
    /// former can close this quote attempt, while ambiguity remains Observe.
    pub async fn get_chain_swap_quote(
        &self,
        swap_id: &str,
    ) -> Result<ChainSwapQuote, ChainSwapQuoteProviderError> {
        let body = self
            .chain_swap_quote_request(reqwest::Method::GET, swap_id, None)
            .await?;
        let response: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::MalformedResponse,
                terminal_evidence_sha256: None,
            })?;
        if !response.is_object() {
            return Err(ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::MalformedResponse,
                terminal_evidence_sha256: None,
            });
        }
        let quote: GetQuoteResponse =
            serde_json::from_value(response.clone()).map_err(|_| ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::MalformedResponse,
                terminal_evidence_sha256: None,
            })?;
        let (_, response_sha256) = crate::canonical_json::canonical_json_and_sha256(&response)
            .map_err(|_| ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::MalformedResponse,
                terminal_evidence_sha256: None,
            })?;
        Ok(ChainSwapQuote {
            amount_sat: quote.amount,
            response_sha256,
        })
    }

    /// Accept a quote returned by
    /// [`Self::get_chain_swap_quote`] so Boltz proceeds to create its server
    /// lockup and the swap settles at `amount_sat`.
    pub async fn accept_chain_swap_quote(
        &self,
        swap_id: &str,
        amount_sat: u64,
    ) -> Result<String, ChainSwapQuoteProviderError> {
        let body = self
            .chain_swap_quote_request(
                reqwest::Method::POST,
                swap_id,
                Some(serde_json::json!({ "amount": amount_sat })),
            )
            .await?;
        parse_chain_swap_quote_acceptance_response(&body)
    }

    async fn chain_swap_quote_request(
        &self,
        method: reqwest::Method,
        swap_id: &str,
        body: Option<serde_json::Value>,
    ) -> Result<String, ChainSwapQuoteProviderError> {
        let client = self
            .quote_http_client
            .as_ref()
            .ok_or(ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::Transport,
                terminal_evidence_sha256: None,
            })?;
        let base_url = self
            .quote_api_url
            .as_deref()
            .ok_or(ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::Transport,
                terminal_evidence_sha256: None,
            })?;
        let url = format!(
            "{}/swap/chain/{}/quote",
            base_url.trim_end_matches('/'),
            swap_id
        );
        let mut request = client
            .request(method, url)
            .timeout(std::time::Duration::from_secs(10));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| ChainSwapQuoteProviderError {
                kind: if error.is_timeout() {
                    ChainSwapQuoteProviderErrorKind::Timeout
                } else {
                    ChainSwapQuoteProviderErrorKind::Transport
                },
                terminal_evidence_sha256: None,
            })?;
        let status = response.status();
        let response_body = response
            .text()
            .await
            .map_err(|_| ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::Transport,
                terminal_evidence_sha256: None,
            })?;
        if status.is_success() {
            return Ok(response_body);
        }
        let error = if status.is_server_error() {
            ChainSwapQuoteProviderError {
                kind: ChainSwapQuoteProviderErrorKind::ProviderServerError,
                terminal_evidence_sha256: None,
            }
        } else {
            classify_chain_swap_quote_protocol_error(&response_body).unwrap_or(
                ChainSwapQuoteProviderError {
                    kind: ChainSwapQuoteProviderErrorKind::UnknownProviderOutcome,
                    terminal_evidence_sha256: None,
                },
            )
        };
        Err(error)
    }
}

fn classify_chain_swap_quote_protocol_error(
    response_body: &str,
) -> Option<ChainSwapQuoteProviderError> {
    let value: serde_json::Value = serde_json::from_str(response_body).ok()?;
    let provider_error = value.get("error")?.as_str()?;
    let kind = match provider_error {
        "a refund for this swap was signed already" => {
            ChainSwapQuoteProviderErrorKind::RefundAlreadySigned
        }
        "lockup transaction was not rejected because of the amount" => {
            ChainSwapQuoteProviderErrorKind::FundingNotAmountRejected
        }
        "time until expiry too short" => ChainSwapQuoteProviderErrorKind::ExpiryMarginTooShort,
        "invalid quote" => ChainSwapQuoteProviderErrorKind::InvalidOrStaleQuote,
        dynamic if exact_u64_bound_message(dynamic, " exceeds maximal of ") => {
            ChainSwapQuoteProviderErrorKind::AboveMaximum
        }
        dynamic if exact_u64_bound_message(dynamic, " is less than minimal of ") => {
            ChainSwapQuoteProviderErrorKind::BelowMinimum
        }
        _ => return None,
    };
    let terminal_evidence_sha256 = crate::canonical_json::canonical_json_and_sha256(
        &serde_json::json!({ "error": provider_error }),
    )
    .ok()
    .map(|(_, digest)| digest)?;
    Some(ChainSwapQuoteProviderError {
        kind,
        terminal_evidence_sha256: Some(terminal_evidence_sha256),
    })
}

fn exact_u64_bound_message(message: &str, separator: &str) -> bool {
    message
        .split_once(separator)
        .is_some_and(|(actual, bound)| {
            [actual, bound].into_iter().all(|value| {
                !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && value.parse::<u64>().is_ok()
            })
        })
}

fn parse_chain_swap_quote_acceptance_response(
    body: &str,
) -> Result<String, ChainSwapQuoteProviderError> {
    let response: serde_json::Value =
        serde_json::from_str(body).map_err(|_| ChainSwapQuoteProviderError {
            kind: ChainSwapQuoteProviderErrorKind::MalformedResponse,
            terminal_evidence_sha256: None,
        })?;
    if !response.is_object() {
        return Err(ChainSwapQuoteProviderError {
            kind: ChainSwapQuoteProviderErrorKind::MalformedResponse,
            terminal_evidence_sha256: None,
        });
    }
    crate::canonical_json::canonical_json_and_sha256(&response)
        .map(|(_, digest)| digest)
        .map_err(|_| ChainSwapQuoteProviderError {
            kind: ChainSwapQuoteProviderErrorKind::MalformedResponse,
            terminal_evidence_sha256: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use axum::{Json, Router};
    use boltz_client::network::Network;
    use boltz_client::swaps::boltz::{ChainSwapDetails, SwapTree, SwapType};
    use boltz_client::{ZKKeyPair, ZKSecp256k1};
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn renegotiation_quote_protocol_classifier_accepts_only_pinned_exact_messages() {
        let cases = [
            (
                "a refund for this swap was signed already",
                ChainSwapQuoteProviderErrorKind::RefundAlreadySigned,
            ),
            (
                "lockup transaction was not rejected because of the amount",
                ChainSwapQuoteProviderErrorKind::FundingNotAmountRejected,
            ),
            (
                "time until expiry too short",
                ChainSwapQuoteProviderErrorKind::ExpiryMarginTooShort,
            ),
            (
                "invalid quote",
                ChainSwapQuoteProviderErrorKind::InvalidOrStaleQuote,
            ),
            (
                "1001 exceeds maximal of 1000",
                ChainSwapQuoteProviderErrorKind::AboveMaximum,
            ),
            (
                "999 is less than minimal of 1000",
                ChainSwapQuoteProviderErrorKind::BelowMinimum,
            ),
        ];
        for (message, expected) in cases {
            let body = serde_json::json!({ "error": message }).to_string();
            let classified = classify_chain_swap_quote_protocol_error(&body).unwrap();
            assert_eq!(classified.kind, expected);
            assert!(classified
                .terminal_evidence_sha256
                .as_deref()
                .is_some_and(is_lower_hex_32));
        }

        for rejected in [
            "2.47: a refund for this swap was signed already",
            "a refund for this swap was signed already ",
            "time until expiry is too short",
            "+1001 exceeds maximal of 1000",
            "1001.0 exceeds maximal of 1000",
            "1001 exceeds maximal of 1000 trailing",
            "-1 is less than minimal of 1000",
            "unknown",
        ] {
            let body = serde_json::json!({ "error": rejected }).to_string();
            assert_eq!(classify_chain_swap_quote_protocol_error(&body), None);
        }
    }

    #[test]
    fn renegotiation_quote_acceptance_requires_a_json_object_and_canonicalizes_it() {
        let first = parse_chain_swap_quote_acceptance_response(r#"{"z":2,"a":1}"#).unwrap();
        let reordered =
            parse_chain_swap_quote_acceptance_response(r#"{ "a": 1, "z": 2 }"#).unwrap();
        assert_eq!(first, reordered);
        assert!(is_lower_hex_32(&first));

        for malformed in ["", "null", "true", "1", r#""accepted""#, "[]"] {
            let error = parse_chain_swap_quote_acceptance_response(malformed).unwrap_err();
            assert_eq!(
                error.kind,
                ChainSwapQuoteProviderErrorKind::MalformedResponse
            );
            assert_eq!(error.terminal_evidence_sha256, None);
        }
    }

    fn test_service(mnemonic: &str) -> BoltzService {
        let key = SwapMasterKey::from_mnemonic(mnemonic, None, Network::Mainnet).unwrap();
        BoltzService::new("http://127.0.0.1:1", key, None)
    }

    fn test_service_at(boltz_url: &str, mnemonic: &str) -> BoltzService {
        let key = SwapMasterKey::from_mnemonic(mnemonic, None, Network::Mainnet).unwrap();
        BoltzService::new(boltz_url, key, None)
    }

    #[derive(Clone)]
    struct ChainTransportFixtureState {
        pair_response: Value,
        height_response: Value,
        creation_response: Value,
        creation_status: StatusCode,
        calls: Arc<Mutex<Vec<String>>>,
        request: Arc<Mutex<Option<Value>>>,
    }

    struct ChainTransportFixture {
        base_url: String,
        calls: Arc<Mutex<Vec<String>>>,
        request: Arc<Mutex<Option<Value>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl ChainTransportFixture {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn request(&self) -> Value {
            self.request
                .lock()
                .unwrap()
                .clone()
                .expect("chain creation request was not captured")
        }

        async fn shutdown(self) {
            self.task.abort();
            let _ = self.task.await;
        }
    }

    async fn chain_pairs_handler(State(state): State<ChainTransportFixtureState>) -> Json<Value> {
        state.calls.lock().unwrap().push("GET /swap/chain".into());
        Json(state.pair_response)
    }

    async fn chain_heights_handler(State(state): State<ChainTransportFixtureState>) -> Json<Value> {
        state
            .calls
            .lock()
            .unwrap()
            .push("GET /chain/heights".into());
        Json(state.height_response)
    }

    async fn create_chain_handler(
        State(state): State<ChainTransportFixtureState>,
        Json(request): Json<Value>,
    ) -> Response {
        state.calls.lock().unwrap().push("POST /swap/chain".into());
        *state.request.lock().unwrap() = Some(request);
        if state.creation_status.is_success() {
            Json(state.creation_response).into_response()
        } else {
            (
                state.creation_status,
                Json(json!({"error": "stale pair hash"})),
            )
                .into_response()
        }
    }

    async fn spawn_chain_transport_fixture(
        pair: &ChainPair,
        heights: &HeightResponse,
        response: &CreateChainResponse,
        creation_status: StatusCode,
    ) -> ChainTransportFixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let request = Arc::new(Mutex::new(None));
        let state = ChainTransportFixtureState {
            pair_response: json!({"BTC": {"L-BTC": pair}, "L-BTC": {}}),
            height_response: serde_json::to_value(heights).unwrap(),
            creation_response: serde_json::to_value(response).unwrap(),
            creation_status,
            calls: calls.clone(),
            request: request.clone(),
        };
        let app = Router::new()
            .route(
                "/swap/chain",
                get(chain_pairs_handler).post(create_chain_handler),
            )
            .route("/chain/heights", get(chain_heights_handler))
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        ChainTransportFixture {
            base_url: format!("http://{address}"),
            calls,
            request,
            task,
        }
    }

    #[derive(Clone)]
    struct ReversePairsFixtureState {
        response: Value,
        calls: Arc<AtomicUsize>,
    }

    struct ReversePairsFixture {
        base_url: String,
        calls: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl ReversePairsFixture {
        async fn shutdown(self) {
            self.task.abort();
            let _ = self.task.await;
        }
    }

    async fn reverse_pairs_handler(State(state): State<ReversePairsFixtureState>) -> Json<Value> {
        state.calls.fetch_add(1, Ordering::SeqCst);
        Json(state.response)
    }

    async fn spawn_reverse_pairs_fixture(response: Value) -> ReversePairsFixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/swap/reverse", get(reverse_pairs_handler))
            .with_state(ReversePairsFixtureState {
                response,
                calls: calls.clone(),
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        ReversePairsFixture {
            base_url: format!("http://{address}"),
            calls,
            task,
        }
    }

    fn reverse_pair_response() -> Value {
        json!({
            "BTC": {
                "L-BTC": {
                    "hash": "1111111111111111111111111111111111111111111111111111111111111111",
                    "rate": 1.0,
                    "limits": {"minimal": 100, "maximal": 1_000},
                    "fees": {
                        "percentage": 0.25,
                        "minerFees": {"lockup": 27, "claim": 20}
                    }
                }
            }
        })
    }

    #[tokio::test]
    async fn reverse_pair_refresh_uses_exact_pinned_sdk_adapter_once() {
        let fixture = spawn_reverse_pairs_fixture(reverse_pair_response()).await;
        let service = test_service_at(&fixture.base_url, TEST_MNEMONIC);
        let before = std::time::Instant::now();

        let outcome = service.refresh_provider_limits().await;
        let after = std::time::Instant::now();

        assert_eq!(
            outcome,
            crate::provider_limits_runtime::ProviderLimitRefreshOutcome::Updated
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        let range = service
            .provider_limits()
            .lightning_address_range(50_000, 2_000_000)
            .unwrap();
        assert_eq!(range.limits_msat(), (100_000, 1_000_000));
        let observed_at = range.snapshot_evidence().2;
        assert!(observed_at >= before);
        assert!(observed_at <= after);
        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn successful_reverse_response_without_exact_pair_is_invalid() {
        let fixture = spawn_reverse_pairs_fixture(json!({"BTC": {}})).await;
        let service = test_service_at(&fixture.base_url, TEST_MNEMONIC);

        assert_eq!(
            service.refresh_provider_limits().await,
            crate::provider_limits_runtime::ProviderLimitRefreshOutcome::Invalid(
                crate::provider_limits::ReversePairValidationError::ExactPairMissing
            )
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            service.provider_limits().snapshot(),
            crate::provider_limits::ReversePairSnapshotState::Invalid(
                crate::provider_limits::ReversePairValidationError::ExactPairMissing
            )
        ));
        fixture.shutdown().await;
    }

    fn dynamic_chain_creation_response(
        pair: &ChainPair,
        heights: &HeightResponse,
        hashlock: hash160::Hash,
        claim_public_key: PublicKey,
        refund_public_key: PublicKey,
        server_lock_amount_sat: u64,
        provider_bip21: &str,
    ) -> CreateChainResponse {
        const BLINDING_KEY: &str =
            "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f";
        let bitcoin_server_key = PublicKey::from_str(
            "031c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8",
        )
        .unwrap();
        let liquid_server_key = PublicKey::from_str(
            "033009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01a",
        )
        .unwrap();
        let bitcoin_timeout = heights.btc + 144;
        let liquid_timeout = heights.lbtc + 720;
        let user_lock_amount_sat =
            expected_chain_user_lock_amount(pair, server_lock_amount_sat).unwrap();

        let bitcoin_tree = SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(expected_claim_script(hashlock, &bitcoin_server_key)),
                version: BTC_TAPSCRIPT_LEAF_VERSION,
            },
            refund_leaf: Leaf {
                output: hex::encode(expected_refund_script(&refund_public_key, bitcoin_timeout)),
                version: BTC_TAPSCRIPT_LEAF_VERSION,
            },
            covenant_claim_leaf: None,
        };
        let liquid_tree = SwapTree {
            claim_leaf: Leaf {
                output: hex::encode(expected_claim_script(hashlock, &claim_public_key)),
                version: LIQUID_TAPSCRIPT_LEAF_VERSION,
            },
            refund_leaf: Leaf {
                output: hex::encode(expected_refund_script(&liquid_server_key, liquid_timeout)),
                version: LIQUID_TAPSCRIPT_LEAF_VERSION,
            },
            covenant_claim_leaf: None,
        };

        let bitcoin_address = BtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Lockup),
            funding_addrs: None,
            hashlock,
            receiver_pubkey: bitcoin_server_key,
            locktime: LockTime::from_consensus(bitcoin_timeout),
            sender_pubkey: refund_public_key,
        }
        .to_address(BitcoinChain::Bitcoin)
        .unwrap()
        .to_string();
        let blinding_key = ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), BLINDING_KEY).unwrap();
        let liquid_address = LBtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Claim),
            funding_addrs: None,
            hashlock,
            receiver_pubkey: claim_public_key,
            locktime: boltz_client::elements::LockTime::from_consensus(liquid_timeout),
            sender_pubkey: liquid_server_key,
            blinding_key,
        }
        .to_address(LiquidChain::Liquid)
        .unwrap()
        .to_string();

        CreateChainResponse {
            id: "DynamicChainTransport1".into(),
            claim_details: ChainSwapDetails {
                swap_tree: liquid_tree,
                lockup_address: liquid_address,
                server_public_key: liquid_server_key,
                timeout_block_height: liquid_timeout,
                amount: server_lock_amount_sat,
                blinding_key: Some(BLINDING_KEY.into()),
                refund_address: None,
                claim_address: None,
                bip21: None,
            },
            lockup_details: ChainSwapDetails {
                swap_tree: bitcoin_tree,
                lockup_address: bitcoin_address,
                server_public_key: bitcoin_server_key,
                timeout_block_height: bitcoin_timeout,
                amount: user_lock_amount_sat,
                blinding_key: None,
                refund_address: None,
                claim_address: None,
                bip21: Some(provider_bip21.into()),
            },
        }
    }

    fn live_chain_creation_fixture() -> (
        ChainPair,
        HeightResponse,
        hash160::Hash,
        PublicKey,
        PublicKey,
        CreateChainResponse,
    ) {
        // Unfunded mainnet response captured from Boltz's public API. Keeping
        // it as a static fixture exercises both real Taproot address families,
        // including Elements' 0xc4 leaf version, without network access.
        let pair = serde_json::from_value(json!({
            "hash": "014261b046f2045ddedd49fe291e0255afe002454c65a5aa7d6457a35cd32f19",
            "rate": 1.0,
            "limits": {
                "maximal": 25_000_000,
                "minimal": 25_000,
                "maximalZeroConf": 0
            },
            "fees": {
                "percentage": 0.1,
                "minerFees": {
                    "server": 405,
                    "user": {"claim": 20, "lockup": 385}
                }
            }
        }))
        .unwrap();
        let heights = serde_json::from_value(json!({
            "BTC": 957_817,
            "L-BTC": 3_970_775
        }))
        .unwrap();
        let expected_hashlock =
            hash160::Hash::from_str("dcecad90204470ac28c82e626e1322468e3984e8").unwrap();
        let claim_public_key = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let refund_public_key = PublicKey::from_str(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        )
        .unwrap();
        let response = serde_json::from_value(json!({
            "id": "KmPUSXvPCtbF",
            "claimDetails": {
                "blindingKey": "0ede1f5a31e6abc5ed59d0ae20c6089782de3296229bf361fbd3e4fe6babf22f",
                "serverPublicKey": "033009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01a",
                "amount": 25_000,
                "lockupAddress": "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg",
                "timeoutBlockHeight": 3_972_215,
                "swapTree": {
                    "claimLeaf": {
                        "version": 196,
                        "output": "82012088a914dcecad90204470ac28c82e626e1322468e3984e8882079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
                    },
                    "refundLeaf": {
                        "version": 196,
                        "output": "203009adf109ae3c4cb4fd6c1887b33e51d8fb5262ed2e4c6deb99fced3da9d01aad03779c3cb1"
                    }
                }
            },
            "lockupDetails": {
                "serverPublicKey": "031c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8",
                "amount": 25_431,
                "lockupAddress": "bc1pas49mmwakcq8gxnenljc7jp9ksu7xga6qsrle9h3jzec3r68ny6surs7hh",
                "timeoutBlockHeight": 958_033,
                "swapTree": {
                    "claimLeaf": {
                        "version": 192,
                        "output": "82012088a914dcecad90204470ac28c82e626e1322468e3984e888201c7f04c2d5c797ec5aa59b432ae3ccc8ffd5e9355db0b5faa91eb1e25a0453e8ac"
                    },
                    "refundLeaf": {
                        "version": 192,
                        "output": "20c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ad03519e0eb1"
                    }
                },
                "bip21": "bitcoin:provider-controlled-and-never-forwarded?amount=999"
            }
        }))
        .unwrap();

        (
            pair,
            heights,
            expected_hashlock,
            claim_public_key,
            refund_public_key,
            response,
        )
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
    fn taproot_role_distinctness_rejects_opposite_parity_for_the_same_x_coordinate() {
        let even = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        let odd = PublicKey::from_str(
            "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();

        assert_ne!(even, odd);
        assert!(!x_only_role_keys_are_distinct(&[&even, &odd]));
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

    #[test]
    fn validates_complete_real_chain_creation_and_records_exact_terms() {
        let (pair, heights, hashlock, claim, refund, response) = live_chain_creation_fixture();
        let (terms, canonical_response) = validate_chain_creation_response(
            &pair, &heights, hashlock, &claim, &refund, 25_000, &response,
        )
        .unwrap();

        assert_eq!(terms.pinned_pair_hash, pair.hash);
        assert_eq!(terms.btc_timeout_height, 958_033);
        assert_eq!(terms.liquid_timeout_height, 3_972_215);
        assert_eq!(terms.btc_network, "bitcoin");
        assert_eq!(terms.liquid_network, "liquid");
        assert_eq!(terms.liquid_asset_id.len(), 64);
        assert!(
            serde_json::from_str::<serde_json::Value>(&terms.canonical_pair_quote_json)
                .unwrap()
                .is_object()
        );
        for digest in [
            &terms.creation_response_sha256,
            &terms.btc_claim_script_sha256,
            &terms.btc_refund_script_sha256,
            &terms.liquid_claim_script_sha256,
            &terms.liquid_refund_script_sha256,
        ] {
            assert!(is_lower_hex_32(digest));
        }
        assert_eq!(
            terms.creation_response_sha256,
            hex::encode(Sha256::digest(canonical_response.as_bytes()))
        );
    }

    #[test]
    fn exact_template_check_rejects_parser_ignored_script_suffix() {
        let (pair, heights, hashlock, claim, refund, mut response) = live_chain_creation_fixture();
        // The dependency parser extracts the known fields and reconstructs its
        // own template; it ignores this trailing opcode. Our exact comparison
        // must still reject the provider leaf bytes.
        response
            .lockup_details
            .swap_tree
            .claim_leaf
            .output
            .push_str("61");

        let error = validate_chain_creation_response(
            &pair, &heights, hashlock, &claim, &refund, 25_000, &response,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("exact expected template"),
            "{error}"
        );
    }

    #[test]
    fn rejects_unexpected_covenant_leaf_in_either_chain_tree() {
        let (pair, heights, hashlock, claim, refund, response) = live_chain_creation_fixture();

        let mut bitcoin_covenant = response.clone();
        bitcoin_covenant
            .lockup_details
            .swap_tree
            .covenant_claim_leaf =
            Some(bitcoin_covenant.lockup_details.swap_tree.claim_leaf.clone());
        let error = validate_chain_creation_response(
            &pair,
            &heights,
            hashlock,
            &claim,
            &refund,
            25_000,
            &bitcoin_covenant,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unexpected covenant leaf"));

        let mut liquid_covenant = response;
        liquid_covenant.claim_details.swap_tree.covenant_claim_leaf =
            Some(liquid_covenant.claim_details.swap_tree.claim_leaf.clone());
        let error = validate_chain_creation_response(
            &pair,
            &heights,
            hashlock,
            &claim,
            &refund,
            25_000,
            &liquid_covenant,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unexpected covenant leaf"));
    }

    #[test]
    fn rejects_inconsistent_amounts_hashlocks_leaf_versions_and_timeout_order() {
        let (pair, heights, hashlock, claim, refund, response) = live_chain_creation_fixture();

        let mut wrong_amount = response.clone();
        wrong_amount.lockup_details.amount += 1;
        assert!(validate_chain_creation_response(
            &pair,
            &heights,
            hashlock,
            &claim,
            &refund,
            25_000,
            &wrong_amount
        )
        .unwrap_err()
        .to_string()
        .contains("user-lock amount mismatch"));

        let mut wrong_hashlock = response.clone();
        wrong_hashlock.lockup_details.swap_tree.claim_leaf.output = wrong_hashlock
            .lockup_details
            .swap_tree
            .claim_leaf
            .output
            .replacen(
                "dcecad90204470ac28c82e626e1322468e3984e8",
                &"00".repeat(20),
                1,
            );
        assert!(validate_chain_creation_response(
            &pair,
            &heights,
            hashlock,
            &claim,
            &refund,
            25_000,
            &wrong_hashlock
        )
        .is_err());

        let mut wrong_version = response.clone();
        wrong_version.claim_details.swap_tree.claim_leaf.version = 192;
        let error = validate_chain_creation_response(
            &pair,
            &heights,
            hashlock,
            &claim,
            &refund,
            25_000,
            &wrong_version,
        )
        .unwrap_err();
        assert!(error.to_string().contains("Liquid claim leaf version"));

        let late_liquid_height = HeightResponse {
            btc: heights.btc,
            lbtc: response.claim_details.timeout_block_height - 2_200,
        };
        let error = validate_chain_creation_response(
            &pair,
            &late_liquid_height,
            hashlock,
            &claim,
            &refund,
            25_000,
            &response,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must close before"));
    }

    #[test]
    fn provider_bip21_is_evidence_only_and_never_an_approved_input() {
        let (pair, heights, hashlock, claim, refund, mut response) = live_chain_creation_fixture();
        let (first_terms, _) = validate_chain_creation_response(
            &pair, &heights, hashlock, &claim, &refund, 25_000, &response,
        )
        .unwrap();
        response.lockup_details.bip21 = Some("bitcoin:attacker?amount=21000000".into());
        let (second_terms, _) = validate_chain_creation_response(
            &pair, &heights, hashlock, &claim, &refund, 25_000, &response,
        )
        .unwrap();

        // It remains in the canonical response audit hash, but no validated
        // creation term or payer URI derives from it.
        assert_ne!(
            first_terms.creation_response_sha256,
            second_terms.creation_response_sha256
        );
        assert_eq!(
            first_terms.btc_claim_script_sha256,
            second_terms.btc_claim_script_sha256
        );
    }

    #[tokio::test]
    async fn chain_creation_transport_pins_quote_and_returns_only_validated_evidence() {
        let key_source = test_service(TEST_MNEMONIC);
        let claim_key = key_source.derive_swap_key(8_000).unwrap();
        let refund_key = key_source.derive_swap_key(8_001).unwrap();
        let claim_public_key = PublicKey::new(claim_key.keypair.public_key());
        let refund_public_key = PublicKey::new(refund_key.keypair.public_key());
        let preimage_hash = claim_key.preimage.sha256.to_string();
        let hashlock = claim_key.preimage.hash160;
        let (pair, heights, _, _, _, _) = live_chain_creation_fixture();
        let provider_bip21 =
            "bitcoin:provider-controlled-and-never-forwarded?amount=21000000&label=unsafe";
        let response = dynamic_chain_creation_response(
            &pair,
            &heights,
            hashlock,
            claim_public_key,
            refund_public_key,
            25_000,
            provider_bip21,
        );
        let expected_lockup_address = response.lockup_details.lockup_address.clone();
        let expected_user_lock_amount = response.lockup_details.amount;
        let fixture =
            spawn_chain_transport_fixture(&pair, &heights, &response, StatusCode::OK).await;
        let service = test_service_at(&fixture.base_url, TEST_MNEMONIC);

        let result = service
            .create_btc_to_lbtc_chain_swap(claim_key, refund_key, 25_000)
            .await
            .unwrap();

        assert_eq!(
            fixture.calls(),
            vec!["GET /swap/chain", "GET /chain/heights", "POST /swap/chain",]
        );
        let request = fixture.request();
        assert_eq!(request["from"], "BTC");
        assert_eq!(request["to"], "L-BTC");
        assert_eq!(request["pairHash"], pair.hash);
        assert_eq!(request["serverLockAmount"], 25_000);
        assert!(request.get("userLockAmount").is_none());
        assert_eq!(request["preimageHash"], preimage_hash);
        assert_eq!(request["claimPublicKey"], claim_public_key.to_string());
        assert_eq!(request["refundPublicKey"], refund_public_key.to_string());

        // Exhaustive destructuring keeps the provider response (and therefore
        // its BIP21) out of the result API while retaining canonical evidence.
        let ChainSwapResult {
            swap_id,
            lockup_address,
            user_lock_amount_sat,
            server_lock_amount_sat,
            preimage,
            claim_keypair: _,
            refund_keypair: _,
            canonical_response_json,
            creation_terms,
        } = result;
        assert_eq!(swap_id, response.id);
        assert_eq!(lockup_address, expected_lockup_address);
        assert!(!lockup_address.contains(':'));
        assert!(!lockup_address.contains('?'));
        assert_eq!(user_lock_amount_sat, expected_user_lock_amount);
        assert_eq!(server_lock_amount_sat, 25_000);
        assert_eq!(preimage.len(), 32);
        assert_eq!(creation_terms.pinned_pair_hash, pair.hash);
        assert_eq!(
            creation_terms.creation_response_sha256,
            hex::encode(Sha256::digest(canonical_response_json.as_bytes()))
        );
        let canonical_response: Value = serde_json::from_str(&canonical_response_json).unwrap();
        assert_eq!(canonical_response["lockupDetails"]["bip21"], provider_bip21);
        let canonical_pair: Value =
            serde_json::from_str(&creation_terms.canonical_pair_quote_json).unwrap();
        assert_eq!(canonical_pair["hash"], pair.hash);

        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn chain_creation_transport_surfaces_stale_pair_provider_error() {
        let key_source = test_service(TEST_MNEMONIC);
        let claim_key = key_source.derive_swap_key(8_010).unwrap();
        let refund_key = key_source.derive_swap_key(8_011).unwrap();
        let claim_public_key = PublicKey::new(claim_key.keypair.public_key());
        let refund_public_key = PublicKey::new(refund_key.keypair.public_key());
        let (pair, heights, _, _, _, _) = live_chain_creation_fixture();
        let response = dynamic_chain_creation_response(
            &pair,
            &heights,
            claim_key.preimage.hash160,
            claim_public_key,
            refund_public_key,
            25_000,
            "bitcoin:not-returned",
        );
        let fixture =
            spawn_chain_transport_fixture(&pair, &heights, &response, StatusCode::CONFLICT).await;
        let service = test_service_at(&fixture.base_url, TEST_MNEMONIC);

        let error = match service
            .create_btc_to_lbtc_chain_swap(claim_key, refund_key, 25_000)
            .await
        {
            Ok(_) => panic!("stale pair response unexpectedly created a chain swap"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("stale pair hash"), "{error}");
        assert_eq!(
            fixture.calls(),
            vec!["GET /swap/chain", "GET /chain/heights", "POST /swap/chain",]
        );
        assert_eq!(fixture.request()["pairHash"], pair.hash);

        fixture.shutdown().await;
    }
}
