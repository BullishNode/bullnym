//! Exact-source, two-phase cooperative Bitcoin refund signing.
//!
//! This module deliberately performs no network or database I/O. The caller
//! persists [`PreparedCooperativeRefund::durable_request`] before sending that
//! exact request to Boltz, persists one exact provider response, and only then
//! consumes the secret nonce to assemble the final key-path witness.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::key::rand::{rngs::OsRng, RngCore};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, Signature as TaprootSignature, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Witness,
};
use boltz_client::swaps::bitcoin::BtcSwapScript;
use boltz_client::swaps::boltz::{ChainSwapDetails, PartialSig, Side};
use boltz_client::{Keypair, PublicKey};
use secp256k1_musig::musig;
use secp256k1_musig::{Keypair as MusigKeypair, PublicKey as MusigPublicKey, Scalar};
use zeroize::Zeroizing;

use crate::builder_fee::BitcoinBuilderFeeDecision;
use crate::error::AppError;

const COOPERATIVE_INPUT_INDEX: u32 = 0;

/// Non-secret exact provider request. Its canonical JSON fields are
/// `pubNonce`, `transaction`, and `index`, matching Boltz API v2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableCooperativeRequest {
    pub unsigned_tx_hex: String,
    pub txid: String,
    pub public_nonce_hex: String,
    pub sighash_hex: String,
    pub tweaked_aggregate_key_hex: String,
    pub input_index: u32,
}

/// Prepared signing state. The secret nonce is intentionally not `Clone`,
/// serializable, or `Debug`; callers may only seal it into the protected
/// operation journal.
pub(crate) struct PreparedCooperativeRefund {
    request: DurableCooperativeRequest,
    secret_nonce: SecretNonceMaterial,
}

impl PreparedCooperativeRefund {
    pub(crate) fn durable_request(&self) -> &DurableCooperativeRequest {
        &self.request
    }

    pub(crate) fn secret_nonce(&self) -> &SecretNonceMaterial {
        &self.secret_nonce
    }
}

/// Key-grade nonce material. It is never formatted and is overwritten on
/// drop after the caller seals it into the protected operation journal.
pub(crate) struct SecretNonceMaterial(Zeroizing<Vec<u8>>);

impl SecretNonceMaterial {
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(crate) struct CompletedCooperativeRefund {
    pub transaction: Transaction,
    pub local_partial_signature_sha256: String,
}

pub(crate) fn exact_chain_lockup_script(
    details: &ChainSwapDetails,
    refund_public_key: PublicKey,
) -> Result<BtcSwapScript, AppError> {
    BtcSwapScript::chain_from_swap_resp(Side::Lockup, details.clone(), refund_public_key)
        .map_err(|error| AppError::ClaimError(format!("chain lockup script build failed: {error}")))
}

/// Fail closed unless every construction-backend outpoint is the one exact
/// independently authorized source. No provider signing request may happen
/// before this succeeds.
pub(crate) fn select_exact_source(
    expected: &OutPoint,
    expected_txout: &TxOut,
    backend_sources: Vec<(OutPoint, TxOut)>,
) -> Result<TxOut, AppError> {
    if backend_sources.len() != 1
        || backend_sources[0].0 != *expected
        || backend_sources[0].1 != *expected_txout
    {
        return Err(AppError::RecoveryNotAvailable(
            "cooperative recovery construction source set differs from primary authority".into(),
        ));
    }
    Ok(backend_sources
        .into_iter()
        .next()
        .expect("length checked")
        .1)
}

pub(crate) fn prepare_exact_cooperative_refund(
    script: &BtcSwapScript,
    details: &ChainSwapDetails,
    refund_keypair: &Keypair,
    source_outpoint: OutPoint,
    source_txout: TxOut,
    destination_address: &str,
    fee_decision: BitcoinBuilderFeeDecision,
) -> Result<PreparedCooperativeRefund, AppError> {
    let destination = Address::from_str(destination_address)
        .map_err(|_| AppError::ClaimError("cooperative recovery destination is invalid".into()))?
        .require_network(bitcoin::Network::Bitcoin)
        .map_err(|_| {
            AppError::ClaimError("cooperative recovery destination is not mainnet".into())
        })?;
    let expected_lockup = script
        .to_address(boltz_client::network::BitcoinChain::Bitcoin)
        .map_err(|error| {
            AppError::ClaimError(format!("derive cooperative lockup address: {error}"))
        })?
        .script_pubkey();
    if source_txout.script_pubkey != expected_lockup {
        return Err(AppError::ClaimError(
            "cooperative recovery source is not the immutable lockup script".into(),
        ));
    }

    let mut template = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: source_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: cooperative_size_witness(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: destination.script_pubkey(),
        }],
    };
    let vbytes = u64::try_from(template.vsize()).map_err(|_| {
        AppError::ClaimError("cooperative recovery virtual size exceeds policy range".into())
    })?;
    let fee_sat = fee_decision
        .rate()
        .checked_fee_for_vbytes(vbytes)
        .map_err(|error| {
            AppError::ClaimError(format!("cooperative recovery fee is invalid: {error}"))
        })?;
    let destination_sat = source_txout
        .value
        .to_sat()
        .checked_sub(fee_sat)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| {
            AppError::ClaimError("cooperative recovery fee consumes its source".into())
        })?;
    template.output[0].value = Amount::from_sat(destination_sat);

    let message = cooperative_sighash(&template, &source_txout)?;
    let key_agg_cache = tweaked_key_agg_cache(script, details)?;
    let source_output_key = p2tr_output_key(&source_txout.script_pubkey)?;
    let tweaked_aggregate_key =
        bitcoin::XOnlyPublicKey::from_slice(&key_agg_cache.agg_pk().serialize()).map_err(|_| {
            AppError::ClaimError("cooperative tweaked aggregate key is invalid".into())
        })?;
    if tweaked_aggregate_key != source_output_key {
        return Err(AppError::ClaimError(
            "cooperative MuSig tree does not match the authoritative source".into(),
        ));
    }
    let our_public_key = convert_public_key(refund_keypair.public_key());
    let mut session_secret_bytes = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(session_secret_bytes.as_mut());
    let session_secret =
        musig::SessionSecretRand::assume_unique_per_nonce_gen(*session_secret_bytes);
    let mut extra_randomness = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(extra_randomness.as_mut());
    let (secret_nonce, public_nonce) =
        key_agg_cache.nonce_gen(session_secret, our_public_key, &message, Some(*extra_randomness));
    let secret_nonce =
        SecretNonceMaterial(Zeroizing::new(secret_nonce.dangerous_into_bytes().to_vec()));
    let unsigned_tx_hex = hex::encode(bitcoin::consensus::serialize(&template));
    let txid = template.compute_txid().to_string();

    Ok(PreparedCooperativeRefund {
        request: DurableCooperativeRequest {
            unsigned_tx_hex,
            txid,
            public_nonce_hex: hex::encode(public_nonce.serialize()),
            sighash_hex: hex::encode(message),
            tweaked_aggregate_key_hex: tweaked_aggregate_key.to_string(),
            input_index: COOPERATIVE_INPUT_INDEX,
        },
        secret_nonce,
    })
}

/// Consume the protected nonce only after the exact provider response has
/// been durably selected. Replaying the same selected response deterministically
/// reconstructs the same final witness after a local transaction rollback.
pub(crate) fn complete_exact_cooperative_refund(
    script: &BtcSwapScript,
    details: &ChainSwapDetails,
    refund_keypair: &Keypair,
    source_txout: &TxOut,
    request: &DurableCooperativeRequest,
    secret_nonce_bytes: &[u8],
    provider_response: &PartialSig,
) -> Result<CompletedCooperativeRefund, AppError> {
    if request.input_index != COOPERATIVE_INPUT_INDEX {
        return Err(AppError::ClaimError(
            "cooperative signing request input index is not canonical".into(),
        ));
    }
    let raw = hex::decode(&request.unsigned_tx_hex)
        .map_err(|_| AppError::ClaimError("cooperative signing template hex is invalid".into()))?;
    let mut transaction: Transaction = bitcoin::consensus::deserialize(&raw)
        .map_err(|_| AppError::ClaimError("cooperative signing template is invalid".into()))?;
    if transaction.compute_txid().to_string() != request.txid
        || transaction.input.len() != 1
        || transaction.input[0].sequence != Sequence::MAX
        || transaction.lock_time != LockTime::ZERO
        || transaction.input[0].witness != cooperative_size_witness()
    {
        return Err(AppError::ClaimError(
            "cooperative signing template shape changed".into(),
        ));
    }

    let message = cooperative_sighash(&transaction, source_txout)?;
    let key_agg_cache = tweaked_key_agg_cache(script, details)?;
    let source_output_key = p2tr_output_key(&source_txout.script_pubkey)?;
    let tweaked_aggregate_key =
        bitcoin::XOnlyPublicKey::from_slice(&key_agg_cache.agg_pk().serialize()).map_err(|_| {
            AppError::ClaimError("cooperative tweaked aggregate key is invalid".into())
        })?;
    if hex::encode(message) != request.sighash_hex
        || tweaked_aggregate_key.to_string() != request.tweaked_aggregate_key_hex
        || tweaked_aggregate_key != source_output_key
    {
        return Err(AppError::ClaimError(
            "cooperative signing session differs from its durable request".into(),
        ));
    }
    let public_nonce = musig::PublicNonce::from_str(&request.public_nonce_hex)
        .map_err(|_| AppError::ClaimError("cooperative signing public nonce is invalid".into()))?;
    let provider_nonce = musig::PublicNonce::from_str(&provider_response.pub_nonce)
        .map_err(|_| AppError::ClaimError("provider cooperative public nonce is invalid".into()))?;
    let provider_partial = musig::PartialSignature::from_str(&provider_response.partial_signature)
        .map_err(|_| {
            AppError::ClaimError("provider cooperative partial signature is invalid".into())
        })?;
    let secret_nonce =
        musig::SecretNonce::dangerous_from_bytes(secret_nonce_bytes.try_into().map_err(|_| {
            AppError::ClaimError("cooperative secret nonce has the wrong length".into())
        })?);
    let aggregate_nonce = musig::AggregatedNonce::new(&[&provider_nonce, &public_nonce]);
    let session = musig::Session::new(&key_agg_cache, aggregate_nonce, &message);
    if !session.partial_verify(
        &key_agg_cache,
        &provider_partial,
        &provider_nonce,
        convert_public_key(script.receiver_pubkey.inner),
    ) {
        return Err(AppError::ClaimError(
            "provider cooperative partial signature failed verification".into(),
        ));
    }
    let local_partial = session.partial_sign(
        secret_nonce,
        &convert_keypair(refund_keypair),
        &key_agg_cache,
    );
    let local_partial_signature_sha256 = sha256_hex(&local_partial.serialize());
    let signature = session
        .partial_sig_agg(&[&provider_partial, &local_partial])
        .assume_valid();
    let bitcoin_signature = bitcoin::secp256k1::schnorr::Signature::from_slice(
        signature.as_byte_array(),
    )
    .map_err(|_| AppError::ClaimError("cooperative aggregate signature is invalid".into()))?;
    let final_signature = TaprootSignature {
        signature: bitcoin_signature,
        sighash_type: TapSighashType::Default,
    };
    transaction.input[0].witness.clear();
    transaction.input[0].witness.push(final_signature.to_vec());

    bitcoin::secp256k1::Secp256k1::verification_only()
        .verify_schnorr(
            &bitcoin_signature,
            &bitcoin::secp256k1::Message::from_digest(message),
            &source_output_key,
        )
        .map_err(|_| {
            AppError::ClaimError("cooperative aggregate signature does not spend the source".into())
        })?;
    Ok(CompletedCooperativeRefund {
        transaction,
        local_partial_signature_sha256,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

fn cooperative_size_witness() -> Witness {
    let mut witness = Witness::new();
    witness.push([0_u8; 64]);
    witness
}

fn cooperative_sighash(
    transaction: &Transaction,
    source_txout: &TxOut,
) -> Result<[u8; 32], AppError> {
    let hash = SighashCache::new(transaction.clone())
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&[source_txout]),
            TapSighashType::Default,
        )
        .map_err(|_| AppError::ClaimError("cooperative recovery sighash is invalid".into()))?;
    Ok(hash.to_byte_array())
}

fn tweaked_key_agg_cache(
    script: &BtcSwapScript,
    details: &ChainSwapDetails,
) -> Result<musig::KeyAggCache, AppError> {
    let mut cache = script.musig_keyagg_cache();
    let internal_key =
        bitcoin::XOnlyPublicKey::from_slice(&cache.agg_pk().serialize()).map_err(|_| {
            AppError::ClaimError("cooperative aggregate internal key is invalid".into())
        })?;
    let claim_script = ScriptBuf::from_hex(&details.swap_tree.claim_leaf.output)
        .map_err(|_| AppError::ClaimError("cooperative claim leaf is invalid".into()))?;
    let refund_script = ScriptBuf::from_hex(&details.swap_tree.refund_leaf.output)
        .map_err(|_| AppError::ClaimError("cooperative refund leaf is invalid".into()))?;
    let claim_version = LeafVersion::from_consensus(details.swap_tree.claim_leaf.version)
        .map_err(|_| AppError::ClaimError("cooperative claim leaf version is invalid".into()))?;
    let refund_version = LeafVersion::from_consensus(details.swap_tree.refund_leaf.version)
        .map_err(|_| AppError::ClaimError("cooperative refund leaf version is invalid".into()))?;
    let spend_info = TaprootBuilder::new()
        .add_leaf_with_ver(1, claim_script, claim_version)
        .and_then(|builder| builder.add_leaf_with_ver(1, refund_script, refund_version))
        .map_err(|_| AppError::ClaimError("cooperative Taproot tree is invalid".into()))?
        .finalize(&bitcoin::secp256k1::Secp256k1::new(), internal_key)
        .map_err(|_| AppError::ClaimError("cooperative Taproot tree is incomplete".into()))?;
    let tweak = Scalar::from_be_bytes(*spend_info.tap_tweak().as_byte_array())
        .map_err(|_| AppError::ClaimError("cooperative Taproot tweak is invalid".into()))?;
    cache
        .pubkey_xonly_tweak_add(&tweak)
        .map_err(|_| AppError::ClaimError("cooperative Taproot tweak failed".into()))?;
    Ok(cache)
}

fn convert_public_key(key: bitcoin::secp256k1::PublicKey) -> MusigPublicKey {
    MusigPublicKey::from_slice(&key.serialize()).expect("compressed public key size is stable")
}

fn convert_keypair(keypair: &bitcoin::secp256k1::Keypair) -> MusigKeypair {
    MusigKeypair::from_seckey_byte_array(keypair.secret_bytes())
        .expect("valid Bitcoin keypair remains a valid MuSig keypair")
}

fn p2tr_output_key(script: &ScriptBuf) -> Result<bitcoin::XOnlyPublicKey, AppError> {
    let bytes = script.as_bytes();
    if bytes.len() != 34 || bytes[0] != 0x51 || bytes[1] != 0x20 {
        return Err(AppError::ClaimError(
            "cooperative recovery source is not Taproot".into(),
        ));
    }
    bitcoin::XOnlyPublicKey::from_slice(&bytes[2..]).map_err(|_| {
        AppError::ClaimError("cooperative recovery Taproot output key is invalid".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_swap_fixture() -> (BtcSwapScript, ChainSwapDetails, Keypair, Keypair, TxOut) {
        use bitcoin::hashes::hash160;
        use bitcoin::opcodes::all::{
            OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
        };
        use bitcoin::script::Builder;
        use boltz_client::swaps::boltz::{Leaf, SwapTree, SwapType};

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let refund_secret = bitcoin::secp256k1::SecretKey::from_slice(&[3_u8; 32]).unwrap();
        let provider_secret = bitcoin::secp256k1::SecretKey::from_slice(&[4_u8; 32]).unwrap();
        let refund_keypair = Keypair::from_secret_key(&secp, &refund_secret);
        let provider_keypair = Keypair::from_secret_key(&secp, &provider_secret);
        let refund_public = PublicKey::new(refund_keypair.public_key());
        let provider_public = PublicKey::new(provider_keypair.public_key());
        let hashlock = hash160::Hash::from_slice(&[5_u8; 20]).unwrap();
        let timeout = LockTime::from_consensus(840_000);
        let claim_script = Builder::new()
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_HASH160)
            .push_slice(hashlock.to_byte_array())
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&provider_public.inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let refund_script = Builder::new()
            .push_x_only_key(&refund_public.inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_lock_time(timeout)
            .push_opcode(OP_CLTV)
            .into_script();
        let mut script = BtcSwapScript {
            swap_type: SwapType::Chain,
            side: Some(Side::Lockup),
            funding_addrs: None,
            hashlock,
            receiver_pubkey: provider_public,
            locktime: timeout,
            sender_pubkey: refund_public,
        };
        let address = script
            .to_address(boltz_client::network::BitcoinChain::Bitcoin)
            .unwrap();
        script.funding_addrs = Some(address.clone());
        let details = ChainSwapDetails {
            swap_tree: SwapTree {
                claim_leaf: Leaf {
                    output: hex::encode(claim_script.as_bytes()),
                    version: 0xc0,
                },
                refund_leaf: Leaf {
                    output: hex::encode(refund_script.as_bytes()),
                    version: 0xc0,
                },
                covenant_claim_leaf: None,
            },
            lockup_address: address.to_string(),
            server_public_key: provider_public,
            timeout_block_height: 840_000,
            amount: 100_000,
            blinding_key: None,
            refund_address: None,
            claim_address: None,
            bip21: None,
        };
        let source = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        };
        (script, details, refund_keypair, provider_keypair, source)
    }

    fn fee_decision() -> BitcoinBuilderFeeDecision {
        use crate::fee_policy::{BitcoinFeePolicy, FeeProvenance, LiveBitcoin, SatPerVbyte};

        let observation = LiveBitcoin::new(
            SatPerVbyte::try_from(2.0).unwrap(),
            1_000,
            FeeProvenance::new("cooperative-test").unwrap(),
        );
        BitcoinBuilderFeeDecision::from(
            &BitcoinFeePolicy::default()
                .decide_typed(Some(&observation), None, 1_000)
                .unwrap(),
        )
    }

    #[test]
    fn late_or_extra_construction_source_fails_closed() {
        let expected = OutPoint::null();
        let txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new(),
        };
        assert_eq!(
            select_exact_source(&expected, &txout, vec![(expected, txout.clone())]).unwrap(),
            txout
        );
        assert!(select_exact_source(
            &expected,
            &txout,
            vec![
                (expected, txout.clone()),
                (
                    OutPoint {
                        txid: "11".repeat(32).parse().unwrap(),
                        vout: 1,
                    },
                    txout.clone(),
                ),
            ],
        )
        .is_err());

        let mut wrong_amount = txout.clone();
        wrong_amount.value = Amount::from_sat(99_999);
        assert!(select_exact_source(&expected, &txout, vec![(expected, wrong_amount)],).is_err());
        let mut wrong_script = txout.clone();
        wrong_script.script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        assert!(select_exact_source(&expected, &txout, vec![(expected, wrong_script)],).is_err());
    }

    #[test]
    fn exact_prepared_request_completes_only_with_a_valid_provider_partial() {
        let (script, details, refund_keypair, provider_keypair, source) = exact_swap_fixture();
        let prepared = prepare_exact_cooperative_refund(
            &script,
            &details,
            &refund_keypair,
            OutPoint::null(),
            source.clone(),
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            fee_decision(),
        )
        .unwrap();
        let request = prepared.durable_request();
        let message: [u8; 32] = hex::decode(&request.sighash_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let cache = tweaked_key_agg_cache(&script, &details).unwrap();
        let provider_session_secret =
            musig::SessionSecretRand::assume_unique_per_nonce_gen([9_u8; 32]);
        let (provider_secret_nonce, provider_public_nonce) = cache.nonce_gen(
            provider_session_secret,
            convert_public_key(provider_keypair.public_key()),
            &message,
            None,
        );
        let client_public_nonce = musig::PublicNonce::from_str(&request.public_nonce_hex).unwrap();
        let aggregate_nonce =
            musig::AggregatedNonce::new(&[&provider_public_nonce, &client_public_nonce]);
        let session = musig::Session::new(&cache, aggregate_nonce, &message);
        let provider_partial = session.partial_sign(
            provider_secret_nonce,
            &convert_keypair(&provider_keypair),
            &cache,
        );
        let response = PartialSig {
            pub_nonce: provider_public_nonce.to_string(),
            partial_signature: provider_partial.to_string(),
        };
        let completed = complete_exact_cooperative_refund(
            &script,
            &details,
            &refund_keypair,
            &source,
            request,
            prepared.secret_nonce().expose(),
            &response,
        )
        .unwrap();
        let final_transaction = completed.transaction;
        assert_eq!(completed.local_partial_signature_sha256.len(), 64);
        assert_eq!(final_transaction.compute_txid().to_string(), request.txid);
        assert_eq!(final_transaction.input.len(), 1);
        assert_eq!(final_transaction.input[0].witness.len(), 1);
        assert_eq!(final_transaction.input[0].witness[0].len(), 64);

        let mut invalid = response;
        invalid.partial_signature.replace_range(0..2, "00");
        assert!(complete_exact_cooperative_refund(
            &script,
            &details,
            &refund_keypair,
            &source,
            request,
            prepared.secret_nonce().expose(),
            &invalid,
        )
        .is_err());
    }
}
