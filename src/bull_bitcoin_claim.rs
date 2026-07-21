//! Exact local authority for a mixed Liquid claim.
//!
//! Bullnym cannot unblind Bull Bitcoin's confidential output. It instead
//! proves the fixed amount by opening the merchant output, independently
//! establishing the all-L-BTC source total, and requiring the only remaining
//! value to be `source - merchant - fee`. The persisted hashes bind retries to
//! the same commitments and proofs without retaining Bull Bitcoin's address.

use std::str::FromStr;

use boltz_client::elements;
use boltz_client::swaps::BtcLikeTransaction;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedClaimOutput {
    pub role: &'static str,
    pub txid: String,
    pub vout: i16,
    pub script_pubkey_hex: String,
    pub authorized_amount_sat: i64,
    pub asset_commitment_sha256: String,
    pub value_commitment_sha256: String,
    pub nonce_commitment_sha256: String,
    pub surjection_proof_sha256: String,
    pub rangeproof_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMixedClaim {
    pub merchant: VerifiedClaimOutput,
    pub bull_bitcoin: VerifiedClaimOutput,
    pub fee_amount_sat: u64,
}

pub fn verify_mixed_liquid_claim(
    claim: &BtcLikeTransaction,
    source_outputs: &[elements::TxOut],
    source_total_sat: u64,
    merchant_address: &str,
    merchant_blinding_key_hex: &str,
    bull_bitcoin_address: &str,
    bull_bitcoin_amount_sat: i64,
) -> Result<VerifiedMixedClaim, String> {
    let bull_bitcoin_address = elements::Address::from_str(bull_bitcoin_address)
        .map_err(|_| "Bull Bitcoin Liquid address is invalid".to_owned())?;
    if bull_bitcoin_address.params != &elements::AddressParams::LIQUID
        || bull_bitcoin_address.blinding_pubkey.is_none()
    {
        return Err(
            "Bull Bitcoin destination must be a confidential Liquid mainnet address".into(),
        );
    }
    verify_mixed_liquid_claim_for_script(
        claim,
        source_outputs,
        source_total_sat,
        merchant_address,
        merchant_blinding_key_hex,
        &hex::encode(bull_bitcoin_address.script_pubkey().as_bytes()),
        bull_bitcoin_amount_sat,
    )
}

/// Replay verifier. Once claim evidence commits, Bullnym erases the provider
/// address and retains only the script that the immutable transaction pays.
pub fn verify_mixed_liquid_claim_for_script(
    claim: &BtcLikeTransaction,
    source_outputs: &[elements::TxOut],
    source_total_sat: u64,
    merchant_address: &str,
    merchant_blinding_key_hex: &str,
    bull_bitcoin_script_pubkey_hex: &str,
    bull_bitcoin_amount_sat: i64,
) -> Result<VerifiedMixedClaim, String> {
    let transaction = claim
        .as_liquid()
        .ok_or_else(|| "mixed claim is not a Liquid transaction".to_owned())?;
    let secp = elements::secp256k1_zkp::Secp256k1::new();
    transaction
        .verify_tx_amt_proofs(&secp, source_outputs)
        .map_err(|_| {
            "mixed claim commitments do not balance against their exact source outputs".to_owned()
        })?;
    if transaction.output.len() != 3 {
        return Err("mixed claim must contain [merchant, Bull Bitcoin, fee]".into());
    }
    let merchant_output = &transaction.output[0];
    let bull_bitcoin_output = &transaction.output[1];
    let fee_output = &transaction.output[2];
    if merchant_output.is_fee() || bull_bitcoin_output.is_fee() || !fee_output.is_fee() {
        return Err("mixed claim output ordering is invalid".into());
    }

    let merchant_address = elements::Address::from_str(merchant_address)
        .map_err(|_| "merchant Liquid address is invalid".to_owned())?;
    if merchant_address.params != &elements::AddressParams::LIQUID
        || merchant_address.blinding_pubkey.is_none()
    {
        return Err("merchant destination must be a confidential Liquid mainnet address".into());
    }
    let bull_bitcoin_script = hex::decode(bull_bitcoin_script_pubkey_hex)
        .map(elements::Script::from)
        .map_err(|_| "Bull Bitcoin output script is invalid hex".to_owned())?;
    if bull_bitcoin_script.is_empty()
        || hex::encode(bull_bitcoin_script.as_bytes()) != bull_bitcoin_script_pubkey_hex
    {
        return Err("Bull Bitcoin output script is not canonical".into());
    }
    if merchant_output.script_pubkey != merchant_address.script_pubkey()
        || bull_bitcoin_output.script_pubkey != bull_bitcoin_script
    {
        return Err("mixed claim output script does not match its authorized destination".into());
    }

    let merchant_blinding_key =
        elements::secp256k1_zkp::SecretKey::from_str(merchant_blinding_key_hex)
            .map_err(|_| "merchant Liquid blinding key is invalid".to_owned())?;
    let merchant_blinding_pubkey =
        elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &merchant_blinding_key);
    if merchant_address.blinding_pubkey != Some(merchant_blinding_pubkey) {
        return Err("merchant blinding key does not match its Liquid address".into());
    }
    let opened = merchant_output
        .unblind(&secp, merchant_blinding_key)
        .map_err(|_| "merchant mixed output could not be unblinded".to_owned())?;
    if opened.asset != elements::AssetId::LIQUID_BTC || opened.value == 0 {
        return Err("merchant mixed output is not a positive L-BTC amount".into());
    }

    let bull_bitcoin_amount = u64::try_from(bull_bitcoin_amount_sat)
        .ok()
        .filter(|amount| *amount > 0)
        .ok_or_else(|| "Bull Bitcoin mixed amount is invalid".to_owned())?;
    let fee_amount = fee_output
        .value
        .explicit()
        .filter(|amount| *amount > 0)
        .ok_or_else(|| "mixed claim fee is not a positive explicit value".to_owned())?;
    if fee_output.asset.explicit() != Some(elements::AssetId::LIQUID_BTC)
        || !fee_output.nonce.is_null()
        || !fee_output.witness.is_empty()
        || transaction.all_fees().len() != 1
        || transaction.fee_in(elements::AssetId::LIQUID_BTC) != fee_amount
    {
        return Err("mixed claim has an invalid explicit L-BTC fee output".into());
    }
    if source_total_sat
        .checked_sub(opened.value)
        .and_then(|remaining| remaining.checked_sub(fee_amount))
        != Some(bull_bitcoin_amount)
    {
        return Err("mixed claim source/output/fee balance does not authorize the fiat leg".into());
    }

    require_confidential_payment_output(merchant_output, "merchant")?;
    require_confidential_payment_output(bull_bitcoin_output, "Bull Bitcoin")?;
    let txid = transaction.txid().to_string();
    let merchant_amount = i64::try_from(opened.value)
        .map_err(|_| "merchant mixed amount exceeds storage range".to_owned())?;
    Ok(VerifiedMixedClaim {
        merchant: output_evidence("merchant", &txid, 0, merchant_output, merchant_amount)?,
        bull_bitcoin: output_evidence(
            "bull_bitcoin",
            &txid,
            1,
            bull_bitcoin_output,
            bull_bitcoin_amount_sat,
        )?,
        fee_amount_sat: fee_amount,
    })
}

fn require_confidential_payment_output(
    output: &elements::TxOut,
    label: &str,
) -> Result<(), String> {
    if !matches!(output.asset, elements::confidential::Asset::Confidential(_))
        || !matches!(output.value, elements::confidential::Value::Confidential(_))
        || !matches!(output.nonce, elements::confidential::Nonce::Confidential(_))
        || output.witness.surjectionproof_len() == 0
        || output.witness.rangeproof_len() == 0
    {
        return Err(format!("{label} mixed output is not fully confidential"));
    }
    Ok(())
}

fn output_evidence(
    role: &'static str,
    txid: &str,
    vout: i16,
    output: &elements::TxOut,
    authorized_amount_sat: i64,
) -> Result<VerifiedClaimOutput, String> {
    let surjection = output
        .witness
        .surjection_proof
        .as_ref()
        .ok_or_else(|| "mixed output has no surjection proof".to_owned())?;
    let rangeproof = output
        .witness
        .rangeproof
        .as_ref()
        .ok_or_else(|| "mixed output has no rangeproof".to_owned())?;
    Ok(VerifiedClaimOutput {
        role,
        txid: txid.to_owned(),
        vout,
        script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
        authorized_amount_sat,
        asset_commitment_sha256: sha256(&elements::encode::serialize(&output.asset)),
        value_commitment_sha256: sha256(&elements::encode::serialize(&output.value)),
        nonce_commitment_sha256: sha256(&elements::encode::serialize(&output.nonce)),
        surjection_proof_sha256: sha256(&surjection.serialize()),
        rangeproof_sha256: sha256(&rangeproof.serialize()),
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS_TEMPLATE: &str = "lq1pqv20pj0v3drz4xuzra5tgl4lylxaaglu6uamqryj06raeztexcyfquafnsttga69pezal4khvghxwkg65cqa9mrm9q4t9z0sk0a0gvsur6lrsu8hg8zg";

    struct MixedFixture {
        claim: BtcLikeTransaction,
        source_outputs: Vec<elements::TxOut>,
        merchant_address: String,
        merchant_blinding_key_hex: String,
        bull_bitcoin_address: String,
        bull_bitcoin_script_hex: String,
    }

    fn mixed_fixture(merchant_amount_sat: u64, bull_bitcoin_amount_sat: u64) -> MixedFixture {
        let secp = elements::secp256k1_zkp::Secp256k1::new();
        let mut rng = elements::secp256k1_zkp::rand::thread_rng();
        let asset = elements::AssetId::LIQUID_BTC;
        let source_amount_sat = 100_000;
        let fee_amount_sat = 1_000;
        let address_template = elements::Address::from_str(ADDRESS_TEMPLATE)
            .unwrap()
            .to_unconfidential();

        let merchant_blinding_key = elements::secp256k1_zkp::SecretKey::new(&mut rng);
        let merchant_blinding_pubkey =
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &merchant_blinding_key);
        let merchant_address = address_template
            .clone()
            .to_confidential(merchant_blinding_pubkey);
        let bull_bitcoin_blinding_key = elements::secp256k1_zkp::SecretKey::new(&mut rng);
        let bull_bitcoin_blinding_pubkey =
            elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &bull_bitcoin_blinding_key);
        let bull_bitcoin_address = address_template.to_confidential(bull_bitcoin_blinding_pubkey);

        let source_secrets = elements::TxOutSecrets::new(
            asset,
            elements::confidential::AssetBlindingFactor::zero(),
            source_amount_sat,
            elements::confidential::ValueBlindingFactor::zero(),
        );
        let source_output = elements::TxOut {
            asset: elements::confidential::Asset::Explicit(asset),
            value: elements::confidential::Value::Explicit(source_amount_sat),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: elements::Script::from(vec![0x51]),
            witness: elements::TxOutWitness::default(),
        };
        let (merchant_output, merchant_abf, merchant_vbf, _) =
            elements::TxOut::new_not_last_confidential(
                &mut rng,
                &secp,
                merchant_amount_sat,
                merchant_address.clone(),
                asset,
                &[source_secrets],
            )
            .unwrap();
        let merchant_secrets =
            elements::TxOutSecrets::new(asset, merchant_abf, merchant_amount_sat, merchant_vbf);
        let fee_secrets = elements::TxOutSecrets::new(
            asset,
            elements::confidential::AssetBlindingFactor::zero(),
            fee_amount_sat,
            elements::confidential::ValueBlindingFactor::zero(),
        );
        let (bull_bitcoin_output, _, _, _) = elements::TxOut::new_last_confidential(
            &mut rng,
            &secp,
            bull_bitcoin_amount_sat,
            asset,
            bull_bitcoin_address.script_pubkey(),
            bull_bitcoin_blinding_pubkey,
            &[source_secrets],
            &[&merchant_secrets, &fee_secrets],
        )
        .unwrap();
        let transaction = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![elements::TxIn {
                previous_output: elements::OutPoint::new(
                    "11".repeat(32).parse().expect("test txid"),
                    0,
                ),
                is_pegin: false,
                script_sig: elements::Script::new(),
                sequence: elements::Sequence::MAX,
                asset_issuance: elements::AssetIssuance::default(),
                witness: elements::TxInWitness::default(),
            }],
            output: vec![
                merchant_output,
                bull_bitcoin_output,
                elements::TxOut::new_fee(fee_amount_sat, asset),
            ],
        };
        MixedFixture {
            claim: BtcLikeTransaction::Liquid(transaction),
            source_outputs: vec![source_output],
            merchant_address: merchant_address.to_string(),
            merchant_blinding_key_hex: merchant_blinding_key.display_secret().to_string(),
            bull_bitcoin_address: bull_bitcoin_address.to_string(),
            bull_bitcoin_script_hex: hex::encode(bull_bitcoin_address.script_pubkey().as_bytes()),
        }
    }

    #[test]
    fn exact_mixed_claim_verifies_fresh_and_erased_address_replay() {
        let fixture = mixed_fixture(59_000, 40_000);
        let fresh = verify_mixed_liquid_claim(
            &fixture.claim,
            &fixture.source_outputs,
            100_000,
            &fixture.merchant_address,
            &fixture.merchant_blinding_key_hex,
            &fixture.bull_bitcoin_address,
            40_000,
        )
        .unwrap();
        let replay = verify_mixed_liquid_claim_for_script(
            &fixture.claim,
            &fixture.source_outputs,
            100_000,
            &fixture.merchant_address,
            &fixture.merchant_blinding_key_hex,
            &fixture.bull_bitcoin_script_hex,
            40_000,
        )
        .unwrap();

        assert_eq!(fresh, replay);
        assert_eq!(fresh.merchant.authorized_amount_sat, 59_000);
        assert_eq!(fresh.bull_bitcoin.authorized_amount_sat, 40_000);
        assert_eq!(fresh.fee_amount_sat, 1_000);
        assert_eq!(fresh.merchant.vout, 0);
        assert_eq!(fresh.bull_bitcoin.vout, 1);
    }

    #[test]
    fn mixed_claim_rejects_unbalanced_or_wrong_source_commitments() {
        let unbalanced = mixed_fixture(59_000, 39_999);
        assert!(verify_mixed_liquid_claim(
            &unbalanced.claim,
            &unbalanced.source_outputs,
            100_000,
            &unbalanced.merchant_address,
            &unbalanced.merchant_blinding_key_hex,
            &unbalanced.bull_bitcoin_address,
            40_000,
        )
        .unwrap_err()
        .contains("commitments do not balance"));

        let valid = mixed_fixture(59_000, 40_000);
        let mut wrong_sources = valid.source_outputs.clone();
        wrong_sources[0].value = elements::confidential::Value::Explicit(99_999);
        assert!(verify_mixed_liquid_claim(
            &valid.claim,
            &wrong_sources,
            100_000,
            &valid.merchant_address,
            &valid.merchant_blinding_key_hex,
            &valid.bull_bitcoin_address,
            40_000,
        )
        .unwrap_err()
        .contains("commitments do not balance"));
    }

    #[test]
    fn mixed_claim_rejects_amount_destination_order_and_proof_tampering() {
        let fixture = mixed_fixture(59_000, 40_000);
        let verify = |claim: &BtcLikeTransaction,
                      address: &str,
                      amount: i64,
                      sources: &[elements::TxOut]| {
            verify_mixed_liquid_claim(
                claim,
                sources,
                100_000,
                &fixture.merchant_address,
                &fixture.merchant_blinding_key_hex,
                address,
                amount,
            )
        };
        assert!(verify(
            &fixture.claim,
            &fixture.bull_bitcoin_address,
            39_999,
            &fixture.source_outputs,
        )
        .is_err());

        let provider = elements::Address::from_str(&fixture.bull_bitcoin_address).unwrap();
        let mut different_script = vec![0x00, 0x14];
        different_script.extend([0x42; 20]);
        let different_address = elements::Address::from_script(
            &elements::Script::from(different_script),
            provider.blinding_pubkey,
            &elements::AddressParams::LIQUID,
        )
        .unwrap()
        .to_string();
        assert!(verify(
            &fixture.claim,
            &different_address,
            40_000,
            &fixture.source_outputs,
        )
        .is_err());

        let mut reordered = fixture.claim.as_liquid().unwrap().clone();
        reordered.output.swap(0, 1);
        assert!(verify(
            &BtcLikeTransaction::Liquid(reordered),
            &fixture.bull_bitcoin_address,
            40_000,
            &fixture.source_outputs,
        )
        .is_err());

        let mut missing_proof = fixture.claim.as_liquid().unwrap().clone();
        missing_proof.output[1].witness.rangeproof = None;
        assert!(verify(
            &BtcLikeTransaction::Liquid(missing_proof),
            &fixture.bull_bitcoin_address,
            40_000,
            &fixture.source_outputs,
        )
        .is_err());
    }
}
