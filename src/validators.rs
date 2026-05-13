//! Mainnet-only address validators for invoice handlers.
//!
//! Used by `POST /api/v1/invoices` and `POST /api/v1/<nym>/invoices` to reject
//! testnet/regtest addresses (or non-confidential Liquid addresses) BEFORE the
//! Schnorr signature is verified — keeps the cheap, deterministic checks ahead
//! of the expensive crypto path.

use crate::error::AppError;
use std::str::FromStr;

/// Validate a Bitcoin mainnet address. Rejects testnet/regtest/signet.
///
/// `bitcoin::Address::from_str` returns `Address<NetworkUnchecked>` because
/// the parser cannot decide network membership without a hint; we then call
/// `require_network(Network::Bitcoin)` which returns `Ok` only if the parsed
/// address is valid for mainnet (and rejects testnet/regtest/signet alike).
pub fn validate_btc_mainnet_address(addr: &str) -> Result<(), AppError> {
    let unchecked = bitcoin::Address::from_str(addr)
        .map_err(|e| AppError::InvalidAmount(format!("bitcoin_address: {e}")))?;
    unchecked
        .require_network(bitcoin::Network::Bitcoin)
        .map_err(|_| {
            AppError::InvalidAmount(
                "bitcoin_address: expected mainnet (bc1.../1.../3...)".to_string(),
            )
        })?;
    Ok(())
}

/// Validate a Liquid mainnet (LBTC) address. Rejects Liquid Testnet, Elements
/// regtest, and non-confidential (unblinded) addresses — the LN claim path
/// requires confidential output for blinding.
pub fn validate_liquid_mainnet_address(addr: &str) -> Result<(), AppError> {
    use lwk_wollet::elements::{Address, AddressParams};

    let parsed = Address::from_str(addr)
        .map_err(|e| AppError::InvalidAmount(format!("liquid_address: {e}")))?;

    if parsed.params != &AddressParams::LIQUID {
        return Err(AppError::InvalidAmount(format!(
            "liquid_address: expected liquid mainnet (LBTC), got params={:?}",
            parsed.params
        )));
    }

    // Confidential-only invariant: the LN claim path embeds a blinded output
    // for the receiver. Unblinded addresses leak the recipient's view key
    // pattern and break Boltz's claim flow.
    if parsed.blinding_pubkey.is_none() {
        return Err(AppError::InvalidAmount(
            "liquid_address: must be confidential (blinded)".into(),
        ));
    }

    Ok(())
}

pub fn validate_liquid_blinding_key_matches_address(
    addr: &str,
    blinding_key_hex: &str,
) -> Result<(), AppError> {
    use lwk_wollet::elements::{secp256k1_zkp, Address};

    let parsed = Address::from_str(addr)
        .map_err(|e| AppError::InvalidAmount(format!("liquid_address: {e}")))?;
    let expected = parsed.blinding_pubkey.ok_or_else(|| {
        AppError::InvalidAmount("liquid_address: must be confidential (blinded)".into())
    })?;
    let key = secp256k1_zkp::SecretKey::from_str(blinding_key_hex).map_err(|_| {
        AppError::InvalidAmount("liquid_blinding_key_hex: invalid secret key".into())
    })?;
    let secp = secp256k1_zkp::Secp256k1::new();
    let actual = key.public_key(&secp);
    if actual != expected {
        return Err(AppError::InvalidAmount(
            "liquid_blinding_key_hex does not match liquid_address".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Bitcoin mainnet ------------------------------------------------------

    #[test]
    fn btc_mainnet_p2pkh_accepted() {
        // Genesis coinbase address — quintessential mainnet P2PKH.
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        validate_btc_mainnet_address(addr).expect("mainnet P2PKH must validate");
    }

    #[test]
    fn btc_mainnet_p2wpkh_accepted() {
        // Bech32 mainnet — bc1q prefix.
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        validate_btc_mainnet_address(addr).expect("mainnet bech32 must validate");
    }

    #[test]
    fn btc_mainnet_p2tr_accepted() {
        // P2TR (taproot) mainnet — bc1p prefix.
        let addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        validate_btc_mainnet_address(addr).expect("mainnet taproot must validate");
    }

    #[test]
    fn btc_testnet_rejected() {
        // tb1q-prefix testnet bech32.
        let addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let err = validate_btc_mainnet_address(addr).expect_err("testnet must be rejected");
        match err {
            AppError::InvalidAmount(msg) => {
                assert!(
                    msg.contains("mainnet"),
                    "error must mention mainnet, got: {msg}"
                );
            }
            other => panic!("expected InvalidAmount, got {other:?}"),
        }
    }

    #[test]
    fn btc_regtest_rejected() {
        // bcrt1-prefix regtest bech32.
        let addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        assert!(
            validate_btc_mainnet_address(addr).is_err(),
            "regtest must be rejected"
        );
    }

    #[test]
    fn btc_garbage_rejected() {
        assert!(validate_btc_mainnet_address("").is_err());
        assert!(validate_btc_mainnet_address("not-a-bitcoin-address").is_err());
        assert!(validate_btc_mainnet_address("0xabc").is_err()); // ethereum-shaped
    }

    // -- Liquid mainnet -------------------------------------------------------

    /// A known Liquid mainnet (LBTC) confidential address. Derived deterministically
    /// from a fixed test descriptor in `descriptor.rs`'s test vectors; pinning the
    /// literal here keeps the validator test independent of descriptor evolution.
    const LIQUID_MAINNET_CT_ADDR: &str =
        "lq1qq2akvug2el2rg6lt6aewh9rzy7dl5guv44h9plgg6jadaqdcxr8xtv0v\
6rxz0v9hu8tewzrt0v8tcqf0jvejphax09rt6r9q";

    #[test]
    fn liquid_mainnet_confidential_accepted() {
        // Derive the canonical mainnet CT addr from the same test descriptor used
        // in `descriptor::tests` so we don't pin a literal that could go stale
        // with lwk's address-encoding tweaks.
        let addr = crate::descriptor::derive_address(
            "ct(slip77(9c8e4f05c7711a98c838be228bcb84924d4570ca53f35fa1c793e58841d47023),\
elwpkh([73c5da0a/84h/1776h/0h]xpub6CRFzUgHFDaiDAQFNX7VeV9JNPDRabq6NYSpzVZ8zW8ANUCiDdenkb1gBoEZuXNZb3wPc1SVcDXgD2ww5UBtTb8s8ArAbTkoRQ8qn34KgcY/<0;1>/*))#y8jljyxl",
            0,
        )
        .expect("descriptor must parse");
        validate_liquid_mainnet_address(&addr).expect("mainnet CT must validate");
    }

    #[test]
    fn liquid_garbage_rejected() {
        assert!(validate_liquid_mainnet_address("").is_err());
        assert!(validate_liquid_mainnet_address("not-a-liquid-address").is_err());
        assert!(
            validate_liquid_mainnet_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_err()
        );
    }

    /// Documenting the reachable-string variable so the linter doesn't whine.
    /// The constant exists to anchor a "known mainnet shape" alongside future
    /// regression tests for testnet rejection (handcrafted vectors when the
    /// lwk dep gains a non-mainnet AddressParams enum value we want to test).
    #[allow(dead_code)]
    fn _liquid_mainnet_ct_anchor() -> &'static str {
        LIQUID_MAINNET_CT_ADDR
    }
}
