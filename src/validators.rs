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
pub fn canonical_btc_mainnet_address(addr: &str) -> Result<String, AppError> {
    let unchecked = bitcoin::Address::from_str(addr)
        .map_err(|e| AppError::InvalidAmount(format!("bitcoin_address: {e}")))?;
    let checked = unchecked
        .require_network(bitcoin::Network::Bitcoin)
        .map_err(|_| {
            AppError::InvalidAmount(
                "bitcoin_address: expected mainnet (bc1.../1.../3...)".to_string(),
            )
        })?;
    Ok(checked.to_string())
}

pub fn validate_btc_mainnet_address(addr: &str) -> Result<(), AppError> {
    canonical_btc_mainnet_address(addr)?;
    Ok(())
}

/// Validate a Liquid mainnet (LBTC) address. Rejects Liquid Testnet, Elements
/// regtest, and non-confidential (unblinded) addresses — the LN claim path
/// requires confidential output for blinding.
pub fn canonical_liquid_mainnet_address(addr: &str) -> Result<String, AppError> {
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

    Ok(parsed.to_string())
}

pub fn validate_liquid_mainnet_address(addr: &str) -> Result<(), AppError> {
    canonical_liquid_mainnet_address(addr)?;
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
mod tests;
