use crate::error::AppError;
use secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// 300s vs NIP-98's 60s default: mobile clocks drift more than desktop.
pub const LA_AUTH_TS_WINDOW_SECS: u64 = 300;

pub const LA_SIG_DOMAIN_TAG: &[u8] = b"bullpay-la-v2";

pub fn verify_signature(
    npub_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), AppError> {
    let secp = Secp256k1::verification_only();

    let pubkey = XOnlyPublicKey::from_str(npub_hex)
        .map_err(|_| AppError::AuthError("invalid npub".to_string()))?;

    let digest = Sha256::digest(message);
    let msg = Message::from_digest(*digest.as_ref());

    let sig = secp256k1::schnorr::Signature::from_str(signature_hex)
        .map_err(|_| AppError::AuthError("invalid signature format".to_string()))?;

    secp.verify_schnorr(&sig, &msg, &pubkey)
        .map_err(|_| AppError::AuthError("signature verification failed".to_string()))
}

// Wire format mirrored in mobile `core/nostr/bullpay_la_v2_signing.dart`:
//   `<domain>\x00<action>\x00<npub_hex>\x00<nym_or_empty>\x00(<field>\x00)*<timestamp>`.
//
// The first payload field is ALWAYS the nym, possibly empty for unlinked
// (npub-keyed) actions like invoice-create / invoice-cancel / invoice-list.
// `payload_fields` are the fields AFTER nym.
pub fn build_la_v2_message(
    action: &str,
    npub_hex: &str,
    nym_or_empty: &str,
    payload_fields: &[&str],
    timestamp: u64,
) -> Vec<u8> {
    let extra_field_bytes: usize = payload_fields.iter().map(|f| f.len() + 1).sum();
    let mut msg = Vec::with_capacity(
        LA_SIG_DOMAIN_TAG.len()
            + action.len()
            + npub_hex.len()
            + nym_or_empty.len()
            + extra_field_bytes
            + 32,
    );
    msg.extend_from_slice(LA_SIG_DOMAIN_TAG);
    msg.push(0);
    msg.extend_from_slice(action.as_bytes());
    msg.push(0);
    msg.extend_from_slice(npub_hex.as_bytes());
    msg.push(0);
    msg.extend_from_slice(nym_or_empty.as_bytes());
    msg.push(0);
    for field in payload_fields {
        msg.extend_from_slice(field.as_bytes());
        msg.push(0);
    }
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg
}

pub fn check_ts_freshness(ts: u64) -> Result<(), AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.abs_diff(ts) > LA_AUTH_TS_WINDOW_SECS {
        return Err(AppError::AuthError(
            "timestamp outside allowed window".into(),
        ));
    }
    Ok(())
}

/// Verify a v2 signed action.
///
/// `nym_or_empty` is the FIRST payload field in the signed byte sequence and
/// must be passed explicitly to make the empty-nym (unlinked) case
/// unmistakable at every call site.
pub fn verify_la_v2(
    action: &str,
    npub_hex: &str,
    nym_or_empty: &str,
    payload_fields: &[&str],
    timestamp: u64,
    signature_hex: &str,
) -> Result<(), AppError> {
    check_ts_freshness(timestamp)?;
    let msg = build_la_v2_message(action, npub_hex, nym_or_empty, payload_fields, timestamp);
    verify_signature(npub_hex, &msg, signature_hex)
}

#[cfg(test)]
mod tests;
