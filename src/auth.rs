use crate::error::AppError;
use secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// 300s vs NIP-98's 60s default: mobile clocks drift more than desktop.
pub const LA_AUTH_TS_WINDOW_SECS: u64 = 300;

pub const LA_SIG_DOMAIN_TAG: &[u8] = b"bullpay-la-v1";

pub fn verify_signature(npub_hex: &str, message: &[u8], signature_hex: &str) -> Result<(), AppError> {
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

// Wire format mirrored in mobile `lightning_address_v1_signing.dart`:
// `<domain>\x00<action>\x00<npub_hex>\x00(<field>\x00)*<timestamp>`.
pub fn build_la_v1_message(
    action: &str,
    npub_hex: &str,
    payload_fields: &[&str],
    timestamp: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + payload_fields.iter().map(|f| f.len() + 1).sum::<usize>());
    msg.extend_from_slice(LA_SIG_DOMAIN_TAG);
    msg.push(0);
    msg.extend_from_slice(action.as_bytes());
    msg.push(0);
    msg.extend_from_slice(npub_hex.as_bytes());
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
        return Err(AppError::AuthError("timestamp outside allowed window".into()));
    }
    Ok(())
}

pub fn verify_la_v1(
    action: &str,
    npub_hex: &str,
    payload_fields: &[&str],
    timestamp: u64,
    signature_hex: &str,
) -> Result<(), AppError> {
    check_ts_freshness(timestamp)?;
    let msg = build_la_v1_message(action, npub_hex, payload_fields, timestamp);
    verify_signature(npub_hex, &msg, signature_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1};
    use sha2::Digest;

    fn test_keypair() -> (Keypair, String) {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let (xonly, _) = keypair.x_only_public_key();
        (keypair, xonly.to_string())
    }

    fn sign_message(keypair: &Keypair, message: &[u8]) -> String {
        let secp = Secp256k1::new();
        let digest = Sha256::digest(message);
        let msg = Message::from_digest(*digest.as_ref());
        let sig = secp.sign_schnorr(&msg, keypair);
        sig.to_string()
    }

    #[test]
    fn valid_signature_passes() {
        let (keypair, npub) = test_keypair();
        let message = b"test message";
        let sig = sign_message(&keypair, message);
        assert!(verify_signature(&npub, message, &sig).is_ok());
    }

    #[test]
    fn wrong_message_fails() {
        let (keypair, npub) = test_keypair();
        let sig = sign_message(&keypair, b"correct message");
        assert!(verify_signature(&npub, b"wrong message", &sig).is_err());
    }

    #[test]
    fn wrong_pubkey_fails() {
        let (keypair, _) = test_keypair();
        let (_, other_npub) = test_keypair();
        let sig = sign_message(&keypair, b"test");
        assert!(verify_signature(&other_npub, b"test", &sig).is_err());
    }

    #[test]
    fn corrupt_signature_fails() {
        let (_, npub) = test_keypair();
        assert!(verify_signature(&npub, b"test", "not_a_valid_hex_signature").is_err());
    }

    #[test]
    fn empty_npub_fails() {
        assert!(verify_signature("", b"test", "aa".repeat(32).as_str()).is_err());
    }

    #[test]
    fn empty_signature_fails() {
        let (_, npub) = test_keypair();
        assert!(verify_signature(&npub, b"test", "").is_err());
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn v1_message_format_is_nul_separated_and_domain_tagged() {
        let msg = build_la_v1_message("register", "abcd", &["alice", "ct(...)"], 1700000000);
        assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 5);
        assert!(msg.starts_with(LA_SIG_DOMAIN_TAG));
        let delete_msg = build_la_v1_message("delete", "abcd", &[], 1700000000);
        assert_eq!(delete_msg.iter().filter(|&&b| b == 0).count(), 3);
    }

    #[test]
    fn v1_signature_round_trip() {
        let (keypair, npub) = test_keypair();
        let ts = now_secs();
        let msg = build_la_v1_message("register", &npub, &["alice", "ct(xpub...)"], ts);
        let sig = sign_message(&keypair, &msg);
        assert!(verify_la_v1("register", &npub, &["alice", "ct(xpub...)"], ts, &sig).is_ok());
    }

    #[test]
    fn v1_cross_action_replay_rejected() {
        let (keypair, npub) = test_keypair();
        let ts = now_secs();
        let register_msg = build_la_v1_message("register", &npub, &["alice", "ct"], ts);
        let sig = sign_message(&keypair, &register_msg);
        assert!(verify_la_v1("delete", &npub, &[], ts, &sig).is_err());
    }

    #[test]
    fn v1_stale_timestamp_rejected() {
        let (keypair, npub) = test_keypair();
        let stale_ts = now_secs() - LA_AUTH_TS_WINDOW_SECS - 60;
        let msg = build_la_v1_message("register", &npub, &["alice", "ct"], stale_ts);
        let sig = sign_message(&keypair, &msg);
        assert!(verify_la_v1("register", &npub, &["alice", "ct"], stale_ts, &sig).is_err());
    }

    #[test]
    fn v1_future_timestamp_outside_window_rejected() {
        let (keypair, npub) = test_keypair();
        let future_ts = now_secs() + LA_AUTH_TS_WINDOW_SECS + 60;
        let msg = build_la_v1_message("register", &npub, &["alice", "ct"], future_ts);
        let sig = sign_message(&keypair, &msg);
        assert!(verify_la_v1("register", &npub, &["alice", "ct"], future_ts, &sig).is_err());
    }
}
