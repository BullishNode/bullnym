use crate::error::AppError;
use secp256k1::{Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// Verifies a schnorr signature over SHA256(message) against an x-only pubkey (npub).
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
}
