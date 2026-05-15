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
fn v2_message_format_is_nul_separated_and_domain_tagged() {
    let msg = build_la_v2_message("register", "abcd", "alice", &["ct(...)"], 1700000000);
    assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 5);
    assert!(msg.starts_with(LA_SIG_DOMAIN_TAG));

    let delete_msg = build_la_v2_message("delete", "abcd", "alice", &[], 1700000000);
    assert_eq!(delete_msg.iter().filter(|&&b| b == 0).count(), 4);
}

#[test]
fn v2_empty_nym_is_first_class() {
    let msg = build_la_v2_message("invoice-create", "abcd", "", &["100000"], 1700000000);
    assert_eq!(msg.iter().filter(|&&b| b == 0).count(), 5);

    let domain_end = LA_SIG_DOMAIN_TAG.len();
    let action = b"invoice-create";
    let prefix_len = domain_end + 1 + action.len() + 1 + 4 + 1;
    assert_eq!(msg[prefix_len], 0, "empty nym slot must be a single NUL");
}

#[test]
fn v2_signature_round_trip() {
    let (keypair, npub) = test_keypair();
    let ts = now_secs();
    let msg = build_la_v2_message("register", &npub, "alice", &["ct(xpub...)"], ts);
    let sig = sign_message(&keypair, &msg);
    assert!(verify_la_v2("register", &npub, "alice", &["ct(xpub...)"], ts, &sig).is_ok());
}

#[test]
fn v2_empty_nym_round_trip() {
    let (keypair, npub) = test_keypair();
    let ts = now_secs();
    let msg = build_la_v2_message("invoice-create", &npub, "", &["100000"], ts);
    let sig = sign_message(&keypair, &msg);
    assert!(verify_la_v2("invoice-create", &npub, "", &["100000"], ts, &sig).is_ok());
}

#[test]
fn v2_cross_action_replay_rejected() {
    let (keypair, npub) = test_keypair();
    let ts = now_secs();
    let register_msg = build_la_v2_message("register", &npub, "alice", &["ct"], ts);
    let sig = sign_message(&keypair, &register_msg);
    assert!(verify_la_v2("delete", &npub, "alice", &[], ts, &sig).is_err());
}

#[test]
fn v2_nym_swap_replay_rejected() {
    let (keypair, npub) = test_keypair();
    let ts = now_secs();
    let alice_msg = build_la_v2_message("register", &npub, "alice", &["ct"], ts);
    let sig = sign_message(&keypair, &alice_msg);
    assert!(verify_la_v2("register", &npub, "bob", &["ct"], ts, &sig).is_err());
}

#[test]
fn v2_empty_to_nonempty_nym_replay_rejected() {
    let (keypair, npub) = test_keypair();
    let ts = now_secs();
    let unlinked_msg = build_la_v2_message("invoice-create", &npub, "", &["100000"], ts);
    let sig = sign_message(&keypair, &unlinked_msg);
    assert!(verify_la_v2("invoice-create", &npub, "alice", &["100000"], ts, &sig).is_err());
}

#[test]
fn v2_stale_timestamp_rejected() {
    let (keypair, npub) = test_keypair();
    let stale_ts = now_secs() - LA_AUTH_TS_WINDOW_SECS - 60;
    let msg = build_la_v2_message("register", &npub, "alice", &["ct"], stale_ts);
    let sig = sign_message(&keypair, &msg);
    assert!(verify_la_v2("register", &npub, "alice", &["ct"], stale_ts, &sig).is_err());
}

#[test]
fn v2_future_timestamp_outside_window_rejected() {
    let (keypair, npub) = test_keypair();
    let future_ts = now_secs() + LA_AUTH_TS_WINDOW_SECS + 60;
    let msg = build_la_v2_message("register", &npub, "alice", &["ct"], future_ts);
    let sig = sign_message(&keypair, &msg);
    assert!(verify_la_v2("register", &npub, "alice", &["ct"], future_ts, &sig).is_err());
}
