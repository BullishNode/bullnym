//! Merchant-signed recovery-address registration contract and endpoint.
//!
//! The always-on authenticated route verifies this sealed contract and appends
//! it to the immutable persistence ledger. Chain-swap creation selects the
//! current commitment and immutably binds its identity and address into the
//! creation record. The registered address is private merchant policy:
//! response types expose only acceptance metadata, never the address itself.

use crate::auth;
use crate::db::{self, RecoveryAddressCommitmentError};
use crate::error::AppError;
use crate::registration;
use crate::validators;
use crate::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;

/// Version of the recovery-address registration contract.
pub const RECOVERY_ADDRESS_REGISTRATION_VERSION: u16 = 1;

/// LA-v2 action allocated to recovery-address registration.
pub const ACTION_RECOVERY_ADDRESS_SET: &str = "recovery-address-set";

/// The signed JSON body is under 400 bytes for every supported address family.
/// Keep modest headroom for JSON whitespace without inheriting the global cap.
pub const RECOVERY_ADDRESS_REGISTRATION_BODY_LIMIT_BYTES: usize = 1024;

const RECOVERY_ADDRESS_REGISTRATION_VERSION_FIELD: &str = "1";

/// Merchant-authenticated request body for the registration endpoint.
///
/// The canonical signed field order is `[version, btc_address]`. This is a
/// merchant-identity-wide commitment, so LA-v2's dedicated nym slot is always
/// empty. Unknown JSON fields are rejected so a client cannot believe an
/// unsigned extension was accepted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAddressRegistrationRequest {
    pub version: u16,
    pub npub: String,
    pub btc_address: String,
    pub timestamp: u64,
    pub signature: String,
}

/// Privacy-safe registration response.
///
/// This type deliberately has no address, npub, or signature field. The signed
/// timestamp is safe acceptance evidence already present in the request; the
/// opaque persistence identity is never returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAddressRegistrationResponse {
    pub version: u16,
    pub recovery_address_registered: bool,
    pub signed_at_unix: u64,
}

impl RecoveryAddressRegistrationResponse {
    pub const fn registered(signed_at_unix: u64) -> Self {
        Self {
            version: RECOVERY_ADDRESS_REGISTRATION_VERSION,
            recovery_address_registered: true,
            signed_at_unix,
        }
    }
}

/// `PUT /api/v1/recovery-address` — authenticate and append one merchant-wide
/// recovery-address commitment. There is intentionally no corresponding read
/// handler: the address and persistence identity stay server-private.
pub async fn register(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(request): Json<RecoveryAddressRegistrationRequest>,
) -> Result<Json<RecoveryAddressRegistrationResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(address)| address);

    // Share the registration-setup abuse boundary and apply it before the
    // comparatively expensive Schnorr verification.
    registration::gate_registration_setup_per_ip(
        &state,
        peer,
        &headers,
        "recovery_address_registration",
    )
    .await?;

    let verified = verify_recovery_address_registration(&request)?;
    let signed_at_unix = verified.timestamp();
    db::persist_recovery_address_commitment(&state.db, &verified)
        .await
        .map_err(map_persistence_error)?;

    Ok(Json(RecoveryAddressRegistrationResponse::registered(
        signed_at_unix,
    )))
}

fn map_persistence_error(error: RecoveryAddressCommitmentError) -> AppError {
    match error {
        // Missing and inactive identities deliberately collapse into the same
        // generic auth response; callers cannot use this route as a registry
        // existence oracle.
        RecoveryAddressCommitmentError::SourceIdentityNotActive => {
            AppError::AuthError("recovery-address registration identity is unavailable".into())
        }
        // Never move the wrapped sqlx error into AppError: PostgreSQL detail
        // can contain the npub, address, and signature. AppError logs only this
        // stable constant and returns its existing generic internal envelope.
        _ => AppError::DbError("recovery-address registration persistence failed".into()),
    }
}

/// Verified evidence ready for the append-only persistence layer.
///
/// Keeping the original signature and timestamp here lets that layer persist
/// the exact merchant authorization rather than reconstructing it. This type
/// is server-internal evidence and is never a response body. Private fields
/// prevent callers from mutating the verified identity or signed payload.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedRecoveryAddressRegistration {
    version: u16,
    npub: String,
    canonical_btc_address: String,
    timestamp: u64,
    original_signature: String,
}

impl VerifiedRecoveryAddressRegistration {
    pub const fn version(&self) -> u16 {
        self.version
    }

    pub fn npub(&self) -> &str {
        &self.npub
    }

    pub fn canonical_btc_address(&self) -> &str {
        &self.canonical_btc_address
    }

    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn original_signature(&self) -> &str {
        &self.original_signature
    }
}

/// Build the byte-exact message clients must sign.
///
/// Wire fields, each separated by one NUL byte:
/// `bullpay-la-v2`, `recovery-address-set`, `<npub>`, empty nym, `1`,
/// `<btc_address>`, `<timestamp>`.
///
/// The address must already be its canonical Bitcoin-mainnet string. The
/// function rejects rather than silently normalizes alternate encodings so the
/// bytes signed by the merchant are exactly the bytes later persisted.
pub fn build_recovery_address_registration_message(
    version: u16,
    npub: &str,
    btc_address: &str,
    timestamp: u64,
) -> Result<Vec<u8>, AppError> {
    validate_contract_fields(version, npub, btc_address)?;
    Ok(auth::build_la_v2_message(
        ACTION_RECOVERY_ADDRESS_SET,
        npub,
        "",
        &[RECOVERY_ADDRESS_REGISTRATION_VERSION_FIELD, btc_address],
        timestamp,
    ))
}

/// Validate the canonical contract and verify the merchant's LA-v2 signature.
///
/// Identity activation is enforced by persistence after this verifier runs.
/// This function proves that the supplied npub signed this exact version,
/// address, and timestamp in the identity-wide empty-nym domain and that the
/// address is canonical Bitcoin mainnet.
pub fn verify_recovery_address_registration(
    request: &RecoveryAddressRegistrationRequest,
) -> Result<VerifiedRecoveryAddressRegistration, AppError> {
    let canonical_btc_address =
        validate_contract_fields(request.version, &request.npub, &request.btc_address)?;
    validate_signature_representation(&request.signature)?;

    auth::verify_la_v2(
        ACTION_RECOVERY_ADDRESS_SET,
        &request.npub,
        "",
        &[
            RECOVERY_ADDRESS_REGISTRATION_VERSION_FIELD,
            &request.btc_address,
        ],
        request.timestamp,
        &request.signature,
    )?;

    Ok(VerifiedRecoveryAddressRegistration {
        version: request.version,
        npub: request.npub.clone(),
        canonical_btc_address,
        timestamp: request.timestamp,
        original_signature: request.signature.clone(),
    })
}

fn validate_signature_representation(signature: &str) -> Result<(), AppError> {
    let parsed = secp256k1::schnorr::Signature::from_str(signature).map_err(|_| {
        AppError::AuthError("invalid recovery-address registration signature representation".into())
    })?;
    if parsed.to_string() != signature {
        return Err(AppError::AuthError(
            "recovery-address registration signature must be canonical lowercase hex".into(),
        ));
    }
    Ok(())
}

fn validate_contract_fields(
    version: u16,
    npub: &str,
    btc_address: &str,
) -> Result<String, AppError> {
    if version != RECOVERY_ADDRESS_REGISTRATION_VERSION {
        return Err(AppError::AuthError(format!(
            "unsupported recovery-address registration version {version}"
        )));
    }

    reject_nul("npub", npub)?;
    reject_nul("btc_address", btc_address)?;

    let canonical_npub = XOnlyPublicKey::from_str(npub)
        .map_err(|_| AppError::AuthError("invalid recovery-address registration npub".into()))?;
    if canonical_npub.to_string() != npub {
        return Err(AppError::AuthError(
            "recovery-address registration npub must be canonical lowercase hex".into(),
        ));
    }

    let canonical = validators::canonical_btc_mainnet_address(btc_address)
        .map_err(|error| AppError::RecoveryAddressInvalid(error.to_string()))?;
    if canonical != btc_address {
        return Err(AppError::RecoveryAddressInvalid(
            "address must use its canonical Bitcoin mainnet encoding".into(),
        ));
    }

    Ok(canonical)
}

fn reject_nul(field: &str, value: &str) -> Result<(), AppError> {
    if value.as_bytes().contains(&0) {
        return Err(AppError::AuthError(format!(
            "recovery-address registration {field} contains a NUL separator"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Message, Secp256k1};
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    const MAINNET_P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const MAINNET_P2TR: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const MAINNET_P2PKH: &str = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
    const TESTNET_P2WPKH: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    fn test_keypair() -> (Keypair, String) {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let (npub, _) = keypair.x_only_public_key();
        (keypair, npub.to_string())
    }

    fn sign_message(keypair: &Keypair, message: &[u8]) -> String {
        let digest = Sha256::digest(message);
        let message = Message::from_digest(*digest.as_ref());
        Secp256k1::new().sign_schnorr(&message, keypair).to_string()
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signed_request(
        keypair: &Keypair,
        npub: &str,
        btc_address: &str,
        timestamp: u64,
    ) -> RecoveryAddressRegistrationRequest {
        let message = build_recovery_address_registration_message(
            RECOVERY_ADDRESS_REGISTRATION_VERSION,
            npub,
            btc_address,
            timestamp,
        )
        .unwrap();
        RecoveryAddressRegistrationRequest {
            version: RECOVERY_ADDRESS_REGISTRATION_VERSION,
            npub: npub.into(),
            btc_address: btc_address.into(),
            timestamp,
            signature: sign_message(keypair, &message),
        }
    }

    #[test]
    fn canonical_message_is_byte_exact_and_versioned() {
        let npub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let message = build_recovery_address_registration_message(
            RECOVERY_ADDRESS_REGISTRATION_VERSION,
            npub,
            MAINNET_P2WPKH,
            1_700_000_000,
        )
        .unwrap();

        let expected = [
            &b"bullpay-la-v2"[..],
            &b"\0"[..],
            &b"recovery-address-set"[..],
            &b"\0"[..],
            npub.as_bytes(),
            &b"\0"[..],
            &b"\0"[..],
            &b"1"[..],
            &b"\0"[..],
            MAINNET_P2WPKH.as_bytes(),
            &b"\0"[..],
            &b"1700000000"[..],
        ]
        .concat();
        assert_eq!(message, expected);
        assert_eq!(message.iter().filter(|&&byte| byte == 0).count(), 6);
    }

    #[test]
    fn valid_signature_round_trip_preserves_commitment_evidence() {
        let (keypair, npub) = test_keypair();
        let timestamp = now_secs();
        let request = signed_request(&keypair, &npub, MAINNET_P2WPKH, timestamp);

        let verified = verify_recovery_address_registration(&request).unwrap();
        assert_eq!(verified.version(), RECOVERY_ADDRESS_REGISTRATION_VERSION);
        assert_eq!(verified.npub(), npub);
        assert_eq!(verified.canonical_btc_address(), MAINNET_P2WPKH);
        assert_eq!(verified.timestamp(), timestamp);
        assert_eq!(verified.original_signature(), request.signature);
    }

    #[test]
    fn cross_action_nym_scope_and_address_replays_are_rejected() {
        let (keypair, npub) = test_keypair();
        let timestamp = now_secs();

        let wrong_action_message = auth::build_la_v2_message(
            "invoice-recover",
            &npub,
            "",
            &[RECOVERY_ADDRESS_REGISTRATION_VERSION_FIELD, MAINNET_P2WPKH],
            timestamp,
        );
        let mut wrong_action = signed_request(&keypair, &npub, MAINNET_P2WPKH, timestamp);
        wrong_action.signature = sign_message(&keypair, &wrong_action_message);
        assert!(verify_recovery_address_registration(&wrong_action).is_err());

        let nym_scoped_message = auth::build_la_v2_message(
            ACTION_RECOVERY_ADDRESS_SET,
            &npub,
            "alice",
            &[RECOVERY_ADDRESS_REGISTRATION_VERSION_FIELD, MAINNET_P2WPKH],
            timestamp,
        );
        let mut wrong_nym_scope = signed_request(&keypair, &npub, MAINNET_P2WPKH, timestamp);
        wrong_nym_scope.signature = sign_message(&keypair, &nym_scoped_message);
        assert!(verify_recovery_address_registration(&wrong_nym_scope).is_err());

        let original = signed_request(&keypair, &npub, MAINNET_P2WPKH, timestamp);
        let mut wrong_address = original;
        wrong_address.btc_address = MAINNET_P2TR.into();
        assert!(verify_recovery_address_registration(&wrong_address).is_err());
    }

    #[test]
    fn stale_and_unknown_version_replays_are_rejected() {
        let (keypair, npub) = test_keypair();
        let stale_timestamp = now_secs() - auth::LA_AUTH_TS_WINDOW_SECS - 1;
        let stale = signed_request(&keypair, &npub, MAINNET_P2WPKH, stale_timestamp);
        assert!(verify_recovery_address_registration(&stale).is_err());

        let mut unknown_version = signed_request(&keypair, &npub, MAINNET_P2WPKH, now_secs());
        unknown_version.version = 2;
        assert!(verify_recovery_address_registration(&unknown_version).is_err());
        assert!(
            build_recovery_address_registration_message(2, &npub, MAINNET_P2WPKH, now_secs(),)
                .is_err()
        );
    }

    #[test]
    fn wrong_signer_and_malformed_signature_are_rejected() {
        let (keypair, npub) = test_keypair();
        let (_, other_npub) = test_keypair();
        let timestamp = now_secs();
        let mut request = signed_request(&keypair, &npub, MAINNET_P2WPKH, timestamp);

        request.npub = other_npub;
        assert!(verify_recovery_address_registration(&request).is_err());

        request.npub = npub;
        request.signature = "not-a-schnorr-signature".into();
        assert!(verify_recovery_address_registration(&request).is_err());
    }

    #[test]
    fn uppercase_and_malformed_signature_representations_are_rejected() {
        let (keypair, npub) = test_keypair();
        let request = signed_request(&keypair, &npub, MAINNET_P2WPKH, now_secs());

        let mut uppercase = request.clone();
        let canonical_signature = "ab".repeat(64);
        uppercase.signature = canonical_signature.to_ascii_uppercase();
        assert_eq!(
            secp256k1::schnorr::Signature::from_str(&uppercase.signature).unwrap(),
            secp256k1::schnorr::Signature::from_str(&canonical_signature).unwrap()
        );
        assert!(matches!(
            verify_recovery_address_registration(&uppercase),
            Err(AppError::AuthError(reason))
                if reason
                    == "recovery-address registration signature must be canonical lowercase hex"
        ));

        let mut malformed = request;
        malformed.signature = "gg".repeat(64);
        assert!(matches!(
            verify_recovery_address_registration(&malformed),
            Err(AppError::AuthError(reason))
                if reason == "invalid recovery-address registration signature representation"
        ));
    }

    #[test]
    fn canonical_bitcoin_mainnet_address_families_are_accepted() {
        let (_, npub) = test_keypair();
        for address in [MAINNET_P2PKH, MAINNET_P2WPKH, MAINNET_P2TR] {
            assert!(build_recovery_address_registration_message(
                RECOVERY_ADDRESS_REGISTRATION_VERSION,
                &npub,
                address,
                1_700_000_000,
            )
            .is_ok());
        }
    }

    #[test]
    fn wrong_network_malformed_and_noncanonical_addresses_are_rejected() {
        let (_, npub) = test_keypair();
        let padded = format!(" {MAINNET_P2WPKH} ");
        let uppercase = MAINNET_P2WPKH.to_ascii_uppercase();
        for address in [
            "",
            TESTNET_P2WPKH,
            "lq1qqnotabitcoinaddress",
            padded.as_str(),
            uppercase.as_str(),
        ] {
            assert!(build_recovery_address_registration_message(
                RECOVERY_ADDRESS_REGISTRATION_VERSION,
                &npub,
                address,
                1_700_000_000,
            )
            .is_err());
        }
    }

    #[test]
    fn nul_delimited_identity_fields_are_rejected() {
        let (_, npub) = test_keypair();
        assert!(build_recovery_address_registration_message(
            RECOVERY_ADDRESS_REGISTRATION_VERSION,
            "abcd\0efgh",
            MAINNET_P2WPKH,
            1_700_000_000,
        )
        .is_err());
        assert!(build_recovery_address_registration_message(
            RECOVERY_ADDRESS_REGISTRATION_VERSION,
            &npub,
            "bc1qaddress\0extension",
            1_700_000_000,
        )
        .is_err());
    }

    #[test]
    fn malformed_and_noncanonical_npubs_are_rejected() {
        let (_, npub) = test_keypair();
        assert!(build_recovery_address_registration_message(
            RECOVERY_ADDRESS_REGISTRATION_VERSION,
            "not-an-x-only-public-key",
            MAINNET_P2WPKH,
            1_700_000_000,
        )
        .is_err());
        assert!(build_recovery_address_registration_message(
            RECOVERY_ADDRESS_REGISTRATION_VERSION,
            &npub.to_ascii_uppercase(),
            MAINNET_P2WPKH,
            1_700_000_000,
        )
        .is_err());
    }

    #[test]
    fn request_serialization_is_stable_and_closed() {
        let request = RecoveryAddressRegistrationRequest {
            version: RECOVERY_ADDRESS_REGISTRATION_VERSION,
            npub: "aa".repeat(32),
            btc_address: MAINNET_P2WPKH.into(),
            timestamp: 1_700_000_000,
            signature: "bb".repeat(64),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"version":1,"npub":"{}","btc_address":"{}","timestamp":1700000000,"signature":"{}"}}"#,
                "aa".repeat(32),
                MAINNET_P2WPKH,
                "bb".repeat(64)
            )
        );
        let decoded: RecoveryAddressRegistrationRequest = serde_json::from_str(&json).unwrap();
        assert!(decoded == request);

        let with_unknown =
            json.replace(r#""signature""#, r#""unsigned_extension":true,"signature""#);
        assert!(serde_json::from_str::<RecoveryAddressRegistrationRequest>(&with_unknown).is_err());
    }

    #[test]
    fn response_serialization_cannot_disclose_recovery_policy() {
        let response = RecoveryAddressRegistrationResponse::registered(1_700_000_000);
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"version":1,"recovery_address_registered":true,"signed_at_unix":1700000000}"#
        );
        for private_field in [MAINNET_P2WPKH, "btc_address", "signature", "npub", "nym"] {
            assert!(!json.contains(private_field));
        }

        let address_injection = format!(
            r#"{{"version":1,"recovery_address_registered":true,"signed_at_unix":1700000000,"btc_address":"{MAINNET_P2WPKH}"}}"#
        );
        assert!(
            serde_json::from_str::<RecoveryAddressRegistrationResponse>(&address_injection)
                .is_err()
        );
    }

    #[test]
    fn persistence_error_mapping_never_carries_raw_database_evidence() {
        let raw_evidence = format!(
            "npub={} address={MAINNET_P2WPKH} signature={}",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "ab".repeat(64)
        );
        let mapped = map_persistence_error(RecoveryAddressCommitmentError::Database(
            sqlx::Error::Protocol(raw_evidence.clone()),
        ));
        assert!(matches!(
            mapped,
            AppError::DbError(ref message)
                if message == "recovery-address registration persistence failed"
        ));
        let rendered = format!("{mapped:?} {mapped}");
        assert!(!rendered.contains(&raw_evidence));
        assert!(!rendered.contains(MAINNET_P2WPKH));

        let unavailable =
            map_persistence_error(RecoveryAddressCommitmentError::SourceIdentityNotActive);
        assert!(matches!(
            unavailable,
            AppError::AuthError(ref message)
                if message == "recovery-address registration identity is unavailable"
        ));
    }
}
