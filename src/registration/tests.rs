use super::*;

#[test]
fn valid_nyms() {
    assert!(NYM_REGEX.is_match("francis"));
    assert!(NYM_REGEX.is_match("my-nym"));
    assert!(NYM_REGEX.is_match("abc"));
    assert!(NYM_REGEX.is_match("user123"));
    assert!(NYM_REGEX.is_match("a-b"));
    assert!(NYM_REGEX.is_match("a".repeat(32).as_str()));
}

#[test]
fn too_short() {
    assert!(NYM_REGEX.is_match("ab"));
    assert!(NYM_REGEX.is_match("a"));
    assert!(!NYM_REGEX.is_match(""));
}

#[test]
fn too_long() {
    assert!(!NYM_REGEX.is_match(&"a".repeat(33)));
}

#[test]
fn uppercase_rejected() {
    assert!(!NYM_REGEX.is_match("Francis"));
    assert!(!NYM_REGEX.is_match("ABC"));
}

#[test]
fn starts_with_hyphen_rejected() {
    assert!(!NYM_REGEX.is_match("-mynym"));
}

#[test]
fn ends_with_hyphen_rejected() {
    assert!(!NYM_REGEX.is_match("mynym-"));
}

#[test]
fn spaces_rejected() {
    assert!(!NYM_REGEX.is_match("has space"));
}

#[test]
fn underscores_rejected() {
    assert!(!NYM_REGEX.is_match("has_underscore"));
}

#[test]
fn special_chars_rejected() {
    assert!(!NYM_REGEX.is_match("user@name"));
    assert!(!NYM_REGEX.is_match("user.name"));
    assert!(!NYM_REGEX.is_match("user!name"));
}

#[test]
fn verification_npub_requires_a_canonical_lowercase_xonly_key() {
    const GENERATOR_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    assert!(validate_verification_npub(GENERATOR_X).is_ok());

    for invalid in [
        GENERATOR_X.to_ascii_uppercase(),
        "f".repeat(64),
        "a".repeat(63),
        "g".repeat(64),
    ] {
        let error = validate_verification_npub(&invalid).unwrap_err();
        assert!(
            matches!(error, AppError::AuthError(_)),
            "accepted {invalid}"
        );
    }
}

/// The lookup route's query contract is load-bearing for the signed-lookup
/// fix and is documented in `docs/api/nyms-and-discovery.md`: every parameter
/// is required and no extra parameter is tolerated. Exercised through the real
/// extractor so the documented 400s cannot drift from `LookupParams`.
#[test]
fn lookup_query_requires_every_parameter_and_rejects_extras() {
    const NPUB: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let signature = "ab".repeat(32);

    let complete: axum::http::Uri =
        format!("/register/lookup?npub={NPUB}&timestamp=1700000000&signature={signature}")
            .parse()
            .unwrap();
    let params = axum::extract::Query::<LookupParams>::try_from_uri(&complete)
        .expect("the documented three-parameter query must deserialize")
        .0;
    assert_eq!(params.npub, NPUB);
    assert_eq!(params.timestamp, 1_700_000_000);
    assert_eq!(params.signature, signature);

    for rejected in [
        // The pre-fix unsigned shape, and partially supplied credentials.
        format!("/register/lookup?npub={NPUB}"),
        format!("/register/lookup?npub={NPUB}&timestamp=1700000000"),
        format!("/register/lookup?npub={NPUB}&signature={signature}"),
        // An unknown parameter is refused rather than ignored.
        format!(
            "/register/lookup?npub={NPUB}&timestamp=1700000000&signature={signature}&utm_source=x"
        ),
    ] {
        let uri: axum::http::Uri = rejected.parse().unwrap();
        assert!(
            axum::extract::Query::<LookupParams>::try_from_uri(&uri).is_err(),
            "accepted {rejected}"
        );
    }
}
