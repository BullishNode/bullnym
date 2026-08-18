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

/// The lookup route's query contract is documented in
/// `docs/api/nyms-and-discovery.md`. The credential pair is optional at the
/// extractor so already-installed mobile builds keep deserializing during the
/// staged rollout; what is *not* tolerated is an unknown parameter. Exercised
/// through axum's real `Query` so the reference cannot drift from
/// `LookupParams`.
#[test]
fn lookup_query_accepts_the_legacy_shape_and_rejects_unknown_parameters() {
    const NPUB: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let signature = "ab".repeat(32);

    let parse = |query: String| {
        let uri: axum::http::Uri = query.parse().unwrap();
        axum::extract::Query::<LookupParams>::try_from_uri(&uri).map(|q| q.0)
    };

    let signed = parse(format!(
        "/register/lookup?npub={NPUB}&timestamp=1700000000&signature={signature}"
    ))
    .expect("the signed three-parameter query must deserialize");
    assert_eq!(signed.npub, NPUB);
    assert_eq!(signed.timestamp, Some(1_700_000_000));
    assert_eq!(signed.signature.as_deref(), Some(signature.as_str()));

    // The pre-fix shape still deserializes; the handler decides whether an
    // absent credential is fatal, per require_signed_registration_lookup.
    let legacy = parse(format!("/register/lookup?npub={NPUB}")).expect("legacy shape");
    assert_eq!(legacy.timestamp, None);
    assert_eq!(legacy.signature, None);

    // A half-supplied credential reaches the handler, which always rejects it.
    let half = parse(format!("/register/lookup?npub={NPUB}&timestamp=1700000000"))
        .expect("half-supplied credential still deserializes");
    assert_eq!(half.timestamp, Some(1_700_000_000));
    assert_eq!(half.signature, None);

    // An unknown parameter is refused outright rather than ignored.
    assert!(
        parse(format!(
            "/register/lookup?npub={NPUB}&timestamp=1700000000&signature={signature}&utm_source=x"
        ))
        .is_err()
    );
    // And npub itself remains mandatory.
    assert!(parse("/register/lookup?timestamp=1700000000".to_owned()).is_err());
}
