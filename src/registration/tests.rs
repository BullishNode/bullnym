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
