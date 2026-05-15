use super::*;

#[test]
fn known_slugs_blocked() {
    assert!(is_reserved("register"));
    assert!(is_reserved("health"));
    assert!(is_reserved("donation-page"));
}

#[test]
fn invoice_slugs_blocked() {
    assert!(is_reserved("i"));
    assert!(is_reserved("invoice"));
    assert!(is_reserved("invoices"));
}

#[test]
fn ordinary_slugs_allowed() {
    assert!(!is_reserved("alice"));
    assert!(!is_reserved("bob123"));
    assert!(!is_reserved("my-shop"));
}

#[test]
fn case_sensitive() {
    // Uppercase nyms fail validation before this helper is called.
    assert!(!is_reserved("Register"));
}
