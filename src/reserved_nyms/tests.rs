use super::*;

#[test]
fn known_slugs_blocked() {
    assert!(is_reserved("register"));
    assert!(is_reserved("health"));
    assert!(is_reserved("ready"));
    assert!(is_reserved("version"));
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

#[test]
fn alias_prefix_slug_reserved() {
    // "a" is the /a/<alias> namespace prefix — no nym may claim it.
    assert!(is_reserved("a"));
}

#[test]
fn is_reserved_alias_covers_both_lists() {
    // Everything a nym can't be, an alias also can't be...
    assert!(is_reserved_alias("pos"));
    assert!(is_reserved_alias("a"));
    assert!(is_reserved_alias("register"));
    // ...plus the alias-specific reservations.
    assert!(is_reserved_alias("0"));
    assert!(is_reserved_alias("1"));
    assert!(is_reserved_alias("bull"));
    assert!(is_reserved_alias("bullbitcoin"));
    assert!(is_reserved_alias("bull-bitcoin"));
    // Ordinary merchant slugs are still allowed.
    assert!(!is_reserved_alias("alices-shop"));
    assert!(!is_reserved_alias("my-shop"));
}
