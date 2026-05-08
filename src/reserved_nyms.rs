//! Nyms that would shadow explicit server routes when the donation-page
//! fallback (`GET /<nym>`) is registered. Blocked at registration time so
//! `/health`, `/register`, etc. can never be reached via a registered slug.

pub const RESERVED_NYMS: &[&str] = &[
    "register",
    "health",
    "webhook",
    "lnurlp",
    "api",
    "img",
    "donation-page",
    "well-known",
    "admin",
    "static",
    "assets",
    "favicon",
    "robots",
    "sitemap",
    "about",
    "terms",
    "privacy",
    "support",
    "help",
    "login",
    "logout",
    "signup",
    "settings",
    "account",
    "dashboard",
    "test",
    // Phase B: blocks shadowing the /<nym>/i/<invoice_id> route. The single
    // segment `/i` falls to the store-page fallback; reserving `i` prevents
    // a registered nym from colliding with the explicit 3-segment route. The
    // longer aliases protect against a future rename without re-broadcasting
    // a reservation list update.
    "i",
    "invoice",
    "invoices",
];

pub fn is_reserved(nym: &str) -> bool {
    RESERVED_NYMS.contains(&nym)
}

#[cfg(test)]
mod tests {
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
        // Nyms are lowercased by NYM_REGEX before reaching is_reserved, so
        // case-sensitive matching here is sufficient. A capitalized slug
        // would already fail NYM_REGEX upstream.
        assert!(!is_reserved("Register"));
    }
}
