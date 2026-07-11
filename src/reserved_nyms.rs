//! Nyms that would shadow explicit server routes when the donation-page
//! fallback (`GET /<nym>`) is registered. Blocked at registration time so
//! `/health`, `/register`, etc. can never be reached via a registered slug.

pub const RESERVED_NYMS: &[&str] = &[
    "register",
    "health",
    "ready",
    "version",
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
    // Blocks shadowing invoice render routes such as /<nym>/i/<invoice_id>.
    "i",
    "invoice",
    "invoices",
    // Blocks shadowing the POS surface routes (/<nym>/pos, /<nym>/pos/invoice).
    "pos",
    // Reserves the `/a/<alias>` slug namespace prefix so no nym can be
    // registered as "a" and shadow the alias routes.
    "a",
];

pub fn is_reserved(nym: &str) -> bool {
    RESERVED_NYMS.contains(&nym)
}

/// Alias-specific reservations for the `/a/<alias>` slug namespace, layered on
/// top of `RESERVED_NYMS` (route hygiene). Two groups:
///
/// - `"0"` / `"1"`: load-bearing for the signed-payload trailing-field trick.
///   They are the `pos_mode` value domain, so an alias equal to either would
///   let a captured legacy save message (whose sole trailing signed field was
///   `pos_mode`) be byte-identical to a new alias-claiming message. Blocking
///   them keeps the alias value domain disjoint from `pos_mode`. See
///   `donation_page.rs` and `docs/reference/compatibility.md`.
/// - Brand/impersonation names, to stop a merchant publishing a link that
///   looks first-party.
///
/// (`"pos"`, `"payment_page"` are covered elsewhere — `"pos"` is in
/// `RESERVED_NYMS`, `"payment_page"` fails the alias charset via its
/// underscore — which also keeps the alias domain disjoint from `kind`.)
pub const RESERVED_ALIASES: &[&str] = &[
    "0",
    "1",
    "bullbitcoin",
    "bull-bitcoin",
    "bullpay",
    "bullnym",
    "bull",
    "bitcoin",
];

/// True if `s` may not be claimed as a donation-page alias — either a reserved
/// route slug (`is_reserved`) or an alias-specific reservation.
pub fn is_reserved_alias(s: &str) -> bool {
    is_reserved(s) || RESERVED_ALIASES.contains(&s)
}

#[cfg(test)]
mod tests;
