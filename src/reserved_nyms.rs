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
];

pub fn is_reserved(nym: &str) -> bool {
    RESERVED_NYMS.contains(&nym)
}

#[cfg(test)]
mod tests;
