use super::*;

#[test]
fn slug_accepts_simple() {
    assert!(is_valid_slug("alice"));
    assert!(is_valid_slug("my-shop"));
    assert!(is_valid_slug("user123"));
}

#[test]
fn slug_rejects_uppercase() {
    assert!(!is_valid_slug("Alice"));
}

#[test]
fn slug_rejects_dots_and_slashes() {
    assert!(!is_valid_slug("a.b"));
    assert!(!is_valid_slug("a/b"));
    assert!(!is_valid_slug("../etc/passwd"));
}

#[test]
fn slug_rejects_empty_and_long() {
    assert!(!is_valid_slug(""));
    assert!(!is_valid_slug(&"a".repeat(33)));
}

#[test]
fn slug_rejects_underscores_and_special() {
    assert!(!is_valid_slug("a_b"));
    assert!(!is_valid_slug("a@b"));
}

#[test]
fn live_template_renders_social_preview_metadata() {
    let og_url = "https://bullpay.ca/img/alice/og.jpg?v=abcd";
    let tpl = DonationPageTpl {
        nym: "alice",
        header: "Alice Store",
        description: "Fresh coffee",
        public_url: "https://bullpay.ca/alice".to_string(),
        avatar_url: None,
        og_url: Some(og_url.to_string()),
        display_currency: "CAD",
        website: None,
        twitter: None,
        instagram: None,
        minor_per_btc: 1_000_000_000,
        last_known_rate: false,
        supported_currencies: vec![CurrencyView {
            code: "CAD".to_string(),
            precision: 2,
        }],
    };

    let html = tpl.render().expect("template renders");

    assert!(html.contains(&format!(r#"<meta property="og:image" content="{og_url}">"#)));
    assert!(html.contains(r#"<meta property="og:image:width" content="1200">"#));
    assert!(html.contains(r#"<meta property="og:image:height" content="630">"#));
    assert!(html.contains(r#"<meta property="og:image:type" content="image/jpeg">"#));
    assert!(html.contains(r#"<meta property="og:image:alt" content="Alice Store">"#));
    assert!(html.contains(&format!(
        r#"<meta name="twitter:image" content="{og_url}">"#
    )));
}
