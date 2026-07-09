use super::*;

fn injected_config_json(html: &str) -> serde_json::Value {
    let (_, after_open) = html
        .split_once(r#"<script id="bullnym-config" type="application/json">"#)
        .expect("config script opens");
    let (json, _) = after_open
        .split_once("</script>")
        .expect("config script closes");
    serde_json::from_str(json).expect("config json parses")
}

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
fn security_headers_keep_donation_csp_tight() {
    let mut resp = StatusCode::OK.into_response();

    apply_security_headers(&mut resp, false);

    let csp = resp
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .expect("csp header")
        .to_str()
        .expect("valid csp");

    assert_eq!(csp, DONATION_CSP);
    assert!(csp.contains("connect-src 'self' wss://liquid.network"));
    assert!(!csp.contains("connect-src 'self' https:"));
}

#[test]
fn security_headers_allow_https_connects_for_pos_csp() {
    let mut resp = StatusCode::OK.into_response();

    apply_security_headers(&mut resp, true);

    let csp = resp
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .expect("csp header")
        .to_str()
        .expect("valid csp");

    assert_eq!(csp, POS_CSP);
    assert!(csp.contains("connect-src 'self' https: wss://liquid.network"));
    assert!(csp.contains("script-src 'self' 'unsafe-inline'"));
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

#[test]
fn web_manifest_falls_back_to_nym_and_truncates_short_name() {
    let page = db::DonationPage {
        nym: "manifestnym".to_string(),
        kind: db::KIND_PAYMENT_PAGE.to_string(),
        ct_descriptor: None,
        next_addr_idx: 0,
        header: "   ".to_string(),
        description: "Description".to_string(),
        avatar_sha256: None,
        og_sha256: None,
        alias: None,
        display_currency: "USD".to_string(),
        website: None,
        twitter: None,
        instagram: None,
        pos_mode: false,
        enabled: true,
        is_archived: false,
    };

    let manifest = web_manifest_for_page(&page, "/manifestnym");

    assert_eq!(manifest.name, "manifestnym");
    assert_eq!(manifest.short_name, "manifestnym");
    assert_eq!(manifest.start_url, "/manifestnym");
    assert_eq!(manifest.background_color, "#161512");
    assert_eq!(manifest.theme_color, "#161512");
    assert_eq!(manifest.icons.len(), 4);
    assert_eq!(manifest.icons[0].purpose, "any");
    assert_eq!(manifest.icons[1].purpose, "maskable");
    assert_eq!(manifest.icons[2].purpose, "any");
    assert_eq!(manifest.icons[3].purpose, "maskable");
}

#[test]
fn web_manifest_uses_header_for_name() {
    let page = db::DonationPage {
        nym: "alice".to_string(),
        kind: db::KIND_PAYMENT_PAGE.to_string(),
        ct_descriptor: None,
        next_addr_idx: 0,
        header: "Alice Coffee Counter".to_string(),
        description: "Description".to_string(),
        avatar_sha256: None,
        og_sha256: None,
        alias: None,
        display_currency: "USD".to_string(),
        website: None,
        twitter: None,
        instagram: None,
        pos_mode: true,
        enabled: true,
        is_archived: false,
    };

    let manifest = web_manifest_for_page(&page, "/alice");

    assert_eq!(manifest.name, "Alice Coffee Counter");
    assert_eq!(manifest.short_name, "Alice Coffee");
    assert_eq!(manifest.start_url, "/alice");
}

#[test]
fn pwa_shell_injects_config_and_og_placeholders() {
    let shell = r#"<!doctype html><head><!-- BULLNYM_OG --><!-- BULLNYM_MANIFEST --></head><body><!-- BULLNYM_CONFIG --></body>"#;
    let config = PwaConfigView {
        nym: "alice",
        mode: "pos",
        currency: "USD",
        header: "Alice & Sons",
        description: r#"Coffee "now""#,
        avatar_url: Some("https://bullpay.ca/img/alice/avatar.webp"),
        website: Some("https://alice.example"),
        twitter: Some("alice"),
        instagram: None,
        minor_per_btc: 1_000_000_000,
        last_known_rate: false,
        liquid_btc_asset_id: crate::invoice::LIQUID_BTC_ASSET_ID,
        domain: "bullpay.ca",
    };

    let html = inject_pwa_shell(
        shell,
        &config,
        Some("https://bullpay.ca/img/alice/og.jpg?v=a&b"),
        "/alice/manifest.webmanifest",
    )
    .expect("injects shell");

    assert!(html.contains(r#"<script id="bullnym-config" type="application/json">"#));
    let config_json = injected_config_json(&html);
    assert_eq!(
        config_json["liquid_btc_asset_id"],
        "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d"
    );
    assert!(html.contains(r#"<link rel="manifest" href="/alice/manifest.webmanifest">"#));
    assert!(html.contains(r#""mode":"pos""#));
    assert!(html.contains(r#""avatar_url":"https://bullpay.ca/img/alice/avatar.webp""#));
    assert!(html.contains(r#"<meta property="og:title" content="Alice &amp; Sons">"#));
    assert!(html.contains(r#"<meta property="og:description" content="Coffee &quot;now&quot;">"#));
    assert!(html.contains(
        r#"<meta property="og:image" content="https://bullpay.ca/img/alice/og.jpg?v=a&amp;b">"#
    ));
    assert!(!html.contains("<!-- BULLNYM_CONFIG -->"));
    assert!(!html.contains("<!-- BULLNYM_MANIFEST -->"));
    assert!(!html.contains("<!-- BULLNYM_OG -->"));
}

#[test]
fn pwa_shell_escapes_manifest_href_attr() {
    // Defense-in-depth: the manifest href is HTML-attr-escaped before it lands
    // in the <link>. A valid slug can't contain quotes (is_valid_slug), so the
    // caller never passes one, but the escaping must hold regardless.
    let shell = "<!-- BULLNYM_MANIFEST -->";
    let config = PwaConfigView {
        nym: "alice",
        mode: "donation",
        currency: "USD",
        header: "Header",
        description: "Description",
        avatar_url: None,
        website: None,
        twitter: None,
        instagram: None,
        minor_per_btc: 0,
        last_known_rate: false,
        liquid_btc_asset_id: crate::invoice::LIQUID_BTC_ASSET_ID,
        domain: "bullpay.ca",
    };

    let html = inject_pwa_shell(shell, &config, None, r#"/bad"name/manifest.webmanifest"#)
        .expect("injects shell");

    assert!(html.contains(r#"<link rel="manifest" href="/bad&quot;name/manifest.webmanifest">"#));
}

#[test]
fn pwa_shell_escapes_script_breakout_in_json() {
    let shell = "<!-- BULLNYM_CONFIG --><!-- BULLNYM_OG -->";
    let config = PwaConfigView {
        nym: "alice",
        mode: "donation",
        currency: "USD",
        header: "</script><script>alert(1)</script>",
        description: "Fresh coffee",
        avatar_url: None,
        website: None,
        twitter: None,
        instagram: None,
        minor_per_btc: 0,
        last_known_rate: false,
        liquid_btc_asset_id: crate::invoice::LIQUID_BTC_ASSET_ID,
        domain: "bullpay.ca",
    };

    let html = inject_pwa_shell(shell, &config, None, "/alice/manifest.webmanifest")
        .expect("injects shell");

    assert!(html.contains(r#"\u003c/script>"#));
    assert!(!html.contains("</script><script>"));
    assert!(html.contains(r#"<meta property="og:title" content="&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;">"#));
}

#[tokio::test]
async fn pwa_shell_reads_current_file_from_disk() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("bullnym-pwa-shell-{unique}-{}", std::process::id()));
    let donation_dir = root.join("apps").join("donation");
    std::fs::create_dir_all(&donation_dir).expect("create donation shell dir");
    let donation_path = donation_dir.join("index.html");
    std::fs::write(&donation_path, "first shell").expect("write first shell");

    let shells = PwaShells::load(&root);

    assert_eq!(
        shells.shell_for(false).await.as_deref(),
        Some("first shell")
    );

    std::fs::write(&donation_path, "rebuilt shell").expect("write rebuilt shell");

    assert_eq!(
        shells.shell_for(false).await.as_deref(),
        Some("rebuilt shell")
    );

    std::fs::remove_dir_all(root).expect("remove temp shell dir");
}

#[tokio::test]
async fn pwa_shell_missing_file_falls_back_to_askama_path() {
    let shells = PwaShells::default();

    assert!(shells.shell_for(false).await.is_none());
}

#[test]
fn pwa_shell_header_marks_donation_shells_only_when_requested() {
    let mut resp = StatusCode::OK.into_response();

    apply_security_headers(&mut resp, false);
    assert!(!resp.headers().contains_key(PWA_SHELL_HEADER));

    mark_pwa_shell_response(&mut resp, false);

    assert_eq!(
        resp.headers()
            .get(PWA_SHELL_HEADER)
            .expect("pwa shell header")
            .to_str()
            .expect("valid header value"),
        "donation"
    );
}

#[test]
fn pwa_shell_header_marks_pos_shells() {
    let mut resp = StatusCode::OK.into_response();

    mark_pwa_shell_response(&mut resp, true);

    assert_eq!(
        resp.headers()
            .get(PWA_SHELL_HEADER)
            .expect("pwa shell header")
            .to_str()
            .expect("valid header value"),
        "pos"
    );
}
