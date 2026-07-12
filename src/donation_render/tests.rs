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
    assert_eq!(
        resp.headers().get("x-robots-tag").expect("robots header"),
        "noindex, nofollow, noarchive"
    );
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).expect("cache header"),
        "public, max-age=60, s-maxage=60, stale-while-revalidate=300"
    );
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
        invoice_base: "/alice".to_string(),
        header: "Alice Store",
        description: "Fresh coffee",
        social_meta: social_meta_tags(
            "Alice Store",
            "Fresh coffee",
            "https://bullpay.ca/alice",
            og_url,
        ),
        avatar_url: None,
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
    assert!(html.contains(
        r#"<meta property="og:image:alt" content="Alice Store — Bull Bitcoin Payment Page">"#
    ));
    assert!(html.contains(&format!(
        r#"<meta name="twitter:image" content="{og_url}">"#
    )));
    assert!(html.contains(r#"<meta property="og:site_name" content="Bull Bitcoin">"#));
    assert!(html.contains(r#"<link rel="canonical" href="https://bullpay.ca/alice">"#));
    assert!(html.contains(r#"<meta name="twitter:card" content="summary_large_image">"#));
    assert!(html.contains(
        r#"<meta name="twitter:image:alt" content="Alice Store — Bull Bitcoin Payment Page">"#
    ));
}

#[test]
fn archived_template_renders_unavailable_social_preview_metadata() {
    let image_url = og_image::fallback_url("bullpay.ca", true);
    let tpl = DonationArchivedTpl {
        nym: "alices-shop",
        social_meta: social_meta_tags(
            "Page unavailable",
            "This Bull Bitcoin Payment Page is no longer available.",
            "https://bullpay.ca/a/alices-shop",
            &image_url,
        ),
    };

    let html = tpl.render().expect("archived template renders");
    assert!(html.contains(r#"<title>Page unavailable</title>"#));
    assert!(html.contains(
        r#"<link rel="canonical" href="https://bullpay.ca/a/alices-shop">"#
    ));
    assert!(html.contains(
        r#"<meta property="og:image" content="https://bullpay.ca/og/fallback-unavailable-v1.jpg">"#
    ));
    assert!(html.contains(r#"<meta name="twitter:card" content="summary_large_image">"#));
}

#[tokio::test]
async fn stored_generated_image_uses_its_own_version_and_requires_the_file() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "bullnym-og-render-url-{unique}-{}",
        std::process::id()
    ));
    let root_str = root.to_string_lossy();
    let key = "ab".repeat(32);
    let path = og_image::generated_path_for_version(&root_str, 7, &key);
    std::fs::create_dir_all(path.parent().expect("version directory"))
        .expect("create version directory");
    std::fs::write(&path, b"present").expect("write image marker");

    assert_eq!(
        stored_generated_og_url(&root_str, "bullpay.ca", "alice", &key, 7).await,
        Some(format!("https://bullpay.ca/img/og/v7/{key}.jpg"))
    );
    assert_eq!(
        stored_generated_og_url(&root_str, "bullpay.ca", "alice", &"cd".repeat(32), 7,).await,
        None
    );

    std::fs::remove_dir_all(root).expect("remove test image directory");
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
        generated_og_key: None,
        generated_og_template_version: None,
        alias: None,
        display_currency: "USD".to_string(),
        website: None,
        twitter: None,
        instagram: None,
        pos_mode: false,
        enabled: true,
        is_archived: false,
    };

    let manifest = web_manifest_for_page(&page, "/manifestnym", "manifestnym");

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
        generated_og_key: None,
        generated_og_template_version: None,
        alias: None,
        display_currency: "USD".to_string(),
        website: None,
        twitter: None,
        instagram: None,
        pos_mode: true,
        enabled: true,
        is_archived: false,
    };

    let manifest = web_manifest_for_page(&page, "/alice", "alice");

    assert_eq!(manifest.name, "Alice Coffee Counter");
    assert_eq!(manifest.short_name, "Alice Coffee");
    assert_eq!(manifest.start_url, "/alice");
}

#[test]
fn pwa_shell_injects_config_and_og_placeholders() {
    let shell = r#"<!doctype html><head><title>bullnym</title><!-- BULLNYM_OG --><!-- BULLNYM_MANIFEST --></head><body><!-- BULLNYM_CONFIG --></body>"#;
    let config = PwaConfigView {
        nym: Some("alice"),
        invoice_base: "/alice/pos",
        page_key: "alice",
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
        "https://bullpay.ca/alice",
        "https://bullpay.ca/img/alice/og.jpg?v=a&b",
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
    assert!(html.contains("<title>Alice &amp; Sons</title>"));
    assert!(!html.contains("<title>bullnym</title>"));
    assert!(html.contains(r#"<meta property="og:description" content="Coffee &quot;now&quot;">"#));
    assert!(html.contains(
        r#"<meta property="og:image" content="https://bullpay.ca/img/alice/og.jpg?v=a&amp;b">"#
    ));
    assert!(
        html.find(r#"<meta property="og:image""#)
            .expect("OG image tag")
            < 8 * 1024,
        "crawler metadata must stay in the first response range"
    );
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
        nym: Some("alice"),
        invoice_base: "/alice",
        page_key: "alice",
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

    let html = inject_pwa_shell(
        shell,
        &config,
        "https://bullpay.ca/alice",
        "https://bullpay.ca/og/fallback-live-v1.jpg",
        r#"/bad"name/manifest.webmanifest"#,
    )
    .expect("injects shell");

    assert!(html.contains(r#"<link rel="manifest" href="/bad&quot;name/manifest.webmanifest">"#));
}

#[test]
fn pwa_shell_escapes_script_breakout_in_json() {
    let shell = "<!-- BULLNYM_CONFIG --><!-- BULLNYM_OG -->";
    let config = PwaConfigView {
        nym: Some("alice"),
        invoice_base: "/alice",
        page_key: "alice",
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

    let html = inject_pwa_shell(
        shell,
        &config,
        "https://bullpay.ca/alice",
        "https://bullpay.ca/og/fallback-live-v1.jpg",
        "/alice/manifest.webmanifest",
    )
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

// --- Alias nym-scrubbing ---

#[test]
fn alias_config_omits_nym_and_carries_invoice_base() {
    let shell = "<!-- BULLNYM_CONFIG -->";
    let config = PwaConfigView {
        nym: None,
        invoice_base: "/a/alices-shop",
        page_key: "alices-shop",
        mode: "donation",
        currency: "USD",
        header: "Alice's Shop",
        description: "Fresh coffee",
        // Alias image URLs are content-addressed (no nym in the path).
        avatar_url: Some("https://bullpay.ca/img/_h/deadbeef.webp"),
        website: None,
        twitter: None,
        instagram: None,
        minor_per_btc: 0,
        last_known_rate: false,
        liquid_btc_asset_id: crate::invoice::LIQUID_BTC_ASSET_ID,
        domain: "bullpay.ca",
    };
    let html = inject_pwa_shell(
        shell,
        &config,
        "https://bullpay.ca/a/alices-shop",
        "https://bullpay.ca/og/fallback-live-v1.jpg",
        "/a/alices-shop/manifest.webmanifest",
    )
    .expect("injects shell");
    let json = injected_config_json(&html);
    assert!(
        json.get("nym").is_none(),
        "alias config must not carry the nym key"
    );
    assert_eq!(json["invoice_base"], "/a/alices-shop");
    assert_eq!(json["page_key"], "alices-shop");
    assert_eq!(
        json["avatar_url"],
        "https://bullpay.ca/img/_h/deadbeef.webp"
    );
}

#[test]
fn nym_config_still_carries_nym_and_invoice_base() {
    // Regression: nym pages keep sending `nym` (installed-PWA back-compat).
    let shell = "<!-- BULLNYM_CONFIG -->";
    let config = PwaConfigView {
        nym: Some("alice"),
        invoice_base: "/alice",
        page_key: "alice",
        mode: "donation",
        currency: "USD",
        header: "Alice",
        description: "d",
        avatar_url: None,
        website: None,
        twitter: None,
        instagram: None,
        minor_per_btc: 0,
        last_known_rate: false,
        liquid_btc_asset_id: crate::invoice::LIQUID_BTC_ASSET_ID,
        domain: "bullpay.ca",
    };
    let html = inject_pwa_shell(
        shell,
        &config,
        "https://bullpay.ca/alice",
        "https://bullpay.ca/og/fallback-live-v1.jpg",
        "/alice/manifest.webmanifest",
    )
    .expect("injects shell");
    let json = injected_config_json(&html);
    assert_eq!(json["nym"], "alice");
    assert_eq!(json["invoice_base"], "/alice");
    assert_eq!(json["page_key"], "alice");
}

#[test]
fn web_manifest_fallback_uses_provided_name_not_nym() {
    // With a blank header the manifest name falls back to the caller-provided
    // name (the slug on alias pages), never the nym.
    let page = db::DonationPage {
        nym: "secretnym".to_string(),
        kind: db::KIND_PAYMENT_PAGE.to_string(),
        ct_descriptor: None,
        next_addr_idx: 0,
        header: "   ".to_string(),
        description: "d".to_string(),
        avatar_sha256: None,
        og_sha256: None,
        generated_og_key: None,
        generated_og_template_version: None,
        alias: Some("alices-shop".to_string()),
        display_currency: "USD".to_string(),
        website: None,
        twitter: None,
        instagram: None,
        pos_mode: false,
        enabled: true,
        is_archived: false,
    };
    let manifest = web_manifest_for_page(&page, "/a/alices-shop", "alices-shop");
    assert_eq!(manifest.name, "alices-shop");
    assert_eq!(manifest.start_url, "/a/alices-shop");
    assert_ne!(manifest.name, "secretnym");
}
