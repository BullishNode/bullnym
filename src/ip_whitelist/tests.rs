use super::*;

#[test]
fn parses_mixed_ipv4_and_cidr() {
    let wl = IpWhitelist::parse(&[
        "203.0.113.42".into(),
        "10.0.0.0/8".into(),
        "2001:db8::/32".into(),
    ])
    .unwrap();
    assert!(wl.contains("203.0.113.42".parse().unwrap()));
    assert!(wl.contains("10.5.1.1".parse().unwrap()));
    assert!(wl.contains("2001:db8::1".parse().unwrap()));
    assert!(!wl.contains("8.8.8.8".parse().unwrap()));
    assert!(!wl.contains("11.0.0.1".parse().unwrap()));
}

#[test]
fn empty_whitelist_matches_nothing() {
    let wl = IpWhitelist::parse(&[]).unwrap();
    assert!(wl.is_empty());
    assert!(!wl.contains("10.0.0.1".parse().unwrap()));
}

#[test]
fn malformed_entry_fails() {
    assert!(IpWhitelist::parse(&["not-an-ip".into()]).is_err());
    assert!(IpWhitelist::parse(&["10.0.0.0/99".into()]).is_err());
}

#[test]
fn blank_entries_ignored() {
    let wl = IpWhitelist::parse(&["".into(), "  ".into(), "10.0.0.0/8".into()]).unwrap();
    assert!(wl.contains("10.0.0.5".parse().unwrap()));
}

#[test]
fn resolve_uses_peer_when_xff_not_trusted() {
    let peer: IpAddr = "1.2.3.4".parse().unwrap();
    let got = resolve_caller_ip(Some(peer), Some("9.9.9.9"), false);
    assert_eq!(got, Some(peer));
}

#[test]
fn resolve_uses_rightmost_xff_when_trusted() {
    let peer: IpAddr = "1.2.3.4".parse().unwrap();
    let got = resolve_caller_ip(Some(peer), Some("9.9.9.9, 8.8.8.8"), true);
    assert_eq!(got, Some("8.8.8.8".parse().unwrap()));
}

#[test]
fn client_cannot_spoof_via_leftmost_xff() {
    let peer: IpAddr = "1.2.3.4".parse().unwrap();
    let real: IpAddr = "203.0.113.7".parse().unwrap();
    let xff = "198.51.100.1, 203.0.113.7";
    let got = resolve_caller_ip(Some(peer), Some(xff), true);
    assert_eq!(got, Some(real));
}

#[test]
fn resolve_falls_back_to_peer_on_malformed_xff() {
    let peer: IpAddr = "1.2.3.4".parse().unwrap();
    let got = resolve_caller_ip(Some(peer), Some("not-an-ip"), true);
    assert_eq!(got, Some(peer));
}

#[test]
fn resolve_falls_back_to_peer_when_xff_malformed() {
    let peer: IpAddr = "1.2.3.4".parse().unwrap();
    let got = resolve_caller_ip(Some(peer), Some("garbage"), true);
    assert_eq!(got, Some(peer));
}

#[test]
fn resolve_none_when_no_source() {
    assert_eq!(resolve_caller_ip(None, None, false), None);
}

#[test]
fn source_key_ipv4_uses_full_address() {
    let a: IpAddr = "203.0.113.7".parse().unwrap();
    let b: IpAddr = "203.0.113.8".parse().unwrap();
    assert_ne!(source_key(a), source_key(b));
    assert_eq!(source_key(a), "v4:/32:203.0.113.7");
}

#[test]
fn source_key_ipv6_aggregates_to_56() {
    let a: IpAddr = "2001:db8:abcd:0100::1".parse().unwrap();
    let b: IpAddr = "2001:db8:abcd:01ff:beef:cafe:dead:0001".parse().unwrap();
    assert_eq!(source_key(a), source_key(b));

    let c: IpAddr = "2001:db8:abcd:0200::1".parse().unwrap();
    assert_ne!(source_key(a), source_key(c));
}

#[test]
fn source_key_ipv6_format_is_stable() {
    let ip: IpAddr = "2001:db8:abcd:01ff:beef:cafe:dead:0001".parse().unwrap();
    assert_eq!(source_key(ip), "v6:/56:2001:0db8:abcd:0100::");
}
