//! IP whitelist + caller-IP resolution.
//!
//! Whitelisted callers skip every rate limit and the proof-of-funds
//! requirement. Supports both exact IPs ("203.0.113.42") and CIDR blocks
//! ("10.0.0.0/8", "2001:db8::/32") for v4 and v6.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// Precompiled whitelist entries. Build once at startup, reuse on every request.
#[derive(Debug, Clone, Default)]
pub struct IpWhitelist {
    nets: Vec<IpNet>,
}

impl IpWhitelist {
    /// Parse a list of IPs and CIDR strings. Any malformed entry causes the
    /// whole parse to fail — fail-closed so a typo can't silently disable
    /// the whole whitelist.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let mut nets = Vec::with_capacity(entries.len());
        for entry in entries {
            let s = entry.trim();
            if s.is_empty() {
                continue;
            }
            // Accept plain IPs (auto-widen to /32 or /128) and CIDRs.
            let net = if s.contains('/') {
                IpNet::from_str(s).map_err(|e| format!("invalid CIDR {s:?}: {e}"))?
            } else {
                let addr = IpAddr::from_str(s)
                    .map_err(|e| format!("invalid IP {s:?}: {e}"))?;
                IpNet::from(addr)
            };
            nets.push(net);
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
    }
}

/// Resolve the effective caller IP from a socket peer and headers.
///
/// When `trust_forwarded_for` is true, we read the **rightmost** entry in
/// X-Forwarded-For — the one our reverse proxy (nginx with
/// `proxy_add_x_forwarded_for`) appends itself, which is the only entry
/// the client can't forge. Anything to the left of that was supplied by
/// the client; trusting the leftmost would let any caller pretend to be
/// any IP by injecting `X-Forwarded-For: <fake-ip>` on their request.
///
/// Only enable `trust_forwarded_for` when actually behind a reverse proxy
/// that appends the real client IP to XFF.
pub fn resolve_caller_ip(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trust_forwarded_for: bool,
) -> Option<IpAddr> {
    if trust_forwarded_for {
        if let Some(xff) = forwarded_for {
            // Right-most entry: prepended by our reverse proxy, not the client.
            let last = xff.split(',').next_back()?.trim();
            if let Ok(ip) = IpAddr::from_str(last) {
                return Some(ip);
            }
        }
    }
    peer
}

#[cfg(test)]
mod tests {
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
        // nginx appends $remote_addr — rightmost entry is the trusted one.
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let got = resolve_caller_ip(Some(peer), Some("9.9.9.9, 8.8.8.8"), true);
        assert_eq!(got, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn client_cannot_spoof_via_leftmost_xff() {
        // Attacker injects "X-Forwarded-For: 198.51.100.1" hoping the
        // server treats it as the caller IP. nginx appends the real
        // peer IP after a comma, producing "198.51.100.1, <real>".
        // Server must use the rightmost entry, not the attacker's.
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
}
