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
/// When `trust_forwarded_for` is true, the first entry in `X-Forwarded-For`
/// takes precedence. Only enable behind a trusted reverse proxy — otherwise
/// clients can trivially spoof the whitelist.
pub fn resolve_caller_ip(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trust_forwarded_for: bool,
) -> Option<IpAddr> {
    if trust_forwarded_for {
        if let Some(xff) = forwarded_for {
            // Pick the left-most entry (original client, per XFF convention).
            let first = xff.split(',').next()?.trim();
            if let Ok(ip) = IpAddr::from_str(first) {
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
    fn resolve_uses_xff_when_trusted() {
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let got = resolve_caller_ip(Some(peer), Some("9.9.9.9, 8.8.8.8"), true);
        assert_eq!(got, Some("9.9.9.9".parse().unwrap()));
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
