//! IP whitelist + caller-IP resolution.
//!
//! Whitelisted callers skip every rate limit and the proof-of-funds
//! requirement. Supports both exact IPs ("203.0.113.42") and CIDR blocks
//! ("10.0.0.0/8", "2001:db8::/32") for v4 and v6.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use axum::http::HeaderMap;
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
                let addr = IpAddr::from_str(s).map_err(|e| format!("invalid IP {s:?}: {e}"))?;
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

/// Compute the rate-limit "source key" string for a caller IP.
///
/// IPv4 hosts get a unique key per address (`/32`).
///
/// IPv6 addresses are aggregated to `/56` so that an attacker with a
/// routed `/64` (the standard ISP allocation, also what cloud VMs hand
/// out) cannot rotate through 2⁶⁴ source addresses to bypass per-source
/// caps. A `/56` covers a single ISP customer allocation — finer-grained
/// would let one VM act as a 2⁶⁴-wide source, coarser would collide many
/// real residential customers under one key.
pub fn source_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("v4:/32:{v4}"),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // /56 = first 7 octets verbatim, 8th masked to 0.
            format!(
                "v6:/56:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}00::",
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6]
            )
        }
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

/// Convenience wrapper used by handlers: takes the axum-extracted peer +
/// headers + a `trust_forwarded_for` config flag. Replaces the
/// 5-line-per-module helper that several donation/registration modules
/// were duplicating.
pub fn caller_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    trust_forwarded_for: bool,
) -> Option<IpAddr> {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    resolve_caller_ip(peer.map(|p| p.ip()), xff, trust_forwarded_for)
}

#[cfg(test)]
mod tests;
