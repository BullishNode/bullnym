use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::config::CertificationConfig;
use crate::error::AppError;
use crate::ip_whitelist;
use crate::AppState;

const CERTIFICATION_TOKEN_HEADER: &str = "x-bullnym-certification-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationScope {
    RegistrationSetup,
    MetadataLookup,
    InvoiceCreate,
    InvoiceStatus,
    LiveMoneyOffer,
}

impl CertificationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegistrationSetup => "registration_setup",
            Self::MetadataLookup => "metadata_lookup",
            Self::InvoiceCreate => "invoice_create",
            Self::InvoiceStatus => "invoice_status",
            Self::LiveMoneyOffer => "live_money_offer",
        }
    }
}

impl FromStr for CertificationScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "registration_setup" => Ok(Self::RegistrationSetup),
            "metadata_lookup" => Ok(Self::MetadataLookup),
            "invoice_create" => Ok(Self::InvoiceCreate),
            "invoice_status" => Ok(Self::InvoiceStatus),
            "live_money_offer" => Ok(Self::LiveMoneyOffer),
            other => Err(format!("unknown certification scope: {other}")),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CertificationAllowlist {
    enabled: bool,
    sources: Vec<IpNet>,
    token: String,
    scopes: HashSet<CertificationScope>,
}

#[derive(Debug, Clone, Copy)]
pub struct CertificationDecision {
    pub allowed: bool,
    pub source_allowed: bool,
    pub token_valid: bool,
    pub scope_enabled: bool,
    pub caller_ip: Option<IpAddr>,
}

impl CertificationAllowlist {
    pub fn parse(cfg: &CertificationConfig) -> Result<Self, String> {
        let mut sources = Vec::with_capacity(cfg.source_allowlist.len());
        for entry in &cfg.source_allowlist {
            let s = entry.trim();
            if s.is_empty() {
                continue;
            }
            let net = if s.contains('/') {
                IpNet::from_str(s).map_err(|e| format!("invalid certification CIDR {s:?}: {e}"))?
            } else {
                let addr = IpAddr::from_str(s)
                    .map_err(|e| format!("invalid certification IP {s:?}: {e}"))?;
                IpNet::from(addr)
            };
            sources.push(net);
        }

        let mut scopes = HashSet::with_capacity(cfg.scopes.len());
        for scope in &cfg.scopes {
            scopes.insert(CertificationScope::from_str(scope.trim())?);
        }

        Ok(Self {
            enabled: cfg.enabled,
            sources,
            token: cfg.token.clone(),
            scopes,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn configured_scopes(&self) -> Vec<&'static str> {
        let mut scopes: Vec<_> = self.scopes.iter().map(|scope| scope.as_str()).collect();
        scopes.sort_unstable();
        scopes
    }

    pub fn decide(
        &self,
        scope: CertificationScope,
        peer: Option<SocketAddr>,
        headers: &HeaderMap,
        trust_forwarded_for: bool,
    ) -> CertificationDecision {
        let caller_ip = ip_whitelist::caller_ip(peer, headers, trust_forwarded_for);
        let source_allowed = self.enabled
            && caller_ip
                .map(|ip| self.sources.iter().any(|net| net.contains(&ip)))
                .unwrap_or(false);
        let scope_enabled = self.enabled && self.scopes.contains(&scope);
        let token_valid = self.enabled && self.header_token_valid(headers);
        CertificationDecision {
            allowed: source_allowed && scope_enabled && token_valid,
            source_allowed,
            token_valid,
            scope_enabled,
            caller_ip,
        }
    }

    fn header_token_valid(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers
            .get(CERTIFICATION_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        if value.len() != self.token.len() {
            return false;
        }
        value.as_bytes().ct_eq(self.token.as_bytes()).into()
    }
}

pub fn audit_bypass(
    decision: CertificationDecision,
    scope: CertificationScope,
    route: &'static str,
    identity: Option<&str>,
) {
    if !decision.allowed {
        return;
    }
    tracing::info!(
        event = "certification_bypass",
        scope = scope.as_str(),
        route = route,
        caller_ip = ?decision.caller_ip,
        identity = identity.unwrap_or(""),
        "certification-scoped rate-limit bypass"
    );
}

pub fn allows_scope(
    state: &AppState,
    scope: CertificationScope,
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    route: &'static str,
    identity: Option<&str>,
) -> bool {
    let decision = state.certification.decide(
        scope,
        peer,
        headers,
        state.config.rate_limit.trust_forwarded_for,
    );
    audit_bypass(decision, scope, route, identity);
    decision.allowed
}

#[derive(Deserialize)]
pub struct CertificationPreflightQuery {
    #[serde(default)]
    pub scopes: Option<String>,
}

#[derive(Serialize)]
pub struct CertificationPreflightResponse {
    pub enabled: bool,
    pub source_allowed: bool,
    pub token_valid: bool,
    pub requested_scopes: Vec<String>,
    pub configured_scopes: Vec<String>,
    pub missing_scopes: Vec<String>,
    pub ready: bool,
}

pub async fn preflight(
    State(state): State<AppState>,
    peer_opt: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(query): Query<CertificationPreflightQuery>,
) -> Result<Json<CertificationPreflightResponse>, AppError> {
    let peer = peer_opt.map(|ConnectInfo(addr)| addr);
    let requested_scopes = query
        .scopes
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    let mut missing_scopes = Vec::new();
    let mut source_allowed = false;
    let mut token_valid = false;
    for scope_name in &requested_scopes {
        let scope = CertificationScope::from_str(scope_name).map_err(AppError::InvalidAmount)?;
        let decision = state.certification.decide(
            scope,
            peer,
            &headers,
            state.config.rate_limit.trust_forwarded_for,
        );
        source_allowed = source_allowed || decision.source_allowed;
        token_valid = token_valid || decision.token_valid;
        if !decision.scope_enabled {
            missing_scopes.push(scope_name.clone());
        }
    }
    if requested_scopes.is_empty() {
        let decision = state.certification.decide(
            CertificationScope::RegistrationSetup,
            peer,
            &headers,
            state.config.rate_limit.trust_forwarded_for,
        );
        source_allowed = decision.source_allowed;
        token_valid = decision.token_valid;
    }

    let authorized_to_inspect = source_allowed && token_valid;
    let ready = state.certification.enabled()
        && authorized_to_inspect
        && !requested_scopes.is_empty()
        && missing_scopes.is_empty();
    let configured_scopes = if authorized_to_inspect {
        state
            .certification
            .configured_scopes()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    } else {
        Vec::new()
    };

    Ok(Json(CertificationPreflightResponse {
        enabled: state.certification.enabled(),
        source_allowed,
        token_valid,
        requested_scopes,
        configured_scopes,
        missing_scopes,
        ready,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn allowlist() -> CertificationAllowlist {
        CertificationAllowlist::parse(&CertificationConfig {
            enabled: true,
            source_allowlist: vec!["203.0.113.10".to_string()],
            token: "secret-token".to_string(),
            scopes: vec!["invoice_status".to_string()],
        })
        .unwrap()
    }

    #[test]
    fn certification_requires_source_token_and_scope() {
        let allowlist = allowlist();
        let mut headers = HeaderMap::new();
        headers.insert(CERTIFICATION_TOKEN_HEADER, "secret-token".parse().unwrap());
        let peer = Some("203.0.113.10:1234".parse::<SocketAddr>().unwrap());

        let decision = allowlist.decide(CertificationScope::InvoiceStatus, peer, &headers, false);
        assert!(decision.allowed);

        let wrong_scope =
            allowlist.decide(CertificationScope::InvoiceCreate, peer, &headers, false);
        assert!(!wrong_scope.allowed);
        assert!(!wrong_scope.scope_enabled);

        let wrong_source = allowlist.decide(
            CertificationScope::InvoiceStatus,
            Some("203.0.113.11:1234".parse::<SocketAddr>().unwrap()),
            &headers,
            false,
        );
        assert!(!wrong_source.allowed);
        assert!(!wrong_source.source_allowed);

        let no_token = allowlist.decide(
            CertificationScope::InvoiceStatus,
            peer,
            &HeaderMap::new(),
            false,
        );
        assert!(!no_token.allowed);
        assert!(!no_token.token_valid);
    }

    #[test]
    fn certification_rejects_unknown_scope_in_config() {
        let err = CertificationAllowlist::parse(&CertificationConfig {
            enabled: true,
            source_allowlist: vec!["203.0.113.10".to_string()],
            token: "secret-token".to_string(),
            scopes: vec!["everything".to_string()],
        })
        .unwrap_err();
        assert!(err.contains("unknown certification scope"));
    }

    #[test]
    fn configured_scopes_are_available_only_after_source_and_token_match() {
        let allowlist = allowlist();
        let mut headers = HeaderMap::new();
        headers.insert(CERTIFICATION_TOKEN_HEADER, "secret-token".parse().unwrap());
        let peer = Some("203.0.113.10:1234".parse::<SocketAddr>().unwrap());
        let decision = allowlist.decide(CertificationScope::InvoiceStatus, peer, &headers, false);
        assert!(decision.source_allowed);
        assert!(decision.token_valid);
        assert_eq!(allowlist.configured_scopes(), vec!["invoice_status"]);
    }
}
