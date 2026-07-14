use axum::Json;
use serde::Serialize;

pub const EXPECTED_SCHEMA_MARKER: &str = env!("BULLNYM_SCHEMA_MARKER");
pub const PUBLIC_NAME_POLICY: &str = "permanent_names_v1";

#[derive(Debug, Clone, Copy, Serialize)]
pub struct BuildProvenance {
    pub service: &'static str,
    pub crate_version: &'static str,
    pub build_commit: &'static str,
    pub build_profile: &'static str,
    pub build_source_state: &'static str,
    pub boltz_client_repository: &'static str,
    pub boltz_client_commit: &'static str,
    pub boltz_client_verification: &'static str,
    pub pwa_content_sha256: &'static str,
    pub expected_schema_marker: &'static str,
    pub rustc_version: &'static str,
    pub cargo_version: &'static str,
    pub build_target: &'static str,
}

impl BuildProvenance {
    pub fn current() -> Self {
        Self {
            service: "pay-service",
            crate_version: env!("CARGO_PKG_VERSION"),
            build_commit: env!("BULLNYM_BUILD_COMMIT"),
            build_profile: env!("BULLNYM_BUILD_PROFILE"),
            build_source_state: env!("BULLNYM_BUILD_SOURCE_STATE"),
            boltz_client_repository: env!("BULLNYM_BOLTZ_CLIENT_REPOSITORY"),
            boltz_client_commit: env!("BULLNYM_BOLTZ_CLIENT_COMMIT"),
            boltz_client_verification: env!("BULLNYM_BOLTZ_CLIENT_VERIFICATION"),
            pwa_content_sha256: env!("BULLNYM_PWA_CONTENT_SHA256"),
            expected_schema_marker: EXPECTED_SCHEMA_MARKER,
            rustc_version: env!("BULLNYM_RUSTC_VERSION"),
            cargo_version: env!("BULLNYM_CARGO_VERSION"),
            build_target: env!("BULLNYM_BUILD_TARGET"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VersionResponse {
    pub service: &'static str,
    pub crate_version: &'static str,
    pub build_commit: &'static str,
    pub build_branch: &'static str,
    pub build_time: &'static str,
    pub build_dirty: &'static str,
    pub runtime_mode: String,
    pub expected_schema_marker: &'static str,
    pub public_name_policy: &'static str,
}

impl VersionResponse {
    pub fn current() -> Self {
        let build = BuildProvenance::current();
        Self {
            service: build.service,
            crate_version: build.crate_version,
            build_commit: build.build_commit,
            build_branch: option_env!("BULLNYM_BUILD_BRANCH").unwrap_or("unknown"),
            build_time: option_env!("BULLNYM_BUILD_TIME").unwrap_or("unknown"),
            build_dirty: match build.build_source_state {
                "clean" => "false",
                "dirty-debug" => "true",
                _ => "unknown",
            },
            runtime_mode: std::env::var("BULLNYM_RUNTIME_MODE")
                .unwrap_or_else(|_| "unknown".into()),
            expected_schema_marker: build.expected_schema_marker,
            public_name_policy: PUBLIC_NAME_POLICY,
        }
    }
}

pub fn build_info_json() -> Result<String, serde_json::Error> {
    serde_json::to_string(&BuildProvenance::current())
}

pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse::current())
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn version_route_returns_public_build_metadata() {
        std::env::set_var("BULLNYM_RUNTIME_MODE", "test");
        let app = Router::new().route("/version", get(super::version));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["service"], "pay-service");
        assert_eq!(json["crate_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            json["expected_schema_marker"],
            super::EXPECTED_SCHEMA_MARKER
        );
        assert_eq!(json["runtime_mode"], "test");
        assert_eq!(json["public_name_policy"], super::PUBLIC_NAME_POLICY);
        assert_eq!(json["build_commit"], env!("BULLNYM_BUILD_COMMIT"));
        assert!(json.get("build_branch").is_some());
        assert!(json.get("build_time").is_some());
        assert!(json.get("build_dirty").is_some());
        assert!(json.get("boltz_client_commit").is_none());
        assert!(json.get("pwa_content_sha256").is_none());
    }

    #[test]
    fn build_info_cli_payload_is_valid_stable_json() {
        let json: Value = serde_json::from_str(&super::build_info_json().unwrap()).unwrap();
        assert_eq!(
            json["expected_schema_marker"],
            super::EXPECTED_SCHEMA_MARKER
        );
        assert_eq!(json["build_commit"], env!("BULLNYM_BUILD_COMMIT"));
        assert_eq!(
            json["boltz_client_commit"],
            env!("BULLNYM_BOLTZ_CLIENT_COMMIT")
        );
        assert_eq!(
            json["boltz_client_verification"],
            env!("BULLNYM_BOLTZ_CLIENT_VERIFICATION")
        );
        assert_eq!(
            json["boltz_client_repository"],
            "https://github.com/BullishNode/boltz-rust.git"
        );
        assert_eq!(json["rustc_version"], env!("BULLNYM_RUSTC_VERSION"));
        assert_eq!(json["cargo_version"], env!("BULLNYM_CARGO_VERSION"));
        assert_eq!(json["build_target"], env!("BULLNYM_BUILD_TARGET"));
    }
}
