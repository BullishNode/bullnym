use axum::Json;
use serde::Serialize;

pub const EXPECTED_SCHEMA_MARKER: &str = "030_invoice_payment_observations";

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
}

pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        service: "pay-service",
        crate_version: env!("CARGO_PKG_VERSION"),
        build_commit: option_env!("BULLNYM_BUILD_COMMIT").unwrap_or("unknown"),
        build_branch: option_env!("BULLNYM_BUILD_BRANCH").unwrap_or("unknown"),
        build_time: option_env!("BULLNYM_BUILD_TIME").unwrap_or("unknown"),
        build_dirty: option_env!("BULLNYM_BUILD_DIRTY").unwrap_or("unknown"),
        runtime_mode: std::env::var("BULLNYM_RUNTIME_MODE").unwrap_or_else(|_| "unknown".into()),
        expected_schema_marker: EXPECTED_SCHEMA_MARKER,
    })
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
        assert!(json.get("build_commit").is_some());
        assert!(json.get("build_dirty").is_some());
    }
}
