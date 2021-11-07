// Arc::new(DiscoveredClient::discover(client_id, client_secret, redirect, issuer))
// FOUND LOCATION URL
use crate::util::{host, OpenIDClient};
use axum::{
    extract::Extension,
    http::header::{HeaderMap, HeaderValue},
};
use http::StatusCode;
use openid::Options;
use std::sync::Arc;
use tracing::instrument;

//#[instrument]
pub async fn authorize(
    Extension(oidc_client): Extension<Arc<OpenIDClient>>,
) -> (StatusCode, HeaderMap) {
    let origin_url = std::env::var("ORIGIN").unwrap_or(host(""));

    let auth_url = oidc_client.auth_url(&Options {
        scope: Some("openid email profile".into()),
        state: Some(origin_url),
        ..Default::default()
    });

    tracing::info!("authorize: {}", auth_url);

    let url = String::from(auth_url);

    let mut headers = HeaderMap::new();
    let val = if let Ok(val) = HeaderValue::from_str(&url) {
        val
    } else {
        return (StatusCode::INTERNAL_SERVER_ERROR, headers);
    };

    headers.insert(http::header::LOCATION, val);
    (StatusCode::FOUND, headers)
}
