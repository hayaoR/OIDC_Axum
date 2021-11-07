use async_session::MemoryStore;
use axum::{
    error_handling::HandleErrorExt,
    routing::{get, service_method_routing as service},
    AddExtensionLayer, Router,
};
use http::StatusCode;
use oidc::routes::{account::account, authorize::authorize, login::login};
use oidc::util::host;
use openid::DiscoveredClient;
use std::sync::Arc;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let client_id = std::env::var("CLIENT_ID").expect("Unspecified CLIENT_ID as env var");
    let client_secret =
        std::env::var("CLIENT_SECRET").expect("Unspecified CLIENT_SECRET as env var");
    let issuer_url = std::env::var("ISSURE").unwrap_or("https://accounts.google.com".to_string());
    let redirect = Some(host("/login/oauth2/code/oidc"));
    let issuer = reqwest::Url::parse(&issuer_url).unwrap();

    let client = Arc::new(
        DiscoveredClient::discover(client_id, client_secret, redirect, issuer)
            .await
            .unwrap(),
    );

    let store = MemoryStore::new();

    let app = Router::new()
        .route(
            "/",
            service::get(ServeDir::new("./static/")).handle_error(|error: std::io::Error| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Unhandled internal error: {}", error),
                )
            }),
        )
        .route("/oauth2/authorization/oidc", get(authorize))
        .route("/login/oauth2/code/oidc", get(login))
        .route("/api/account", get(account))
        .layer(AddExtensionLayer::new(client))
        .layer(AddExtensionLayer::new(store));

    axum::Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
