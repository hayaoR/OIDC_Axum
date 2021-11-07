use async_session::{MemoryStore, Session, SessionStore as _};
use axum::{
    extract::{Extension, Query},
    http::header::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use http::StatusCode;
use openid::{Token, Userinfo};
use std::sync::Arc;
use tracing::instrument;

use crate::user::{User, UserInfo};
use crate::util::{host, LoginQuery, OpenIDClient};

//#[instrument]
pub async fn login(
    Extension(oidc_client): Extension<Arc<OpenIDClient>>,
    Extension(store): Extension<MemoryStore>,
    headers: HeaderMap,
    login_query: Query<LoginQuery>,
) -> impl IntoResponse {
    let request_token = request_token(oidc_client, &login_query).await;
    match request_token {
        Ok(Some((token, user_info))) => {
            let login = user_info.preferred_username.clone();
            let email = user_info.email.clone();

            let user = User {
                id: user_info.sub.clone().unwrap_or_default(),
                login,
                last_name: user_info.family_name.clone(),
                first_name: user_info.name.clone(),
                email,
                activated: user_info.email_verified,
                image_url: user_info.picture.clone().map(|x| x.to_string()),
                lang_key: Some("en".to_string()),
                authorities: vec!["ROLE_USER".to_string()],
            };

            let mut session = Session::new();
            match session.insert(
                "user_info",
                UserInfo {
                    user,
                    token: token.bearer,
                    user_info,
                },
            ) {
                Ok(_) => (),
                Err(err) => {
                    tracing::error!("cannot insert info to session: {}", err);
                    return (StatusCode::UNAUTHORIZED, HeaderMap::new());
                }
            };
            let cookie = store.store_session(session).await.unwrap().unwrap();
            let cookie = format!("sessionId={}; HttpOnly; Path=/", cookie).to_string();
            tracing::info!("set_cookie: {}", cookie);

            let redirect_url = login_query.state.clone().unwrap_or_else(|| host("/"));
            tracing::info!("redirect_url: {}", redirect_url);

            let mut headers = HeaderMap::new();
            let url = if let Ok(url) = HeaderValue::from_str(&redirect_url) {
                url
            } else {
                return (StatusCode::INTERNAL_SERVER_ERROR, headers);
            };
            headers.insert(http::header::LOCATION, url);
            let cookie = if let Ok(cookie) = HeaderValue::from_str(&cookie) {
                cookie
            } else {
                return (StatusCode::INTERNAL_SERVER_ERROR, headers);
            };
            headers.insert(http::header::SET_COOKIE, cookie);

            tracing::info!("header {:?}", headers);
            (StatusCode::MOVED_PERMANENTLY, headers)
        }
        Ok(None) => {
            tracing::error!("login error in call: no id_token found");
            (StatusCode::UNAUTHORIZED, HeaderMap::new())
        }
        Err(err) => {
            tracing::error!("login error in call: {:?}", err);
            (StatusCode::UNAUTHORIZED, HeaderMap::new())
        }
    }
}

//#[instrument]
async fn request_token(
    oidc_client: Arc<OpenIDClient>,
    login_query: &LoginQuery,
) -> anyhow::Result<Option<(Token, Userinfo)>> {
    let mut token: Token = oidc_client.request_token(&login_query.code).await?.into();

    if let Some(mut id_token) = token.id_token.as_mut() {
        oidc_client.decode_token(&mut id_token)?;
        oidc_client.validate_token(&id_token, None, None)?;
        tracing::info!("token: {:?}", id_token);
    } else {
        return Ok(None);
    }

    let userinfo = oidc_client.request_userinfo(&token).await?;

    tracing::info!("user info: {:?}", userinfo);

    Ok(Some((token, userinfo)))
}
