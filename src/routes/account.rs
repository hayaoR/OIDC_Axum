use crate::user::{User, UserInfo};
use async_session::{MemoryStore, SessionStore as _};
use axum::{extract::Extension, http::header::HeaderMap, response::Json};
use cookie::Cookie;
use http::StatusCode;

pub async fn account(
    Extension(store): Extension<MemoryStore>,
    headers: HeaderMap,
) -> Result<Json<User>, StatusCode> {
    let cookie = if let Some(cookie) = headers
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
    {
        cookie
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let mut cookie_value = "".to_string();
    tracing::info!("cookie: {}", cookie);
    let v: Vec<&str> = cookie.split(';').collect();
    for c in &v {
        let c = c.trim_start();
        if c.starts_with("sessionId=") {
            let parsed_cookie = Cookie::parse(c).unwrap();
            cookie_value = parsed_cookie.name_value().1.to_string();
        }
    }

    let session = match store.load_session(cookie_value).await {
        Ok(session) => session,
        Err(err) => {
            tracing::error!("Can not load session : {}", err);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let user_info = if let Some(session) = session {
        if let Some(user_info) = session.get::<UserInfo>("user_info") {
            user_info
        } else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    Ok(Json(user_info.user))
}
