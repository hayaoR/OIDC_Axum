use openid::{Client, Discovered, StandardClaims};
use serde::Deserialize;

pub type OpenIDClient = Client<Discovered, StandardClaims>;

pub fn host(path: &str) -> String {
    std::env::var("REDIRECT_URL").unwrap_or("http://localhost:8080".to_string()) + path
}

#[derive(Deserialize, Debug)]
pub struct LoginQuery {
    pub code: String,
    pub state: Option<String>,
}
