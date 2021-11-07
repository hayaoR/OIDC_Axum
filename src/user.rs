use openid::Bearer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub login: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub image_url: Option<String>,
    pub activated: bool,
    pub lang_key: Option<String>,
    pub authorities: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub user: User,
    pub token: Bearer,
    pub user_info: openid::Userinfo,
}
