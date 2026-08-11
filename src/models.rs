use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::schema::{apps, oauth_flows, tokens};

#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = apps)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct App {
    pub id: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: Vec<u8>,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub scopes: String,
    pub token_auth_method: String,
    pub extra_auth_params: String,
    pub extra_headers: String,
    pub public_key: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = apps)]
pub struct NewApp {
    pub id: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: Vec<u8>,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub scopes: String,
    pub token_auth_method: String,
    pub extra_auth_params: String,
    pub extra_headers: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = oauth_flows)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct OauthFlow {
    pub id: String,
    pub app_id: String,
    pub state: String,
    pub pkce_verifier: Vec<u8>,
    pub redirect_after: String,
    pub external_account_hint: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = oauth_flows)]
pub struct NewOauthFlow {
    pub id: String,
    pub app_id: String,
    pub state: String,
    pub pkce_verifier: Vec<u8>,
    pub redirect_after: String,
    pub external_account_hint: Option<String>,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = tokens)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Token {
    pub id: String,
    pub app_id: String,
    pub external_account: String,
    pub access_token: Vec<u8>,
    pub refresh_token: Option<Vec<u8>>,
    pub scopes: String,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = tokens)]
pub struct NewToken {
    pub id: String,
    pub app_id: String,
    pub external_account: String,
    pub access_token: Vec<u8>,
    pub refresh_token: Option<Vec<u8>>,
    pub scopes: String,
    pub expires_at: Option<NaiveDateTime>,
}
