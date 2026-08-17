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
    pub allowed_redirect_uris: String,
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
    pub allowed_redirect_uris: String,
    pub scopes: String,
    pub token_auth_method: String,
    pub extra_auth_params: String,
    pub extra_headers: String,
    pub public_key: String,
}

/// Partial update for `PUT`/`PATCH /apps/{app_id}`. Every field is optional
/// so callers can overwrite only what they mean to change.
#[derive(Debug, Default, AsChangeset)]
#[diesel(table_name = apps)]
pub struct AppChanges {
    pub name: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<Vec<u8>>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub redirect_url: Option<String>,
    pub allowed_redirect_uris: Option<String>,
    pub scopes: Option<String>,
    pub token_auth_method: Option<String>,
    pub extra_auth_params: Option<String>,
    pub extra_headers: Option<String>,
    pub public_key: Option<String>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Queryable, Selectable, Identifiable)]
#[diesel(table_name = oauth_flows)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct OauthFlow {
    pub id: String,
    pub app_id: String,
    /// CSRF state wowauth sends to the upstream provider.
    pub state: String,
    pub pkce_verifier: Vec<u8>,
    /// Where to send the caller once the flow completes.
    pub redirect_after: String,
    pub external_account_hint: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    /// CSRF state the caller sent wowauth, echoed back on completion.
    pub caller_state: String,
    /// The caller's own PKCE challenge, verified at `/oauth/token`.
    pub caller_code_challenge: String,
    pub issued_code: Option<String>,
    pub token_id: Option<String>,
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
    pub caller_state: String,
    pub caller_code_challenge: String,
}

/// Marks a flow as completed on the upstream side: it now redeems to a
/// specific user record via a single-use code, rather than the caller
/// hitting a still-pending flow.
#[derive(Debug, AsChangeset)]
#[diesel(table_name = oauth_flows)]
pub struct OauthFlowIssued {
    pub issued_code: Option<String>,
    pub token_id: Option<String>,
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
    pub label: Option<String>,
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
    pub label: Option<String>,
}

/// Fields updated after a successful token refresh.
#[derive(Debug, AsChangeset)]
#[diesel(table_name = tokens)]
pub struct TokenRefresh {
    pub access_token: Vec<u8>,
    pub refresh_token: Option<Vec<u8>>,
    pub expires_at: Option<NaiveDateTime>,
    pub updated_at: NaiveDateTime,
}
