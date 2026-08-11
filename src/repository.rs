use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use uuid::Uuid;

use crate::crypto::Cipher;
use crate::models::{App, AppChanges, NewApp, Token, TokenRefresh};
use crate::schema::{apps, tokens};

pub struct CreateApp {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub allowed_redirect_uris: String,
    pub scopes: String,
    pub token_auth_method: String,
    pub extra_auth_params: String,
    pub extra_headers: String,
    /// Provided by the caller through the API. Tokens wowauth returns for
    /// this app are encrypted to this key.
    pub public_key: String,
}

/// Registers a new app. `client_secret` is encrypted at rest with the
/// server's master key before it's written; `public_key` isn't, since it's
/// public by design.
pub fn create_app(
    conn: &mut SqliteConnection,
    cipher: &Cipher,
    new: CreateApp,
) -> QueryResult<App> {
    let record = NewApp {
        id: Uuid::new_v4().to_string(),
        name: new.name,
        client_id: new.client_id,
        client_secret: cipher.encrypt(new.client_secret.as_bytes()),
        auth_url: new.auth_url,
        token_url: new.token_url,
        redirect_url: new.redirect_url,
        allowed_redirect_uris: new.allowed_redirect_uris,
        scopes: new.scopes,
        token_auth_method: new.token_auth_method,
        extra_auth_params: new.extra_auth_params,
        extra_headers: new.extra_headers,
        public_key: new.public_key,
    };

    diesel::insert_into(apps::table)
        .values(&record)
        .returning(App::as_returning())
        .get_result(conn)
}

pub fn get_app(conn: &mut SqliteConnection, app_id: &str) -> QueryResult<Option<App>> {
    apps::table
        .find(app_id)
        .select(App::as_select())
        .first(conn)
        .optional()
}

/// Applies `changes` to an app. If `changes.public_key` differs from the
/// app's current key, every user under this app is deleted first — an
/// intentional security measure: rotating the key invalidates every grant
/// encrypted under the old one. Returns `Ok(None)` if the app doesn't exist.
pub fn update_app(
    conn: &mut SqliteConnection,
    app_id: &str,
    mut changes: AppChanges,
) -> QueryResult<Option<App>> {
    changes.updated_at = Some(chrono::Utc::now().naive_utc());

    conn.transaction(|conn| {
        let Some(current) = get_app(conn, app_id)? else {
            return Ok(None);
        };

        let rotating_key = changes
            .public_key
            .as_deref()
            .is_some_and(|new_key| new_key != current.public_key);

        if rotating_key {
            diesel::delete(tokens::table.filter(tokens::app_id.eq(app_id))).execute(conn)?;
        }

        diesel::update(apps::table.find(app_id))
            .set(&changes)
            .execute(conn)?;

        get_app(conn, app_id)
    })
}

pub fn list_tokens_for_app(conn: &mut SqliteConnection, app_id: &str) -> QueryResult<Vec<Token>> {
    tokens::table
        .filter(tokens::app_id.eq(app_id))
        .select(Token::as_select())
        .load(conn)
}

pub fn get_token(
    conn: &mut SqliteConnection,
    app_id: &str,
    user_id: &str,
) -> QueryResult<Option<Token>> {
    tokens::table
        .filter(tokens::app_id.eq(app_id))
        .filter(tokens::id.eq(user_id))
        .select(Token::as_select())
        .first(conn)
        .optional()
}

/// Returns whether a row was actually deleted.
pub fn delete_token(conn: &mut SqliteConnection, app_id: &str, user_id: &str) -> QueryResult<bool> {
    let deleted = diesel::delete(
        tokens::table
            .filter(tokens::app_id.eq(app_id))
            .filter(tokens::id.eq(user_id)),
    )
    .execute(conn)?;
    Ok(deleted > 0)
}

pub fn save_refreshed_token(
    conn: &mut SqliteConnection,
    token_id: &str,
    access_token: Vec<u8>,
    refresh_token: Option<Vec<u8>>,
    expires_at: Option<NaiveDateTime>,
) -> QueryResult<Token> {
    let changes = TokenRefresh {
        access_token,
        refresh_token,
        expires_at,
        updated_at: chrono::Utc::now().naive_utc(),
    };

    diesel::update(tokens::table.find(token_id))
        .set(&changes)
        .returning(Token::as_returning())
        .get_result(conn)
}
