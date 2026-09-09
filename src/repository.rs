use crate::crypto::Cipher;
use crate::models::{
    App, AppChanges, NewApp, NewOauthFlow, NewToken, OauthFlow, OauthFlowIssued, Token,
    TokenRefresh,
};
use crate::schema::{apps, oauth_flows, tokens};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use uuid::Uuid;

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

pub fn list_apps(conn: &mut SqliteConnection) -> QueryResult<Vec<App>> {
    apps::table
        .select(App::as_select())
        .order(apps::name.asc())
        .load(conn)
}

pub fn get_app(conn: &mut SqliteConnection, app_id: &str) -> QueryResult<Option<App>> {
    apps::table
        .find(app_id)
        .select(App::as_select())
        .first(conn)
        .optional()
}

/// Looks up an app by its (unique) human-readable name, e.g. so a setup
/// script can resume against a connection it registered in an earlier,
/// incomplete run instead of registering a duplicate.
pub fn get_app_by_name(conn: &mut SqliteConnection, name: &str) -> QueryResult<Option<App>> {
    apps::table
        .filter(apps::name.eq(name))
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

pub struct CreateOauthFlow {
    pub app_id: String,
    /// CSRF state wowauth will send to the upstream provider.
    pub state: String,
    pub pkce_verifier: Vec<u8>,
    pub redirect_after: String,
    pub external_account_hint: Option<String>,
    pub expires_at: NaiveDateTime,
    pub caller_state: String,
    pub caller_code_challenge: String,
}

pub fn create_oauth_flow(
    conn: &mut SqliteConnection,
    new: CreateOauthFlow,
) -> QueryResult<OauthFlow> {
    let record = NewOauthFlow {
        id: Uuid::new_v4().to_string(),
        app_id: new.app_id,
        state: new.state,
        pkce_verifier: new.pkce_verifier,
        redirect_after: new.redirect_after,
        external_account_hint: new.external_account_hint,
        expires_at: new.expires_at,
        caller_state: new.caller_state,
        caller_code_challenge: new.caller_code_challenge,
    };

    diesel::insert_into(oauth_flows::table)
        .values(&record)
        .returning(OauthFlow::as_returning())
        .get_result(conn)
}

/// Looks up a live (not necessarily unexpired — callers should check
/// `expires_at` themselves) flow by the upstream CSRF state.
pub fn get_oauth_flow_by_state(
    conn: &mut SqliteConnection,
    state: &str,
) -> QueryResult<Option<OauthFlow>> {
    oauth_flows::table
        .filter(oauth_flows::state.eq(state))
        .select(OauthFlow::as_select())
        .first(conn)
        .optional()
}

pub fn get_oauth_flow_by_code(
    conn: &mut SqliteConnection,
    code: &str,
) -> QueryResult<Option<OauthFlow>> {
    oauth_flows::table
        .filter(oauth_flows::issued_code.eq(code))
        .select(OauthFlow::as_select())
        .first(conn)
        .optional()
}

pub fn delete_oauth_flow(conn: &mut SqliteConnection, flow_id: &str) -> QueryResult<()> {
    diesel::delete(oauth_flows::table.find(flow_id)).execute(conn)?;
    Ok(())
}

/// Marks a flow as redeemable: the upstream exchange succeeded, so it now
/// hands out a single-use code for the resulting user record instead of
/// still being a pending authorization attempt. Codes are short-lived.
pub fn mark_flow_issued(
    conn: &mut SqliteConnection,
    flow_id: &str,
    issued_code: &str,
    token_id: &str,
) -> QueryResult<()> {
    let changes = OauthFlowIssued {
        issued_code: Some(issued_code.to_string()),
        token_id: Some(token_id.to_string()),
        // Long enough for a human to manually copy the code out of the
        // browser's address bar into a terminal; still single-use and
        // still bound to the original PKCE verifier, so this isn't a
        // meaningful security relaxation over a shorter window.
        expires_at: chrono::Utc::now().naive_utc() + chrono::Duration::minutes(5),
    };
    diesel::update(oauth_flows::table.find(flow_id))
        .set(&changes)
        .execute(conn)?;
    Ok(())
}

/// Creates or updates the grant for `(app_id, external_account)`, keeping
/// the same `id` (the "user id") across re-authorizations rather than
/// minting a new one.
#[allow(clippy::too_many_arguments)]
pub fn upsert_token(
    conn: &mut SqliteConnection,
    app_id: &str,
    external_account: &str,
    access_token: Vec<u8>,
    refresh_token: Option<Vec<u8>>,
    scopes: String,
    expires_at: Option<NaiveDateTime>,
    label: Option<String>,
) -> QueryResult<Token> {
    #[derive(AsChangeset)]
    #[diesel(table_name = tokens)]
    struct Update {
        access_token: Vec<u8>,
        refresh_token: Option<Vec<u8>>,
        scopes: String,
        expires_at: Option<NaiveDateTime>,
        label: Option<String>,
        updated_at: NaiveDateTime,
    }

    let new_token = NewToken {
        id: Uuid::new_v4().to_string(),
        app_id: app_id.to_string(),
        external_account: external_account.to_string(),
        access_token: access_token.clone(),
        refresh_token: refresh_token.clone(),
        scopes: scopes.clone(),
        expires_at,
        label: label.clone(),
    };
    let update = Update {
        access_token,
        refresh_token,
        scopes,
        expires_at,
        label,
        updated_at: chrono::Utc::now().naive_utc(),
    };

    diesel::insert_into(tokens::table)
        .values(&new_token)
        .on_conflict((tokens::app_id, tokens::external_account))
        .do_update()
        .set(&update)
        .returning(Token::as_returning())
        .get_result(conn)
}
