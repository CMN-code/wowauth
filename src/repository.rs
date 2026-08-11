use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use uuid::Uuid;

use crate::crypto::Cipher;
use crate::models::{App, NewApp};
use crate::schema::apps;

pub struct CreateApp {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
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

pub fn get_app_by_name(conn: &mut SqliteConnection, name: &str) -> QueryResult<Option<App>> {
    apps::table
        .filter(apps::name.eq(name))
        .select(App::as_select())
        .first(conn)
        .optional()
}
