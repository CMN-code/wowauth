use std::collections::HashMap;

use diesel::result::{DatabaseErrorKind, Error as DieselError};
use poem::http::StatusCode;
use poem::web::{Data, Json, Path};
use poem::{Error as PoemError, Result as PoemResult, handler};
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::models::App;
use crate::repository;

#[derive(Deserialize)]
pub struct CreateAppRequest {
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(default = "default_token_auth_method")]
    pub token_auth_method: String,
    #[serde(default)]
    pub extra_auth_params: HashMap<String, String>,
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
    /// Set by the caller; tokens wowauth returns for this app are encrypted
    /// to this key, so only whoever holds the matching private key can read
    /// them.
    pub public_key: String,
}

fn default_token_auth_method() -> String {
    "basic".to_string()
}

/// What we hand back for an app. Deliberately excludes `client_secret` —
/// that's write-only through this API. `public_key` is fine to echo back,
/// since it's public by design.
#[derive(Serialize)]
pub struct AppView {
    pub id: String,
    pub name: String,
    pub client_id: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub scopes: String,
    pub token_auth_method: String,
    pub extra_auth_params: HashMap<String, String>,
    pub extra_headers: HashMap<String, String>,
    pub public_key: String,
}

impl From<App> for AppView {
    fn from(app: App) -> Self {
        Self {
            id: app.id,
            name: app.name,
            client_id: app.client_id,
            auth_url: app.auth_url,
            token_url: app.token_url,
            redirect_url: app.redirect_url,
            scopes: app.scopes,
            token_auth_method: app.token_auth_method,
            extra_auth_params: serde_json::from_str(&app.extra_auth_params).unwrap_or_default(),
            extra_headers: serde_json::from_str(&app.extra_headers).unwrap_or_default(),
            public_key: app.public_key,
        }
    }
}

fn map_db_error(err: DieselError) -> PoemError {
    match err {
        DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) => {
            PoemError::from_string(info.message().to_string(), StatusCode::CONFLICT)
        }
        DieselError::DatabaseError(DatabaseErrorKind::CheckViolation, info) => {
            PoemError::from_string(info.message().to_string(), StatusCode::BAD_REQUEST)
        }
        DieselError::NotFound => PoemError::from_status(StatusCode::NOT_FOUND),
        other => PoemError::from_string(other.to_string(), StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[handler]
pub fn create_app(
    Data(state): Data<&AppState>,
    Json(req): Json<CreateAppRequest>,
) -> PoemResult<Json<AppView>> {
    let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;

    let new = repository::CreateApp {
        name: req.name,
        client_id: req.client_id,
        client_secret: req.client_secret,
        auth_url: req.auth_url,
        token_url: req.token_url,
        redirect_url: req.redirect_url,
        scopes: req.scopes,
        token_auth_method: req.token_auth_method,
        extra_auth_params: serde_json::to_string(&req.extra_auth_params)
            .expect("HashMap<String, String> always serializes"),
        extra_headers: serde_json::to_string(&req.extra_headers)
            .expect("HashMap<String, String> always serializes"),
        public_key: req.public_key,
    };

    let app = repository::create_app(&mut conn, &state.cipher, new).map_err(map_db_error)?;
    Ok(Json(app.into()))
}

#[handler]
pub fn get_app(
    Path(name): Path<String>,
    Data(state): Data<&AppState>,
) -> PoemResult<Json<AppView>> {
    let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;

    let app = repository::get_app_by_name(&mut conn, &name)
        .map_err(map_db_error)?
        .ok_or_else(|| PoemError::from_status(StatusCode::NOT_FOUND))?;

    Ok(Json(app.into()))
}
