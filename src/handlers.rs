use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::{Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};

use crate::AppState;
use crate::auth::AdminAuth;
use crate::models::{App, AppChanges, Token};
use crate::{oauth_client, repository, token_seal};

fn default_token_auth_method() -> String {
    "basic".to_string()
}

/// `anyhow::Error` doesn't implement `std::error::Error` itself, so it can't
/// go through `poem::error::InternalServerError` directly.
pub(crate) fn internal_error(err: anyhow::Error) -> poem::Error {
    poem::Error::from_string(
        err.to_string(),
        poem::http::StatusCode::INTERNAL_SERVER_ERROR,
    )
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
}

/// A token is still usable from the caller's point of view if it isn't
/// expired, or if it is but wowauth can transparently refresh it. Only
/// "expired with no refresh token" means the user actually has to reauth.
fn is_active(token: &Token) -> bool {
    match token.expires_at {
        Some(expires_at) => expires_at > Utc::now().naive_utc() || token.refresh_token.is_some(),
        None => true,
    }
}

#[derive(Object)]
struct CreateAppRequest {
    name: String,
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
    /// The redirect URI wowauth registers with the provider.
    redirect_url: String,
    /// Allow-list of redirect URIs the `/oauth/*` facade accepts back from
    /// calling clients.
    #[oai(default)]
    allowed_redirect_uris: Vec<String>,
    #[oai(default)]
    scopes: String,
    #[oai(default = "default_token_auth_method")]
    token_auth_method: String,
    #[oai(default)]
    extra_auth_params: HashMap<String, String>,
    #[oai(default)]
    extra_headers: HashMap<String, String>,
    /// X25519 public key, base64-encoded. Tokens returned for this app are
    /// encrypted to this key with HPKE (RFC 9180).
    public_key: String,
}

/// Partial update; every field is optional. Changing `public_key` deletes
/// every user under this app first — rotating the key invalidates every
/// grant encrypted under the old one.
#[derive(Object)]
struct UpdateAppRequest {
    name: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    redirect_url: Option<String>,
    allowed_redirect_uris: Option<Vec<String>>,
    scopes: Option<String>,
    token_auth_method: Option<String>,
    extra_auth_params: Option<HashMap<String, String>>,
    extra_headers: Option<HashMap<String, String>>,
    public_key: Option<String>,
}

/// Never includes `client_secret` — that's write-only through this API.
/// `public_key` is fine to echo back, since it's public by design.
#[derive(Object)]
struct AppView {
    id: String,
    name: String,
    client_id: String,
    auth_url: String,
    token_url: String,
    redirect_url: String,
    allowed_redirect_uris: Vec<String>,
    scopes: String,
    token_auth_method: String,
    extra_auth_params: HashMap<String, String>,
    extra_headers: HashMap<String, String>,
    public_key: String,
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
            allowed_redirect_uris: serde_json::from_str(&app.allowed_redirect_uris)
                .unwrap_or_default(),
            scopes: app.scopes,
            token_auth_method: app.token_auth_method,
            extra_auth_params: serde_json::from_str(&app.extra_auth_params).unwrap_or_default(),
            extra_headers: serde_json::from_str(&app.extra_headers).unwrap_or_default(),
            public_key: app.public_key,
        }
    }
}

#[derive(Object)]
struct AppStatus {
    app_id: String,
    name: String,
    user_count: i64,
    active_user_count: i64,
    needs_reauth_count: i64,
}

#[derive(Object)]
struct UserView {
    user_id: String,
    label: Option<String>,
    scopes: String,
}

impl From<Token> for UserView {
    fn from(token: Token) -> Self {
        Self {
            user_id: token.id,
            label: token.label,
            scopes: token.scopes,
        }
    }
}

#[derive(Object)]
struct UserStatus {
    user_id: String,
    status: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Object)]
struct TokenInfo {
    /// `base64(HPKE-encapsulated key || ciphertext)`; decrypt with your
    /// private key.
    token: String,
    expires_at: Option<DateTime<Utc>>,
}

// poem-openapi's `Payload` trait isn't implemented for `Box<Json<T>>`, so the
// usual "box the large variant" fix isn't available for response enums.
#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum CreateAppResponse {
    #[oai(status = 200)]
    Ok(Json<AppView>),
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    #[oai(status = 409)]
    Conflict(PlainText<String>),
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum UpdateAppResponse {
    #[oai(status = 200)]
    Ok(Json<AppView>),
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(PlainText<String>),
}

#[allow(clippy::large_enum_variant)]
#[derive(ApiResponse)]
enum GetAppResponse {
    #[oai(status = 200)]
    Ok(Json<AppView>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum StatusResponse {
    #[oai(status = 200)]
    Ok(Json<AppStatus>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserView>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UserStatusResponse {
    #[oai(status = 200)]
    Ok(Json<UserStatus>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UserTokenResponse {
    #[oai(status = 200)]
    Ok(Json<TokenInfo>),
    #[oai(status = 404)]
    NotFound,
    /// The access token is expired and either there's no refresh token or
    /// the upstream provider rejected it — the user needs to reauth.
    #[oai(status = 409)]
    NeedsReauth,
}

pub struct Api;

#[OpenApi]
impl Api {
    /// Register a new app
    #[oai(path = "/apps", method = "post")]
    async fn create_app(
        &self,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
        req: Json<CreateAppRequest>,
    ) -> poem::Result<CreateAppResponse> {
        if let Err(err) = token_seal::validate_public_key(&req.0.public_key) {
            return Ok(CreateAppResponse::BadRequest(PlainText(err.to_string())));
        }

        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let new = repository::CreateApp {
            name: req.0.name,
            client_id: req.0.client_id,
            client_secret: req.0.client_secret,
            auth_url: req.0.auth_url,
            token_url: req.0.token_url,
            redirect_url: req.0.redirect_url,
            allowed_redirect_uris: serde_json::to_string(&req.0.allowed_redirect_uris)
                .expect("Vec<String> always serializes"),
            scopes: req.0.scopes,
            token_auth_method: req.0.token_auth_method,
            extra_auth_params: serde_json::to_string(&req.0.extra_auth_params)
                .expect("HashMap<String, String> always serializes"),
            extra_headers: serde_json::to_string(&req.0.extra_headers)
                .expect("HashMap<String, String> always serializes"),
            public_key: req.0.public_key,
        };

        match repository::create_app(&mut conn, &state.cipher, new) {
            Ok(app) => Ok(CreateAppResponse::Ok(Json(app.into()))),
            Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info)) => Ok(
                CreateAppResponse::Conflict(PlainText(info.message().to_string())),
            ),
            Err(DieselError::DatabaseError(DatabaseErrorKind::CheckViolation, info)) => Ok(
                CreateAppResponse::BadRequest(PlainText(info.message().to_string())),
            ),
            Err(err) => Err(poem::error::InternalServerError(err)),
        }
    }

    /// Overwrite app properties
    #[oai(path = "/apps/:app_id", method = "put", method = "patch")]
    async fn update_app(
        &self,
        app_id: Path<String>,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
        req: Json<UpdateAppRequest>,
    ) -> poem::Result<UpdateAppResponse> {
        if let Some(public_key) = &req.0.public_key
            && let Err(err) = token_seal::validate_public_key(public_key)
        {
            return Ok(UpdateAppResponse::BadRequest(PlainText(err.to_string())));
        }

        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let changes = AppChanges {
            name: req.0.name,
            client_id: req.0.client_id,
            client_secret: req
                .0
                .client_secret
                .map(|s| state.cipher.encrypt(s.as_bytes())),
            auth_url: req.0.auth_url,
            token_url: req.0.token_url,
            redirect_url: req.0.redirect_url,
            allowed_redirect_uris: req
                .0
                .allowed_redirect_uris
                .map(|v| serde_json::to_string(&v).expect("Vec<String> always serializes")),
            scopes: req.0.scopes,
            token_auth_method: req.0.token_auth_method,
            extra_auth_params: req.0.extra_auth_params.map(|m| {
                serde_json::to_string(&m).expect("HashMap<String, String> always serializes")
            }),
            extra_headers: req.0.extra_headers.map(|m| {
                serde_json::to_string(&m).expect("HashMap<String, String> always serializes")
            }),
            public_key: req.0.public_key,
            updated_at: None,
        };

        match repository::update_app(&mut conn, &app_id.0, changes) {
            Ok(Some(app)) => Ok(UpdateAppResponse::Ok(Json(app.into()))),
            Ok(None) => Ok(UpdateAppResponse::NotFound),
            Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info)) => Ok(
                UpdateAppResponse::Conflict(PlainText(info.message().to_string())),
            ),
            Err(DieselError::DatabaseError(DatabaseErrorKind::CheckViolation, info)) => Ok(
                UpdateAppResponse::BadRequest(PlainText(info.message().to_string())),
            ),
            Err(err) => Err(poem::error::InternalServerError(err)),
        }
    }

    /// Find app by name
    #[oai(path = "/apps/by-name/:name", method = "get")]
    async fn get_app_by_name(
        &self,
        name: Path<String>,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
    ) -> poem::Result<GetAppResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        match repository::get_app_by_name(&mut conn, &name.0)
            .map_err(poem::error::InternalServerError)?
        {
            Some(app) => Ok(GetAppResponse::Ok(Json(app.into()))),
            None => Ok(GetAppResponse::NotFound),
        }
    }

    /// Get status of app
    #[oai(path = "/apps/:app_id/status", method = "get")]
    async fn app_status(
        &self,
        app_id: Path<String>,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
    ) -> poem::Result<StatusResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let Some(app) =
            repository::get_app(&mut conn, &app_id.0).map_err(poem::error::InternalServerError)?
        else {
            return Ok(StatusResponse::NotFound);
        };
        let tokens = repository::list_tokens_for_app(&mut conn, &app_id.0)
            .map_err(poem::error::InternalServerError)?;
        let active_user_count = tokens.iter().filter(|t| is_active(t)).count() as i64;
        let user_count = tokens.len() as i64;

        Ok(StatusResponse::Ok(Json(AppStatus {
            app_id: app.id,
            name: app.name,
            user_count,
            active_user_count,
            needs_reauth_count: user_count - active_user_count,
        })))
    }

    /// List users
    #[oai(path = "/apps/:app_id/users", method = "get")]
    async fn list_users(
        &self,
        app_id: Path<String>,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
    ) -> poem::Result<UsersResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        if repository::get_app(&mut conn, &app_id.0)
            .map_err(poem::error::InternalServerError)?
            .is_none()
        {
            return Ok(UsersResponse::NotFound);
        }

        let tokens = repository::list_tokens_for_app(&mut conn, &app_id.0)
            .map_err(poem::error::InternalServerError)?;
        Ok(UsersResponse::Ok(Json(
            tokens.into_iter().map(UserView::from).collect(),
        )))
    }

    /// Revoke user
    #[oai(path = "/apps/:app_id/users/:user_id", method = "delete")]
    async fn delete_user(
        &self,
        app_id: Path<String>,
        user_id: Path<String>,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
    ) -> poem::Result<DeleteUserResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let deleted = repository::delete_token(&mut conn, &app_id.0, &user_id.0)
            .map_err(poem::error::InternalServerError)?;
        Ok(if deleted {
            DeleteUserResponse::Ok
        } else {
            DeleteUserResponse::NotFound
        })
    }

    /// Get user status
    #[oai(path = "/apps/:app_id/users/:user_id/status", method = "get")]
    async fn user_status(
        &self,
        app_id: Path<String>,
        user_id: Path<String>,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
    ) -> poem::Result<UserStatusResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let Some(token) = repository::get_token(&mut conn, &app_id.0, &user_id.0)
            .map_err(poem::error::InternalServerError)?
        else {
            return Ok(UserStatusResponse::NotFound);
        };

        let status = if is_active(&token) {
            "active"
        } else {
            "expired"
        };
        Ok(UserStatusResponse::Ok(Json(UserStatus {
            user_id: token.id,
            status: status.to_string(),
            expires_at: token.expires_at.map(to_utc),
        })))
    }

    /// Get encrypted token
    #[oai(path = "/apps/:app_id/users/:user_id/token", method = "get")]
    async fn user_token(
        &self,
        app_id: Path<String>,
        user_id: Path<String>,
        _auth: AdminAuth,
        Data(state): Data<&AppState>,
    ) -> poem::Result<UserTokenResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let Some(app) =
            repository::get_app(&mut conn, &app_id.0).map_err(poem::error::InternalServerError)?
        else {
            return Ok(UserTokenResponse::NotFound);
        };
        let Some(token) = repository::get_token(&mut conn, &app_id.0, &user_id.0)
            .map_err(poem::error::InternalServerError)?
        else {
            return Ok(UserTokenResponse::NotFound);
        };

        let now = Utc::now().naive_utc();
        let is_expired = token.expires_at.is_some_and(|expires_at| expires_at <= now);

        let (access_token_plaintext, expires_at) = if is_expired {
            let Some(refresh_token_enc) = &token.refresh_token else {
                return Ok(UserTokenResponse::NeedsReauth);
            };
            let refresh_token_plaintext = state
                .cipher
                .decrypt(refresh_token_enc)
                .map_err(internal_error)?;
            let refresh_token = String::from_utf8(refresh_token_plaintext)
                .map_err(poem::error::InternalServerError)?;

            let Ok(refreshed) = oauth_client::refresh(&app, &state.cipher, &refresh_token).await
            else {
                return Ok(UserTokenResponse::NeedsReauth);
            };

            let new_expires_at = refreshed
                .expires_in
                .and_then(|d| chrono::Duration::from_std(d).ok())
                .map(|d| now + d);
            // Providers don't always rotate the refresh token; keep the old
            // one if a new one wasn't issued.
            let new_refresh_token_enc = refreshed
                .refresh_token
                .as_ref()
                .map(|t| state.cipher.encrypt(t.as_bytes()))
                .or_else(|| token.refresh_token.clone());

            let updated = repository::save_refreshed_token(
                &mut conn,
                &token.id,
                state.cipher.encrypt(refreshed.access_token.as_bytes()),
                new_refresh_token_enc,
                new_expires_at,
            )
            .map_err(poem::error::InternalServerError)?;

            (refreshed.access_token.into_bytes(), updated.expires_at)
        } else {
            let plaintext = state
                .cipher
                .decrypt(&token.access_token)
                .map_err(internal_error)?;
            (plaintext, token.expires_at)
        };

        let aad = format!("{}:{}", app_id.0, user_id.0);
        let sealed = token_seal::seal(&app.public_key, &access_token_plaintext, aad.as_bytes())
            .map_err(internal_error)?;

        Ok(UserTokenResponse::Ok(Json(TokenInfo {
            token: sealed,
            expires_at: expires_at.map(to_utc),
        })))
    }
}
