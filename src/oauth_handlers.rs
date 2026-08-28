use crate::AppState;
use crate::handlers::internal_error;
use crate::{oauth_client, pkce, repository};
use chrono::Utc;
use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::{Form, Json, PlainText};
use poem_openapi::{ApiResponse, Object, OpenApi};
use uuid::Uuid;

#[derive(Object)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    /// wowauth's `/oauth/*` facade treats callers as public clients (PKCE
    /// only, no client secret), the standard model for apps that can't keep
    /// a secret confidential.
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(ApiResponse)]
enum DiscoveryResponse {
    #[oai(status = 200)]
    Ok(Json<Discovery>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object)]
struct OAuthError {
    error: String,
    error_description: Option<String>,
}

fn oauth_error(error: &str, description: &str) -> Json<OAuthError> {
    Json(OAuthError {
        error: error.to_string(),
        error_description: Some(description.to_string()),
    })
}

#[derive(ApiResponse)]
enum AuthorizeResponse {
    /// Redirects the caller's browser on to the app's upstream provider.
    #[oai(status = 302)]
    Redirect(#[oai(header = "Location")] String),
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum CallbackResponse {
    /// Redirects back to the caller's own `redirect_uri`, with either
    /// `code`/`state` on success or `error`/`error_description`/`state` on
    /// failure — standard RFC 6749 §4.1.2 shape either way.
    #[oai(status = 302)]
    Redirect(#[oai(header = "Location")] String),
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object, serde::Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
}

#[derive(Object)]
struct TokenResponseBody {
    access_token: String,
    token_type: String,
    expires_in: Option<i64>,
    scope: Option<String>,
}

#[derive(ApiResponse)]
enum TokenEndpointResponse {
    #[oai(status = 200)]
    Ok(Json<TokenResponseBody>),
    #[oai(status = 400)]
    BadRequest(Json<OAuthError>),
}

#[derive(Object, serde::Deserialize)]
struct RevokeRequest {
    token: String,
    #[serde(default)]
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

#[derive(ApiResponse)]
enum RevokeResponse {
    /// Per RFC 7009, always 200 — whether or not `token` was recognized —
    /// so this endpoint can't be used to probe for valid tokens.
    #[oai(status = 200)]
    Ok,
}

fn redirect_with(base: &str, pairs: &[(&str, &str)]) -> Result<String, poem::Error> {
    let mut url = url::Url::parse(base).map_err(|err| {
        tracing::error!(redirect_uri = %base, error = %err, "flow's redirect_uri is not a valid url");
        poem::Error::from_string(
            "app has an invalid redirect_uri on file",
            poem::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    })?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

pub struct OauthApi;

#[OpenApi]
impl OauthApi {
    /// OIDC discovery
    #[oai(path = "/:app_id/.well-known/openid-configuration", method = "get")]
    async fn discovery(
        &self,
        app_id: Path<String>,
        Data(state): Data<&AppState>,
    ) -> poem::Result<DiscoveryResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        if repository::get_app(&mut conn, &app_id.0)
            .map_err(poem::error::InternalServerError)?
            .is_none()
        {
            return Ok(DiscoveryResponse::NotFound);
        }

        let base = &state.public_base_url;
        let app_id = &app_id.0;
        Ok(DiscoveryResponse::Ok(Json(Discovery {
            issuer: format!("{base}/{app_id}"),
            authorization_endpoint: format!("{base}/{app_id}/oauth/auth"),
            token_endpoint: format!("{base}/{app_id}/oauth/token"),
            revocation_endpoint: format!("{base}/{app_id}/oauth/revoke"),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            token_endpoint_auth_methods_supported: vec!["none".to_string()],
        })))
    }

    /// Start authorization code flow
    #[oai(path = "/:app_id/oauth/auth", method = "get")]
    #[allow(clippy::too_many_arguments)]
    async fn authorize(
        &self,
        Path(app_id): Path<String>,
        Query(redirect_uri): Query<String>,
        Query(state): Query<String>,
        Query(code_challenge): Query<String>,
        Query(code_challenge_method): Query<String>,
        /// Identifies which end-user account this authorization is for
        /// (e.g. their email), so that re-authorizing the same account
        /// later reuses the same user id instead of minting a new one.
        /// Optional — if omitted, every authorization is treated as a new,
        /// distinct user.
        Query(account_hint): Query<Option<String>>,
        Query(scope): Query<Option<String>>,
        Data(app_state): Data<&AppState>,
    ) -> poem::Result<AuthorizeResponse> {
        let mut conn = app_state
            .pool
            .get()
            .map_err(poem::error::InternalServerError)?;
        let Some(app) =
            repository::get_app(&mut conn, &app_id).map_err(poem::error::InternalServerError)?
        else {
            return Ok(AuthorizeResponse::NotFound);
        };

        if code_challenge_method != "S256" {
            return Ok(AuthorizeResponse::BadRequest(PlainText(
                "code_challenge_method must be S256".to_string(),
            )));
        }

        let allowed: Vec<String> =
            serde_json::from_str(&app.allowed_redirect_uris).unwrap_or_else(|err| {
                tracing::warn!(
                    app_id = %app_id,
                    error = %err,
                    "app has malformed allowed_redirect_uris in db, rejecting all redirect_uris"
                );
                Vec::new()
            });
        if !allowed.contains(&redirect_uri) {
            return Ok(AuthorizeResponse::BadRequest(PlainText(
                "redirect_uri is not allow-listed for this app".to_string(),
            )));
        }

        let scopes = scope.unwrap_or_else(|| app.scopes.clone());
        let upstream =
            oauth_client::build_authorization_request(&app, &scopes).map_err(internal_error)?;

        repository::create_oauth_flow(
            &mut conn,
            repository::CreateOauthFlow {
                app_id,
                state: upstream.state.secret().clone(),
                pkce_verifier: app_state
                    .cipher
                    .encrypt(upstream.pkce_verifier.secret().as_bytes()),
                redirect_after: redirect_uri,
                external_account_hint: account_hint,
                expires_at: Utc::now().naive_utc() + chrono::Duration::minutes(10),
                caller_state: state,
                caller_code_challenge: code_challenge,
            },
        )
        .map_err(poem::error::InternalServerError)?;

        Ok(AuthorizeResponse::Redirect(upstream.url))
    }

    /// Callback endpoint
    #[oai(path = "/:app_id/oauth/callback", method = "get")]
    async fn callback(
        &self,
        app_id: Path<String>,
        code: Query<Option<String>>,
        state: Query<String>,
        error: Query<Option<String>>,
        error_description: Query<Option<String>>,
        Data(app_state): Data<&AppState>,
    ) -> poem::Result<CallbackResponse> {
        let mut conn = app_state
            .pool
            .get()
            .map_err(poem::error::InternalServerError)?;
        let Some(flow) = repository::get_oauth_flow_by_state(&mut conn, &state.0)
            .map_err(poem::error::InternalServerError)?
        else {
            return Ok(CallbackResponse::BadRequest(PlainText(
                "unknown or already-used state".to_string(),
            )));
        };

        if flow.app_id != app_id.0 || flow.expires_at <= Utc::now().naive_utc() {
            repository::delete_oauth_flow(&mut conn, &flow.id)
                .map_err(poem::error::InternalServerError)?;
            return Ok(CallbackResponse::BadRequest(PlainText(
                "flow expired or does not match app".to_string(),
            )));
        }

        if let Some(error) = error.0 {
            repository::delete_oauth_flow(&mut conn, &flow.id)
                .map_err(poem::error::InternalServerError)?;
            let description = error_description.0.unwrap_or_default();
            let location = redirect_with(
                &flow.redirect_after,
                &[
                    ("error", &error),
                    ("error_description", &description),
                    ("state", &flow.caller_state),
                ],
            )?;
            return Ok(CallbackResponse::Redirect(location));
        }

        let Some(code) = code.0 else {
            repository::delete_oauth_flow(&mut conn, &flow.id)
                .map_err(poem::error::InternalServerError)?;
            return Ok(CallbackResponse::BadRequest(PlainText(
                "missing code".to_string(),
            )));
        };
        let Some(app) = repository::get_app(&mut conn, &flow.app_id)
            .map_err(poem::error::InternalServerError)?
        else {
            repository::delete_oauth_flow(&mut conn, &flow.id)
                .map_err(poem::error::InternalServerError)?;
            return Ok(CallbackResponse::NotFound);
        };

        let pkce_verifier_plaintext = app_state.cipher.decrypt(&flow.pkce_verifier).map_err(|e| {
            tracing::error!(app_id = %flow.app_id, flow_id = %flow.id, "unable to decrypt stored pkce verifier");
            internal_error(e)
        })?;
        let pkce_verifier = oauth2::PkceCodeVerifier::new(
            String::from_utf8(pkce_verifier_plaintext).map_err(|e| {
                tracing::error!(app_id = %flow.app_id, flow_id = %flow.id, "decrypted pkce verifier was not utf8");
                poem::error::InternalServerError(e)
            })?,
        );

        let upstream = match oauth_client::exchange_code(
            &app,
            &app_state.cipher,
            &code,
            pkce_verifier,
        )
        .await
        {
            Ok(token) => token,
            Err(err) => {
                tracing::error!(app_id = %flow.app_id, error = %err, "upstream code exchange failed");
                repository::delete_oauth_flow(&mut conn, &flow.id)
                    .map_err(poem::error::InternalServerError)?;
                let location = redirect_with(
                    &flow.redirect_after,
                    &[("error", "server_error"), ("state", &flow.caller_state)],
                )?;
                return Ok(CallbackResponse::Redirect(location));
            }
        };

        let external_account = flow
            .external_account_hint
            .clone()
            .unwrap_or(flow.id.clone());
        let expires_at = upstream
            .expires_in
            .and_then(|d| chrono::Duration::from_std(d).ok())
            .map(|d| Utc::now().naive_utc() + d);
        let scopes = upstream.scopes.map(|s| s.join(" ")).unwrap_or(app.scopes);

        let token = repository::upsert_token(
            &mut conn,
            &flow.app_id,
            &external_account,
            app_state.cipher.encrypt(upstream.access_token.as_bytes()),
            upstream
                .refresh_token
                .map(|t| app_state.cipher.encrypt(t.as_bytes())),
            scopes,
            expires_at,
            flow.external_account_hint,
        )
        .map_err(poem::error::InternalServerError)?;

        // The flow row survives, now representing a fresh, short-lived,
        // single-use code redeemable at /oauth/token instead of a pending
        // authorization attempt.
        let issued_code = Uuid::new_v4().to_string();
        repository::mark_flow_issued(&mut conn, &flow.id, &issued_code, &token.id)
            .map_err(poem::error::InternalServerError)?;

        let location = redirect_with(
            &flow.redirect_after,
            &[("code", &issued_code), ("state", &flow.caller_state)],
        )?;
        Ok(CallbackResponse::Redirect(location))
    }

    /// Exchange auth code for token
    #[oai(path = "/:app_id/oauth/token", method = "post")]
    async fn token(
        &self,
        app_id: Path<String>,
        Data(state): Data<&AppState>,
        req: Form<TokenRequest>,
    ) -> poem::Result<TokenEndpointResponse> {
        if req.0.grant_type != "authorization_code" {
            return Ok(TokenEndpointResponse::BadRequest(oauth_error(
                "unsupported_grant_type",
                "only authorization_code is supported",
            )));
        }
        let (Some(code), Some(redirect_uri), Some(code_verifier)) =
            (&req.0.code, &req.0.redirect_uri, &req.0.code_verifier)
        else {
            return Ok(TokenEndpointResponse::BadRequest(oauth_error(
                "invalid_request",
                "code, redirect_uri, and code_verifier are all required",
            )));
        };

        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let Some(flow) = repository::get_oauth_flow_by_code(&mut conn, code)
            .map_err(poem::error::InternalServerError)?
        else {
            return Ok(TokenEndpointResponse::BadRequest(oauth_error(
                "invalid_grant",
                "code is unknown, expired, or already used",
            )));
        };
        // Single-use regardless of outcome below.
        repository::delete_oauth_flow(&mut conn, &flow.id)
            .map_err(poem::error::InternalServerError)?;

        let valid = flow.app_id == app_id.0
            && flow.expires_at > Utc::now().naive_utc()
            && &flow.redirect_after == redirect_uri
            && pkce::verify_s256(code_verifier, &flow.caller_code_challenge);
        if !valid {
            return Ok(TokenEndpointResponse::BadRequest(oauth_error(
                "invalid_grant",
                "code is unknown, expired, or already used",
            )));
        }

        let Some(token_id) = flow.token_id else {
            return Ok(TokenEndpointResponse::BadRequest(oauth_error(
                "invalid_grant",
                "code is unknown, expired, or already used",
            )));
        };
        let Some(token) = repository::get_token(&mut conn, &flow.app_id, &token_id)
            .map_err(poem::error::InternalServerError)?
        else {
            return Ok(TokenEndpointResponse::BadRequest(oauth_error(
                "invalid_grant",
                "the underlying grant no longer exists",
            )));
        };

        let access_token = state
            .cipher
            .decrypt(&token.access_token)
            .map_err(internal_error)?;
        let access_token =
            String::from_utf8(access_token).map_err(poem::error::InternalServerError)?;

        // Deliberately no refresh_token in the response: wowauth keeps that
        // to itself and handles renewal server-side (via the proprietary
        // /apps/.../token endpoint) rather than handing it to whichever
        // downstream client happens to complete this flow.
        Ok(TokenEndpointResponse::Ok(Json(TokenResponseBody {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: token
                .expires_at
                .map(|exp| (exp - Utc::now().naive_utc()).num_seconds()),
            scope: Some(token.scopes),
        })))
    }

    /// Revoke a token (RFC 7009)
    #[oai(path = "/:app_id/oauth/revoke", method = "post")]
    async fn revoke(
        &self,
        app_id: Path<String>,
        Data(state): Data<&AppState>,
        req: Form<RevokeRequest>,
    ) -> poem::Result<RevokeResponse> {
        let mut conn = state.pool.get().map_err(poem::error::InternalServerError)?;
        let tokens = repository::list_tokens_for_app(&mut conn, &app_id.0)
            .map_err(poem::error::InternalServerError)?;

        let presented = req.0.token.as_bytes();
        for candidate in tokens {
            let is_match = match state.cipher.decrypt(&candidate.access_token) {
                Ok(plaintext) => plaintext == presented,
                Err(err) => {
                    tracing::warn!(app_id = %app_id.0, user_id = %candidate.id, error = %err, "unable to decrypt stored access token while checking for revoke match");
                    false
                }
            };
            if is_match {
                repository::delete_token(&mut conn, &app_id.0, &candidate.id)
                    .map_err(poem::error::InternalServerError)?;
                break;
            }
        }

        Ok(RevokeResponse::Ok)
    }
}
