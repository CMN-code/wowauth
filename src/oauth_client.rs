use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    TokenResponse, TokenUrl,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::crypto::Cipher;
use crate::models::App;

type TokenClient =
    BasicClient<EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Builds a client for talking to the app's upstream token endpoint (used
/// for both the code exchange and refreshes), with that app's configured
/// auth style and extra headers applied to every request it sends.
fn build_token_client(app: &App, cipher: &Cipher) -> Result<(TokenClient, reqwest::Client)> {
    let client_secret_bytes = cipher
        .decrypt(&app.client_secret)
        .context("failed to decrypt stored client_secret")?;
    let client_secret = String::from_utf8(client_secret_bytes)
        .context("decrypted client_secret is not valid UTF-8")?;

    let auth_type = match app.token_auth_method.as_str() {
        "post" => AuthType::RequestBody,
        _ => AuthType::BasicAuth,
    };

    let client = BasicClient::new(ClientId::new(app.client_id.clone()))
        .set_client_secret(ClientSecret::new(client_secret))
        .set_token_uri(
            TokenUrl::new(app.token_url.clone()).context("app has an invalid token_url")?,
        )
        .set_auth_type(auth_type);

    let extra_headers: HashMap<String, String> =
        serde_json::from_str(&app.extra_headers).unwrap_or_default();
    let mut header_map = HeaderMap::new();
    for (name, value) in &extra_headers {
        header_map.insert(
            HeaderName::from_bytes(name.as_bytes())
                .context("invalid header name in extra_headers")?,
            HeaderValue::from_str(value).context("invalid header value in extra_headers")?,
        );
    }

    let http_client = reqwest::Client::builder()
        .default_headers(header_map)
        // Prevents SSRF via a redirect to an unexpected host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")?;

    Ok((client, http_client))
}

pub struct UpstreamToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<Duration>,
    pub scopes: Option<Vec<String>>,
}

impl<TT> From<oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, TT>> for UpstreamToken
where
    TT: oauth2::TokenType,
{
    fn from(token: oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, TT>) -> Self {
        Self {
            access_token: token.access_token().secret().clone(),
            refresh_token: token.refresh_token().map(|t| t.secret().clone()),
            expires_in: token.expires_in(),
            scopes: token
                .scopes()
                .map(|scopes| scopes.iter().map(|s| s.as_ref().to_string()).collect()),
        }
    }
}

/// Exchanges a refresh token for a fresh access token at the app's upstream
/// provider — this is the "wowauth takes care of refreshing your tokens"
/// behavior.
pub async fn refresh(app: &App, cipher: &Cipher, refresh_token: &str) -> Result<UpstreamToken> {
    let (client, http_client) = build_token_client(app, cipher)?;

    let token = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|err| anyhow::anyhow!("token refresh failed: {err}"))?;

    Ok(token.into())
}

/// Exchanges an authorization code for tokens at the app's upstream
/// provider, completing the `/oauth/auth` flow this app started.
pub async fn exchange_code(
    app: &App,
    cipher: &Cipher,
    code: &str,
    pkce_verifier: PkceCodeVerifier,
) -> Result<UpstreamToken> {
    let (client, http_client) = build_token_client(app, cipher)?;
    let redirect_uri =
        RedirectUrl::new(app.redirect_url.clone()).context("app has an invalid redirect_url")?;

    let token = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(pkce_verifier)
        .set_redirect_uri(Cow::Owned(redirect_uri))
        .request_async(&http_client)
        .await
        .map_err(|err| anyhow::anyhow!("code exchange failed: {err}"))?;

    Ok(token.into())
}

pub struct AuthorizationRequest {
    pub url: String,
    pub state: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
}

/// Builds the URL wowauth redirects the caller's browser to, to start the
/// authorization code flow (with PKCE) against the app's upstream
/// provider.
pub fn build_authorization_request(app: &App, scopes: &str) -> Result<AuthorizationRequest> {
    let client = BasicClient::new(ClientId::new(app.client_id.clone()))
        .set_auth_uri(AuthUrl::new(app.auth_url.clone()).context("app has an invalid auth_url")?);
    let redirect_uri =
        RedirectUrl::new(app.redirect_url.clone()).context("app has an invalid redirect_url")?;
    let extra_auth_params: HashMap<String, String> =
        serde_json::from_str(&app.extra_auth_params).unwrap_or_default();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut request = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .set_redirect_uri(Cow::Owned(redirect_uri));
    for scope in scopes.split_whitespace() {
        request = request.add_scope(Scope::new(scope.to_string()));
    }
    for (name, value) in &extra_auth_params {
        request = request.add_extra_param(name.clone(), value.clone());
    }

    let (url, state) = request.url();
    Ok(AuthorizationRequest {
        url: url.to_string(),
        state,
        pkce_verifier,
    })
}
