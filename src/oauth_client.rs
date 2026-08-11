use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use oauth2::basic::BasicClient;
use oauth2::{AuthType, ClientId, ClientSecret, RefreshToken, TokenResponse, TokenUrl};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::crypto::Cipher;
use crate::models::App;

pub struct RefreshedToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<Duration>,
}

/// Exchanges a refresh token for a fresh access token at the app's upstream
/// provider, using that app's configured auth style and extra headers —
/// this is the "wowauth takes care of refreshing your tokens" behavior.
pub async fn refresh(app: &App, cipher: &Cipher, refresh_token: &str) -> Result<RefreshedToken> {
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

    let token = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
        .request_async(&http_client)
        .await
        .map_err(|err| anyhow::anyhow!("token refresh failed: {err}"))?;

    Ok(RefreshedToken {
        access_token: token.access_token().secret().clone(),
        refresh_token: token.refresh_token().map(|t| t.secret().clone()),
        expires_in: token.expires_in(),
    })
}
