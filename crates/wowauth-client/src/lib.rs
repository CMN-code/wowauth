//! Client library for fetching fresh tokens from a wowauth deployment.
//!
//! [`WowAuth<T>`] holds everything wowauth itself needs (in [`WowConfig`]),
//! plus whatever the upstream provider needs beyond that -- wowauth doesn't
//! know or care about `T`, so it lives alongside `wowauth`, not inside it.
//! For Nmbrs, for example, `T` would carry the subscription key Nmbrs's API
//! requires on every request.
//!
//! `WowAuth<T>` deserializes straight from the JSON a wowauth setup script
//! (e.g. `docs/examples/nmbrs-setup.ts`) writes out:
//!
//! ```json
//! {
//!   "specific": { "subscription_key": "..." },
//!   "wowauth": {
//!     "name": "nmbrs",
//!     "admin_url": "https://wowauth.example.com",
//!     "config_secret": "...",
//!     "app_id": "...",
//!     "user_id": "...",
//!     "private_key": { "format": "x25519-raw-base64", "value": "..." }
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Everything needed to fetch a fresh token from one wowauth app connection,
/// for one authorized user, plus whatever the upstream provider needs beyond
/// that (`T`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WowAuth<T> {
    pub specific: T,
    pub wowauth: WowConfig,
}

/// Everything wowauth itself needs, independent of which upstream provider
/// this connection is for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WowConfig {
    /// Human label for this connection. Informational only -- not sent to
    /// wowauth.
    pub name: String,
    /// Base URL for wowauth's management API.
    pub admin_url: String,
    /// Bearer secret for wowauth's `/apps/*` endpoints.
    pub config_secret: String,
    /// wowauth's id for the registered app.
    pub app_id: String,
    /// wowauth's id for the authorized account under this app.
    pub user_id: String,
    /// The X25519 private key matching the `public_key` registered for this
    /// app -- the only thing that can decrypt tokens wowauth returns.
    pub private_key: WowPrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WowPrivateKey {
    pub format: String,
    pub value: String,
}

/// What can go wrong fetching a fresh token.
#[derive(Debug, thiserror::Error)]
pub enum FetchTokenError {
    /// wowauth doesn't recognize `app_id`/`user_id` -- check they're
    /// current (e.g. the user wasn't deleted, or a public key rotation
    /// didn't wipe them).
    #[error("wowauth app or user not found -- check app_id/user_id")]
    NotFound,
    /// The upstream access token expired and there's no refresh token (or
    /// the upstream rejected it) -- the user needs to redo the browser
    /// login flow.
    #[error("this user needs to reauthenticate with the upstream provider")]
    NeedsReauth,
    #[error("request to wowauth failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("wowauth returned {status}: {body}")]
    Unexpected {
        status: reqwest::StatusCode,
        body: String,
    },
    #[error("failed to decrypt the returned token: {0}")]
    Decrypt(#[source] anyhow::Error),
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

impl<T> WowAuth<T> {
    /// Fetches a fresh, decrypted access token for this connection.
    ///
    /// Hits wowauth's `GET /apps/{app_id}/users/{user_id}/token`, which
    /// transparently refreshes the upstream token first if it's expired,
    /// then decrypts the HPKE-sealed result with this connection's private
    /// key.
    pub async fn fetch_token(&self) -> Result<String, FetchTokenError> {
        let config = &self.wowauth;
        let url = format!(
            "{}/apps/{}/users/{}/token",
            config.admin_url.trim_end_matches('/'),
            config.app_id,
            config.user_id,
        );

        let response = reqwest::Client::new()
            .get(&url)
            .bearer_auth(&config.config_secret)
            .send()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(FetchTokenError::NotFound);
        }
        if status == reqwest::StatusCode::CONFLICT {
            return Err(FetchTokenError::NeedsReauth);
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(FetchTokenError::Unexpected { status, body });
        }

        let body: TokenResponse = response.json().await?;
        let aad = format!("{}:{}", config.app_id, config.user_id);
        let plaintext =
            wowauth_token_seal::open(&config.private_key.value, &body.token, aad.as_bytes())
                .map_err(FetchTokenError::Decrypt)?;

        String::from_utf8(plaintext).map_err(|err| {
            FetchTokenError::Decrypt(anyhow::anyhow!("decrypted token is not valid UTF-8: {err}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct NmbrsData {
        subscription_key: String,
    }

    #[test]
    fn deserializes_the_documented_shape() {
        let json = r#"{
            "specific": { "subscription_key": "abc123" },
            "wowauth": {
                "name": "nmbrs",
                "admin_url": "https://wowauth.example.com",
                "config_secret": "secret",
                "app_id": "app-1",
                "user_id": "user-1",
                "private_key": { "format": "x25519-raw-base64", "value": "..." }
            }
        }"#;

        let parsed: WowAuth<NmbrsData> = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.specific.subscription_key, "abc123");
        assert_eq!(parsed.wowauth.app_id, "app-1");
        assert_eq!(parsed.wowauth.private_key.format, "x25519-raw-base64");
    }

    #[test]
    fn round_trips_through_serialize() {
        let original = WowAuth {
            specific: NmbrsData {
                subscription_key: "abc123".to_string(),
            },
            wowauth: WowConfig {
                name: "nmbrs".to_string(),
                admin_url: "https://wowauth.example.com".to_string(),
                config_secret: "secret".to_string(),
                app_id: "app-1".to_string(),
                user_id: "user-1".to_string(),
                private_key: WowPrivateKey {
                    format: "x25519-raw-base64".to_string(),
                    value: "...".to_string(),
                },
            },
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: WowAuth<NmbrsData> = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.specific.subscription_key,
            original.specific.subscription_key
        );
        assert_eq!(parsed.wowauth.app_id, original.wowauth.app_id);
    }
}
