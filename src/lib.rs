pub mod auth;
pub mod crypto;
pub mod db;
pub mod handlers;
pub mod models;
pub mod oauth_client;
pub mod oauth_handlers;
pub mod pkce;
pub mod repository;
pub mod schema;

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use crate::crypto::Cipher;
use crate::db::DbPool;

/// Per-(app_id, user_id) locks that serialize token refreshes. Guards
/// against racing the same stored refresh token against the upstream
/// provider from two concurrent requests -- see [`AppState::refresh_lock`].
pub type RefreshLocks = Arc<StdMutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>>;

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub cipher: Arc<Cipher>,
    pub config_secret: String,
    /// Used to build absolute URLs in the OIDC discovery document (e.g.
    /// `https://wowauth.example.com`), since relative URIs aren't valid
    /// there.
    pub public_base_url: String,
    pub refresh_locks: RefreshLocks,
}

impl AppState {
    /// Serializes token refreshes for a given (app_id, user_id) pair.
    ///
    /// Providers like Exact Online invalidate a refresh token the instant
    /// it's used, so two concurrent callers reading the same expired token
    /// row would otherwise both send the same stored refresh token
    /// upstream -- the loser gets "old refresh token used", and since it
    /// never persists a new token, every future refresh attempt fails the
    /// same way forever. Callers should acquire this lock, then re-read the
    /// token row before deciding whether a refresh is still needed: while
    /// waiting, another request may have already refreshed and saved it.
    pub async fn refresh_lock(
        &self,
        app_id: &str,
        user_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let entry = {
            let mut locks = self.refresh_locks.lock().unwrap();
            locks
                .entry((app_id.to_string(), user_id.to_string()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        entry.lock_owned().await
    }
}
