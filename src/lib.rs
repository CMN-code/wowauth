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

use std::sync::Arc;

use crate::crypto::Cipher;
use crate::db::DbPool;

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub cipher: Arc<Cipher>,
    pub config_secret: String,
    /// Used to build absolute URLs in the OIDC discovery document (e.g.
    /// `https://wowauth.example.com`), since relative URIs aren't valid
    /// there.
    pub public_base_url: String,
}
