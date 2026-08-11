mod auth;
mod crypto;
mod db;
mod handlers;
mod models;
mod oauth_client;
mod repository;
mod schema;
mod token_seal;

use std::sync::Arc;

use anyhow::Context;
use poem::web::{Data, Json};
use poem::{EndpointExt, Route, Server, get, handler, listener::TcpListener};
use poem_openapi::OpenApiService;
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;

use crate::crypto::Cipher;
use crate::db::DbPool;

#[derive(Clone)]
struct AppState {
    pool: DbPool,
    cipher: Arc<Cipher>,
    config_secret: String,
}

#[handler]
fn health(Data(state): Data<&AppState>) -> Json<Value> {
    let database_ok = state.pool.get().is_ok();
    Json(json!({
        "status": if database_ok { "ok" } else { "degraded" },
        "database": database_ok,
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "wowauth.db".to_string());
    let pool = db::init_pool(&database_url)?;
    let cipher = Arc::new(Cipher::from_env()?);
    let config_secret =
        std::env::var("CONFIG_SECRET").context("CONFIG_SECRET must be set to a bearer secret")?;
    let state = AppState {
        pool,
        cipher,
        config_secret,
    };

    let api_service = OpenApiService::new(handlers::Api, "wowauth", env!("CARGO_PKG_VERSION"));

    let app = Route::new()
        .at("/health", get(health))
        .at("/docs/schema", api_service.spec_endpoint())
        .nest("/", api_service)
        .data(state);

    // Linux binds this dual-stack by default (net.ipv6.bindv6only=0), so it also accepts IPv4.
    Server::new(TcpListener::bind("[::]:3000")).run(app).await?;
    Ok(())
}
