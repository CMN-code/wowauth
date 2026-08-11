mod crypto;
mod db;
mod handlers;
mod models;
mod repository;
mod schema;

use std::sync::Arc;

use poem::web::{Data, Json};
use poem::{EndpointExt, Route, Server, get, handler, listener::TcpListener, post};
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;

use crate::crypto::Cipher;
use crate::db::DbPool;

#[derive(Clone)]
struct AppState {
    pool: DbPool,
    cipher: Arc<Cipher>,
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
    let state = AppState { pool, cipher };

    let app = Route::new()
        .at("/health", get(health))
        .at("/apps", post(handlers::create_app))
        .at("/apps/:name", get(handlers::get_app))
        .data(state);

    // Linux binds this dual-stack by default (net.ipv6.bindv6only=0), so it also accepts IPv4.
    Server::new(TcpListener::bind("[::]:3000")).run(app).await?;
    Ok(())
}
