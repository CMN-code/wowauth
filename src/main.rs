use anyhow::Context;
use poem::endpoint::{EmbeddedFileEndpoint, EmbeddedFilesEndpoint};
use poem::web::{Data, Json};
use poem::{Endpoint, EndpointExt, Route, Server, get, handler, listener::TcpListener};
use poem_openapi::{ApiResponse, OpenApi, OpenApiService};
use rust_embed::Embed;
use serde_json::{Value, json};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use wowauth::crypto::Cipher;
use wowauth::{AppState, db, handlers, oauth_handlers};

#[derive(Embed)]
#[folder = "./frontend/dist/"]
struct Assets;

// Avoid musl's default allocator due to lackluster performance
// https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(ApiResponse)]
enum RootResponse {
    /// Redirect to the API docs
    #[oai(status = 302)]
    Redirect(#[oai(header = "Location")] String),
}

struct HomeApi;

#[OpenApi(prefix_path = "/")]
impl HomeApi {
    /// Home page redirect
    #[oai(path = "/", method = "get")]
    async fn index(&self) -> RootResponse {
        RootResponse::Redirect("/ui".to_string())
    }
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
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .init();

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "wowauth.db".to_string());
    let pool = db::init_pool(&database_url)?;
    let cipher = Arc::new(Cipher::from_env()?);
    let config_secret =
        std::env::var("CONFIG_SECRET").context("CONFIG_SECRET must be set to a bearer secret")?;
    let public_base_url = std::env::var("PUBLIC_BASE_URL")
        .context("PUBLIC_BASE_URL must be set to this server's own public URL")?
        .trim_end_matches('/')
        .to_string();
    let state = AppState {
        pool,
        cipher,
        config_secret,
        public_base_url,
    };

    let api_service = OpenApiService::new(
        (handlers::Api, oauth_handlers::OauthApi, HomeApi),
        "wowauth",
        env!("CARGO_PKG_VERSION"),
    );

    let app = Route::new()
        .nest("/ui", EmbeddedFileEndpoint::<Assets>::new("index.html"))
        .nest("/assets", EmbeddedFilesEndpoint::<Assets>::new())
        .at("/health", get(health))
        .nest("/docs/schema", api_service.spec_endpoint())
        .nest("/docs/scalar", api_service.scalar())
        .nest("/", api_service)
        .data(state)
        // Audit trail: every request wowauth handles logs its method, path, and
        // outcome. `path` alone captures which app/user a call touched, since
        // both ids are path segments (e.g. /apps/{app_id}/users/{user_id}/token)
        // -- deliberately never the query string or headers, so a PKCE
        // verifier/state or the CONFIG_SECRET bearer never ends up in logs.
        .around(|ep, req| async move {
            let method = req.method().clone();
            let path = req.uri().path().to_string();
            let res = ep.call(req).await;
            match &res {
                Ok(resp) => tracing::info!(%method, %path, status = %resp.status()),
                // `err` is always something we constructed ourselves (db
                // errors, decrypt failures, etc.) -- never raw request
                // headers/query -- so logging its message here doesn't
                // violate the no-secrets rule above.
                Err(err) if err.status().is_server_error() => {
                    tracing::error!(%method, %path, status = %err.status(), error = %err)
                }
                Err(err) => tracing::warn!(%method, %path, status = %err.status(), error = %err),
            }
            res
        });

    // Overridable so the integration test suite can run its own instance
    // alongside a dev server without a port clash.
    let port: u16 = std::env::var("LISTEN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);
    // Linux binds this dual-stack by default (net.ipv6.bindv6only=0), so it also accepts IPv4.
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    Server::new(TcpListener::bind(addr)).run(app).await?;
    Ok(())
}
