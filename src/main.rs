use poem::{get, handler, listener::TcpListener, web::Json, Route, Server};
use serde_json::{json, Value};
use tracing_subscriber::EnvFilter;

#[handler]
fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let app = Route::new().at("/health", get(health));

    // Linux binds this dual-stack by default (net.ipv6.bindv6only=0), so it also accepts IPv4.
    Server::new(TcpListener::bind("[::]:3000")).run(app).await
}
