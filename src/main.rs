use poem::{get, handler, listener::TcpListener, web::Json, Route, Server};
use serde_json::{json, Value};

#[handler]
fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt::init();

    let app = Route::new().at("/health", get(health));

    let addr = "0.0.0.0:3000";
    tracing::info!("listening on {addr}");
    Server::new(TcpListener::bind(addr)).run(app).await
}
