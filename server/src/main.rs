mod crypto;
mod db;
mod error;
mod handlers;

use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crypto::MasterKey;
use db::Db;

pub struct AppState {
    db: Db,
    master_key: MasterKey,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let master_key = MasterKey::from_env();
    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "passvault-keyserver.sqlite".to_string());
    let db = Db::open(&db_path).expect("failed to open database");

    let state = Arc::new(AppState { db, master_key });

    let app = Router::new()
        .route("/accounts", post(handlers::register))
        .route("/otp/request", post(handlers::otp_request))
        .route("/otp/verify", post(handlers::otp_verify))
        .route("/key", post(handlers::store_key).get(handlers::fetch_key))
        .route("/account", delete(handlers::delete_account))
        .route("/healthz", get(|| async { "ok" }))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8787);
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("failed to bind port");
    tracing::info!("passvault-keyserver listening on {addr}");
    axum::serve(listener, app).await.expect("server error");
}
