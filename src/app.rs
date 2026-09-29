//! Router, middleware stack and the operational routes.

use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{BoxError, Json, Router};
use serde_json::json;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::account;
use crate::address::{routes as address, store};
use crate::auth::Admin;
use crate::error::ApiError;
use crate::state::AppState;
use crate::telemetry;
use crate::webhooks::inbound;

pub fn router(state: AppState) -> Router {
    let cfg = &state.config.server;
    let request_id = HeaderName::from_static("x-request-id");

    let api = Router::new()
        // The public API: apps create addresses; anyone looks them up.
        .route("/v1/address/create", post(address::create))
        .route("/v1/address/{address}", get(address::lookup))
        .route("/v1/address/{address}/status", get(address::status))
        .route("/v1/chains", get(address::chains))
        // The dashboard (execute.cash, Privy session).
        .route("/v1/account", get(account::get))
        .route("/v1/account/api-key", post(account::create_key))
        .route("/v1/account/api-key/rotate", post(account::rotate_key))
        .route("/v1/account/client-id/rotate", post(account::rotate_client_id))
        .route("/v1/account/allowed-origins", put(account::set_allowed_origins))
        .route("/v1/account/webhook-url", put(account::set_webhook_url).delete(account::delete_webhook_url))
        .route("/v1/account/webhook-secret/rotate", post(account::rotate_webhook_secret))
        .route("/v1/account/addresses", get(account::addresses))
        // Callbacks from the services chain work is delegated to (private network only).
        .route("/v1/webhooks/indexer", post(inbound::indexer))
        .route("/v1/webhooks/engine", post(inbound::engine))
        // Operator.
        .route("/v1/admin/address/{address}/retry", post(admin_retry))
        .route("/v1/admin/outbox", get(admin_outbox))
        .route("/v1/admin/outbox/{id}/requeue", post(admin_requeue))
        .layer(DefaultBodyLimit::max(cfg.max_body_bytes));

    let ops = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(render_metrics));

    let trace = TraceLayer::new_for_http()
        .make_span_with(|req: &axum::http::Request<_>| {
            let request_id = req.headers().get("x-request-id").and_then(|v| v.to_str().ok()).unwrap_or("-");
            tracing::info_span!("request", method = %req.method(), path = %req.uri().path(), request_id)
        })
        .on_response(|res: &axum::http::Response<_>, latency: Duration, _span: &tracing::Span| {
            let status = res.status().as_u16();
            if status >= 500 {
                tracing::error!(status, latency_ms = latency.as_millis() as u64, "response");
            } else {
                tracing::info!(status, latency_ms = latency.as_millis() as u64, "response");
            }
        });

    Router::new()
        .merge(api)
        .merge(ops)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(telemetry::http_metrics))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            Duration::from_millis(cfg.request_timeout_ms),
        ))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    ApiError::unavailable("server is overloaded; retry")
                }))
                .layer(tower::load_shed::LoadShedLayer::new())
                .layer(tower::limit::ConcurrencyLimitLayer::new(cfg.max_in_flight)),
        )
        .layer(middleware::from_fn(cors))
        .layer(trace)
        .layer(CatchPanicLayer::custom(|_| ApiError::internal().into_response()))
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .with_state(state)
}

/// The public API (`/v1/address/…`, `/v1/chains`) is callable from any web page: a client ID's
/// origin is checked on the server, and nothing is sent with cookies, so `*` grants nothing. The
/// dashboard, webhook and admin routes send no CORS headers: only servers call them.
async fn cors(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let public = path.starts_with("/v1/address/") || path == "/v1/chains";
    if !public {
        return next.run(req).await;
    }
    if req.method() == Method::OPTIONS {
        let mut res = StatusCode::NO_CONTENT.into_response();
        let h = res.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST"));
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("content-type, x-client-id"));
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
        return res;
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("x-request-id"));
    res
}

async fn not_found() -> ApiError {
    ApiError::not_found("no such route")
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "method not allowed")
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Ready when the database answers. Upstream health is reported but does not gate readiness:
/// creating an address works (and queues) while gum-indexer / gum-engine are down.
async fn readyz(State(state): State<AppState>) -> Response {
    let db = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    let (indexer, engine) = tokio::join!(state.indexer.healthy(), state.engine.healthy());
    let body = json!({ "db": db, "indexer": indexer, "engine": engine, "privy": state.privy.is_configured() });
    let status = if db { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(body)).into_response()
}

async fn render_metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

/// Retries a `failing` address whose automatic retries stopped (e.g. `already_executed` was wrong).
async fn admin_retry(
    State(state): State<AppState>,
    _admin: Admin,
    Path(address): Path<String>,
) -> Result<Response, ApiError> {
    let row = store::retry_failing(&state.pool, &address.to_ascii_lowercase()).await?;
    let Some(row) = row else {
        return Err(ApiError::conflict("not_retryable", "the address is not failing, or an execute is in flight"));
    };
    state.outbox_wake.notify_one();
    tracing::warn!(address = %row.address, "execute retried by operator");
    Ok(Json(row.status()).into_response())
}

async fn admin_outbox(State(state): State<AppState>, _admin: Admin) -> Result<Json<serde_json::Value>, ApiError> {
    #[derive(serde::Serialize, sqlx::FromRow)]
    struct Row {
        id: uuid::Uuid,
        kind: String,
        address: String,
        attempts: i32,
        last_error: Option<String>,
        dead_at: Option<chrono::DateTime<chrono::Utc>>,
        created_at: chrono::DateTime<chrono::Utc>,
    }
    let jobs: Vec<Row> = sqlx::query_as(
        "SELECT id, kind, address, attempts, last_error, dead_at, created_at FROM outbox
         WHERE attempts > 1 OR dead_at IS NOT NULL ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({ "jobs": jobs })))
}

async fn admin_requeue(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, ApiError> {
    let updated = sqlx::query(
        "UPDATE outbox SET dead_at = NULL, next_attempt_at = now(), locked_until = NULL, created_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(ApiError::not_found("no such outbox job"));
    }
    state.outbox_wake.notify_one();
    Ok(StatusCode::ACCEPTED)
}
