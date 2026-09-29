//! Logs (single-line JSON on stdout, `RUST_LOG` filter) and Prometheus metrics.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::EnvFilter;

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,hyper=warn"));
    let pretty = std::env::var("EXECUTE_LOG_FORMAT").is_ok_and(|v| v == "pretty");
    if pretty {
        tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
    } else {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_current_span(true)
            .with_span_list(false)
            .flatten_event(true)
            .init();
    }
}

/// Panics become a structured error line and `execute_panics_total`. The default hook prints plain
/// text to stderr, which log search and alerting missed while panics were killing the outbox task
/// (2026-09-23). Written directly rather than through `tracing`: the panic may have come from
/// inside the subscriber itself.
pub fn init_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        metrics::counter!("execute_panics_total").increment(1);
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let line = serde_json::json!({
            "timestamp": chrono::Utc::now(),
            "level": "ERROR",
            "message": "panic",
            "panic": payload,
            "location": info.location().map(|l| format!("{}:{}", l.file(), l.line())),
            "thread": std::thread::current().name(),
            "target": "execute_server::panic",
        });
        eprintln!("{line}");
    }));
}

pub fn init_metrics() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Suffix("_duration_seconds".into()),
            &[0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )?
        .install_recorder()?;
    describe();
    Ok(handle)
}

fn describe() {
    use metrics::{describe_counter, describe_gauge, describe_histogram};
    describe_histogram!("execute_http_request_duration_seconds", "HTTP request latency by route and status");
    describe_counter!("execute_http_requests_total", "HTTP requests by route and status");
    describe_gauge!("execute_http_in_flight", "HTTP requests currently being served");
    describe_counter!("execute_addresses_created_total", "Executable addresses created (not re-registrations)");
    describe_counter!("execute_address_transitions_total", "Address lifecycle events");
    describe_counter!("execute_execution_failures_total", "Execute attempts that failed, by code and decoded revert");
    describe_gauge!("execute_addresses_in_flight", "Addresses with an execute job in flight");
    describe_gauge!("execute_addresses_in_flight_oldest_age_seconds", "Age of the oldest in-flight execute job");
    describe_gauge!("execute_tokens_unwatched", "Configured tokens gum-indexer does not watch");
    describe_counter!("execute_inbound_webhooks_total", "Webhooks received from gum-indexer / gum-engine");
    describe_counter!("execute_outbox_jobs_total", "Outbox jobs by kind and result");
    describe_histogram!("execute_outbox_job_duration_seconds", "Outbox job execution time");
    describe_gauge!("execute_outbox_pending", "Outbox rows waiting or retrying");
    describe_gauge!("execute_outbox_dead", "Outbox rows given up on");
    describe_histogram!("execute_outbox_lag_seconds", "Age of a job when it is picked up");
    describe_histogram!("execute_upstream_request_duration_seconds", "Latency of calls to gum-indexer / gum-engine");
    describe_counter!("execute_upstream_requests_total", "Calls to gum-indexer / gum-engine by outcome");
    describe_counter!("execute_app_webhook_deliveries_total", "Deliveries to app webhooks by outcome");
    describe_counter!("execute_auth_total", "Authentication attempts by method and outcome");
    describe_counter!("execute_db_errors_total", "Database errors");
    describe_counter!("execute_panics_total", "Panics anywhere in the process");
    describe_counter!("execute_task_restarts_total", "Background tasks restarted after stopping unexpectedly");
}

/// Per-request latency/count metrics keyed by the matched route template, never the raw path.
pub async fn http_metrics(req: Request, next: Next) -> Response {
    let route =
        req.extensions().get::<MatchedPath>().map(|p| p.as_str().to_owned()).unwrap_or_else(|| "unmatched".to_owned());
    let method = req.method().as_str().to_owned();
    let started = Instant::now();
    metrics::gauge!("execute_http_in_flight").increment(1.0);
    let response = next.run(req).await;
    metrics::gauge!("execute_http_in_flight").decrement(1.0);
    let status = response.status().as_u16().to_string();
    let labels = [("route", route), ("method", method), ("status", status)];
    metrics::histogram!("execute_http_request_duration_seconds", &labels).record(started.elapsed().as_secs_f64());
    metrics::counter!("execute_http_requests_total", &labels).increment(1);
    response
}
