//! HTTP clients for the two services every blockchain interaction is delegated to.

pub mod engine;
pub mod indexer;

use std::time::Instant;

use serde::Deserialize;

/// The `{"error":{"code","message"}}` body both services return.
#[derive(Debug, Deserialize)]
pub struct UpstreamErrorBody {
    pub error: UpstreamErrorDetail,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamErrorDetail {
    pub code: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("{service} is not configured")]
    NotConfigured { service: &'static str },
    #[error("{service} transport error: {source}")]
    Transport {
        service: &'static str,
        #[source]
        source: reqwest::Error,
    },
    /// 4xx: the request is wrong; retrying the same thing will not help.
    #[error("{service} rejected the request ({status}): {code}: {message}")]
    Rejected { service: &'static str, status: u16, code: String, message: String },
    /// 5xx or 429: try again later.
    #[error("{service} unavailable ({status}): {code}: {message}")]
    Unavailable { service: &'static str, status: u16, code: String, message: String },
    #[error("{service} returned an unexpected body: {detail}")]
    Malformed { service: &'static str, detail: String },
}

impl UpstreamError {
    pub fn is_retryable(&self) -> bool {
        !matches!(self, Self::Rejected { .. })
    }

    async fn from_response(service: &'static str, response: reqwest::Response) -> Self {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        let (code, message) = match serde_json::from_str::<UpstreamErrorBody>(&text) {
            Ok(body) => (body.error.code, body.error.message),
            Err(_) => ("http_error".to_owned(), text.chars().take(512).collect()),
        };
        if status == 429 || status >= 500 {
            Self::Unavailable { service, status, code, message }
        } else {
            Self::Rejected { service, status, code, message }
        }
    }
}

fn record(service: &'static str, op: &'static str, started: Instant, outcome: &'static str) {
    let labels = [("service", service), ("op", op), ("outcome", outcome)];
    metrics::histogram!("execute_upstream_request_duration_seconds", &labels).record(started.elapsed().as_secs_f64());
    metrics::counter!("execute_upstream_requests_total", &labels).increment(1);
}

fn base_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
}
