//! One error type for every route. The wire shape is always
//! `{"error":{"code":"…","message":"…","issues":[{"path":"…","message":"…"}]}}`: `issues` lists every
//! invalid field of a request at once, with a JSON Pointer into the body, and is `[]` for errors that
//! are not about a field.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// One problem with one field of a request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    /// JSON Pointer (RFC 6901) to the field, e.g. `/calls/1/args/0`; `""` for the body itself.
    pub path: String,
    pub message: String,
}

impl Issue {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self { path: path.into(), message: message.into() }
    }
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub issues: Vec<Issue>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
    issues: &'a [Issue],
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), issues: Vec::new() }
    }

    /// `400 invalid_intent` with every problem found.
    pub fn invalid_intent(issues: Vec<Issue>) -> Self {
        let message = match issues.as_slice() {
            [one] if one.path.is_empty() => one.message.clone(),
            [one] => format!("{}: {}", one.path, one.message),
            many => format!("{} fields are invalid", many.len()),
        };
        Self { status: StatusCode::BAD_REQUEST, code: "invalid_intent", message, issues }
    }

    /// `400 invalid_request` with the problems found in a (non-intent) body.
    pub fn invalid_body(issues: Vec<Issue>) -> Self {
        let mut err = Self::invalid_intent(issues);
        err.code = "invalid_request";
        err
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }

    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body =
            Json(ErrorBody { error: ErrorDetail { code: self.code, message: &self.message, issues: &self.issues } });
        (self.status, body).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) => {
                tracing::error!(error = %err, "database unavailable");
                metrics::counter!("execute_db_errors_total", "kind" => "unavailable").increment(1);
                Self::unavailable("database unavailable; retry")
            }
            other => {
                tracing::error!(error = %other, "database error");
                metrics::counter!("execute_db_errors_total", "kind" => "query").increment(1);
                Self::internal()
            }
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!(error = ?err, "unhandled error");
        Self::internal()
    }
}

/// A body that is not JSON at all, rendered in our error shape instead of axum's plain text.
impl From<axum::extract::rejection::JsonRejection> for ApiError {
    fn from(rej: axum::extract::rejection::JsonRejection) -> Self {
        Self::invalid_body(vec![Issue::new("", rej.body_text())])
    }
}
