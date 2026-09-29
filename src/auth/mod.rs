//! Request authentication.
//!
//! Creating an address takes one of an account's two credentials:
//!
//! * its **API key**, `Authorization: Bearer exe_sk_…`, from the app's servers only. A request that
//!   carries it and an `Origin` header came from a browser and is refused, so a key pasted into a web
//!   page fails loudly instead of leaking quietly;
//! * its **client ID**, `X-Client-Id: exe_client_…`, from the app's web pages. It is public by design:
//!   it only works when the browser's `Origin` is one the account allows.
//!
//! The dashboard at execute.cash manages both, with a Privy session (`Authorization: Bearer <jwt>`).
//! Looking up an address or its status needs no credentials.

pub mod api_key;
pub mod origin;
pub mod privy;

use axum::extract::FromRequestParts;
use axum::http::header::{AUTHORIZATION, ORIGIN};
use axum::http::request::Parts;
use subtle::ConstantTimeEq;

use self::api_key::ClientIdOwner;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    ApiKey,
    ClientId,
}

impl Credential {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::ClientId => "client_id",
        }
    }
}

/// An app creating an address, with its API key or its client ID.
#[derive(Debug, Clone)]
pub struct AppCaller {
    pub account_id: String,
    pub credential: Credential,
}

/// A signed-in dashboard user (Privy).
#[derive(Debug, Clone)]
pub struct Dashboard {
    pub account_id: String,
}

/// The operator, authenticated with `admin.token`.
#[derive(Debug, Clone, Copy)]
pub struct Admin;

fn header(parts: &Parts, name: impl axum::http::header::AsHeaderName) -> Result<Option<&str>, ApiError> {
    match parts.headers.get(name) {
        None => Ok(None),
        Some(v) => v.to_str().map(|s| Some(s.trim())).map_err(|_| ApiError::invalid("headers must be ASCII")),
    }
}

fn bearer(value: &str) -> Result<&str, ApiError> {
    let token = value.strip_prefix("Bearer ").map(str::trim).unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::unauthorized("Authorization must be \"Bearer <credential>\""));
    }
    Ok(token)
}

impl FromRequestParts<AppState> for AppCaller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let authorization = header(parts, AUTHORIZATION)?;
        let client_id = header(parts, "x-client-id")?;
        let origin = header(parts, ORIGIN)?;
        match (authorization, client_id) {
            (Some(_), Some(_)) => Err(ApiError::invalid(
                "send one credential: your API key (Authorization) from a server, or your client ID (X-Client-Id) from a browser",
            )),
            (None, Some(client_id)) => authenticate_client_id(state, client_id, origin).await,
            (Some(authorization), None) => {
                let token = bearer(authorization)?;
                if !api_key::looks_like_key(token) {
                    return Err(ApiError::unauthorized(
                        "creating an address takes your API key (exe_sk_…) or your client ID; dashboard sessions cannot",
                    ));
                }
                if origin.is_some() {
                    metrics::counter!("execute_auth_total", "method" => "api_key", "outcome" => "browser").increment(1);
                    return Err(ApiError::forbidden(
                        "api_key_in_browser",
                        "API keys are secret and work from servers only; this request came from a browser. Use your client ID there, and rotate this key if it was exposed",
                    ));
                }
                authenticate_api_key(state, token).await
            }
            (None, None) => Err(ApiError::unauthorized(
                "missing credentials: send your API key as \"Authorization: Bearer exe_sk_…\" from your server, or your client ID as \"X-Client-Id\" from the browser",
            )),
        }
    }
}

async fn authenticate_api_key(state: &AppState, secret: &str) -> Result<AppCaller, ApiError> {
    let key_hash = api_key::hash(secret);
    let account_id = match state.credentials.key(&key_hash) {
        Some(owner) => owner,
        None => {
            let row: Option<(String,)> = sqlx::query_as("SELECT account_id FROM api_keys WHERE key_hash = $1")
                .bind(&key_hash)
                .fetch_optional(&state.pool)
                .await?;
            let Some((account_id,)) = row else {
                metrics::counter!("execute_auth_total", "method" => "api_key", "outcome" => "invalid").increment(1);
                return Err(ApiError::unauthorized("invalid API key"));
            };
            state.credentials.insert_key(key_hash.clone(), account_id)
        }
    };
    if !state.credentials.allow_key(&key_hash) {
        metrics::counter!("execute_auth_total", "method" => "api_key", "outcome" => "rate_limited").increment(1);
        return Err(ApiError::rate_limited("API key rate limit exceeded"));
    }
    if state.first_touch(format!("key:{}", hex::encode(&key_hash))) {
        let (pool, hash) = (state.pool.clone(), key_hash.clone());
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1")
                .bind(hash)
                .execute(&pool)
                .await;
        });
    }
    metrics::counter!("execute_auth_total", "method" => "api_key", "outcome" => "ok").increment(1);
    Ok(AppCaller { account_id: account_id.as_str().to_owned(), credential: Credential::ApiKey })
}

async fn authenticate_client_id(
    state: &AppState,
    client_id: &str,
    origin: Option<&str>,
) -> Result<AppCaller, ApiError> {
    let Some(origin) = origin else {
        metrics::counter!("execute_auth_total", "method" => "client_id", "outcome" => "no_origin").increment(1);
        return Err(ApiError::forbidden(
            "origin_required",
            "client IDs work from web pages only, whose browsers send Origin; from a server, use your API key",
        ));
    };
    let owner = match state.credentials.client_id(client_id) {
        Some(owner) => owner,
        None => {
            let row: Option<(String, Vec<String>)> =
                sqlx::query_as("SELECT id, allowed_origins FROM accounts WHERE client_id = $1")
                    .bind(client_id)
                    .fetch_optional(&state.pool)
                    .await?;
            let Some((account_id, allowed_origins)) = row else {
                metrics::counter!("execute_auth_total", "method" => "client_id", "outcome" => "invalid").increment(1);
                return Err(ApiError::unauthorized("invalid client ID"));
            };
            state.credentials.insert_client_id(client_id.to_owned(), ClientIdOwner { account_id, allowed_origins })
        }
    };
    if !state.credentials.allow_client_id(client_id) {
        metrics::counter!("execute_auth_total", "method" => "client_id", "outcome" => "rate_limited").increment(1);
        return Err(ApiError::rate_limited("client ID rate limit exceeded"));
    }
    if !origin::is_allowed(origin, &owner.allowed_origins) {
        metrics::counter!("execute_auth_total", "method" => "client_id", "outcome" => "origin_not_allowed")
            .increment(1);
        return Err(ApiError::forbidden(
            "origin_not_allowed",
            format!(
                "{origin} is not an allowed origin for this client ID; add it under Allowed origins in the dashboard"
            ),
        ));
    }
    metrics::counter!("execute_auth_total", "method" => "client_id", "outcome" => "ok").increment(1);
    Ok(AppCaller { account_id: owner.account_id.clone(), credential: Credential::ClientId })
}

impl FromRequestParts<AppState> for Dashboard {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let Some(authorization) = header(parts, AUTHORIZATION)? else {
            return Err(ApiError::unauthorized("sign in at execute.cash"));
        };
        let token = bearer(authorization)?;
        if api_key::looks_like_key(token) {
            return Err(ApiError::forbidden(
                "session_required",
                "account routes need a dashboard session, not an API key",
            ));
        }
        let claims = match state.privy.verify(token) {
            Ok(claims) => claims,
            Err(privy::PrivyError::NotConfigured) => {
                metrics::counter!("execute_auth_total", "method" => "privy", "outcome" => "unconfigured").increment(1);
                return Err(ApiError::unavailable("dashboard sign-in is not configured"));
            }
            Err(privy::PrivyError::Invalid(reason)) => {
                metrics::counter!("execute_auth_total", "method" => "privy", "outcome" => "invalid").increment(1);
                tracing::debug!(reason, "privy token rejected");
                return Err(ApiError::unauthorized("invalid or expired session; sign in again"));
            }
        };
        // First contact creates the account with its client ID; later calls refresh last_seen_at at
        // most once a minute.
        if state.first_touch(format!("account:{}", claims.sub)) {
            sqlx::query(
                "INSERT INTO accounts (id, client_id, webhook_secret) VALUES ($1, $2, $3)
                 ON CONFLICT (id) DO UPDATE SET last_seen_at = now()",
            )
            .bind(&claims.sub)
            .bind(api_key::generate_client_id())
            .bind(api_key::generate_webhook_secret())
            .execute(&state.pool)
            .await?;
        }
        metrics::counter!("execute_auth_total", "method" => "privy", "outcome" => "ok").increment(1);
        Ok(Self { account_id: claims.sub })
    }
}

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let expected = state.config.admin.token.as_bytes();
        if expected.is_empty() {
            return Err(ApiError::not_found("no such route"));
        }
        let presented =
            header(parts, AUTHORIZATION)?.and_then(|v| v.strip_prefix("Bearer ")).map(str::trim).unwrap_or_default();
        if presented.len() != expected.len() || presented.as_bytes().ct_eq(expected).unwrap_u8() != 1 {
            return Err(ApiError::unauthorized("invalid admin token"));
        }
        Ok(Self)
    }
}
