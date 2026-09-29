//! The dashboard's routes (execute.cash, signed in with Privy): the account's two credentials, the
//! origins its client ID works from, its webhook, and the addresses it has created.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::address::StatusView;
use crate::address::store::{self, Cursor};
use crate::auth::{Dashboard, api_key, origin};
use crate::error::{ApiError, Issue};
use crate::state::AppState;
use crate::webhooks::target;

#[derive(Debug, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyInfo {
    pub prefix: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub id: String,
    /// `null` until the account creates its key.
    pub api_key: Option<ApiKeyInfo>,
    pub client_id: String,
    pub allowed_origins: Vec<String>,
    pub webhook_url: Option<String>,
    /// Verifies our `X-Execute-Signature` on webhooks.
    pub webhook_secret: String,
    pub created_at: DateTime<Utc>,
}

/// A new API key. The secret is returned exactly once, here.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedKey {
    pub api_key: String,
    pub prefix: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct AccountRow {
    client_id: String,
    allowed_origins: Vec<String>,
    webhook_url: Option<String>,
    webhook_secret: String,
    created_at: DateTime<Utc>,
}

async fn view(state: &AppState, account_id: &str) -> Result<AccountView, ApiError> {
    let account: AccountRow = sqlx::query_as(
        "SELECT client_id, allowed_origins, webhook_url, webhook_secret, created_at FROM accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("no such account"))?;
    let api_key: Option<ApiKeyInfo> = sqlx::query_as(
        "SELECT key_prefix AS prefix, created_at, rotated_at, last_used_at FROM api_keys WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(AccountView {
        id: account_id.to_owned(),
        api_key,
        client_id: account.client_id,
        allowed_origins: account.allowed_origins,
        webhook_url: account.webhook_url,
        webhook_secret: account.webhook_secret,
        created_at: account.created_at,
    })
}

pub async fn get(State(state): State<AppState>, session: Dashboard) -> Result<Json<AccountView>, ApiError> {
    Ok(Json(view(&state, &session.account_id).await?))
}

/// Creates the account's API key: `201`, or `409 api_key_exists` when it has one (rotate it instead).
pub async fn create_key(State(state): State<AppState>, session: Dashboard) -> Result<Response, ApiError> {
    let key = api_key::generate_key();
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        "INSERT INTO api_keys (account_id, key_hash, key_prefix) VALUES ($1, $2, $3)
         ON CONFLICT (account_id) DO NOTHING RETURNING created_at",
    )
    .bind(&session.account_id)
    .bind(&key.hash)
    .bind(&key.prefix)
    .fetch_optional(&state.pool)
    .await?;
    let Some((created_at,)) = row else {
        return Err(ApiError::conflict("api_key_exists", "this account already has an API key; rotate it instead"));
    };
    tracing::info!(account_id = %session.account_id, prefix = %key.prefix, "api key created");
    Ok((StatusCode::CREATED, Json(IssuedKey { api_key: key.secret, prefix: key.prefix, created_at, rotated_at: None }))
        .into_response())
}

/// Replaces the account's API key. The old one stops working at once on this instance, and within
/// `credentials.cache_ttl_secs` on the others.
pub async fn rotate_key(State(state): State<AppState>, session: Dashboard) -> Result<Json<IssuedKey>, ApiError> {
    let key = api_key::generate_key();
    #[derive(FromRow)]
    struct Rotated {
        old_hash: Vec<u8>,
        created_at: DateTime<Utc>,
        rotated_at: Option<DateTime<Utc>>,
    }
    let row: Option<Rotated> = sqlx::query_as(
        "UPDATE api_keys AS k SET key_hash = $2, key_prefix = $3, rotated_at = now()
         FROM (SELECT key_hash AS old_hash FROM api_keys WHERE account_id = $1) AS prev
         WHERE k.account_id = $1
         RETURNING prev.old_hash, k.created_at, k.rotated_at",
    )
    .bind(&session.account_id)
    .bind(&key.hash)
    .bind(&key.prefix)
    .fetch_optional(&state.pool)
    .await?;
    let Some(Rotated { old_hash, created_at, rotated_at }) = row else {
        return Err(ApiError::not_found("this account has no API key yet; create one first"));
    };
    state.credentials.invalidate_key(&old_hash);
    tracing::info!(account_id = %session.account_id, prefix = %key.prefix, "api key rotated");
    Ok(Json(IssuedKey { api_key: key.secret, prefix: key.prefix, created_at, rotated_at }))
}

/// Replaces the client ID: the old one stops working (web pages must ship the new one).
pub async fn rotate_client_id(
    State(state): State<AppState>,
    session: Dashboard,
) -> Result<Json<AccountView>, ApiError> {
    let (old,): (String,) = sqlx::query_as(
        "UPDATE accounts AS a SET client_id = $2 FROM (SELECT client_id AS old FROM accounts WHERE id = $1) AS prev
         WHERE a.id = $1 RETURNING prev.old",
    )
    .bind(&session.account_id)
    .bind(api_key::generate_client_id())
    .fetch_one(&state.pool)
    .await?;
    state.credentials.invalidate_client_id(&old);
    tracing::info!(account_id = %session.account_id, "client id rotated");
    Ok(Json(view(&state, &session.account_id).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AllowedOrigins {
    pub allowed_origins: Vec<String>,
}

/// Replaces the list of origins the client ID works from.
pub async fn set_allowed_origins(
    State(state): State<AppState>,
    session: Dashboard,
    body: Result<Json<AllowedOrigins>, JsonRejection>,
) -> Result<Json<AccountView>, ApiError> {
    let Json(body) = body?;
    let max = state.config.credentials.max_allowed_origins;
    let mut issues = Vec::new();
    if body.allowed_origins.len() > max {
        issues.push(Issue::new("/allowedOrigins", format!("at most {max} origins")));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, entry) in body.allowed_origins.iter().enumerate() {
        if let Err(message) = origin::validate(entry) {
            issues.push(Issue::new(format!("/allowedOrigins/{i}"), message));
        } else if !seen.insert(entry.as_str()) {
            issues.push(Issue::new(format!("/allowedOrigins/{i}"), "listed twice"));
        }
    }
    if !issues.is_empty() {
        return Err(ApiError::invalid_body(issues));
    }
    let (client_id,): (String,) =
        sqlx::query_as("UPDATE accounts SET allowed_origins = $2 WHERE id = $1 RETURNING client_id")
            .bind(&session.account_id)
            .bind(&body.allowed_origins)
            .fetch_one(&state.pool)
            .await?;
    state.credentials.invalidate_client_id(&client_id);
    Ok(Json(view(&state, &session.account_id).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WebhookUrl {
    pub webhook_url: String,
}

/// Sets where the account's webhooks go.
pub async fn set_webhook_url(
    State(state): State<AppState>,
    session: Dashboard,
    body: Result<Json<WebhookUrl>, JsonRejection>,
) -> Result<Json<AccountView>, ApiError> {
    let Json(body) = body?;
    let url = target::validate(&body.webhook_url, state.config.webhooks.allow_insecure_targets)
        .map_err(|m| ApiError::invalid_body(vec![Issue::new("/webhookUrl", m)]))?;
    sqlx::query("UPDATE accounts SET webhook_url = $2 WHERE id = $1")
        .bind(&session.account_id)
        .bind(url.as_str())
        .execute(&state.pool)
        .await?;
    Ok(Json(view(&state, &session.account_id).await?))
}

/// Stops webhooks.
pub async fn delete_webhook_url(
    State(state): State<AppState>,
    session: Dashboard,
) -> Result<Json<AccountView>, ApiError> {
    sqlx::query("UPDATE accounts SET webhook_url = NULL WHERE id = $1")
        .bind(&session.account_id)
        .execute(&state.pool)
        .await?;
    Ok(Json(view(&state, &session.account_id).await?))
}

pub async fn rotate_webhook_secret(
    State(state): State<AppState>,
    session: Dashboard,
) -> Result<Json<AccountView>, ApiError> {
    sqlx::query("UPDATE accounts SET webhook_secret = $2 WHERE id = $1")
        .bind(&session.account_id)
        .bind(api_key::generate_webhook_secret())
        .execute(&state.pool)
        .await?;
    tracing::info!(account_id = %session.account_id, "webhook secret rotated");
    Ok(Json(view(&state, &session.account_id).await?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressItem {
    pub address: String,
    pub chain_id: i64,
    pub token: String,
    pub amount: String,
    pub expiration_timestamp: u64,
    pub functions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub status: StatusView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressPage {
    pub items: Vec<AddressItem>,
    pub next_cursor: Option<String>,
}

/// The addresses the account created, newest first.
pub async fn addresses(
    State(state): State<AppState>,
    session: Dashboard,
    Query(page): Query<Page>,
) -> Result<Json<AddressPage>, ApiError> {
    let limit = page.limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(ApiError::invalid("limit must be between 1 and 200"));
    }
    let cursor = match page.cursor.as_deref() {
        None | Some("") => None,
        Some(raw) => Some(Cursor::decode(raw).ok_or_else(|| ApiError::invalid("invalid cursor"))?),
    };
    let (rows, next) = store::list_for_account(&state.pool, &session.account_id, cursor.as_ref(), limit).await?;
    let items = rows
        .into_iter()
        .map(|(row, created_at)| {
            let intent = row.intent();
            AddressItem {
                address: row.address().to_checksum(None),
                chain_id: row.chain_id,
                token: intent.token.clone(),
                amount: intent.amount.clone(),
                expiration_timestamp: intent.expiration_timestamp,
                functions: intent.calls.iter().map(|c| c.function.clone()).collect(),
                created_at,
                status: row.status(),
            }
        })
        .collect();
    Ok(Json(AddressPage { items, next_cursor: next.map(|c| c.encode()) }))
}
