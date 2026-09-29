//! gum-indexer `/v1/watches`: one watch per executable address, retired once the confirmed total
//! reaches its amount. Reached over the Railway private network; no authentication.

use std::time::{Duration, Instant};

use alloy_primitives::{Address, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{UpstreamError, base_url, record};
use crate::config::IndexerConfig;

const SERVICE: &str = "indexer";

pub struct IndexerClient {
    http: reqwest::Client,
    base_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateWatch<'a> {
    pub payment_address: Address,
    pub chain: String,
    pub token: Address,
    pub balance_threshold: String,
    pub webhook_endpoint: &'a str,
    pub expires_at: DateTime<Utc>,
    /// When the address was handed out. Payments can arrive before the watch is registered (the
    /// outbox may lag), and gum-indexer scans back to here so none is missed.
    pub payments_since: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct Watch {
    pub id: Uuid,
    pub chain_id: u64,
    pub payment_address: Address,
    pub status: String,
    #[serde(default)]
    pub confirmed_amount: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WatchDetail {
    pub id: Uuid,
    pub status: String,
    #[serde(default)]
    pub confirmed_amount: Option<String>,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

/// A chain as gum-indexer reports it on `GET /v1/chains`.
#[derive(Debug, Deserialize)]
pub struct IndexedChain {
    pub chain_id: u64,
    pub tokens: Vec<IndexedToken>,
}

#[derive(Debug, Deserialize)]
pub struct IndexedToken {
    pub symbol: String,
    pub address: Address,
}

impl WatchDetail {
    pub fn confirmed(&self) -> U256 {
        self.confirmed_amount.as_deref().and_then(|s| U256::from_str_radix(s, 10).ok()).unwrap_or_default()
    }
}

impl IndexerClient {
    pub fn new(cfg: &IndexerConfig) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .connect_timeout(Duration::from_millis(cfg.timeout_ms.min(3000)))
            .user_agent("execute-server/1")
            .build()?;
        Ok(Self { http, base_url: base_url(&cfg.base_url) })
    }

    pub fn is_configured(&self) -> bool {
        self.base_url.is_some()
    }

    fn url(&self, path: &str) -> Result<String, UpstreamError> {
        let base = self.base_url.as_ref().ok_or(UpstreamError::NotConfigured { service: SERVICE })?;
        Ok(format!("{base}{path}"))
    }

    /// Registers a watch. Idempotent on the indexer side: an identical active watch returns the
    /// existing one.
    pub async fn create_watch(&self, req: &CreateWatch<'_>) -> Result<Watch, UpstreamError> {
        let url = self.url("/v1/watches")?;
        let started = Instant::now();
        let response = self.http.post(url).json(req).send().await.map_err(|source| {
            record(SERVICE, "create_watch", started, "transport");
            UpstreamError::Transport { service: SERVICE, source }
        })?;
        if !response.status().is_success() {
            let err = UpstreamError::from_response(SERVICE, response).await;
            record(SERVICE, "create_watch", started, if err.is_retryable() { "unavailable" } else { "rejected" });
            return Err(err);
        }
        let watch = response
            .json::<Watch>()
            .await
            .map_err(|e| UpstreamError::Malformed { service: SERVICE, detail: e.to_string() });
        record(SERVICE, "create_watch", started, if watch.is_ok() { "ok" } else { "malformed" });
        watch
    }

    pub async fn get_watch(&self, id: Uuid) -> Result<Option<WatchDetail>, UpstreamError> {
        let url = self.url(&format!("/v1/watches/{id}"))?;
        let started = Instant::now();
        let response = self.http.get(url).send().await.map_err(|source| {
            record(SERVICE, "get_watch", started, "transport");
            UpstreamError::Transport { service: SERVICE, source }
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            record(SERVICE, "get_watch", started, "not_found");
            return Ok(None);
        }
        if !response.status().is_success() {
            let err = UpstreamError::from_response(SERVICE, response).await;
            record(SERVICE, "get_watch", started, if err.is_retryable() { "unavailable" } else { "rejected" });
            return Err(err);
        }
        let watch = response
            .json::<WatchDetail>()
            .await
            .map_err(|e| UpstreamError::Malformed { service: SERVICE, detail: e.to_string() });
        record(SERVICE, "get_watch", started, if watch.is_ok() { "ok" } else { "malformed" });
        watch.map(Some)
    }

    /// gum-indexer's chains and the tokens it watches on each (`GET /v1/chains`).
    pub async fn chains(&self) -> Result<Vec<IndexedChain>, UpstreamError> {
        #[derive(Deserialize)]
        struct Body {
            chains: Vec<IndexedChain>,
        }
        let url = self.url("/v1/chains")?;
        let started = Instant::now();
        let response = self.http.get(url).send().await.map_err(|source| {
            record(SERVICE, "chains", started, "transport");
            UpstreamError::Transport { service: SERVICE, source }
        })?;
        if !response.status().is_success() {
            let err = UpstreamError::from_response(SERVICE, response).await;
            record(SERVICE, "chains", started, if err.is_retryable() { "unavailable" } else { "rejected" });
            return Err(err);
        }
        let body = response
            .json::<Body>()
            .await
            .map_err(|e| UpstreamError::Malformed { service: SERVICE, detail: e.to_string() });
        record(SERVICE, "chains", started, if body.is_ok() { "ok" } else { "malformed" });
        body.map(|b| b.chains)
    }

    pub async fn healthy(&self) -> bool {
        let Ok(url) = self.url("/healthz") else { return false };
        self.http.get(url).send().await.is_ok_and(|r| r.status().is_success())
    }
}
