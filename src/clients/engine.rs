//! gum-engine `/v1/transactions`: submit `PaymentFactory.execute` and let the engine simulate,
//! sign, broadcast, confirm and call us back.

use std::time::{Duration, Instant};

use alloy_primitives::{Address, B256, Bytes};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{UpstreamError, base_url, record};
use crate::config::EngineConfig;

const SERVICE: &str = "engine";

pub struct EngineClient {
    http: reqwest::Client,
    base_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitTransaction<'a> {
    pub chain_id: u64,
    pub to: Address,
    pub data: Bytes,
    pub webhook: Webhook<'a>,
}

#[derive(Debug, Serialize)]
pub struct Webhook<'a> {
    pub url: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct Submitted {
    pub job_id: Uuid,
    #[serde(default)]
    pub replayed: bool,
}

/// Why the engine failed a job, on webhooks and on `GET /v1/transactions/{id}`.
#[derive(Debug, Deserialize)]
pub struct EngineError {
    pub code: String,
    #[serde(default)]
    pub message: String,
    /// `0x` hex. Set when the engine's simulation (gas estimation) reverted: for
    /// `PaymentFactory.execute`, the `Payment` constructor's own revert data.
    #[serde(default)]
    pub revert_data: Option<String>,
}

impl EngineError {
    /// The revert data as bytes; `None` when there is none or it is not valid hex.
    pub fn revert_bytes(&self) -> Option<Bytes> {
        let raw = self.revert_data.as_deref()?;
        match raw.parse::<Bytes>() {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                tracing::warn!(revert_data = raw, error = %err, "engine revert data is not hex; ignored");
                None
            }
        }
    }
}

/// The subset of `GET /v1/transactions/{job_id}` the reconciler needs.
#[derive(Debug, Deserialize)]
pub struct Job {
    pub job_id: Uuid,
    pub status: String,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub tx_hash: Option<B256>,
    #[serde(default)]
    pub block_number: Option<u64>,
    #[serde(default)]
    pub receipt: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<EngineError>,
}

impl EngineClient {
    pub fn new(cfg: &EngineConfig) -> anyhow::Result<Self> {
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

    /// Submits a transaction. `idempotency_key` makes resubmission after a crash safe: the engine
    /// replays the original job instead of broadcasting twice.
    pub async fn submit(&self, req: &SubmitTransaction<'_>, idempotency_key: &str) -> Result<Submitted, UpstreamError> {
        let url = self.url("/v1/transactions")?;
        let started = Instant::now();
        let response = self.http.post(url).header("Idempotency-Key", idempotency_key).json(req).send().await.map_err(
            |source| {
                record(SERVICE, "submit", started, "transport");
                UpstreamError::Transport { service: SERVICE, source }
            },
        )?;
        if !response.status().is_success() {
            let err = UpstreamError::from_response(SERVICE, response).await;
            record(SERVICE, "submit", started, if err.is_retryable() { "unavailable" } else { "rejected" });
            return Err(err);
        }
        let job = response
            .json::<Submitted>()
            .await
            .map_err(|e| UpstreamError::Malformed { service: SERVICE, detail: e.to_string() });
        record(SERVICE, "submit", started, if job.is_ok() { "ok" } else { "malformed" });
        job
    }

    pub async fn get_job(&self, job_id: Uuid) -> Result<Option<Job>, UpstreamError> {
        let url = self.url(&format!("/v1/transactions/{job_id}"))?;
        let started = Instant::now();
        let response = self.http.get(url).send().await.map_err(|source| {
            record(SERVICE, "get_job", started, "transport");
            UpstreamError::Transport { service: SERVICE, source }
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            record(SERVICE, "get_job", started, "not_found");
            return Ok(None);
        }
        if !response.status().is_success() {
            let err = UpstreamError::from_response(SERVICE, response).await;
            record(SERVICE, "get_job", started, if err.is_retryable() { "unavailable" } else { "rejected" });
            return Err(err);
        }
        let job = response
            .json::<Job>()
            .await
            .map_err(|e| UpstreamError::Malformed { service: SERVICE, detail: e.to_string() });
        record(SERVICE, "get_job", started, if job.is_ok() { "ok" } else { "malformed" });
        job.map(Some)
    }

    pub async fn healthy(&self) -> bool {
        let Ok(url) = self.url("/healthz") else { return false };
        self.http.get(url).send().await.is_ok_and(|r| r.status().is_success())
    }
}
