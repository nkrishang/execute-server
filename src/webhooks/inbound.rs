//! `POST /v1/webhooks/indexer` and `POST /v1/webhooks/engine`.
//!
//! Both senders deliver at-least-once with `X-Gum-Signature`. A delivery is verified, deduplicated on
//! its event id inside the same transaction as the state change it causes, and acknowledged with
//! `200` as soon as that transaction commits. Anything slow (submitting to the engine, notifying
//! apps) is queued to the outbox, never done on the sender's clock.
//!
//! `200` for an event we cannot map to an address: retrying would not help. `503` on database
//! trouble, and for an engine job we have not recorded *yet* (the engine can report a job before our
//! outbox has written its id): retrying will. A handler uses exactly one connection, its transaction.

use alloy_primitives::{Address, B256, Bytes, U256};
use axum::body::Bytes as Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::Instrument;
use uuid::Uuid;

use super::sign;
use crate::address::AddressRow;
use crate::address::store::{self, Failure};
use crate::chain::payment::{self, ExecutionOutcome, ReceiptLog};
use crate::chain::revert::{self, Reason, RevertView};
use crate::clients::engine::EngineError;
use crate::config::AddressesConfig;
use crate::error::ApiError;
use crate::state::AppState;

/// Engine failure codes for jobs that never executed: submitted again.
const NOT_EXECUTED: &[&str] = &["expired", "stuck_cancelled", "internal"];
/// An engine event for a job we have no record of is retried (503) while the job is this young.
const UNKNOWN_JOB_GRACE_SECS: u64 = 600;

fn verify(
    state: &AppState,
    source: &'static str,
    secret: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ApiError> {
    if secret.is_empty() {
        metrics::counter!("execute_inbound_webhooks_total", "source" => source, "outcome" => "unconfigured")
            .increment(1);
        return Err(ApiError::unavailable("inbound webhook secret is not configured"));
    }
    let header = headers.get("x-gum-signature").and_then(|v| v.to_str().ok()).unwrap_or_default();
    if !sign::verify(secret, header, body, Utc::now().timestamp(), state.config.webhooks.inbound_tolerance_secs) {
        metrics::counter!("execute_inbound_webhooks_total", "source" => source, "outcome" => "bad_signature")
            .increment(1);
        return Err(ApiError::unauthorized("invalid webhook signature"));
    }
    Ok(())
}

fn parse<T: for<'de> Deserialize<'de>>(source: &'static str, body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| {
        metrics::counter!("execute_inbound_webhooks_total", "source" => source, "outcome" => "malformed").increment(1);
        ApiError::invalid(format!("malformed {source} event: {e}"))
    })
}

// ---------------------------------------------------------------------------------------------
// gum-indexer
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct IndexerEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub watch: IndexerWatch,
    #[serde(default)]
    pub transfer: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct IndexerWatch {
    pub id: Uuid,
    pub chain_id: u64,
    pub payment_address: Address,
    #[serde(default)]
    pub confirmed_amount: Option<String>,
}

impl IndexerWatch {
    fn confirmed(&self) -> U256 {
        self.confirmed_amount.as_deref().and_then(|s| U256::from_str_radix(s, 10).ok()).unwrap_or_default()
    }
}

pub async fn indexer(State(state): State<AppState>, headers: HeaderMap, body: Body) -> Result<StatusCode, ApiError> {
    verify(&state, "indexer", &state.config.indexer.webhook_secret, &headers, &body)?;
    let event: IndexerEvent = parse("indexer", &body)?;
    let span = tracing::info_span!("indexer_event", event_id = %event.id, event_type = %event.event_type, watch_id = %event.watch.id);
    apply_indexer_event(state, event).instrument(span).await
}

async fn apply_indexer_event(state: AppState, event: IndexerEvent) -> Result<StatusCode, ApiError> {
    let mut tx = state.pool.begin().await?;
    if !store::claim_inbound(&mut tx, "indexer", &event.id).await? {
        metrics::counter!("execute_inbound_webhooks_total", "source" => "indexer", "outcome" => "duplicate")
            .increment(1);
        return Ok(StatusCode::OK);
    }
    let row = match store::get_by_watch(&mut tx, event.watch.id).await? {
        Some(r) => Some(r),
        // The watch id is written by an outbox job; the first event can beat it.
        None => store::get_on(&mut tx, &format!("{:#x}", event.watch.payment_address)).await?,
    };
    let Some(row) = row.filter(|r| r.chain_id as u64 == event.watch.chain_id) else {
        tracing::warn!(address = %event.watch.payment_address, chain_id = event.watch.chain_id, "indexer event for an unknown address");
        metrics::counter!("execute_inbound_webhooks_total", "source" => "indexer", "outcome" => "unknown_address")
            .increment(1);
        tx.commit().await?;
        return Ok(StatusCode::OK);
    };
    if row.watch_id.is_none() {
        sqlx::query("UPDATE addresses SET watch_id = $2, watch_registered_at = COALESCE(watch_registered_at, now()) WHERE address = $1 AND watch_id IS NULL")
            .bind(&row.address)
            .bind(event.watch.id)
            .execute(&mut *tx)
            .await?;
    }

    let confirmed = event.watch.confirmed();
    let data =
        json!({ "indexer_event_id": event.id, "transfer": event.transfer, "confirmed_amount": confirmed.to_string() });
    let applied = match event.event_type.as_str() {
        "payment.pending" => store::apply_detected(&mut tx, &row.address, data).await?,
        "payment.confirmed" => store::apply_confirmed(&mut tx, &row.address, confirmed, data).await?,
        "payment.orphaned" => store::apply_orphaned(&mut tx, &row.address, data).await?,
        "threshold.reached" => store::apply_threshold(&mut tx, &row.address, confirmed, data).await?,
        "watch.expired" => store::apply_watch_expired(&mut tx, &row.address, confirmed, data).await?,
        other => {
            tracing::warn!(event_type = other, "unknown indexer event type");
            None
        }
    };
    tx.commit().await?;
    state.outbox_wake.notify_one();

    let outcome = if applied.is_some() { "applied" } else { "ignored" };
    metrics::counter!("execute_inbound_webhooks_total", "source" => "indexer", "outcome" => outcome, "type" => event.event_type.clone())
        .increment(1);
    tracing::info!(address = %row.address, outcome, "indexer event processed");
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------------------------
// gum-engine
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EngineEvent {
    pub event_id: String,
    pub event: String,
    pub job_id: Uuid,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub tx_hash: Option<B256>,
    #[serde(default)]
    pub block_number: Option<u64>,
    #[serde(default)]
    pub receipt: Option<Value>,
    #[serde(default)]
    pub error: Option<EngineError>,
}

/// Whether an engine job id (UUIDv7, stamped with its creation time) is young enough that we may not
/// have recorded it yet.
fn job_is_recent(job_id: Uuid) -> bool {
    let Some(created) = job_id.get_timestamp() else { return false };
    let now = Utc::now().timestamp().max(0) as u64;
    now.saturating_sub(created.to_unix().0) < UNKNOWN_JOB_GRACE_SECS
}

pub async fn engine(State(state): State<AppState>, headers: HeaderMap, body: Body) -> Result<StatusCode, ApiError> {
    verify(&state, "engine", &state.config.engine.webhook_secret, &headers, &body)?;
    let event: EngineEvent = parse("engine", &body)?;
    let span = tracing::info_span!("engine_event", event_id = %event.event_id, event_type = %event.event, job_id = %event.job_id);
    apply_engine_event(state, event).instrument(span).await
}

async fn apply_engine_event(state: AppState, event: EngineEvent) -> Result<StatusCode, ApiError> {
    let mut tx = state.pool.begin().await?;
    if !store::claim_inbound(&mut tx, "engine", &event.event_id).await? {
        metrics::counter!("execute_inbound_webhooks_total", "source" => "engine", "outcome" => "duplicate")
            .increment(1);
        return Ok(StatusCode::OK);
    }
    let row = match store::job_address(&mut tx, event.job_id).await? {
        Some(address) => store::get_on(&mut tx, &address).await?,
        None => None,
    };
    let Some(row) = row else {
        if job_is_recent(event.job_id) {
            // Dropping the transaction rolls the claim back, so the engine's retry is processed once
            // the outbox has recorded the job.
            tracing::warn!("engine event for a job not recorded yet; asking the engine to retry");
            metrics::counter!("execute_inbound_webhooks_total", "source" => "engine", "outcome" => "job_not_recorded_yet").increment(1);
            return Err(ApiError::unavailable("job not recorded yet; retry"));
        }
        tracing::warn!("engine event for an unknown job");
        metrics::counter!("execute_inbound_webhooks_total", "source" => "engine", "outcome" => "unknown_job")
            .increment(1);
        tx.commit().await?;
        return Ok(StatusCode::OK);
    };

    let outcome = ExecuteOutcome::from_event(&event, &row);
    let applied = apply_outcome(&mut tx, &state.config.addresses, &row, event.job_id, outcome).await?;
    tx.commit().await?;
    state.outbox_wake.notify_one();

    let label = if applied { "applied" } else { "ignored" };
    metrics::counter!("execute_inbound_webhooks_total", "source" => "engine", "outcome" => label, "type" => event.event.clone()).increment(1);
    tracing::info!(address = %row.address, outcome = label, "engine event processed");
    Ok(StatusCode::OK)
}

/// What an engine event (or a polled job) means for the address.
#[derive(Debug)]
pub enum ExecuteOutcome {
    /// Mined; waiting for confirmation.
    Included {
        tx_hash: String,
        block_number: Option<i64>,
        data: Value,
    },
    Settled {
        tx_hash: String,
        block_number: Option<i64>,
        data: Value,
    },
    /// Executed after expiry: the balance went to recovery.
    Refunded {
        tx_hash: String,
        block_number: Option<i64>,
        amount: U256,
        data: Value,
    },
    /// The attempt failed; `retry` says whether trying again can help.
    Failed {
        failure: Failure,
        retry: bool,
        data: Value,
    },
    /// The engine gave up before the transaction executed: submit it again.
    NotExecuted {
        data: Value,
    },
    /// Nothing to act on yet.
    Pending,
}

impl ExecuteOutcome {
    pub fn from_event(event: &EngineEvent, row: &AddressRow) -> Self {
        let tx_hash = event.tx_hash.map(|h| format!("{h:#x}"));
        let block_number = event.block_number.map(|n| n as i64);
        let data = json!({
            "engine_event_id": event.event_id,
            "engine_job_id": event.job_id,
            "tx_hash": tx_hash,
            "block_number": event.block_number,
            "outcome": event.outcome,
        });
        match event.event.as_str() {
            "transaction.included" => match tx_hash {
                Some(tx_hash) => Self::Included { tx_hash, block_number, data },
                None => Self::Pending,
            },
            "transaction.confirmed" => Self::from_receipt(
                event.outcome.as_deref(),
                tx_hash,
                block_number,
                event.receipt.as_ref(),
                event.error.as_ref(),
                row,
                data,
            ),
            "transaction.failed" => Self::engine_failure(event.error.as_ref(), tx_hash, row, data),
            _ => Self::Pending,
        }
    }

    /// Reads the `Payment` constructor's events out of the receipt: the engine's `outcome` says
    /// whether the transaction reverted, the logs say where the money went.
    pub fn from_receipt(
        outcome: Option<&str>,
        tx_hash: Option<String>,
        block_number: Option<i64>,
        receipt: Option<&Value>,
        error: Option<&EngineError>,
        row: &AddressRow,
        data: Value,
    ) -> Self {
        let Some(tx_hash) = tx_hash else { return Self::Pending };
        let mut data = data;
        data["receipt"] = receipt.cloned().unwrap_or(Value::Null);
        match outcome {
            Some("success") => {
                let logs: Vec<ReceiptLog> = receipt
                    .and_then(|r| r.get("logs"))
                    .and_then(|l| serde_json::from_value(l.clone()).ok())
                    .unwrap_or_default();
                match payment::execution_outcome(&logs, row.address()) {
                    ExecutionOutcome::Settled => Self::Settled { tx_hash, block_number, data },
                    ExecutionOutcome::Recovered { amount } => Self::Refunded { tx_hash, block_number, amount, data },
                    ExecutionOutcome::WrongChain => Self::Failed {
                        failure: Failure {
                            code: "wrong_chain".into(),
                            message: "the payment was deployed on a chain other than its own".into(),
                            revert_data: None,
                        },
                        retry: false,
                        data,
                    },
                    ExecutionOutcome::NoEvents => Self::Failed {
                        failure: Failure {
                            code: "unexpected_outcome".into(),
                            message: "execute succeeded but the address emitted neither Settled nor Recovered".into(),
                            revert_data: None,
                        },
                        retry: false,
                        data,
                    },
                }
            }
            Some("reverted") => Self::engine_failure(error, Some(tx_hash), row, data),
            _ => Self::Pending,
        }
    }

    /// A job the engine failed, or an `execute` that reverted on chain. With the revert data (the
    /// engine's simulation reverted), the failure says exactly what went wrong.
    pub fn engine_failure(error: Option<&EngineError>, tx_hash: Option<String>, row: &AddressRow, data: Value) -> Self {
        let mut data = data;
        let code = error.map_or("failed", |e| e.code.as_str());
        if tx_hash.is_none() && NOT_EXECUTED.contains(&code) {
            data["reason"] = json!(code);
            return Self::NotExecuted { data };
        }
        let engine_message = error.map(|e| e.message.as_str()).filter(|m| !m.is_empty()).unwrap_or("execute failed");
        data["engine_message"] = json!(engine_message);
        let revert_data: Option<Bytes> = error.and_then(EngineError::revert_bytes);
        let (message, retry, code) = match &revert_data {
            Some(bytes) => {
                let calls = row.calls();
                data["revert"] = json!(RevertView::of_execute(bytes, &calls));
                let reason = revert::decode_execute(bytes);
                // Someone else executed the address: there is nothing left for us to do.
                let already = matches!(reason, Reason::AlreadyDeployed);
                (
                    reason.describe(&calls),
                    !already,
                    if already { "already_executed".to_owned() } else { format!("engine_{code}") },
                )
            }
            None => (engine_message.to_owned(), true, format!("engine_{code}")),
        };
        Self::Failed { failure: Failure { code, message, revert_data }, retry, data }
    }
}

/// The delay before execute attempt number `attempts + 1`.
pub fn retry_delay_ms(cfg: &AddressesConfig, attempts: i32) -> u64 {
    let exp = cfg.execute_retry_base_ms.saturating_mul(1u64 << attempts.saturating_sub(1).clamp(0, 20));
    exp.min(cfg.execute_retry_cap_ms)
}

/// Applies an execute outcome inside `conn`; returns whether the address changed.
pub async fn apply_outcome(
    conn: &mut sqlx::PgConnection,
    cfg: &AddressesConfig,
    row: &AddressRow,
    job_id: Uuid,
    outcome: ExecuteOutcome,
) -> Result<bool, sqlx::Error> {
    let delay = retry_delay_ms(cfg, row.execute_attempts);
    let changed = match outcome {
        ExecuteOutcome::Included { tx_hash, block_number, data } => {
            store::apply_included(conn, &row.address, job_id, &tx_hash, block_number, data).await?.is_some()
        }
        ExecuteOutcome::Settled { tx_hash, block_number, data } => {
            store::apply_settled(conn, &row.address, job_id, &tx_hash, block_number, data).await?.is_some()
        }
        ExecuteOutcome::Refunded { tx_hash, block_number, amount, data } => {
            store::apply_refunded(conn, &row.address, job_id, &tx_hash, block_number, amount, data).await?.is_some()
        }
        ExecuteOutcome::Failed { failure, retry, data } => {
            let failed =
                store::apply_attempt_failed(conn, &row.address, Some(job_id), &failure, retry.then_some(delay), data)
                    .await?
                    .is_some();
            if failed {
                let revert =
                    failure.revert_data.as_ref().map_or("none".to_owned(), |d| revert::decode_execute(d).label());
                tracing::warn!(address = %row.address, code = %failure.code, revert, message = %failure.message, retry, "execute failed");
                metrics::counter!("execute_execution_failures_total", "code" => failure.code.clone(), "revert" => revert).increment(1);
            }
            failed
        }
        ExecuteOutcome::NotExecuted { data } => {
            tracing::warn!(address = %row.address, "execute never ran; submitting it again");
            store::retry_execute(conn, &row.address, job_id, delay, data).await?.is_some()
        }
        ExecuteOutcome::Pending => false,
    };
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_back_off_to_the_cap() {
        let cfg = AddressesConfig {
            factory_address: String::new(),
            min_expiry_lead_secs: 60,
            max_expiry_lead_secs: 300,
            late_payment_window_secs: 86_400,
            execute_retry_base_ms: 5_000,
            execute_retry_cap_ms: 60_000,
            expiry_margin_secs: 3,
        };
        assert_eq!(retry_delay_ms(&cfg, 1), 5_000);
        assert_eq!(retry_delay_ms(&cfg, 2), 10_000);
        assert_eq!(retry_delay_ms(&cfg, 4), 40_000);
        assert_eq!(retry_delay_ms(&cfg, 5), 60_000);
        assert_eq!(retry_delay_ms(&cfg, 500), 60_000);
        assert_eq!(retry_delay_ms(&cfg, 0), 5_000);
    }
}
